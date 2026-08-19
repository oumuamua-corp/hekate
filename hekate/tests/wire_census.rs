// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

//! Every field element a proof publishes carries a
//! hiding mechanism, and the padded ones are exactly
//! the scalars the verifier's pad accounting covers.

use hekate::core::config::Config;
use hekate::core::poly::univariate::UnivariatePoly;
use hekate::core::proofs::{
    EvalBatchProof, InnerProof, LogUpAux, OuterOpening, OuterProof, SumcheckProof,
};
use hekate::core::trace::{ColumnTrace, ColumnType, TraceColumn};
use hekate::crypto::DefaultHasher;
use hekate::crypto::transcript::Transcript;
use hekate::math::{Bit, Block32, Block64, Block128, TowerField};
use hekate_core::trace::{IntoTraceColumn, TraceBuilder};
use hekate_gadgets::{CpuMemColumns, CpuMemoryUnit, MemoryEvent, RamChiplet, generate_ram_trace};
use hekate_keccak::{
    CpuKeccakColumns, CpuKeccakUnit, KeccakChiplet, KeccakWitness, generate_keccak_trace,
};
use hekate_program::chiplet::ChipletDef;
use hekate_program::constraint::builder::ConstraintSystem;
use hekate_program::constraint::{BoundaryConstraint, ConstraintAst};
use hekate_program::outer::OuterStatement;
use hekate_program::permutation::PermutationCheckSpec;
use hekate_program::{Air, FixedColumn, Program, ProgramInstance, ProgramWitness};
use hekate_prover_sys::prove;
use hekate_verifier::HekateVerifier;

type F = Block128;
type H = DefaultHasher;

const NUM_VARS: usize = 4;

#[derive(Clone)]
struct StepAir;

impl Air<F> for StepAir {
    fn num_columns(&self) -> usize {
        2
    }

    fn column_layout(&self) -> &'static [ColumnType] {
        &[ColumnType::B32, ColumnType::Bit]
    }

    fn fixed_columns(&self) -> Vec<FixedColumn<F>> {
        vec![FixedColumn::last_row(1)]
    }

    fn constraint_ast(&self) -> ConstraintAst<F> {
        let cs = ConstraintSystem::<F>::new();
        let val = cs.col(0);
        let q = cs.col(1);

        cs.constrain(q * (cs.next(0) + val));

        cs.build()
    }
}

impl Program<F> for StepAir {}

#[derive(Clone)]
struct RamAir {
    num_rows: usize,
}

impl Air<F> for RamAir {
    fn num_columns(&self) -> usize {
        CpuMemColumns::NUM_COLUMNS
    }

    fn column_layout(&self) -> &[ColumnType] {
        static LAYOUT: std::sync::OnceLock<Vec<ColumnType>> = std::sync::OnceLock::new();
        LAYOUT.get_or_init(CpuMemColumns::build_layout)
    }

    fn permutation_checks(&self) -> Vec<(String, PermutationCheckSpec)> {
        vec![(RamChiplet::BUS_ID.into(), CpuMemoryUnit::linking_spec())]
    }

    fn constraint_ast(&self) -> ConstraintAst<F> {
        let cs = ConstraintSystem::<F>::new();
        cs.assert_boolean(cs.col(CpuMemColumns::SELECTOR));
        cs.assert_boolean(cs.col(CpuMemColumns::IS_WRITE));

        cs.build()
    }
}

impl Program<F> for RamAir {
    fn chiplet_defs(&self) -> hekate_core::errors::Result<Vec<ChipletDef<F>>> {
        Ok(vec![ChipletDef::from_air(&RamChiplet::new(self.num_rows))?])
    }
}

#[derive(Clone)]
struct KeccakCpu {
    chiplet_rows: usize,
}

impl Air<F> for KeccakCpu {
    fn num_columns(&self) -> usize {
        CpuKeccakColumns::NUM_COLUMNS
    }

    fn boundary_constraints(&self) -> Vec<BoundaryConstraint<F>> {
        vec![CpuKeccakUnit::direction_boundary(0)]
    }

    fn column_layout(&self) -> &[ColumnType] {
        static LAYOUT: std::sync::OnceLock<Vec<ColumnType>> = std::sync::OnceLock::new();
        LAYOUT.get_or_init(CpuKeccakColumns::build_layout)
    }

    fn permutation_checks(&self) -> Vec<(String, PermutationCheckSpec)> {
        vec![(KeccakChiplet::BUS_ID.into(), CpuKeccakUnit::linking_spec())]
    }

    fn constraint_ast(&self) -> ConstraintAst<F> {
        let cs = ConstraintSystem::<F>::new();
        CpuKeccakUnit::constrain(&cs, 0);

        cs.build()
    }
}

impl Program<F> for KeccakCpu {
    fn chiplet_defs(&self) -> hekate_core::errors::Result<Vec<ChipletDef<F>>> {
        Ok(vec![ChipletDef::from_air(&KeccakChiplet::new(
            self.chiplet_rows,
        ))?])
    }
}

#[derive(Default)]
struct Census {
    padded: usize,
    running_claim: usize,
    whole_fold: usize,
    ring_fold: usize,
    outer: usize,
    challenge_point: usize,
    opened_bytes: usize,
}

fn config() -> Config {
    Config {
        num_queries: 4,
        min_security_bits: 0,
        zero_knowledge: true,
        ldt_support_size: 4,
        ..Config::default()
    }
}

fn sumcheck(proof: &SumcheckProof<F>, census: &mut Census) -> usize {
    let SumcheckProof {
        round_polys,
        claimed_evaluation: _,
    } = proof;

    for UnivariatePoly { evals } in round_polys {
        census.padded += evals.len();
    }

    census.running_claim += 1;

    round_polys.len()
}

fn opening(opening: &OuterOpening<F>) -> usize {
    let OuterOpening {
        columns: _,
        values,
        siblings: _,
    } = opening;

    values.len()
}

fn eval_batch(proof: &EvalBatchProof<F>, census: &mut Census) {
    let EvalBatchProof {
        sumcheck_proof,
        ldt_proof,
        point_evaluation,
        tensor_vec,
        tensor_vec_ring,
    } = proof;

    let rounds = sumcheck(sumcheck_proof, census);

    assert_eq!(point_evaluation.0.len(), rounds);

    census.opened_bytes += ldt_proof.opened_columns.iter().map(Vec::len).sum::<usize>();
    census.challenge_point += point_evaluation.0.len();
    census.padded += point_evaluation.1.len();
    census.whole_fold += tensor_vec.len();
    census.ring_fold += tensor_vec_ring.len();
}

fn logup(aux: &LogUpAux<F>, census: &mut Census) {
    let LogUpAux {
        h_evals,
        claimed_sums,
        h_commitment: _,
        h_eval_proof,
    } = aux;

    census.padded += h_evals.len() + claimed_sums.len();

    if let Some(proof) = h_eval_proof {
        eval_batch(proof, census);
    }
}

fn outer(proof: &OuterProof<F>, census: &mut Census) {
    let OuterProof {
        aux_root: _,
        interleaved,
        linear,
        quadratic,
        pad_opening,
        aux_opening,
    } = proof;

    census.outer += interleaved.len() + linear.len() + quadratic.len();
    census.outer += opening(pad_opening) + opening(aux_opening);
}

/// No `..` in any wire pattern: a new field element
/// on the wire must stop this compiling until it is
/// classified. `BrakedownProof` is exempt, a private
/// marker blocks the pattern outside `hekate-core`.
fn census(proof: &InnerProof<F>) -> Census {
    let InnerProof {
        trace_commitment: _,
        zerocheck_proof,
        main_logup_aux,
        eval_proof,
        chiplet_commitments: _,
        chiplet_zerocheck_proofs,
        chiplet_logup_aux,
        chiplet_eval_proofs,
        pad_root: _,
        outer: outer_proof,
    } = proof;

    let mut census = Census::default();

    sumcheck(zerocheck_proof, &mut census);
    logup(main_logup_aux, &mut census);
    eval_batch(eval_proof, &mut census);

    for proof in chiplet_zerocheck_proofs {
        sumcheck(proof, &mut census);
    }

    for aux in chiplet_logup_aux {
        logup(aux, &mut census);
    }

    for proof in chiplet_eval_proofs {
        eval_batch(proof, &mut census);
    }

    if let Some(proof) = outer_proof {
        outer(proof, &mut census);
    }

    census
}

/// The `h` opening's bus claims ride the `h_eval`
/// entries, hence one repeat per bus of a bus table.
fn pad_reuse<P: Program<F>>(program: &P) -> usize {
    program
        .chiplet_defs()
        .unwrap()
        .iter()
        .map(|def| def.permutation_checks().len())
        .sum::<usize>()
        + program.permutation_checks().len()
}

fn pad_budget<P: Program<F> + Sync>(program: &P, chiplet_num_vars: &[usize]) -> usize {
    let statement =
        OuterStatement::for_program(program, NUM_VARS, chiplet_num_vars, config().blind_units())
            .unwrap();

    statement.masked_scalars + pad_reuse(program)
}

#[test]
fn every_scalar_of_bus_free_proof_is_accounted() {
    let num_rows = 1 << NUM_VARS;

    let mut q = vec![Bit::ONE; num_rows];
    q[num_rows - 1] = Bit::ZERO;

    let mut trace = ColumnTrace::new(NUM_VARS).unwrap();
    trace
        .add_column(vec![Block32::from(10u32); num_rows].into_trace_column())
        .unwrap();
    trace.add_column(TraceColumn::Bit(q)).unwrap();

    let instance = ProgramInstance::new(num_rows, vec![]);
    let witness = ProgramWitness::new(trace);

    let proof = prove(
        b"Census_Step",
        &StepAir,
        &instance,
        &witness,
        &config(),
        [0x71u8; 32],
        None,
    )
    .unwrap();

    let mut vt = Transcript::<H>::new(b"Census_Step");
    assert!(
        HekateVerifier::<F, H>::verify(&StepAir, &instance, &proof, &mut vt, &config()).unwrap()
    );

    let counted = census(&proof);

    assert_eq!(counted.padded, pad_budget(&StepAir, &[]));
    assert_eq!(counted.running_claim, 2);
    assert_eq!(counted.ring_fold, 0);
    assert!(counted.padded > 0);
    assert!(counted.whole_fold > 0);
    assert!(counted.outer > 0);
    assert!(counted.challenge_point > 0);
    assert!(counted.opened_bytes > 0);
}

#[test]
fn every_scalar_of_bus_proof_is_accounted() {
    let num_rows = 1 << NUM_VARS;
    let events = vec![
        MemoryEvent::write(0x1000, 0, 42),
        MemoryEvent::write(0x2000, 1, 99),
        MemoryEvent::read(0x1000, 2, 42),
        MemoryEvent::read(0x2000, 3, 99),
    ];

    let mut tb = TraceBuilder::new(&CpuMemColumns::build_layout(), NUM_VARS).unwrap();
    for (i, event) in events.iter().enumerate() {
        let addr = event.addr_bytes();
        let val = event.val_bytes();

        for j in 0..4 {
            tb.set_b32(CpuMemColumns::ADDR_B0 + j, i, Block32::from(addr[j] as u32))
                .unwrap();
            tb.set_b32(CpuMemColumns::VAL_B0 + j, i, Block32::from(val[j] as u32))
                .unwrap();
        }

        let is_write = match event.is_write {
            true => Bit::ONE,
            false => Bit::ZERO,
        };

        tb.set_bit(CpuMemColumns::IS_WRITE, i, is_write).unwrap();
        tb.set_bit(CpuMemColumns::SELECTOR, i, Bit::ONE).unwrap();
    }

    let air = RamAir { num_rows };
    let instance = ProgramInstance::new(num_rows, vec![]);
    let witness = ProgramWitness::new(tb.build())
        .with_chiplets(vec![generate_ram_trace(&events, num_rows).unwrap()]);

    let proof = prove(
        b"Census_Ram",
        &air,
        &instance,
        &witness,
        &config(),
        [0x72u8; 32],
        None,
    )
    .unwrap();

    let mut vt = Transcript::<H>::new(b"Census_Ram");
    assert!(HekateVerifier::<F, H>::verify(&air, &instance, &proof, &mut vt, &config()).unwrap());

    let counted = census(&proof);
    let budget = pad_budget(&air, &[NUM_VARS]);

    assert!(pad_reuse(&air) > 0);
    assert_eq!(counted.padded, budget);
    assert_eq!(counted.running_claim, 6);
    assert!(counted.padded > 0);
    assert!(counted.whole_fold > 0);
    assert!(counted.ring_fold > 0);
    assert!(counted.outer > 0);
    assert!(counted.challenge_point > 0);
    assert!(counted.opened_bytes > 0);

    let mut ghost_sum = proof.clone();
    ghost_sum
        .main_logup_aux
        .claimed_sums
        .push(("ghost".into(), F::ONE));

    let mut ghost_eval = proof.clone();
    ghost_eval
        .main_logup_aux
        .h_evals
        .push(("ghost".into(), F::ONE));

    assert_ne!(census(&ghost_sum).padded, budget);
    assert_ne!(census(&ghost_eval).padded, budget);
}

#[test]
fn every_scalar_of_virtually_packed_proof_is_accounted() {
    const CHIPLET_VARS: usize = 5;

    let chiplet_rows = 1 << CHIPLET_VARS;
    let num_rows = 1 << NUM_VARS;

    let state: [u64; 25] = core::array::from_fn(|i| 0x0706_0504_0302_0100u64 ^ (i as u64 + 1));
    let permuted = KeccakChiplet::ROUND_CONSTANTS
        .iter()
        .fold(state, |acc, &rc| KeccakWitness::keccak_f_round(acc, rc));

    let mut tb = TraceBuilder::new(&CpuKeccakColumns::build_layout(), NUM_VARS).unwrap();
    for (i, (input, output)) in state.iter().zip(&permuted).enumerate() {
        tb.set_b64(CpuKeccakColumns::LANES + i, 0, Block64::from(*input))
            .unwrap();
        tb.set_b64(CpuKeccakColumns::LANES + i, 1, Block64::from(*output))
            .unwrap();
    }

    tb.set_bit(CpuKeccakColumns::SELECTOR, 0, Bit::ONE).unwrap();
    tb.set_bit(CpuKeccakColumns::SELECTOR, 1, Bit::ONE).unwrap();
    tb.set_bit(CpuKeccakColumns::IS_OUTPUT, 1, Bit::ONE)
        .unwrap();

    let calls = [core::array::from_fn::<Block64, 25, _>(|i| {
        Block64::from(state[i])
    })];
    let chiplet = generate_keccak_trace(&calls, Some(&[(0, 1)]), chiplet_rows).unwrap();

    let air = KeccakCpu { chiplet_rows };
    let instance = ProgramInstance::new(num_rows, vec![]);
    let witness = ProgramWitness::new(tb.build()).with_chiplets(vec![chiplet]);

    let proof = prove(
        b"Census_Keccak",
        &air,
        &instance,
        &witness,
        &config(),
        [0x73u8; 32],
        None,
    )
    .unwrap();

    let mut vt = Transcript::<H>::new(b"Census_Keccak");
    assert!(HekateVerifier::<F, H>::verify(&air, &instance, &proof, &mut vt, &config()).unwrap());

    let counted = census(&proof);

    assert_eq!(counted.padded, pad_budget(&air, &[CHIPLET_VARS]));
    assert_eq!(counted.running_claim, 6);
    assert!(counted.padded > 0);
    assert!(counted.whole_fold > 0);
    assert!(counted.ring_fold > 0);
    assert!(counted.outer > 0);
    assert!(counted.challenge_point > 0);
    assert!(counted.opened_bytes > 0);
}
