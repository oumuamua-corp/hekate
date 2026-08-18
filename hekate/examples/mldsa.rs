// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

//! ML-DSA signature verification
//! proof (FIPS 204).
//!
//! Usage:
//! mldsa [44|65|87]
//!
//! Proof existence IS the verdict:
//! an honest transcript requires
//! c̃ == c̃'. Invalid signatures yield
//! an unsatisfiable constraint system,
//! no valid proof can be constructed,
//! so no verdict-bit column is needed.

#[path = "common/mod.rs"]
mod common;

use hekate::core::trace::{ColumnType, TraceBuilder};
use hekate::crypto::DefaultHasher;
use hekate::crypto::transcript::Transcript;
use hekate::math::{Bit, Block32, Block128};
use hekate_core::config::Config;
use hekate_math::TowerField;
use hekate_pqc::mldsa::{
    self, CpuMlDsaColumns, CpuMlDsaUnit, MlDsaChiplet, MlDsaLevel, MlDsaPublicKey, MlDsaSignature,
};
use hekate_program::chiplet::ChipletDef;
use hekate_program::constraint::builder::ConstraintSystem;
use hekate_program::constraint::{BoundaryConstraint, ConstraintAst};
use hekate_program::permutation::PermutationCheckSpec;
use hekate_program::{Air, Program, ProgramInstance, ProgramWitness};
use hekate_prover_sys::prove;
use hekate_verifier::HekateVerifier;
use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{B32, MlDsa44, MlDsa65, MlDsa87, SigningKey};
use rand::TryRngCore;
use rand::rngs::OsRng;

type F = Block128;
type H = DefaultHasher;

// =================================================================
// ML-DSA Verification Program
// =================================================================

#[derive(Clone)]
struct MlDsaVerifyProgram {
    mldsa: MlDsaChiplet<F>,
    num_public: usize,
}

impl Air<F> for MlDsaVerifyProgram {
    fn name(&self) -> String {
        "MlDsaVerifyProgram".into()
    }

    fn num_columns(&self) -> usize {
        CpuMlDsaUnit::num_columns()
    }

    fn boundary_constraints(&self) -> Vec<BoundaryConstraint<F>> {
        (0..self.num_public)
            .map(|k| BoundaryConstraint::with_public_input(CpuMlDsaColumns::DATA, k, k))
            .collect()
    }

    fn column_layout(&self) -> &[ColumnType] {
        Box::leak(CpuMlDsaColumns::build_layout().into_boxed_slice())
    }

    fn permutation_checks(&self) -> Vec<(String, PermutationCheckSpec)> {
        vec![(
            mldsa::MLDSA_DATA_BUS_ID.into(),
            CpuMlDsaUnit::linking_spec(),
        )]
    }

    fn constraint_ast(&self) -> ConstraintAst<F> {
        let cs = ConstraintSystem::<F>::new();
        cs.assert_boolean(cs.col(CpuMlDsaColumns::SELECTOR));

        cs.build()
    }
}

impl Program<F> for MlDsaVerifyProgram {
    fn num_public_inputs(&self) -> usize {
        self.num_public
    }

    fn chiplet_defs(&self) -> hekate_core::errors::Result<Vec<ChipletDef<F>>> {
        self.mldsa.composite().flatten_defs()
    }
}

// =================================================================
// Main
// =================================================================

fn run_mldsa(label: &str, level: MlDsaLevel, pk_bytes: &[u8], sig_bytes: &[u8], msg: &[u8]) {
    common::init(label);

    let cpu_num_rows: usize = 1 << 10;
    let domain = b"ML-DSA_Verify";

    println!("  Public key:     {} bytes", pk_bytes.len());
    println!("  Signature:      {} bytes", sig_bytes.len());
    println!("  Message:        {} bytes", msg.len());

    let pk = MlDsaPublicKey::from_bytes(level, pk_bytes);
    let sig = MlDsaSignature::from_bytes(level, sig_bytes).expect("NIST signature must parse");

    // Phase 1:
    // Generate traces.
    let mldsa_chiplet = MlDsaChiplet::<F>::new(level);

    let (cpu_trace, chiplet_traces, io_public) = common::phase("Trace Generation", || {
        let chiplet_traces = mldsa_chiplet
            .generate_traces(&pk, &sig, msg)
            .expect("Trace generation failed");

        let layout = CpuMlDsaColumns::build_layout();
        let cpu_vars = cpu_num_rows.trailing_zeros() as usize;

        let mut cpu_tb = TraceBuilder::new(&layout, cpu_vars).expect("CPU trace build failed");

        // Public input:
        // c̃ from the signature, B32-aligned.
        let mut io_buf = sig.c_tilde.clone();
        while !io_buf.len().is_multiple_of(4) {
            io_buf.push(0);
        }

        for (i, chunk) in io_buf.chunks(4).enumerate() {
            let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

            cpu_tb
                .set_b32(CpuMlDsaColumns::DATA, i, Block32::from(val))
                .expect("CPU DATA set");
            cpu_tb
                .set_bit(CpuMlDsaColumns::SELECTOR, i, Bit::ONE)
                .expect("CPU SELECTOR set");
        }

        let cpu_trace = cpu_tb.build();

        (cpu_trace, chiplet_traces, io_buf)
    });

    println!("  Chiplet traces: {}", chiplet_traces.len());

    let ct_public: Vec<F> = io_public
        .chunks(4)
        .map(|chunk| Block128(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u128))
        .collect();

    println!(
        "  Public inputs:  {} (c̃ as {} × B32)",
        ct_public.len(),
        ct_public.len()
    );

    // Phase 2:
    // Prove
    let air = MlDsaVerifyProgram {
        mldsa: mldsa_chiplet,
        num_public: ct_public.len(),
    };

    let instance = ProgramInstance::new(cpu_num_rows, ct_public);
    let witness = ProgramWitness::new(cpu_trace).with_chiplets(chiplet_traces);

    let config = Config {
        zero_knowledge: true,
        ..Config::default()
    };

    let mut blinding_seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut blinding_seed).unwrap();

    let proof = common::phase("Proving", || {
        prove(
            domain,
            &air,
            &instance,
            &witness,
            &config,
            blinding_seed,
            None,
        )
        .expect("Prover failed")
    });

    common::proof_breakdown(&proof);

    // Phase 3:
    // Verify
    let mut verifier_transcript = Transcript::<H>::new(domain);
    let is_valid = common::phase_with_mem("Verifying", || {
        HekateVerifier::<F, H>::verify(&air, &instance, &proof, &mut verifier_transcript, &config)
            .expect("Verifier failed")
    });

    common::result(is_valid);
}

fn main() {
    let level_arg = std::env::args().nth(1).unwrap_or_else(|| "65".to_string());

    let mut seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut seed).unwrap();

    let xi = B32::from(seed);

    match level_arg.as_str() {
        "44" => {
            let key = SigningKey::<MlDsa44>::from_seed(&xi);
            let msg = b"Hekate ML-DSA-44 verification example";
            let pk = key.verifying_key().encode();
            let sig = key.sign(msg).encode();

            run_mldsa(
                "ML-DSA-44 Signature Verification",
                MlDsaLevel::MLDSA_44,
                &pk,
                &sig,
                msg,
            );
        }
        "65" => {
            let key = SigningKey::<MlDsa65>::from_seed(&xi);
            let msg = b"Hekate ML-DSA-65 verification example";
            let pk = key.verifying_key().encode();
            let sig = key.sign(msg).encode();

            run_mldsa(
                "ML-DSA-65 Signature Verification",
                MlDsaLevel::MLDSA_65,
                &pk,
                &sig,
                msg,
            );
        }
        "87" => {
            let key = SigningKey::<MlDsa87>::from_seed(&xi);
            let msg = b"Hekate ML-DSA-87 verification example";
            let pk = key.verifying_key().encode();
            let sig = key.sign(msg).encode();

            run_mldsa(
                "ML-DSA-87 Signature Verification",
                MlDsaLevel::MLDSA_87,
                &pk,
                &sig,
                msg,
            );
        }
        other => {
            eprintln!("Usage: mldsa [44|65|87] (got {:?})", other);
            std::process::exit(1);
        }
    }
}
