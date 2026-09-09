// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

//! ML-KEM-768 Decapsulation Proof Example.
//!
//! Proves ML-KEM-768 decapsulation (FIPS 203)
//! using the composite chiplet architecture.
//!
//! Pipeline:
//! 1. Generate keypair
//! 2. Encapsulate (create ciphertext + shared secret)
//! 3. Decapsulate (recover shared secret) with traced ops
//! 4. Generate chiplet traces
//! 5. Prove and verify

#[path = "common/mod.rs"]
mod common;

use hekate::core::trace::TraceBuilder;
use hekate::crypto::DefaultHasher;
use hekate::crypto::transcript::Transcript;
use hekate::math::{Bit, Block32, Block128};
use hekate_core::config::Config;
use hekate_core::errors;
use hekate_math::TowerField;
use hekate_pqc::mlkem::{self, CpuMlKemColumns, MlKemChiplet, MlKemLevel};
use hekate_program::circuit::{Circuit, CircuitProgram};
use hekate_program::{FixedShape, ProgramInstance, ProgramWitness};
use hekate_prover_sys::prove;
use hekate_verifier::HekateVerifier;
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::kem::Encapsulate;
use ml_kem::{DecapsulationKey, MlKem768};
use rand::TryRngCore;
use rand::rngs::OsRng;

type F = Block128;
type H = DefaultHasher;

// =================================================================
// ML-KEM Decapsulation Program
// =================================================================

/// The ciphertext words are read on the rows the
/// pinned `SELECTOR` forces onto the data bus.
fn build_program(
    cpu_rows: usize,
    num_public: usize,
    mlkem: &MlKemChiplet<F>,
) -> errors::Result<CircuitProgram<F>> {
    let mut cx = Circuit::<F>::new("MlKemDecapsProgram", cpu_rows)?;
    let cpu = cx.schema(&CpuMlKemColumns::build_layout());

    let data = cpu.at(CpuMlKemColumns::DATA);
    let selector = cpu.at(CpuMlKemColumns::SELECTOR);
    let ss_selector = cpu.at(CpuMlKemColumns::SS_SELECTOR);

    cx.bus(mlkem::MLKEM_DATA_BUS_ID, mlkem::cpu_data_spec());
    cx.bus(mlkem::MLKEM_SS_BUS_ID, mlkem::cpu_ss_spec());

    cx.fix(
        selector,
        FixedShape::Cadence {
            stride: 1,
            count: num_public,
            origin: 0,
            values: vec![F::ONE],
        },
    );

    cx.fix(ss_selector, FixedShape::Sparse(vec![(num_public, F::ONE)]));

    for row in 0..num_public {
        cx.publish(data, row);
    }

    for def in mlkem.composite().flatten_defs()? {
        cx.attach(def);
    }

    cx.compile()
}

// =================================================================
// Main
// =================================================================

fn main() {
    common::init("ML-KEM-768 Decapsulation");

    let cpu_num_rows: usize = 1 << 10; // 1024

    // Phase 1:
    // NIST reference keygen (RustCrypto ml-kem)
    let dk = common::phase("Key Generation (NIST)", || {
        let mut seed = [0u8; 64];
        OsRng.try_fill_bytes(&mut seed).unwrap();

        DecapsulationKey::<MlKem768>::from_seed(seed.into())
    });

    // Phase 2:
    // NIST reference encapsulation
    let (ct_enc, ss_enc) = common::phase("Encapsulation (NIST)", || {
        dk.encapsulation_key().encapsulate()
    });

    // The chiplet consumes the expanded FIPS 203
    // decapsulation key, not the 64-byte seed.
    #[allow(deprecated)]
    let dk_expanded = dk.to_expanded_bytes();

    let ct = ct_enc.as_slice();
    let sk = dk_expanded.as_slice();

    let expected_ss = ss_enc.as_slice();

    println!("  Ciphertext:     {} bytes", ct.len());

    // Phase 3:
    // Generate traces.
    let mlkem_chiplet = MlKemChiplet::<F>::new(MlKemLevel::MLKEM_768);

    let (cpu_trace, chiplet_traces, shared_secret) = common::phase("Trace Generation", || {
        let (chiplet_traces, shared_secret) = mlkem_chiplet
            .generate_traces(ct, sk)
            .expect("Trace generation failed");

        let layout = CpuMlKemColumns::build_layout();
        let cpu_vars = cpu_num_rows.trailing_zeros() as usize;

        let mut cpu_tb = TraceBuilder::new(&layout, cpu_vars).expect("CPU trace build failed");

        for (i, chunk) in ct.chunks(4).enumerate() {
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);

            cpu_tb
                .set_b32(
                    CpuMlKemColumns::DATA,
                    i,
                    Block32::from(u32::from_le_bytes(buf)),
                )
                .expect("CPU DATA set");
            cpu_tb
                .set_bit(CpuMlKemColumns::SELECTOR, i, Bit::ONE)
                .expect("CPU SELECTOR set");
        }

        let ss_row = ct.chunks(4).count();
        for i in 0..4 {
            let lo = u32::from_le_bytes(shared_secret[i * 8..i * 8 + 4].try_into().unwrap());
            let hi = u32::from_le_bytes(shared_secret[i * 8 + 4..i * 8 + 8].try_into().unwrap());

            cpu_tb
                .set_b32(CpuMlKemColumns::SS_DATA + i, ss_row, Block32::from(lo))
                .expect("CPU SS_DATA lo set");
            cpu_tb
                .set_b32(CpuMlKemColumns::SS_DATA + 4 + i, ss_row, Block32::from(hi))
                .expect("CPU SS_DATA hi set");
        }

        cpu_tb
            .set_bit(CpuMlKemColumns::SS_SELECTOR, ss_row, Bit::ONE)
            .expect("CPU SS_SELECTOR set");

        let cpu_trace = cpu_tb.build();

        (cpu_trace, chiplet_traces, shared_secret)
    });

    assert_eq!(
        &shared_secret, expected_ss,
        "Shared secret mismatch vs NIST reference"
    );

    println!("  Shared secret:  matches encapsulation");
    println!("  Chiplet traces: {}", chiplet_traces.len());

    let ct_public: Vec<F> = ct
        .chunks(4)
        .map(|chunk| {
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);

            Block128(u32::from_le_bytes(buf) as u128)
        })
        .collect();

    println!(
        "  Public inputs:  {} (ct as {} × B32)",
        ct_public.len(),
        ct_public.len()
    );

    // Phase 5:
    // Prove
    let air = build_program(cpu_num_rows, ct_public.len(), &mlkem_chiplet).unwrap();

    let instance = ProgramInstance::new(cpu_num_rows, ct_public);
    let witness = ProgramWitness::new(cpu_trace).with_chiplets(chiplet_traces);

    let config = Config {
        zero_knowledge: common::zero_knowledge(),
        ..Config::default()
    };

    let mut blinding_seed = [0u8; 32];
    OsRng.try_fill_bytes(&mut blinding_seed).unwrap();

    let proof = common::phase("Proving", || {
        prove(
            b"ML-KEM-768_Decaps",
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

    // Phase 6:
    // Verify
    let mut verifier_transcript = Transcript::<H>::new(b"ML-KEM-768_Decaps");
    let pinned_id = common::audited_id(&air);

    let is_valid = common::phase_with_mem("Verifying", || {
        HekateVerifier::<F, H>::verify(
            &pinned_id,
            &air,
            &instance,
            &proof,
            &mut verifier_transcript,
            &config,
        )
        .expect("Verifier failed")
    });

    common::result(is_valid);
}
