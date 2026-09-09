// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

//! ML-DSA signature verification
//! proof (FIPS 204).
//!
//! Usage:
//! HEKATE_LEVEL=[44|65|87] mldsa
//!
//! Proof existence IS the verdict:
//! an honest transcript requires
//! c̃ == c̃'. Invalid signatures yield
//! an unsatisfiable constraint system,
//! no valid proof can be constructed,
//! so no verdict-bit column is needed.

#[path = "common/mod.rs"]
mod common;

use hekate::core::trace::TraceBuilder;
use hekate::crypto::DefaultHasher;
use hekate::crypto::transcript::Transcript;
use hekate::math::{Bit, Block32, Block128};
use hekate_core::config::Config;
use hekate_core::errors;
use hekate_math::TowerField;
use hekate_pqc::mldsa::{
    self, CpuMlDsaColumns, MlDsaChiplet, MlDsaLevel, MlDsaPublicKey, MlDsaSignature,
};
use hekate_program::circuit::{Circuit, CircuitProgram};
use hekate_program::{FixedShape, ProgramInstance, ProgramWitness};
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

/// The commitment hash words are read on the rows
/// the pinned `SELECTOR` forces onto the data bus.
fn build_program(
    cpu_rows: usize,
    num_public: usize,
    mldsa: &MlDsaChiplet<F>,
) -> errors::Result<CircuitProgram<F>> {
    let mut cx = Circuit::<F>::new("MlDsaVerifyProgram", cpu_rows)?;
    let cpu = cx.schema(&CpuMlDsaColumns::build_layout());

    let data = cpu.at(CpuMlDsaColumns::DATA);
    let selector = cpu.at(CpuMlDsaColumns::SELECTOR);

    cx.bus(mldsa::MLDSA_DATA_BUS_ID, mldsa::cpu_data_spec());

    cx.fix(
        selector,
        FixedShape::Cadence {
            stride: 1,
            count: num_public,
            origin: 0,
            values: vec![F::ONE],
        },
    );

    for row in 0..num_public {
        cx.publish(data, row);
    }

    for def in mldsa.composite().flatten_defs()? {
        cx.attach(def);
    }

    cx.compile()
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
    let mldsa_chiplet = MlDsaChiplet::<F>::new(level, msg.len());

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
    let air = build_program(cpu_num_rows, ct_public.len(), &mldsa_chiplet).unwrap();

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

fn main() {
    let level_arg = common::level("65");

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
            eprintln!("Usage: HEKATE_LEVEL=[44|65|87] mldsa (got {:?})", other);
            std::process::exit(1);
        }
    }
}
