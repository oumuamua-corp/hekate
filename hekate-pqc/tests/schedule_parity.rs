// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

use hekate_core::trace::{ColumnTrace, Trace};
use hekate_math::Block128;
use hekate_pqc::mldsa::{MlDsaChiplet, MlDsaLevel, MlDsaPublicKey, MlDsaSignature};
use hekate_pqc::mlkem::{MlKemChiplet, MlKemLevel};
use hekate_program::Air;
use hekate_program::chiplet::ChipletDef;
use ml_dsa::signature::{Keypair, Signer};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey};
#[allow(deprecated)]
use ml_kem::ExpandedKeyEncoding;
use ml_kem::{B32, DecapsulationKey, MlKem512, MlKem768, MlKem1024};
use rand::{TryRngCore, rngs::OsRng};

type F = Block128;

fn assert_pins_match_trace(def: &ChipletDef<F>, trace: &ColumnTrace) {
    let num_rows = trace.num_rows().expect("uniform column heights");
    let num_vars = num_rows.trailing_zeros() as usize;

    let variants = def
        .expand_variants(trace)
        .expect("virtual expansion of a generated trace");

    for fc in Air::<F>::fixed_columns(def) {
        for row in 0..num_rows {
            assert_eq!(
                variants[fc.col_idx].get_at(row),
                fc.shape.value_at_row(row, num_vars),
                "{} col {} row {}",
                Air::<F>::name(def),
                fc.col_idx,
                row,
            );
        }
    }
}

fn assert_composite_pins_match(defs: &[ChipletDef<F>], traces: &[ColumnTrace]) {
    assert_eq!(defs.len(), traces.len());

    for (def, trace) in defs.iter().zip(traces) {
        assert_pins_match_trace(def, trace);
    }
}

macro_rules! mlkem_parity {
    ($fn:ident, $kem:ty, $level:expr) => {
        #[test]
        #[allow(deprecated)]
        fn $fn() {
            let mut seed = [0u8; 64];
            OsRng.try_fill_bytes(&mut seed).unwrap();

            let dk = DecapsulationKey::<$kem>::from_seed(seed.into());

            let mut m = [0u8; 32];
            OsRng.try_fill_bytes(&mut m).unwrap();

            let (ct, _ss) = dk
                .encapsulation_key()
                .encapsulate_deterministic(&B32::from(m));

            let chiplet = MlKemChiplet::<F>::new($level);
            let (traces, _secret) = chiplet
                .generate_traces(ct.as_slice(), dk.to_expanded_bytes().as_slice())
                .expect("trace generation");

            let defs = chiplet.composite().flatten_defs().expect("flatten defs");

            assert_composite_pins_match(&defs, &traces);
        }
    };
}

mlkem_parity!(mlkem_512_pins_match_trace, MlKem512, MlKemLevel::MLKEM_512);
mlkem_parity!(mlkem_768_pins_match_trace, MlKem768, MlKemLevel::MLKEM_768);
mlkem_parity!(
    mlkem_1024_pins_match_trace,
    MlKem1024,
    MlKemLevel::MLKEM_1024
);

macro_rules! mldsa_parity {
    ($fn:ident, $dsa:ty, $level:expr, $lengths:expr) => {
        #[test]
        fn $fn() {
            let mut xi = [0u8; 32];
            OsRng.try_fill_bytes(&mut xi).unwrap();

            let key = SigningKey::<$dsa>::from_seed(&ml_dsa::B32::from(xi));
            let pk_bytes = key.verifying_key().encode();

            let level = $level;
            let pk = MlDsaPublicKey::from_bytes(level, pk_bytes.as_slice());

            for msg_len in $lengths {
                let msg = vec![0x5au8; msg_len];
                let sig_bytes = key.sign(&msg).encode();

                let sig = MlDsaSignature::from_bytes(level, sig_bytes.as_slice())
                    .expect("signature parse");

                let chiplet = MlDsaChiplet::<F>::new(level, msg_len);
                let traces = chiplet
                    .generate_traces(&pk, &sig, &msg)
                    .expect("trace generation");

                let defs = chiplet.composite().flatten_defs().expect("flatten defs");

                assert_composite_pins_match(&defs, &traces);
            }
        }
    };
}

mldsa_parity!(
    mldsa_44_pins_match_trace,
    MlDsa44,
    MlDsaLevel::MLDSA_44,
    [64]
);
mldsa_parity!(
    mldsa_87_pins_match_trace,
    MlDsa87,
    MlDsaLevel::MLDSA_87,
    [64]
);
mldsa_parity!(
    mldsa_65_pins_match_trace,
    MlDsa65,
    MlDsaLevel::MLDSA_65,
    [64, 69, 70, 206]
);

#[test]
fn long_messages_widen_the_circuit() {
    for level in [
        MlDsaLevel::MLDSA_44,
        MlDsaLevel::MLDSA_65,
        MlDsaLevel::MLDSA_87,
    ] {
        for msg_len in [16_662usize, 65_536, 1 << 20] {
            MlDsaChiplet::<F>::new(level, msg_len)
                .composite()
                .flatten_defs()
                .expect("composite must build for any message length");
        }
    }
}
