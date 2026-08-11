// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod common;

use common::{
    AES_ROWS, DECOY_IDX, FIPS128_CIPHER, FIPS128_KEY, FREE_CIPHER, IN_ROW, OUT_ROW,
    assert_air_clean, assert_air_violated, b8_at, build_cpu_trace_128, copy_b8_block,
    deactivate_rom, fips_call_128, make_program_128, prove_and_verify, set_b8, set_b16, set_b32,
    set_bit, whitened_128,
};
use hekate_aes::{
    CpuAes128Columns, PhysAes128Columns,
    trace::{Aes128Call, expand_key, generate_aes_trace},
};
use hekate_core::trace::ColumnTrace;
use hekate_math::{Bit, TowerField};

const ACTIVE_ROWS: usize = 10;
const OUTPUT_ROW: usize = 10;

/// Oracle over the crate's own generator,
/// not a second AES implementation.
fn aes_rounds(state: &[u8; 16]) -> [u8; 16] {
    let round_keys = expand_key(&FIPS128_KEY);
    let plaintext: [u8; 16] = core::array::from_fn(|j| state[j] ^ round_keys[0][j]);

    let trace = generate_aes_trace(
        &[Aes128Call {
            key: FIPS128_KEY,
            plaintext,
            round_keys,
        }],
        None,
        AES_ROWS,
    )
    .unwrap();

    core::array::from_fn(|j| b8_at(&trace, PhysAes128Columns::P_STATE_IN + j, OUTPUT_ROW))
}

/// Clears the selectors and every cell pinned off its gate.
fn make_idle(aes: &mut ColumnTrace, row: usize) {
    for col in [
        PhysAes128Columns::P_S_ROUND,
        PhysAes128Columns::P_S_FINAL,
        PhysAes128Columns::P_S_IN_OUT,
        PhysAes128Columns::P_S_ACTIVE,
        PhysAes128Columns::P_S_INPUT,
    ] {
        set_bit(aes, col, row, Bit::ZERO);
    }

    for j in 0..4 {
        set_b8(aes, PhysAes128Columns::P_KS_INV + j, row, 0);
        set_b8(aes, PhysAes128Columns::P_K0_INV + j, row, 0);
        set_bit(aes, PhysAes128Columns::P_KS_Z + j, row, Bit::ZERO);
        set_bit(aes, PhysAes128Columns::P_K0_Z + j, row, Bit::ZERO);
    }

    set_b16(aes, PhysAes128Columns::P_ROUND_IDX, row, 0);
    set_b32(aes, PhysAes128Columns::P_REQUEST_IDX_LINK, row, 0);
    set_b32(aes, PhysAes128Columns::P_REQUEST_IDX_KEY, row, 0);
}

fn make_bare_emit(aes: &mut ColumnTrace, row: usize, partner: u32) {
    make_idle(aes, row);
    set_bit(aes, PhysAes128Columns::P_S_IN_OUT, row, Bit::ONE);
    set_b32(aes, PhysAes128Columns::P_REQUEST_IDX_LINK, row, partner);
}

/// Rehomes the key emit; the key bus still balances
/// once the link request indices are swapped.
fn move_key_row(cpu: &mut ColumnTrace, from: usize, to: usize) {
    copy_b8_block(cpu, CpuAes128Columns::KEY, 16, from, to);

    for j in 0..16 {
        set_b8(cpu, CpuAes128Columns::KEY + j, from, 0);
    }

    set_bit(cpu, CpuAes128Columns::KEY_SELECTOR, from, Bit::ZERO);
    set_bit(cpu, CpuAes128Columns::KEY_SELECTOR, to, Bit::ONE);
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn honest_block_verifies() {
    let air = make_program_128(AES_ROWS);
    let chiplet_traces = air.aes.generate_traces(&[fips_call_128()]).unwrap();
    let cpu_trace = build_cpu_trace_128(&[(whitened_128(), FIPS128_CIPHER)]);

    match prove_and_verify(&air, cpu_trace, chiplet_traces) {
        Ok(true) => {}
        Ok(false) => panic!("rejected"),
        Err(e) => panic!("error: {e}"),
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn free_ciphertext_rejected() {
    let air = make_program_128(AES_ROWS);
    let mut traces = air.aes.generate_traces(&[fips_call_128()]).unwrap();

    {
        let (head, tail) = traces.split_at_mut(1);
        let (aes, rom) = (&mut head[0], &mut tail[0]);

        make_bare_emit(aes, 1, DECOY_IDX);
        make_bare_emit(aes, 2, DECOY_IDX);

        copy_b8_block(aes, PhysAes128Columns::P_STATE_IN, 16, 1, 2);

        make_bare_emit(aes, 3, OUT_ROW);

        for (j, &byte) in FREE_CIPHER.iter().enumerate() {
            set_b8(aes, PhysAes128Columns::P_STATE_IN + j, 3, byte);
        }

        for row in 4..=OUTPUT_ROW {
            make_idle(aes, row);
        }

        deactivate_rom(rom, 1..ACTIVE_ROWS);
    }

    assert_ne!(FREE_CIPHER, FIPS128_CIPHER);

    let cpu_trace = build_cpu_trace_128(&[(whitened_128(), FREE_CIPHER)]);
    assert_air_violated(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(false) | Err(_) => {}
        Ok(true) => panic!("accepted"),
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn single_round_block_rejected() {
    let air = make_program_128(AES_ROWS);
    let mut traces = air.aes.generate_traces(&[fips_call_128()]).unwrap();

    let after_round_one: [u8; 16] =
        core::array::from_fn(|j| b8_at(&traces[0], PhysAes128Columns::P_STATE_IN + j, 1));

    {
        let (head, tail) = traces.split_at_mut(1);
        let (aes, rom) = (&mut head[0], &mut tail[0]);

        make_bare_emit(aes, 1, OUT_ROW);

        for row in 2..=OUTPUT_ROW {
            make_idle(aes, row);
        }

        deactivate_rom(rom, 1..ACTIVE_ROWS);
    }

    assert_ne!(after_round_one, FIPS128_CIPHER);

    let cpu_trace = build_cpu_trace_128(&[(whitened_128(), after_round_one)]);
    assert_air_violated(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(false) | Err(_) => {}
        Ok(true) => panic!("accepted"),
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn reversed_pairing_rejected() {
    let air = make_program_128(AES_ROWS);
    let mut traces = air.aes.generate_traces(&[fips_call_128()]).unwrap();

    set_b32(
        &mut traces[0],
        PhysAes128Columns::P_REQUEST_IDX_LINK,
        0,
        OUT_ROW,
    );
    set_b32(
        &mut traces[0],
        PhysAes128Columns::P_REQUEST_IDX_LINK,
        OUTPUT_ROW,
        IN_ROW,
    );

    let whitened = whitened_128();
    assert_ne!(aes_rounds(&FIPS128_CIPHER), whitened);

    let cpu_trace = build_cpu_trace_128(&[(FIPS128_CIPHER, whitened)]);
    assert_air_clean(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(false) | Err(_) => {}
        Ok(true) => panic!("accepted"),
    }
}

/// Both buses balance; only the CPU-side pin rejects this.
#[test]
#[cfg_attr(debug_assertions, ignore)]
fn reversed_pairing_with_moved_key_rejected() {
    let air = make_program_128(AES_ROWS);
    let mut traces = air.aes.generate_traces(&[fips_call_128()]).unwrap();

    set_b32(
        &mut traces[0],
        PhysAes128Columns::P_REQUEST_IDX_LINK,
        0,
        OUT_ROW,
    );
    set_b32(
        &mut traces[0],
        PhysAes128Columns::P_REQUEST_IDX_LINK,
        OUTPUT_ROW,
        IN_ROW,
    );
    set_b32(
        &mut traces[0],
        PhysAes128Columns::P_REQUEST_IDX_KEY,
        0,
        OUT_ROW,
    );

    let whitened = whitened_128();
    let mut cpu_trace = build_cpu_trace_128(&[(FIPS128_CIPHER, whitened)]);

    move_key_row(&mut cpu_trace, IN_ROW as usize, OUT_ROW as usize);

    assert_air_violated(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(false) | Err(_) => {}
        Ok(true) => panic!("accepted"),
    }
}
