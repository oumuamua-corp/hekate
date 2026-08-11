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
    AES_ROWS, DECOY_IDX, FIPS256_CIPHER, FIPS256_KEY, FREE_CIPHER, IN_ROW, OUT_ROW,
    assert_air_clean, assert_air_violated, build_cpu_trace_256, copy_b8_block, deactivate_rom,
    fips_call_256, make_program_256, prove_and_verify, set_b8, set_b16, set_b32, set_bit,
    whitened_256,
};
use hekate_aes::{
    CpuAes256Columns, PhysAes256Columns,
    trace::{aes256_encrypt_block, expand_key_256},
};
use hekate_core::trace::ColumnTrace;
use hekate_math::{Bit, TowerField};

const ACTIVE_ROWS: usize = 14;
const OUTPUT_ROW: usize = 14;

/// Fourteen rounds applied to `state`, which the block
/// enters already whitened.
fn aes_rounds(state: &[u8; 16]) -> [u8; 16] {
    let round_keys = expand_key_256(&FIPS256_KEY);
    let plaintext: [u8; 16] = core::array::from_fn(|j| state[j] ^ round_keys[0][j]);

    aes256_encrypt_block(&round_keys, &plaintext)
}

/// Clears the selectors and every cell pinned off its gate.
fn make_idle(aes: &mut ColumnTrace, row: usize) {
    for col in [
        PhysAes256Columns::P_S_ROUND,
        PhysAes256Columns::P_S_FINAL,
        PhysAes256Columns::P_S_IN_OUT,
        PhysAes256Columns::P_S_ACTIVE,
        PhysAes256Columns::P_S_INPUT,
    ] {
        set_bit(aes, col, row, Bit::ZERO);
    }

    for j in 0..4 {
        set_b8(aes, PhysAes256Columns::P_KS_INV + j, row, 0);
        set_bit(aes, PhysAes256Columns::P_KS_Z + j, row, Bit::ZERO);
    }

    set_b16(aes, PhysAes256Columns::P_ROUND_IDX, row, 0);
    set_b32(aes, PhysAes256Columns::P_REQUEST_IDX_LINK, row, 0);
    set_b32(aes, PhysAes256Columns::P_REQUEST_IDX_KEY, row, 0);
}

fn make_bare_emit(aes: &mut ColumnTrace, row: usize, partner: u32) {
    make_idle(aes, row);
    set_bit(aes, PhysAes256Columns::P_S_IN_OUT, row, Bit::ONE);
    set_b32(aes, PhysAes256Columns::P_REQUEST_IDX_LINK, row, partner);
}

/// Rehomes the key emit; the key bus still balances
/// once the link request indices are swapped.
fn move_key_row(cpu: &mut ColumnTrace, from: usize, to: usize) {
    copy_b8_block(cpu, CpuAes256Columns::KEY, 32, from, to);

    for j in 0..32 {
        set_b8(cpu, CpuAes256Columns::KEY + j, from, 0);
    }

    set_bit(cpu, CpuAes256Columns::KEY_SELECTOR, from, Bit::ZERO);
    set_bit(cpu, CpuAes256Columns::KEY_SELECTOR, to, Bit::ONE);
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn honest_block_verifies() {
    let air = make_program_256(AES_ROWS);
    let chiplet_traces = air.aes.generate_traces(&[fips_call_256()]).unwrap();
    let cpu_trace = build_cpu_trace_256(&whitened_256(), &FIPS256_CIPHER);

    match prove_and_verify(&air, cpu_trace, chiplet_traces) {
        Ok(true) => {}
        Ok(false) => panic!("rejected"),
        Err(e) => panic!("error: {e}"),
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn free_ciphertext_rejected() {
    let air = make_program_256(AES_ROWS);
    let mut traces = air.aes.generate_traces(&[fips_call_256()]).unwrap();

    {
        let (head, tail) = traces.split_at_mut(1);
        let (aes, rom) = (&mut head[0], &mut tail[0]);

        make_bare_emit(aes, 1, DECOY_IDX);
        make_bare_emit(aes, 2, DECOY_IDX);

        copy_b8_block(aes, PhysAes256Columns::P_STATE_IN, 16, 1, 2);

        make_bare_emit(aes, 3, OUT_ROW);

        for (j, &byte) in FREE_CIPHER.iter().enumerate() {
            set_b8(aes, PhysAes256Columns::P_STATE_IN + j, 3, byte);
        }

        for row in 4..=OUTPUT_ROW {
            make_idle(aes, row);
        }

        deactivate_rom(rom, 1..ACTIVE_ROWS);
    }

    assert_ne!(FREE_CIPHER, FIPS256_CIPHER);

    let cpu_trace = build_cpu_trace_256(&whitened_256(), &FREE_CIPHER);
    assert_air_violated(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(false) | Err(_) => {}
        Ok(true) => panic!("accepted"),
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn reversed_pairing_rejected() {
    let air = make_program_256(AES_ROWS);
    let mut traces = air.aes.generate_traces(&[fips_call_256()]).unwrap();

    set_b32(
        &mut traces[0],
        PhysAes256Columns::P_REQUEST_IDX_LINK,
        0,
        OUT_ROW,
    );
    set_b32(
        &mut traces[0],
        PhysAes256Columns::P_REQUEST_IDX_LINK,
        OUTPUT_ROW,
        IN_ROW,
    );

    let whitened = whitened_256();
    assert_ne!(aes_rounds(&FIPS256_CIPHER), whitened);

    let cpu_trace = build_cpu_trace_256(&FIPS256_CIPHER, &whitened);
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
    let air = make_program_256(AES_ROWS);
    let mut traces = air.aes.generate_traces(&[fips_call_256()]).unwrap();

    set_b32(
        &mut traces[0],
        PhysAes256Columns::P_REQUEST_IDX_LINK,
        0,
        OUT_ROW,
    );
    set_b32(
        &mut traces[0],
        PhysAes256Columns::P_REQUEST_IDX_LINK,
        OUTPUT_ROW,
        IN_ROW,
    );
    set_b32(
        &mut traces[0],
        PhysAes256Columns::P_REQUEST_IDX_KEY,
        0,
        OUT_ROW,
    );

    let whitened = whitened_256();
    let mut cpu_trace = build_cpu_trace_256(&FIPS256_CIPHER, &whitened);

    move_key_row(&mut cpu_trace, IN_ROW as usize, OUT_ROW as usize);

    assert_air_violated(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(false) | Err(_) => {}
        Ok(true) => panic!("accepted"),
    }
}
