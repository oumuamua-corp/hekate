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

//! What the CPU-side run-opener root buys.
//!
//! Without it a host admits `idle -> response`; two
//! identical blocks can cancel their own input and
//! key emits and hand the CPU a ciphertext no row
//! of its trace ever bound a plaintext or a key to.

mod common;

use common::{
    CPU_ROWS, F, FIPS128_CIPHER, SBOX_ROM_ROWS, assert_air_clean, assert_air_violated,
    fips_call_128, make_program_128, prove_and_verify, set_b32,
};
use hekate_aes::{
    Aes128Chiplet, AesRound128Air, CpuAes128Columns, CpuAes128Unit, PhysAes128Columns,
};
use hekate_core::errors;
use hekate_core::trace::{ColumnTrace, ColumnType, TraceBuilder};
use hekate_math::{Bit, Block8, TowerField};
use hekate_program::constraint::ConstraintAst;
use hekate_program::constraint::builder::ConstraintSystem;
use hekate_program::permutation::PermutationCheckSpec;
use hekate_program::{Air, Program};

const AES_ROWS: usize = 32;
const ROWS_PER_CALL: usize = 11;

/// Free of the CPU row indices the honest generator
/// picks; the two input emits collide and cancel.
const SHARED_IDX: u32 = 7;

/// Every root of `CpuAes128Unit::constrain` except the run opener.
#[derive(Clone)]
struct UnpinnedHost {
    aes: Aes128Chiplet<F>,
}

impl Air<F> for UnpinnedHost {
    fn column_layout(&self) -> &[ColumnType] {
        static LAYOUT: std::sync::OnceLock<Vec<ColumnType>> = std::sync::OnceLock::new();
        LAYOUT.get_or_init(CpuAes128Columns::build_layout)
    }

    fn permutation_checks(&self) -> Vec<(String, PermutationCheckSpec)> {
        vec![
            (
                AesRound128Air::LINK_BUS_ID.into(),
                CpuAes128Unit::linking_spec(),
            ),
            (
                AesRound128Air::KEY_BUS_ID.into(),
                CpuAes128Unit::key_linking_spec(),
            ),
        ]
    }

    fn constraint_ast(&self) -> ConstraintAst<F> {
        let cs = ConstraintSystem::<F>::new();

        let sel = cs.col(CpuAes128Columns::SELECTOR);
        let dir = cs.col(CpuAes128Columns::KEY_SELECTOR);
        let next_sel = cs.next(CpuAes128Columns::SELECTOR);
        let next_dir = cs.next(CpuAes128Columns::KEY_SELECTOR);
        let one = cs.one();

        cs.assert_boolean(sel);
        cs.assert_boolean(dir);
        cs.constrain(dir * (one + sel));
        cs.constrain(sel * (dir + next_dir + next_sel));

        cs.build()
    }
}

impl Program<F> for UnpinnedHost {
    fn num_public_inputs(&self) -> usize {
        0
    }

    fn chiplet_defs(&self) -> errors::Result<Vec<hekate_program::chiplet::ChipletDef<F>>> {
        self.aes.composite().flatten_defs()
    }
}

/// Collides both input emits and both key emits onto
/// `SHARED_IDX`; the surviving pair is the two outputs.
fn collide_input_emits(aes: &mut ColumnTrace) {
    for block in 0..2usize {
        let input_row = block * ROWS_PER_CALL;
        let output_row = input_row + ROWS_PER_CALL - 1;

        set_b32(
            aes,
            PhysAes128Columns::P_REQUEST_IDX_LINK,
            input_row,
            SHARED_IDX,
        );
        set_b32(
            aes,
            PhysAes128Columns::P_REQUEST_IDX_KEY,
            input_row,
            SHARED_IDX,
        );
        set_b32(
            aes,
            PhysAes128Columns::P_REQUEST_IDX_LINK,
            output_row,
            (2 * block + 1) as u32,
        );
    }
}

/// Rows 1 and 3 read the ciphertext. No row
/// carries a plaintext, a key, or a direction bit.
fn response_only_cpu_trace() -> ColumnTrace {
    let num_vars = CPU_ROWS.trailing_zeros() as usize;
    let mut tb = TraceBuilder::new(&CpuAes128Columns::build_layout(), num_vars).unwrap();

    for row in [1usize, 3] {
        for (j, &byte) in FIPS128_CIPHER.iter().enumerate() {
            tb.set_b8(CpuAes128Columns::DATA + j, row, Block8(byte))
                .unwrap();
        }

        tb.set_bit(CpuAes128Columns::SELECTOR, row, Bit::ONE)
            .unwrap();
    }

    tb.build()
}

fn unbound_ciphertext_witness(aes: &Aes128Chiplet<F>) -> (ColumnTrace, Vec<ColumnTrace>) {
    let call = fips_call_128();
    let mut traces = aes.generate_traces(&[call.clone(), call]).unwrap();

    collide_input_emits(&mut traces[0]);

    (response_only_cpu_trace(), traces)
}

/// Both buses balance and every AIR equation holds;
/// the verdict is attributable to the missing root alone.
#[test]
#[cfg_attr(debug_assertions, ignore)]
fn unpinned_host_accepts_unbound_ciphertext() {
    let air = UnpinnedHost {
        aes: Aes128Chiplet::new(AES_ROWS, SBOX_ROM_ROWS).unwrap(),
    };

    let (cpu_trace, traces) = unbound_ciphertext_witness(&air.aes);
    assert_air_clean(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(true) => {}
        Ok(false) => panic!("rejected: the run-opener root is not what closes this"),
        Err(e) => panic!("error: {e}"),
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn constrain_rejects_unbound_ciphertext() {
    let air = make_program_128(AES_ROWS);
    let (cpu_trace, traces) = unbound_ciphertext_witness(&air.aes);

    assert_air_violated(&air, &cpu_trace, &traces);

    match prove_and_verify(&air, cpu_trace, traces) {
        Ok(false) | Err(_) => {}
        Ok(true) => panic!("accepted a ciphertext bound to no CPU request row"),
    }
}
