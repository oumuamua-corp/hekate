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

//! AES-128 Round Chiplet.
//!
//! 11 rows per block:
//! 9 full rounds + 1 final + 1 output.
//! Constraints operate at GF(2^8) byte level, the binary tower preserves
//! subfield multiplication; MixColumns ×2/×3 constants need no bit decomposition.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use hekate_core::errors::Error;
use hekate_core::trace::{ColumnTrace, ColumnType, TraceCompatibleField};
use hekate_math::TowerField;
use hekate_math::{Flat, HardwareField, PackableField};
use hekate_program::Air;
use hekate_program::chiplet::CompositeChiplet;
use hekate_program::constraint::ConstraintAst;
use hekate_program::constraint::builder::ConstraintSystem;
use hekate_program::define_columns;
use hekate_program::expander::VirtualExpander;
use hekate_program::permutation::{PermutationCheckSpec, REQUEST_IDX_LABEL, Source};

use super::sbox_rom;
use super::{AES_BYTE_LABELS, AES_DIRECTION_LABEL, ROT_MAP, SBOX_IN_LABELS, SBOX_OUT_LABELS};

#[rustfmt::skip]
pub const AES_KEY_LABELS: [&[u8]; 16] = [
    b"aes_key_byte_0",  b"aes_key_byte_1",
    b"aes_key_byte_2",  b"aes_key_byte_3",
    b"aes_key_byte_4",  b"aes_key_byte_5",
    b"aes_key_byte_6",  b"aes_key_byte_7",
    b"aes_key_byte_8",  b"aes_key_byte_9",
    b"aes_key_byte_10", b"aes_key_byte_11",
    b"aes_key_byte_12", b"aes_key_byte_13",
    b"aes_key_byte_14", b"aes_key_byte_15",
];

// Physical layout. Column order must match VirtualExpander sequence
// exactly. ROUND_IDX / KS_INV / K0_INV are bit-decomposed by the expander.
define_columns! {
    pub PhysAes128Columns {
        P_STATE_IN: [B8; 16],
        P_SBOX_OUT: [B8; 16],
        P_ROUND_KEY: [B8; 16],
        P_ROUND_IDX: B16,
        P_S_ROUND: Bit,
        P_S_FINAL: Bit,
        P_S_IN_OUT: Bit,
        P_S_ACTIVE: Bit,
        P_S_INPUT: Bit,
        P_K0: [B8; 16],
        P_KS_SUB: [B8; 4],
        P_KS_INV: [B8; 4],
        P_KS_Z: [Bit; 4],
        P_K0_SUB: [B8; 4],
        P_K0_INV: [B8; 4],
        P_K0_Z: [Bit; 4],
        P_REQUEST_IDX_LINK: B32,
        P_REQUEST_IDX_KEY: B32,
    }
}

// Virtual column indices.
// Constraints reference these.
define_columns! {
    pub Aes128Columns {
        STATE_IN: [B8; 16],
        SBOX_OUT: [B8; 16],
        ROUND_KEY: [B8; 16],

        // One-hot over the block's active rows
        ROUND_BITS: [Bit; 16],

        S_ROUND: Bit,
        S_FINAL: Bit,
        S_IN_OUT: Bit,

        // Gates S-box bus lookups.
        // 1 on all round rows
        // (s_round OR s_final).
        S_ACTIVE: Bit,

        // s_in_out ∧ s_round (input row only)
        S_INPUT: Bit,

        // Raw AES-128 key. Populated
        // on s_input rows. Bound to
        // consumer via "aes_key_in" bus.
        K0: [B8; 16],

        // Forward chain:
        // SubWord(RotWord(ROUND_KEY)) witness.
        // Proves K_{i+2} = expand(K_{i+1})
        // on s_round rows.
        KS_SUB: [B8; 4],
        KS_INV_BITS: [Bit; 32],
        KS_Z: [Bit; 4],

        // Init:
        // SubWord(RotWord(K0)) witness.
        // Proves K1 = expand(K0)
        // on s_input rows.
        K0_SUB: [B8; 4],
        K0_INV_BITS: [Bit; 32],
        K0_Z: [Bit; 4],

        // Partner CPU row index for the
        // aes128_link bus (S_IN_OUT-gated:
        // input row + output row per block).
        REQUEST_IDX_LINK: B32,

        // Partner CPU row index for the
        // aes128_key_in bus (S_INPUT-gated:
        // input row only).
        REQUEST_IDX_KEY: B32,
    }
}

#[derive(Clone, Debug)]
pub struct AesRound128Air {
    pub num_rows: usize,
}

impl AesRound128Air {
    pub const LINK_BUS_ID: &'static str = "aes128_link";
    pub const KEY_BUS_ID: &'static str = "aes128_key_in";

    /// 9 full rounds and the final round.
    pub const ACTIVE_ROWS: usize = 10;

    /// FIPS 197 §5.2 round constants.
    const RCON: [u8; Self::ACTIVE_ROWS] =
        [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

    pub(crate) fn new(num_rows: usize) -> Self {
        Self { num_rows }
    }

    pub fn for_constraints() -> Self {
        Self { num_rows: 0 }
    }

    /// External bus:
    /// 16 state_in bytes gated by s_in_out.
    pub fn link_spec() -> PermutationCheckSpec {
        let mut sources: Vec<_> = (0..16)
            .map(|i| {
                (
                    Source::Column(Aes128Columns::STATE_IN + i),
                    AES_BYTE_LABELS[i],
                )
            })
            .collect();

        sources.push((
            Source::Column(Aes128Columns::REQUEST_IDX_LINK),
            REQUEST_IDX_LABEL,
        ));
        sources.push((Source::Column(Aes128Columns::S_INPUT), AES_DIRECTION_LABEL));

        PermutationCheckSpec::new(sources, Some(Aes128Columns::S_IN_OUT))
    }

    /// External bus:
    /// 16 K0 bytes gated by s_input.
    pub fn key_spec() -> PermutationCheckSpec {
        let mut sources: Vec<_> = (0..16)
            .map(|i| (Source::Column(Aes128Columns::K0 + i), AES_KEY_LABELS[i]))
            .collect();

        sources.push((
            Source::Column(Aes128Columns::REQUEST_IDX_KEY),
            REQUEST_IDX_LABEL,
        ));

        PermutationCheckSpec::new(sources, Some(Aes128Columns::S_INPUT))
    }

    /// Per-byte-position S-box bus specs.
    pub fn sbox_specs() -> Vec<(String, PermutationCheckSpec)> {
        let mut sources = Vec::with_capacity(32);
        for i in 0..16 {
            sources.push((
                Source::Column(Aes128Columns::STATE_IN + i),
                SBOX_IN_LABELS[i],
            ));
            sources.push((
                Source::Column(Aes128Columns::SBOX_OUT + i),
                SBOX_OUT_LABELS[i],
            ));
        }

        sources.push((Source::RowIndexLeBytes(4), REQUEST_IDX_LABEL));

        let spec = PermutationCheckSpec::new(sources, Some(Aes128Columns::S_ACTIVE));

        vec![(sbox_rom::SboxRomChiplet::BUS_ID.into(), spec)]
    }
}

impl<F: TowerField> Air<F> for AesRound128Air {
    fn name(&self) -> String {
        "AesRound128Air".to_string()
    }

    fn column_layout(&self) -> &[ColumnType] {
        static LAYOUT: once_cell::race::OnceBox<Vec<ColumnType>> = once_cell::race::OnceBox::new();
        LAYOUT.get_or_init(|| Box::new(PhysAes128Columns::build_layout()))
    }

    fn permutation_checks(&self) -> Vec<(String, PermutationCheckSpec)> {
        let mut checks = Vec::with_capacity(3);
        checks.push((Self::LINK_BUS_ID.into(), Self::link_spec()));
        checks.push((Self::KEY_BUS_ID.into(), Self::key_spec()));
        checks.extend(Self::sbox_specs());

        checks
    }

    fn virtual_expander(&self) -> Option<&VirtualExpander> {
        static E: once_cell::race::OnceBox<VirtualExpander> = once_cell::race::OnceBox::new();
        Some(E.get_or_init(|| {
            Box::new(
                VirtualExpander::new()
                    .pass_through(48, ColumnType::B8) // STATE_IN..ROUND_KEY
                    .expand_bits(1, ColumnType::B16) // ROUND_IDX -> ROUND_BITS
                    .control_bits(5) // S_ROUND..S_INPUT
                    .pass_through(16, ColumnType::B8) // K0
                    .pass_through(4, ColumnType::B8) // KS_SUB
                    .expand_bits(4, ColumnType::B8) // KS_INV -> KS_INV_BITS
                    .control_bits(4) // KS_Z
                    .pass_through(4, ColumnType::B8) // K0_SUB
                    .expand_bits(4, ColumnType::B8) // K0_INV -> K0_INV_BITS
                    .control_bits(4) // K0_Z
                    .pass_through(2, ColumnType::B32) // REQUEST_IDX_LINK, REQUEST_IDX_KEY
                    .build()
                    .expect("AesRound128Air expander"),
            )
        }))
    }

    #[allow(clippy::needless_range_loop)]
    fn constraint_ast(&self) -> ConstraintAst<F> {
        let cs = ConstraintSystem::<F>::new();

        let s_round = cs.col(Aes128Columns::S_ROUND);
        let s_final = cs.col(Aes128Columns::S_FINAL);
        let s_in_out = cs.col(Aes128Columns::S_IN_OUT);
        let s_active = cs.col(Aes128Columns::S_ACTIVE);

        let s_input = cs.col(Aes128Columns::S_INPUT);
        let one = cs.one();

        // Bus selectors: link, sbox, key
        cs.assert_boolean(s_in_out);
        cs.assert_boolean(s_active);
        cs.assert_boolean(s_input);

        // Round index: one-hot at 0 on the input row, one
        // shift per active row, block ends after round 9.
        const ACTIVE: usize = AesRound128Air::ACTIVE_ROWS;

        let round = |k: usize| cs.col(Aes128Columns::ROUND_BITS + k);
        let weighted = |lo: usize, hi: usize| {
            cs.sum(
                &(lo..hi)
                    .map(|k| cs.scale(F::from(1u128 << k), round(k)))
                    .collect::<Vec<_>>(),
            )
        };
        let weighted_next = |lo: usize, hi: usize| {
            cs.sum(
                &(lo..hi)
                    .map(|k| cs.scale(F::from(1u128 << k), cs.next(Aes128Columns::ROUND_BITS + k)))
                    .collect::<Vec<_>>(),
            )
        };

        cs.constrain(weighted(ACTIVE, 16));

        // Every selector is a function of the index;
        // none of them is free witness anywhere.
        cs.constrain(s_active + cs.sum(&(0..ACTIVE).map(round).collect::<Vec<_>>()));
        cs.constrain(s_final + round(ACTIVE - 1));
        cs.constrain(s_input + round(0));
        cs.constrain(s_round + s_active + s_final);

        // A run may only begin on an input row
        let not_active = one + s_active;

        cs.assert_zero_when(not_active, weighted(0, ACTIVE));
        cs.assert_zero_when(not_active, weighted_next(1, ACTIVE));
        cs.constrain(round(0) * (one + s_in_out));

        for k in 0..ACTIVE - 1 {
            cs.constrain(s_active * (cs.next(Aes128Columns::ROUND_BITS + k + 1) + round(k)));
        }

        let next_s_active = cs.next(Aes128Columns::S_ACTIVE);
        let next_s_in_out = cs.next(Aes128Columns::S_IN_OUT);

        // An active row is followed by an active row or an output
        // row, and the row before an output row is active. `next`
        // wraps at the trace end, which carries this onto row 0.
        cs.constrain(s_active * (one + next_s_active + next_s_in_out));
        cs.constrain(next_s_in_out * (one + next_s_active) * (one + s_active));
        cs.constrain(s_active * (next_s_active + one + round(ACTIVE - 1)));

        super::build_round_constraints(
            &cs,
            Aes128Columns::STATE_IN,
            Aes128Columns::SBOX_OUT,
            Aes128Columns::ROUND_KEY,
            Aes128Columns::S_ROUND,
            Aes128Columns::S_FINAL,
        );

        // =============================================================
        // Key schedule: inline FIPS 197 §5.2
        // =============================================================

        // Forward chain:
        // SubWord(RotWord(ROUND_KEY))
        super::build_sbox_inversion_constraints(
            &cs,
            core::array::from_fn(|j| Aes128Columns::ROUND_KEY + ROT_MAP[j]),
            Aes128Columns::KS_SUB,
            Aes128Columns::KS_INV_BITS,
            Aes128Columns::KS_Z,
            Aes128Columns::S_ROUND,
        );

        // Init:
        // SubWord(RotWord(K0))
        super::build_sbox_inversion_constraints(
            &cs,
            core::array::from_fn(|j| Aes128Columns::K0 + ROT_MAP[j]),
            Aes128Columns::K0_SUB,
            Aes128Columns::K0_INV_BITS,
            Aes128Columns::K0_Z,
            Aes128Columns::S_INPUT,
        );

        // Rcon reads off the index;
        // no round constant is ever a witness.
        let rcon_next = cs.sum(
            &(0..ACTIVE - 1)
                .map(|k| cs.scale(F::from(Self::RCON[k + 1]), round(k)))
                .collect::<Vec<_>>(),
        );

        // Forward chain word cascade:
        // next_RK = expand(RK, KS_SUB, rcon_next)
        for j in 0..16usize {
            let next_rk = cs.next(Aes128Columns::ROUND_KEY + j);
            let rk = cs.col(Aes128Columns::ROUND_KEY + j);

            let body = match j {
                0 => next_rk + rk + cs.col(Aes128Columns::KS_SUB) + rcon_next,
                1..=3 => next_rk + rk + cs.col(Aes128Columns::KS_SUB + j),
                4..=15 => next_rk + rk + cs.next(Aes128Columns::ROUND_KEY + j - 4),
                _ => unreachable!(),
            };

            cs.assert_zero_when(s_round, body);
        }

        // Init word cascade:
        // RK (= K1) = expand(K0, K0_SUB, RCON[0])
        let rcon_init = cs.constant(F::from(Self::RCON[0]));

        for j in 0..16usize {
            let rk = cs.col(Aes128Columns::ROUND_KEY + j);
            let k0 = cs.col(Aes128Columns::K0 + j);

            let body = match j {
                0 => rk + k0 + cs.col(Aes128Columns::K0_SUB) + rcon_init,
                1..=3 => rk + k0 + cs.col(Aes128Columns::K0_SUB + j),
                4..=15 => rk + k0 + cs.col(Aes128Columns::ROUND_KEY + j - 4),
                _ => unreachable!(),
            };

            cs.assert_zero_when(s_input, body);
        }

        // KS_Z / KS_INV load-bearing
        // only on s_round rows.
        let not_s_round = one + s_round;
        for i in 0..4 {
            let ks_inv_byte = cs.sum(
                &(0..8)
                    .map(|k| {
                        cs.scale(
                            F::from(1u8 << k),
                            cs.col(Aes128Columns::KS_INV_BITS + i * 8 + k),
                        )
                    })
                    .collect::<Vec<_>>(),
            );

            cs.assert_zero_when(not_s_round, cs.col(Aes128Columns::KS_Z + i));
            cs.assert_zero_when(not_s_round, ks_inv_byte);
        }

        // K0_Z / K0_INV load-bearing
        // only on s_input (init row).
        let not_s_input = one + s_input;
        for i in 0..4 {
            let k0_inv_byte = cs.sum(
                &(0..8)
                    .map(|k| {
                        cs.scale(
                            F::from(1u8 << k),
                            cs.col(Aes128Columns::K0_INV_BITS + i * 8 + k),
                        )
                    })
                    .collect::<Vec<_>>(),
            );

            cs.assert_zero_when(not_s_input, cs.col(Aes128Columns::K0_Z + i));
            cs.assert_zero_when(not_s_input, k0_inv_byte);
        }

        cs.build()
    }
}

// =================================================================
// CPU-Side Interface
// =================================================================

define_columns! {
    pub CpuAes128Columns {
        KEY: [B8; 16],
        KEY_SELECTOR: Bit,
        DATA: [B8; 16],
        SELECTOR: Bit,
    }
}

/// The host writes `KEY_SELECTOR` on each block's input
/// row, `SELECTOR` on both emit rows, and calls `constrain`.
pub struct CpuAes128Unit;

impl CpuAes128Unit {
    pub const NUM_ROOTS: usize = 5;

    pub fn num_columns() -> usize {
        CpuAes128Columns::NUM_COLUMNS
    }

    /// Requires each call's two emits on adjacent rows;
    /// a host that separates them pins `KEY_SELECTOR` itself.
    ///
    /// `offset` is where `CpuAes128Columns` starts in the host layout.
    pub fn constrain<F: TowerField>(cs: &ConstraintSystem<F>, offset: usize) {
        let sel = cs.col(offset + CpuAes128Columns::SELECTOR);
        let dir = cs.col(offset + CpuAes128Columns::KEY_SELECTOR);
        let next_sel = cs.next(offset + CpuAes128Columns::SELECTOR);
        let next_dir = cs.next(offset + CpuAes128Columns::KEY_SELECTOR);
        let one = cs.one();

        cs.assert_boolean(sel);
        cs.assert_boolean(dir);

        cs.constrain(dir * (one + sel));
        cs.constrain(sel * (dir + next_dir + next_sel));
        cs.constrain(next_sel * (one + sel) * (one + next_dir));
    }

    /// `KEY_SELECTOR` doubles as the emit direction;
    /// it must fire on exactly the block's input row.
    pub fn linking_spec() -> PermutationCheckSpec {
        let mut sources: Vec<_> = (0..16)
            .map(|i| {
                (
                    Source::Column(CpuAes128Columns::DATA + i),
                    AES_BYTE_LABELS[i],
                )
            })
            .collect();

        sources.push((Source::RowIndexLeBytes(4), REQUEST_IDX_LABEL));
        sources.push((
            Source::Column(CpuAes128Columns::KEY_SELECTOR),
            AES_DIRECTION_LABEL,
        ));

        PermutationCheckSpec::new(sources, Some(CpuAes128Columns::SELECTOR))
    }

    pub fn key_linking_spec() -> PermutationCheckSpec {
        let mut sources: Vec<_> = (0..16)
            .map(|i| (Source::Column(CpuAes128Columns::KEY + i), AES_KEY_LABELS[i]))
            .collect();

        sources.push((Source::RowIndexLeBytes(4), REQUEST_IDX_LABEL));

        PermutationCheckSpec::new(sources, Some(CpuAes128Columns::KEY_SELECTOR))
    }
}

// =================================================================
// AES-128 Composite Chiplet
// =================================================================

#[derive(Clone)]
pub struct Aes128Chiplet<F: TraceCompatibleField> {
    composite: CompositeChiplet<F>,
    num_rows: usize,
    sbox_rom_rows: usize,
}

impl<F> Aes128Chiplet<F>
where
    F: TowerField + TraceCompatibleField + PackableField + HardwareField + 'static,
    <F as PackableField>::Packed: Copy + Send + Sync,
    Flat<F>: Send + Sync,
{
    pub fn new(num_rows: usize, sbox_rom_rows: usize) -> Result<Self, Error> {
        if !num_rows.is_power_of_two() {
            return Err(Error::Protocol {
                protocol: "aes128_chiplet",
                message: "num_rows must be power of 2",
            });
        }

        let round_air = AesRound128Air::new(num_rows);
        let sbox_rom = sbox_rom::SboxRomChiplet::new(sbox_rom_rows)?;

        let composite = CompositeChiplet::<F>::builder("aes128")
            .chiplet(round_air)
            .chiplet(sbox_rom)
            .external_bus(AesRound128Air::LINK_BUS_ID, AesRound128Air::link_spec())
            .external_bus(AesRound128Air::KEY_BUS_ID, AesRound128Air::key_spec())
            .build()?;

        Ok(Self {
            composite,
            num_rows,
            sbox_rom_rows,
        })
    }

    pub fn composite(&self) -> &CompositeChiplet<F> {
        &self.composite
    }

    pub fn generate_traces(
        &self,
        calls: &[super::trace::Aes128Call],
    ) -> Result<Vec<ColumnTrace>, Error> {
        let aes_trace = super::trace::generate_aes_trace(calls, None, self.num_rows)?;

        let mut sbox_rounds = Vec::new();
        let s_active = aes_trace.columns[PhysAes128Columns::P_S_ACTIVE]
            .as_bit_slice()
            .ok_or(Error::Protocol {
                protocol: "aes128_chiplet",
                message: "S_ACTIVE column type mismatch",
            })?;

        for (row, &active) in s_active.iter().enumerate() {
            if active != hekate_math::Bit::ONE {
                continue;
            }

            let mut inputs = [0u8; 16];
            let mut outputs = [0u8; 16];

            for j in 0..16 {
                inputs[j] = aes_trace.columns[PhysAes128Columns::P_STATE_IN + j]
                    .as_b8_slice()
                    .unwrap()[row]
                    .to_tower()
                    .0;
                outputs[j] = aes_trace.columns[PhysAes128Columns::P_SBOX_OUT + j]
                    .as_b8_slice()
                    .unwrap()[row]
                    .to_tower()
                    .0;
            }

            sbox_rounds.push(sbox_rom::SboxRound {
                inputs,
                outputs,
                request_idx: row as u32,
            });
        }

        let sbox_trace = sbox_rom::generate_sbox_rom_trace(&sbox_rounds, self.sbox_rom_rows)?;

        Ok(vec![aes_trace, sbox_trace])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hekate_math::Block128;

    type F = Block128;

    #[test]
    fn virtual_column_count() {
        assert_eq!(Aes128Columns::NUM_COLUMNS, 167);
        assert_eq!(Aes128Columns::STATE_IN, 0);
        assert_eq!(Aes128Columns::SBOX_OUT, 16);
        assert_eq!(Aes128Columns::ROUND_KEY, 32);
        assert_eq!(Aes128Columns::ROUND_BITS, 48);
        assert_eq!(Aes128Columns::S_ROUND, 64);
        assert_eq!(Aes128Columns::S_FINAL, 65);
        assert_eq!(Aes128Columns::S_IN_OUT, 66);
        assert_eq!(Aes128Columns::S_ACTIVE, 67);
        assert_eq!(Aes128Columns::S_INPUT, 68);
        assert_eq!(Aes128Columns::K0, 69);
        assert_eq!(Aes128Columns::KS_SUB, 85);
        assert_eq!(Aes128Columns::KS_INV_BITS, 89);
        assert_eq!(Aes128Columns::KS_Z, 121);
        assert_eq!(Aes128Columns::K0_SUB, 125);
        assert_eq!(Aes128Columns::K0_INV_BITS, 129);
        assert_eq!(Aes128Columns::K0_Z, 161);
        assert_eq!(Aes128Columns::REQUEST_IDX_LINK, 165);
        assert_eq!(Aes128Columns::REQUEST_IDX_KEY, 166);
    }

    #[test]
    fn physical_column_count() {
        let layout = PhysAes128Columns::build_layout();
        assert_eq!(layout.len(), PhysAes128Columns::NUM_COLUMNS);
        assert_eq!(PhysAes128Columns::NUM_COLUMNS, 96);

        assert_eq!(PhysAes128Columns::P_STATE_IN, 0);
        assert_eq!(PhysAes128Columns::P_ROUND_IDX, 48);
        assert_eq!(PhysAes128Columns::P_S_ROUND, 49);
        assert_eq!(PhysAes128Columns::P_K0, 54);
        assert_eq!(PhysAes128Columns::P_KS_SUB, 70);
        assert_eq!(PhysAes128Columns::P_KS_INV, 74);
        assert_eq!(PhysAes128Columns::P_KS_Z, 78);
        assert_eq!(PhysAes128Columns::P_K0_SUB, 82);
        assert_eq!(PhysAes128Columns::P_K0_INV, 86);
        assert_eq!(PhysAes128Columns::P_K0_Z, 90);
        assert_eq!(PhysAes128Columns::P_REQUEST_IDX_LINK, 94);
        assert_eq!(PhysAes128Columns::P_REQUEST_IDX_KEY, 95);
    }

    #[test]
    fn constraint_count() {
        let ast: ConstraintAst<F> = AesRound128Air::for_constraints().constraint_ast();
        assert_eq!(ast.roots.len(), 207);
    }

    #[test]
    fn link_spec_structure() {
        let spec = AesRound128Air::link_spec();
        assert_eq!(spec.num_sources(), 18);
        assert_eq!(spec.selector, Some(Aes128Columns::S_IN_OUT));
        assert_eq!(spec.sources[16].1, REQUEST_IDX_LABEL);
        assert_eq!(spec.sources[17].1, AES_DIRECTION_LABEL);
    }

    #[test]
    fn cpu_num_roots_matches_constrain() {
        let cs = ConstraintSystem::<F>::new();
        CpuAes128Unit::constrain(&cs, 0);

        assert_eq!(cs.build().roots.len(), CpuAes128Unit::NUM_ROOTS);
    }

    #[test]
    fn link_endpoints_agree() {
        let chiplet = AesRound128Air::link_spec();
        let cpu = CpuAes128Unit::linking_spec();

        assert_eq!(chiplet.num_sources(), cpu.num_sources());

        for (c, p) in chiplet.sources.iter().zip(cpu.sources.iter()) {
            assert_eq!(c.1, p.1);
        }
    }

    #[test]
    fn sbox_specs_structure() {
        let specs = AesRound128Air::sbox_specs();
        assert_eq!(specs.len(), 1);

        let (bus_id, spec) = &specs[0];
        assert_eq!(bus_id, sbox_rom::SboxRomChiplet::BUS_ID);
        assert_eq!(spec.num_sources(), 33);
        assert_eq!(spec.sources[32].1, REQUEST_IDX_LABEL);
        assert_eq!(spec.selector, Some(Aes128Columns::S_ACTIVE));
        assert!(spec.clock_waiver.is_none());
    }

    #[test]
    fn key_spec_structure() {
        let spec = AesRound128Air::key_spec();
        assert_eq!(spec.num_sources(), 17);
        assert_eq!(spec.selector, Some(Aes128Columns::S_INPUT));
        assert_eq!(spec.sources[16].1, REQUEST_IDX_LABEL);
    }

    #[test]
    fn virtual_expander_dimensions() {
        let air = AesRound128Air::for_constraints();
        let exp = Air::<F>::virtual_expander(&air).expect("expander must exist");

        assert_eq!(exp.num_physical_columns(), PhysAes128Columns::NUM_COLUMNS);
        assert_eq!(exp.num_virtual_columns(), Aes128Columns::NUM_COLUMNS);
    }

    #[test]
    fn composite_builds() {
        let aes = Aes128Chiplet::<F>::new(16, 256).unwrap();
        assert_eq!(aes.composite().flatten_defs().unwrap().len(), 2);
    }

    #[test]
    fn new_validates() {
        assert!(Aes128Chiplet::<F>::new(100, 256).is_err());
        assert!(Aes128Chiplet::<F>::new(16, 7).is_err());
        assert!(Aes128Chiplet::<F>::new(16, 16).is_ok());
    }
}
