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

//! The control language the AIR admits, enumerated.

use hekate_keccak::{KeccakChiplet, KeccakColumns};
use hekate_math::Block128;
use hekate_program::Air;
use hekate_program::constraint::ConstraintAst;
use hekate_scribble::language::{ControlPlane, RowState, analyze};
use std::collections::{BTreeMap, BTreeSet};

type F = Block128;

const ROUNDS: usize = 24;

/// Selector order fixes the mask bits used below.
const S_ROUND: u32 = 1;
const S_IN_OUT: u32 = 2;
const IS_OUTPUT: u32 = 4;

fn plane() -> ControlPlane {
    ControlPlane {
        round_bits: KeccakColumns::ROUND_BITS,
        bit_width: 32,
        selectors: vec![
            KeccakColumns::S_ROUND,
            KeccakColumns::S_IN_OUT,
            KeccakColumns::IS_OUTPUT,
        ],
        num_columns: KeccakColumns::NUM_COLUMNS,
    }
}

/// `idle -> (I R^22 R23) -> O -> idle`;
/// the only shape a well-formed block may take.
fn honest_automaton() -> BTreeMap<RowState, BTreeSet<RowState>> {
    let idle = RowState {
        index: 0,
        selectors: 0,
    };

    let emit = RowState {
        index: 0,
        selectors: S_IN_OUT | IS_OUTPUT,
    };

    let round = |k: usize| RowState {
        index: 1 << k,
        selectors: S_ROUND | if k == 0 { S_IN_OUT } else { 0 },
    };

    let mut edges: BTreeMap<RowState, BTreeSet<RowState>> = BTreeMap::new();

    edges.insert(idle, [idle, round(0)].into_iter().collect());
    edges.insert(emit, [idle, round(0)].into_iter().collect());

    for k in 0..ROUNDS - 1 {
        edges.insert(round(k), [round(k + 1)].into_iter().collect());
    }

    edges.insert(round(ROUNDS - 1), [emit].into_iter().collect());

    edges
}

fn indices(max_weight: u32) -> Vec<u32> {
    (0u32..1 << ROUNDS)
        .filter(|i| i.count_ones() <= max_weight)
        .collect()
}

/// Bounded to Hamming weight 3: one-hot plus
/// every single skipped or duplicated shift.
/// Exhausting 2^24 is 10^13 pairs.
#[test]
#[cfg_attr(debug_assertions, ignore)]
fn admits_only_the_honest_language() {
    let ast: ConstraintAst<F> = KeccakChiplet::new(64).constraint_ast();
    let language = analyze(&ast, &plane(), &indices(3));

    assert_eq!(language.candidates, 1797);
    assert_eq!(language.core, honest_automaton());
}
