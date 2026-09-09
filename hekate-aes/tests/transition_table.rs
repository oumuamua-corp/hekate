// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

//! The control language the AIR admits, enumerated.

use hekate_aes::{
    Aes128Columns, Aes256Columns, AesRound128Air, AesRound256Air, CpuAes128Columns, CpuAes128Unit,
    CpuAes256Columns, CpuAes256Unit,
};
use hekate_math::Block128;
use hekate_program::Air;
use hekate_program::constraint::ConstraintAst;
use hekate_program::constraint::builder::ConstraintSystem;
use hekate_scribble::language::{
    ControlPlane, Language, RowState, analyze, assert_direction_pinned,
};
use std::collections::{BTreeMap, BTreeSet};

type F = Block128;

/// Selector order fixes the mask bits used below.
const S_ROUND: u32 = 1;
const S_FINAL: u32 = 2;
const S_IN_OUT: u32 = 4;
const S_ACTIVE: u32 = 8;
const S_INPUT: u32 = 16;

/// `idle -> (I R^{n-2} F) -> O -> idle`;
/// the only shape a well-formed block may take.
fn honest_automaton(active_rows: usize) -> BTreeMap<RowState, BTreeSet<RowState>> {
    let idle = RowState {
        index: 0,
        selectors: 0,
    };

    let emit = RowState {
        index: 0,
        selectors: S_IN_OUT,
    };

    let round = |k: usize| RowState {
        index: 1 << k,
        selectors: S_ACTIVE
            | if k + 1 == active_rows {
                S_FINAL
            } else {
                S_ROUND
            }
            | if k == 0 { S_IN_OUT | S_INPUT } else { 0 },
    };

    let mut edges: BTreeMap<RowState, BTreeSet<RowState>> = BTreeMap::new();

    edges.insert(idle, [idle, round(0)].into_iter().collect());
    edges.insert(emit, [idle, round(0)].into_iter().collect());

    for k in 0..active_rows - 1 {
        edges.insert(round(k), [round(k + 1)].into_iter().collect());
    }

    edges.insert(round(active_rows - 1), [emit].into_iter().collect());

    edges
}

/// Exhaustive over the whole index column, including the
/// bits above the active range that the AIR pins to zero.
fn exhaustive(ast: &ConstraintAst<F>, plane: &ControlPlane) -> Language {
    let indices: Vec<u32> = (0u32..1 << plane.bit_width).collect();

    analyze(ast, plane, &indices)
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn aes128_admits_only_the_honest_language() {
    let ast: ConstraintAst<F> = AesRound128Air::for_constraints().constraint_ast();

    let plane = ControlPlane {
        round_bits: Aes128Columns::ROUND_BITS,
        bit_width: 16,
        selectors: vec![
            Aes128Columns::S_ROUND,
            Aes128Columns::S_FINAL,
            Aes128Columns::S_IN_OUT,
            Aes128Columns::S_ACTIVE,
            Aes128Columns::S_INPUT,
        ],
        num_columns: Aes128Columns::NUM_COLUMNS,
    };

    let language = exhaustive(&ast, &plane);

    assert_eq!(language.candidates, 770);
    assert_eq!(language.core, honest_automaton(AesRound128Air::ACTIVE_ROWS));
}

#[test]
#[cfg_attr(debug_assertions, ignore)]
fn aes256_admits_only_the_honest_language() {
    let ast: ConstraintAst<F> = AesRound256Air::for_constraints().constraint_ast();

    let plane = ControlPlane {
        round_bits: Aes256Columns::ROUND_BITS,
        bit_width: 16,
        selectors: vec![
            Aes256Columns::S_ROUND,
            Aes256Columns::S_FINAL,
            Aes256Columns::S_IN_OUT,
            Aes256Columns::S_ACTIVE,
            Aes256Columns::S_INPUT,
        ],
        num_columns: Aes256Columns::NUM_COLUMNS,
    };

    let language = exhaustive(&ast, &plane);

    assert_eq!(language.candidates, 12290);
    assert_eq!(language.core, honest_automaton(AesRound256Air::ACTIVE_ROWS));
}

#[test]
fn cpu128_pins_the_link_direction() {
    let cs = ConstraintSystem::<F>::new();
    CpuAes128Unit::constrain(&cs, 0);

    assert_direction_pinned(
        &cs.build(),
        CpuAes128Columns::NUM_COLUMNS,
        CpuAes128Columns::SELECTOR,
        CpuAes128Columns::KEY_SELECTOR,
    );
}

#[test]
fn cpu256_pins_the_link_direction() {
    let cs = ConstraintSystem::<F>::new();
    CpuAes256Unit::constrain(&cs, 0);

    assert_direction_pinned(
        &cs.build(),
        CpuAes256Columns::NUM_COLUMNS,
        CpuAes256Columns::SELECTOR,
        CpuAes256Columns::KEY_SELECTOR,
    );
}

/// The shape every consumer carried before `constrain`:
/// both columns boolean, direction otherwise free.
#[test]
#[should_panic(expected = "wider than")]
fn boolean_only_host_is_rejected() {
    let cs = ConstraintSystem::<F>::new();
    cs.assert_boolean(cs.col(CpuAes128Columns::SELECTOR));
    cs.assert_boolean(cs.col(CpuAes128Columns::KEY_SELECTOR));

    assert_direction_pinned(
        &cs.build(),
        CpuAes128Columns::NUM_COLUMNS,
        CpuAes128Columns::SELECTOR,
        CpuAes128Columns::KEY_SELECTOR,
    );
}

/// Dropping the run-opener root alone
/// reopens `reversed_pairing_with_moved_key`.
#[test]
#[should_panic(expected = "wider than")]
fn missing_run_opener_root_is_rejected() {
    let cs = ConstraintSystem::<F>::new();
    let sel = cs.col(CpuAes128Columns::SELECTOR);
    let dir = cs.col(CpuAes128Columns::KEY_SELECTOR);
    let one = cs.one();

    cs.assert_boolean(sel);
    cs.assert_boolean(dir);
    cs.constrain(dir * (one + sel));
    cs.constrain(
        sel * (dir + cs.next(CpuAes128Columns::KEY_SELECTOR) + cs.next(CpuAes128Columns::SELECTOR)),
    );

    assert_direction_pinned(
        &cs.build(),
        CpuAes128Columns::NUM_COLUMNS,
        CpuAes128Columns::SELECTOR,
        CpuAes128Columns::KEY_SELECTOR,
    );
}
