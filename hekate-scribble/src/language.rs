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

//! Enumerates the row-to-row language an AIR admits.
//!
//! A chiplet built on a one-hot round index has a control plane
//! of that index plus its selector bits. Every other column is
//! data. Holding the data at zero and evaluating only the roots
//! that read control columns yields a transition relation at least
//! as permissive as the AIR itself; a core matching the honest
//! block shape proves no other shape is admitted.

use hekate_math::{Flat, HardwareField, TowerField};
use hekate_program::constraint::{ConstraintArena, ConstraintAst, ConstraintExpr, ExprId};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};

/// Where the control plane sits in the virtual layout.
pub struct ControlPlane {
    pub round_bits: usize,
    pub bit_width: usize,
    pub selectors: Vec<usize>,
    pub num_columns: usize,
}

impl ControlPlane {
    fn columns(&self) -> BTreeSet<usize> {
        let mut cols: BTreeSet<usize> = (0..self.bit_width).map(|k| self.round_bits + k).collect();

        cols.extend(self.selectors.iter().copied());

        cols
    }

    fn write_row<F>(&self, state: RowState, row: &mut Vec<Flat<F>>)
    where
        F: TowerField + HardwareField,
    {
        let one = F::ONE.to_hardware();

        row.clear();
        row.resize(self.num_columns, F::ZERO.to_hardware());

        for k in 0..self.bit_width {
            if state.index >> k & 1 == 1 {
                row[self.round_bits + k] = one;
            }
        }

        for (k, &col) in self.selectors.iter().enumerate() {
            if state.selectors >> k & 1 == 1 {
                row[col] = one;
            }
        }
    }

    fn row<F>(&self, state: RowState) -> Vec<Flat<F>>
    where
        F: TowerField + HardwareField,
    {
        let mut row = Vec::new();
        self.write_row(state, &mut row);

        row
    }
}

/// One row's control plane. `selectors` is a mask
/// over `ControlPlane::selectors`, in that order.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct RowState {
    pub index: u32,
    pub selectors: u32,
}

/// The admitted language over the enumerated candidates.
pub struct Language {
    /// Row states the row-local roots admit.
    pub candidates: usize,

    /// Transitions left after dropping every
    /// state with no successor or no predecessor.
    pub core: BTreeMap<RowState, BTreeSet<RowState>>,
}

/// Sub-AST spanned by `roots`, renumbered; evaluation
/// costs their cone rather than the whole arena.
fn cone<F: TowerField>(ast: &ConstraintAst<F>, roots: &[usize]) -> ConstraintAst<F> {
    let mut mapped: Vec<Option<ExprId>> = vec![None; ast.arena.len()];
    let mut arena = ConstraintArena::new();
    let mut stack: Vec<(ExprId, bool)> = roots.iter().map(|&i| (ast.roots[i], false)).collect();

    while let Some((id, expanded)) = stack.pop() {
        if mapped[id.0 as usize].is_some() {
            continue;
        }

        if !expanded {
            stack.push((id, true));

            match ast.arena.get(id) {
                ConstraintExpr::Add(a, b) | ConstraintExpr::Mul(a, b) => {
                    stack.push((*a, false));
                    stack.push((*b, false));
                }
                ConstraintExpr::Scale(_, a) => stack.push((*a, false)),
                ConstraintExpr::Sum(children) => stack.extend(children.iter().map(|&c| (c, false))),
                _ => {}
            }

            continue;
        }

        let at = |id: ExprId| mapped[id.0 as usize].expect("child mapped before parent");

        let expr = match ast.arena.get(id) {
            ConstraintExpr::Cell(cell) => ConstraintExpr::Cell(*cell),
            ConstraintExpr::Const(c) => ConstraintExpr::Const(*c),
            ConstraintExpr::Add(a, b) => ConstraintExpr::Add(at(*a), at(*b)),
            ConstraintExpr::Mul(a, b) => ConstraintExpr::Mul(at(*a), at(*b)),
            ConstraintExpr::Scale(c, a) => ConstraintExpr::Scale(*c, at(*a)),
            ConstraintExpr::Sum(children) => {
                ConstraintExpr::Sum(children.iter().map(|&c| at(c)).collect())
            }
        };

        mapped[id.0 as usize] = Some(arena.alloc(expr));
    }

    let roots: Vec<ExprId> = roots
        .iter()
        .map(|&i| mapped[ast.roots[i].0 as usize].expect("root mapped"))
        .collect();

    let labels = vec![None; roots.len()];

    ConstraintAst {
        arena,
        roots,
        labels,
    }
}

/// Roots reading only control columns, split
/// by whether they reach into the next row.
fn control_roots<F: TowerField>(
    ast: &ConstraintAst<F>,
    plane: &ControlPlane,
) -> (Vec<usize>, Vec<usize>) {
    let control = plane.columns();

    let mut row_local = Vec::new();
    let mut transition = Vec::new();

    // Node-visited, not path-visited: a shared sub-DAG
    // reached by many paths would otherwise be exponential.
    let mut seen = vec![u32::MAX; ast.arena.len()];

    for (i, &root) in ast.roots.iter().enumerate() {
        let mut cols = BTreeSet::new();
        let mut uses_next = false;
        let mut stack = vec![root];

        while let Some(id) = stack.pop() {
            if seen[id.0 as usize] == i as u32 {
                continue;
            }

            seen[id.0 as usize] = i as u32;

            match ast.arena.get(id) {
                ConstraintExpr::Cell(cell) => {
                    cols.insert(cell.col_idx);

                    uses_next |= cell.next_row;
                }
                ConstraintExpr::Const(_) => {}
                ConstraintExpr::Add(a, b) | ConstraintExpr::Mul(a, b) => {
                    stack.push(*a);
                    stack.push(*b);
                }
                ConstraintExpr::Scale(_, a) => stack.push(*a),
                ConstraintExpr::Sum(children) => stack.extend(children.iter().copied()),
            }
        }

        if !cols.is_subset(&control) {
            continue;
        }

        match uses_next {
            true => transition.push(i),
            false => row_local.push(i),
        }
    }

    (row_local, transition)
}

fn cycle_core(
    mut edges: BTreeMap<RowState, BTreeSet<RowState>>,
) -> BTreeMap<RowState, BTreeSet<RowState>> {
    loop {
        let live: BTreeSet<RowState> = edges
            .iter()
            .filter(|(_, out)| !out.is_empty())
            .map(|(s, _)| *s)
            .collect();

        let reachable: BTreeSet<RowState> = edges.values().flatten().copied().collect();
        let keep: BTreeSet<RowState> = live.intersection(&reachable).copied().collect();

        let before = edges.len();

        edges.retain(|s, _| keep.contains(s));

        for out in edges.values_mut() {
            out.retain(|t| keep.contains(t));
        }

        edges.retain(|_, out| !out.is_empty());

        if edges.len() == before {
            return edges;
        }
    }
}

/// Panics unless `direction_col` is 1 on exactly
/// the opening row of every `selector_col` emit pair.
pub fn assert_direction_pinned<F>(
    ast: &ConstraintAst<F>,
    num_columns: usize,
    selector_col: usize,
    direction_col: usize,
) where
    F: TowerField + HardwareField,
{
    let plane = ControlPlane {
        round_bits: 0,
        bit_width: 0,
        selectors: vec![selector_col, direction_col],
        num_columns,
    };

    let state = |selectors: u32| RowState {
        index: 0,
        selectors,
    };

    let idle = state(0b00);
    let response = state(0b01);
    let request = state(0b11);

    let mut honest: BTreeMap<RowState, BTreeSet<RowState>> = BTreeMap::new();

    honest.insert(idle, [idle, request].into_iter().collect());
    honest.insert(request, [response].into_iter().collect());
    honest.insert(response, [idle, request].into_iter().collect());

    let language = analyze(ast, &plane, &[0]);

    assert_eq!(
        language.core, honest,
        "selector {selector_col} / direction {direction_col} admit a \
         language wider than `idle -> request -> response -> idle`"
    );
}

/// Enumerates the control states the AIR admits over `indices`,
/// then drops every state with no successor or no predecessor.
/// Caller picks `indices`; anything short of every value
/// in `bit_width` bounds the claim.
pub fn analyze<F>(ast: &ConstraintAst<F>, plane: &ControlPlane, indices: &[u32]) -> Language
where
    F: TowerField + HardwareField,
{
    let (row_local, transition) = control_roots(ast, plane);
    let row_ast = cone(ast, &row_local);
    let edge_ast = cone(ast, &transition);
    let zero = F::ZERO.to_hardware();

    let row_consts = row_ast.precompute_hardware_consts();

    let mut buf = Vec::new();
    let mut row = Vec::new();
    let mut states = Vec::new();

    for &index in indices {
        for selectors in 0..(1u32 << plane.selectors.len()) {
            let state = RowState { index, selectors };
            plane.write_row::<F>(state, &mut row);

            row_ast.evaluate_into(&row_consts, &row, &row, &mut buf);

            if row_ast.roots.iter().all(|r| buf[r.0 as usize] == zero) {
                states.push(state);
            }
        }
    }

    let edge_consts = edge_ast.precompute_hardware_consts();
    let rows: Vec<Vec<Flat<F>>> = states.iter().map(|&s| plane.row::<F>(s)).collect();

    let successors = |cur: &Vec<Flat<F>>| {
        let mut buf = Vec::new();

        states
            .iter()
            .zip(rows.iter())
            .filter(|(_, next)| {
                edge_ast.evaluate_into(&edge_consts, cur, next, &mut buf);

                edge_ast.roots.iter().all(|r| buf[r.0 as usize] == zero)
            })
            .map(|(b, _)| *b)
            .collect::<BTreeSet<RowState>>()
    };

    #[cfg(feature = "parallel")]
    let edges: BTreeMap<RowState, BTreeSet<RowState>> = states
        .par_iter()
        .zip(rows.par_iter())
        .map(|(a, cur)| (*a, successors(cur)))
        .collect();

    #[cfg(not(feature = "parallel"))]
    let edges: BTreeMap<RowState, BTreeSet<RowState>> = states
        .iter()
        .zip(rows.iter())
        .map(|(a, cur)| (*a, successors(cur)))
        .collect();

    Language {
        candidates: states.len(),
        core: cycle_core(edges),
    }
}
