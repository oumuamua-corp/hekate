// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>. All rights reserved.
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

/// 16 B element + 1 B bincode length prefix.
const Q_VECTOR_ELEM_BYTES: usize = 17;

#[cfg(feature = "std")]
pub use std::time::Instant;

#[cfg(not(feature = "std"))]
#[derive(Clone, Copy, Debug)]
pub struct Instant;

#[cfg(not(feature = "std"))]
impl Instant {
    pub fn now() -> Self {
        Self
    }

    pub fn elapsed(&self) -> core::time::Duration {
        core::time::Duration::from_secs(0)
    }
}

/// Splitting variable `c` minimising
/// `2^c · 17 · num_vectors + num_queries · 2^(num_vars - c) · row_bytes`
/// at `rs_field` row widths, floored toward `2^c >= max(2, support_size)`,
/// then capped at `num_vars`.
#[inline(always)]
pub fn compute_split_vars(
    num_vars: usize,
    num_queries: usize,
    support_size: usize,
    row_bytes: usize,
    num_vectors: usize,
) -> usize {
    if num_vars == 0 {
        return 0;
    }

    let vector_cost = (Q_VECTOR_ELEM_BYTES * num_vectors.max(1)) as u128;
    let opened_cost = ((num_queries * row_bytes).max(1)) as u128;

    let factor = (opened_cost / vector_cost).max(1);
    let floor_c = ((num_vars + factor.ilog2() as usize) / 2).min(num_vars);

    let cost = |c: usize| vector_cost * (1u128 << c) + opened_cost * (1u128 << (num_vars - c));

    // floor_c never overshoots the argmin
    let mut optimal_c = floor_c;
    while optimal_c < num_vars && cost(optimal_c + 1) < cost(optimal_c) {
        optimal_c += 1;
    }

    let support_floor = if support_size > 1 {
        (support_size - 1).ilog2() as usize + 1
    } else {
        1
    };

    optimal_c.max(support_floor).clamp(1, num_vars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    const QUERIES: [usize; 4] = [8, 32, 128, 176];
    const SUPPORTS: [usize; 4] = [4, 32, 128, 512];
    const ROW_BYTES: [usize; 7] = [4, 12, 44, 244, 1024, 4096, 27056];
    const VECTORS: [usize; 2] = [1, 2];

    fn scan_argmin(
        num_vars: usize,
        num_queries: usize,
        support_size: usize,
        row_bytes: usize,
        num_vectors: usize,
    ) -> usize {
        let vector_cost = (Q_VECTOR_ELEM_BYTES * num_vectors.max(1)) as u128;
        let opened_cost = ((num_queries * row_bytes).max(1)) as u128;

        let support_floor = if support_size > 1 {
            (support_size - 1).ilog2() as usize + 1
        } else {
            1
        };

        let lo = support_floor.clamp(1, num_vars);

        (lo..=num_vars)
            .min_by_key(|&c| vector_cost * (1u128 << c) + opened_cost * (1u128 << (num_vars - c)))
            .unwrap()
    }

    fn cases() -> Vec<(usize, usize, usize, usize, usize)> {
        let mut out = Vec::new();
        for num_vars in 1..=24 {
            for &q in &QUERIES {
                for &s in &SUPPORTS {
                    for &rb in &ROW_BYTES {
                        out.extend(VECTORS.iter().map(|&v| (num_vars, q, s, rb, v)));
                    }
                }
            }
        }

        out
    }

    #[test]
    fn split_vars_hits_the_discrete_argmin() {
        for (num_vars, q, s, rb, v) in cases() {
            assert_eq!(
                compute_split_vars(num_vars, q, s, rb, v),
                scan_argmin(num_vars, q, s, rb, v),
                "n={num_vars} q={q} s={s} rb={rb} v={v}"
            );
        }
    }

    #[test]
    fn split_vars_respects_the_support_floor() {
        for (num_vars, q, s, rb, v) in cases() {
            let c = compute_split_vars(num_vars, q, s, rb, v);
            let floor = (s - 1).ilog2() as usize + 1;

            assert!(
                c >= floor.min(num_vars),
                "n={num_vars} q={q} s={s} rb={rb} v={v} gave c={c}"
            );
        }
    }

    #[test]
    fn split_vars_collapses_for_a_single_row() {
        assert_eq!(compute_split_vars(0, 176, 128, 244, 2), 0);
    }
}
