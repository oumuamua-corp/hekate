// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod basemul;
pub mod high_bits;
#[allow(clippy::needless_range_loop)]
pub mod mldsa;
#[allow(clippy::needless_range_loop)]
pub mod mlkem;
pub mod norm_check;
pub mod ntt;
pub mod twiddle_rom;
pub mod utils;
