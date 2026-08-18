// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#[allow(unused_imports, clippy::all, dead_code)]
#[rustfmt::skip]
mod hekate_program_generated;

#[allow(unused_imports, clippy::all, dead_code)]
#[rustfmt::skip]
mod hekate_proof_generated;

pub use hekate_program_generated::hekate::wire as program;
pub use hekate_proof_generated::hekate::wire as proof;
