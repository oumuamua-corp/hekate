// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod generated;
mod program;
mod wire;

pub mod preflight;

pub use preflight::preflight;
pub use program::BundleProgram;
pub use wire::bundle::{
    DeserializedBundle, deserialize_bundle, serialize_bundle, serialize_bundle_header,
};
pub use wire::proof::{deserialize_proof, serialize_proof_bytes};
