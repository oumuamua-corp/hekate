// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

//! Chiplet modules for the Hekate.
//!
//! Chiplets are specialized execution units that
//! handle specific operations and link to the main
//! CPU via Grand Product Arguments.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate core;

pub mod atoms;
pub mod chiplets;

pub use chiplets::int::arith::{
    ArithmeticOpcode, CpuArithColumns, CpuIntArithmeticUnit, IntArithmeticChiplet,
    IntArithmeticLayout, IntArithmeticOp, generate_arithmetic_trace,
};
pub use chiplets::ram::{
    CpuMemColumns, CpuMemoryUnit, MemoryEvent, RamChiplet, RamColumns, generate_ram_trace,
};
pub use chiplets::rom::{
    CpuFetchColumns, CpuFetchUnit, Instruction, RomChiplet, RomColumns, generate_rom_trace,
};
