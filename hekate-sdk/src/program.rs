// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

use alloc::string::String;
use alloc::vec::Vec;
use hekate_core::errors;
use hekate_core::trace::ColumnType;
use hekate_math::TowerField;
use hekate_program::chiplet::ChipletDef;
use hekate_program::constraint::{BoundaryConstraint, ConstraintAst};
use hekate_program::expander::VirtualExpander;
use hekate_program::permutation::PermutationCheckSpec;
use hekate_program::{Air, FixedColumn, InlineKernelHint, Program};

use crate::wire::bundle::DeserializedBundle;

/// Program reconstructed from a
/// deserialized `ProgramBundle`.
///
/// Implements `Air<F>` + `Program<F>` so the
/// prover and verifier can consume it directly.
#[derive(Clone)]
pub struct BundleProgram<F: TowerField> {
    name: String,
    num_columns: usize,
    num_public_inputs: usize,
    column_layout: Vec<ColumnType>,
    virtual_column_layout: Vec<ColumnType>,
    virtual_expander: Option<VirtualExpander>,
    constraint_ast: ConstraintAst<F>,
    boundary_constraints: Vec<BoundaryConstraint<F>>,
    fixed_columns: Vec<FixedColumn<F>>,
    permutation_checks: Vec<(String, PermutationCheckSpec)>,
    chiplet_defs: Vec<ChipletDef<F>>,
    inline_chiplets: Vec<ChipletDef<F>>,
    inline_chiplet_kernels: Vec<InlineKernelHint>,
}

impl<F: TowerField> BundleProgram<F> {
    pub fn from_bundle(bundle: &DeserializedBundle<F>) -> Self {
        Self {
            name: bundle.name.clone(),
            num_columns: bundle.num_columns,
            num_public_inputs: bundle.num_public_inputs,
            column_layout: bundle.column_layout.clone(),
            virtual_column_layout: bundle.virtual_column_layout.clone(),
            virtual_expander: bundle.virtual_expander.clone(),
            constraint_ast: bundle.constraint_ast.clone(),
            boundary_constraints: bundle.boundary_constraints.clone(),
            fixed_columns: bundle.fixed_columns.clone(),
            permutation_checks: bundle.permutation_checks.clone(),
            chiplet_defs: bundle.chiplet_defs.clone(),
            inline_chiplets: bundle.inline_chiplets.clone(),
            inline_chiplet_kernels: bundle.inline_chiplet_kernels.clone(),
        }
    }
}

impl<F: TowerField> Air<F> for BundleProgram<F> {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn num_columns(&self) -> usize {
        self.num_columns
    }

    fn boundary_constraints(&self) -> Vec<BoundaryConstraint<F>> {
        self.boundary_constraints.clone()
    }

    fn column_layout(&self) -> &[ColumnType] {
        &self.column_layout
    }

    fn virtual_column_layout(&self) -> &[ColumnType] {
        &self.virtual_column_layout
    }

    fn permutation_checks(&self) -> Vec<(String, PermutationCheckSpec)> {
        self.permutation_checks.clone()
    }

    fn fixed_columns(&self) -> Vec<FixedColumn<F>> {
        self.fixed_columns.clone()
    }

    fn virtual_expander(&self) -> Option<&VirtualExpander> {
        self.virtual_expander.as_ref()
    }

    fn constraint_ast(&self) -> ConstraintAst<F> {
        self.constraint_ast.clone()
    }

    fn inline_chiplets(&self) -> errors::Result<Vec<ChipletDef<F>>> {
        Ok(self.inline_chiplets.clone())
    }

    fn inline_chiplet_kernels(&self) -> Vec<InlineKernelHint> {
        self.inline_chiplet_kernels.clone()
    }
}

impl<F: TowerField> Program<F> for BundleProgram<F> {
    fn num_public_inputs(&self) -> usize {
        self.num_public_inputs
    }

    fn chiplet_defs(&self) -> errors::Result<Vec<ChipletDef<F>>> {
        Ok(self.chiplet_defs.clone())
    }
}
