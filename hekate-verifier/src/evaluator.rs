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

use crate::brakedown::BrakedownVerifier;
use crate::sumcheck::verify;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use hekate_core::config::Config;
use hekate_core::errors;
use hekate_core::proofs::{BrakedownCommitment, EvalBatchProof};
use hekate_core::tensor::TensorProduct;
use hekate_core::trace::{ColumnType, TraceCompatibleField};
use hekate_crypto::Hasher;
use hekate_crypto::transcript::Transcript;
use hekate_math::{
    AdditiveFft, BinaryFieldExtras, Block128, Flat, HardwareField, PackableField, TowerField,
};
use hekate_program::expander::RingSwitchPlan;
use tracing::{instrument, warn};

#[cfg(feature = "parallel")]
const PARALLEL_PROXIMITY_THRESHOLD: usize = 1 << 18;

const NBITS: usize = 128;

pub struct EvaluatorVerifier<F, H: Hasher> {
    _marker: PhantomData<(F, H)>,
}

pub struct EvalVerifyContext<'a, F: HardwareField> {
    pub point: &'a [Flat<F>],
    pub claimed_values: &'a [Flat<F>],
    pub num_vars: usize,
    pub ring_plan: &'a RingSwitchPlan,

    /// `true` when the claims carry a next-row half,
    /// proven through the K_P / A_next weights.
    pub shifted_claims: bool,
}

impl<F, H: Hasher> EvaluatorVerifier<F, H>
where
    F: HardwareField + PackableField + TraceCompatibleField,
{
    /// Verifies the ring-switch TensorPCS evaluation argument,
    /// binding the claimed virtual evals to the base-only
    /// Brakedown commitment. A degree-2 sumcheck reduces
    /// `[A + η^U·A_next]·master_bit + [Eq + η^U·K_P]·master_whole`
    /// to `r_final`; the final check pairs the transparent weight
    /// evals at `r'` with two whole-column openings that the
    /// proximity test binds to the committed codewords.
    #[instrument(skip_all, name = "Evaluator::verify")]
    pub fn verify(
        commitment: &BrakedownCommitment,
        proof: &EvalBatchProof<F>,
        transcript: &mut Transcript<H>,
        ctx: EvalVerifyContext<'_, F>,
        config: &Config,
    ) -> errors::Result<bool>
    where
        F: BinaryFieldExtras + Into<Block128> + From<u128>,
    {
        let point = ctx.point;
        let claims = ctx.claimed_values;
        let num_vars = ctx.num_vars;
        let plan = ctx.ring_plan;
        let shifted_claims = ctx.shifted_claims;
        let claim_halves = if shifted_claims { 2 } else { 1 };
        let zero = Flat::from_raw(F::ZERO);

        if claims.len() != plan.total_claims() * claim_halves {
            return Err(errors::Error::Protocol {
                protocol: "evaluator_verifier",
                message: "ring-switch plan claim count does not match the claimed evaluations",
            });
        }

        transcript.append_message(b"eval_batch_start", b"");

        for &val in claims {
            transcript.append_field(b"claimed_val", val.to_tower());
        }

        let eta_tower = transcript.challenge_field::<F>(b"eval_eta")?;
        let eta = eta_tower.to_hardware();

        let has_ring = plan.has_ring();

        if has_ring && F::BITS != NBITS {
            return Err(errors::Error::Protocol {
                protocol: "evaluator_verifier",
                message: "ring-switch evaluation requires a 128-bit field",
            });
        }

        // Order is load-bearing:
        // r'' follows the claimed evals, precedes the sumcheck.
        let kappa = F::BITS.ilog2() as usize;

        let r_mix: Vec<Block128> = if has_ring {
            let mut m = Vec::with_capacity(kappa);
            for _ in 0..kappa {
                m.push(transcript.challenge_field::<F>(b"eval_rmix")?.into());
            }

            m
        } else {
            Vec::new()
        };

        let target = ring_target::<F>(plan, claims, eta_tower, &r_mix, shifted_claims);
        let target_flat = F::from(target.0).to_hardware();

        let sc_res = verify(num_vars, 2, target_flat, &proof.sumcheck_proof, transcript)?;
        let (r_row, sumcheck_final_eval) = match sc_res {
            Some(res) => res,
            None => {
                warn!("Sumcheck failed");
                return Ok(false);
            }
        };

        let q_whole = &proof.tensor_vec;
        let q_ring = &proof.tensor_vec_ring;

        transcript.append_field_list(b"tensor_q", q_whole);

        if has_ring {
            transcript.append_field_list(b"tensor_q_ring", q_ring);
        }

        let split_vars = plan.split_vars(num_vars, config);

        let grid_cols = 1 << split_vars;
        let grid_rows = 1 << (num_vars - split_vars);
        let geom = config.table_geom(grid_cols);
        let encoded_width = geom.encoded_width;

        if grid_cols + geom.support_size > encoded_width {
            warn!("support + data message exceeds the codeword width");
            return Ok(false);
        }

        config.check_security(size_of::<F>() * 8, grid_cols)?;

        let expected_len = grid_cols + geom.support_size;
        let expected_ring_len = if has_ring { expected_len } else { 0 };

        if q_whole.len() != expected_len || q_ring.len() != expected_ring_len {
            warn!("tensor_q length mismatch");
            return Ok(false);
        }

        let q_whole_flat: Vec<Flat<F>> = q_whole.iter().map(|v| v.to_hardware()).collect();
        let q_ring_flat: Vec<Flat<F>> = if has_ring {
            q_ring.iter().map(|v| v.to_hardware()).collect()
        } else {
            Vec::new()
        };

        // Two independent encodes
        #[cfg(feature = "parallel")]
        let (q_whole_res, q_ring_res) = rayon::join(
            || rs_encode_row::<F>(&q_whole_flat, grid_cols, config),
            || {
                if has_ring {
                    rs_encode_row::<F>(&q_ring_flat, grid_cols, config)
                } else {
                    Ok(Vec::new())
                }
            },
        );

        #[cfg(feature = "parallel")]
        let (q_whole_encoded, q_ring_encoded) = (q_whole_res?, q_ring_res?);

        #[cfg(not(feature = "parallel"))]
        let q_whole_encoded = rs_encode_row::<F>(&q_whole_flat, grid_cols, config)?;

        #[cfg(not(feature = "parallel"))]
        let q_ring_encoded = if has_ring {
            rs_encode_row::<F>(&q_ring_flat, grid_cols, config)?
        } else {
            Vec::new()
        };

        let r_col_low = &r_row[..split_vars];
        let tensor_col = build_tensor_table::<F>(r_col_low);

        let master_eval = |q: &[Flat<F>]| {
            let mut acc = Flat::from_raw(F::ZERO);
            for (&val, &t) in q.iter().take(grid_cols).zip(&tensor_col) {
                acc += val * t;
            }

            acc
        };

        let master_whole_eval = master_eval(&q_whole_flat);
        let master_bit_eval = match has_ring {
            true => master_eval(&q_ring_flat),
            false => zero,
        };

        let (coeff_bit, coeff_whole, eta_shift) = plan.column_coeffs::<F>(eta);

        // The weight evals at r' are transparent;
        // the two master evals are bound by the
        // whole-column proximity check below.
        let (whole_weight_at_r, ring_weight_at_r) =
            master_weights_at::<F>(point, &r_row, &r_mix, eta_shift, has_ring, shifted_claims);

        if sumcheck_final_eval
            != ring_weight_at_r * master_bit_eval + whole_weight_at_r * master_whole_eval
        {
            warn!("ring-switch final check failed");
            return Ok(false);
        }

        // Fork transcript to reproduce
        // exact random queries generated by LDT
        transcript.append_message(b"eval_batch_ldt", b"");

        let mut ldt_transcript = transcript.clone();

        let openings = BrakedownVerifier::<F, H>::verify(
            commitment,
            &proof.ldt_proof,
            transcript, // advances the real transcript
            config,
            split_vars,
        )?;

        let opened_columns = openings.columns;
        let slot_map = &openings.slot_map;

        // Replay randomness generation
        let mut random_indices = Vec::with_capacity(config.num_queries);
        for _ in 0..config.num_queries {
            let bytes = ldt_transcript
                .challenge_field::<F>(b"idx_query")?
                .to_bytes();

            let mut rng_val: u64 = 0;
            for (k, &b) in bytes.iter().take(8).enumerate() {
                rng_val |= (b as u64) << (8 * k);
            }

            random_indices.push((rng_val % (encoded_width as u64)) as usize);
        }

        let r_row_high = &r_row[split_vars..];
        let tensor_row = TensorProduct::<F>::new(r_row_high.to_vec());

        let mut tensor_row_evals = Vec::with_capacity(grid_rows);
        for r in 0..grid_rows {
            tensor_row_evals.push(tensor_row.evaluate_at_index(r));
        }

        let num_phys = plan.phys_rs.len();
        let phys_row_bytes = plan.opened_row_bytes();

        // Re-derive both folded openings from the physical columns
        // in the opened leaf; RS commutes with a whole-column fold,
        // this must match the RS re-encodings of the prover's
        // committed q vectors.
        let check_query =
            |q_idx: usize, col_idx: usize, phys_row: &mut Vec<Flat<F>>| -> errors::Result<bool> {
                let col_bytes = &opened_columns[slot_map[q_idx]];

                if col_bytes.len() != grid_rows * phys_row_bytes {
                    warn!("opened column length does not match the physical row layout");
                    return Ok(false);
                }

                let mut q_whole_val = Flat::from_raw(F::ZERO);
                let mut q_ring_val = Flat::from_raw(F::ZERO);

                for r in 0..grid_rows {
                    let row_data = &col_bytes[r * phys_row_bytes..(r + 1) * phys_row_bytes];

                    phys_row.clear();

                    parse_physical_row::<F>(row_data, &plan.phys_rs, phys_row);

                    let mut fold_whole = Flat::from_raw(F::ZERO);
                    let mut fold_bit = Flat::from_raw(F::ZERO);

                    for p in 0..num_phys {
                        let base = phys_row[p];
                        fold_whole += base * coeff_whole[p];

                        if has_ring {
                            fold_bit += base * coeff_bit[p];
                        }
                    }

                    let tr = tensor_row_evals[r];
                    q_whole_val += fold_whole * tr;
                    q_ring_val += fold_bit * tr;
                }

                let ok = q_whole_val == q_whole_encoded[col_idx]
                    && (!has_ring || q_ring_val == q_ring_encoded[col_idx]);

                if !ok {
                    warn!("TensorPCS proximity mismatch for column {}", col_idx);
                }

                Ok(ok)
            };

        let run_sequential = |indices: &[usize]| -> errors::Result<bool> {
            let mut phys_row = Vec::with_capacity(num_phys);
            for (q_idx, &col_idx) in indices.iter().enumerate() {
                if !check_query(q_idx, col_idx, &mut phys_row)? {
                    return Ok(false);
                }
            }

            Ok(true)
        };

        #[cfg(feature = "parallel")]
        let all_matched = {
            let per_row_cols = num_phys * if has_ring { 3 } else { 2 };
            let proximity_work = config.num_queries * grid_rows * per_row_cols;

            if proximity_work >= PARALLEL_PROXIMITY_THRESHOLD {
                use rayon::prelude::*;

                random_indices
                    .par_iter()
                    .enumerate()
                    .map_init(
                        || Vec::<Flat<F>>::with_capacity(num_phys),
                        |phys_row, (q_idx, &col_idx)| check_query(q_idx, col_idx, phys_row),
                    )
                    .try_reduce(|| true, |a, b| Ok(a && b))?
            } else {
                run_sequential(&random_indices)?
            }
        };

        #[cfg(not(feature = "parallel"))]
        let all_matched = run_sequential(&random_indices)?;

        if !all_matched {
            return Ok(false);
        }

        Ok(true)
    }
}

/// `q_flat = [q_data(grid_cols), q_support(ldt)]`. Layout must
/// match the prover's `rs_encode_grid`; `master_eval` reads `q_data`
/// alone, the support masks openings without entering the claim.
fn rs_encode_row<F: HardwareField + BinaryFieldExtras>(
    q_flat: &[Flat<F>],
    grid_cols: usize,
    config: &Config,
) -> errors::Result<Vec<Flat<F>>> {
    let geom = config.table_geom(grid_cols);
    let ldt = geom.support_size;
    let code_width = geom.encoded_width;

    let mut buf = vec![Flat::from_raw(F::ZERO); code_width];
    buf[..ldt].copy_from_slice(&q_flat[grid_cols..grid_cols + ldt]);
    buf[ldt..ldt + grid_cols].copy_from_slice(&q_flat[..grid_cols]);

    let fft = AdditiveFft::<F>::new(code_width.trailing_zeros());

    fft.forward_scalar(&mut buf)
        .map_err(|_| errors::Error::Protocol {
            protocol: "evaluator",
            message: "additive-FFT row encode failed",
        })?;

    Ok(buf)
}

fn build_tensor_table<F: HardwareField>(r: &[Flat<F>]) -> Vec<Flat<F>> {
    let one = Flat::from_raw(F::ONE);
    let mut table = vec![one];

    for &ri in r {
        let one_minus = one - ri;
        let n = table.len();

        let mut next = Vec::with_capacity(2 * n);

        for &v in &table {
            next.push(v * one_minus);
        }

        for &v in &table {
            next.push(v * ri);
        }

        table = next;
    }

    table
}

fn eq_tensor_b(r: &[Block128]) -> Vec<Block128> {
    let mut t = vec![Block128::ONE];
    for &ri in r {
        let len = t.len();
        let mut nt = Vec::with_capacity(len * 2);

        for &v in &t {
            nt.push(v * (Block128::ONE + ri));
        }

        for &v in &t {
            nt.push(v * ri);
        }

        t = nt;
    }

    t
}

fn transpose128(cols: &[Block128; NBITS]) -> [Block128; NBITS] {
    let mut m = *cols;
    let mut j = NBITS / 2;
    let mut mask = (1u128 << (NBITS / 2)) - 1;

    while j != 0 {
        let mut k = 0;

        while k < NBITS {
            for i in k..k + j {
                let a = m[i].0;
                let b = m[i + j].0;
                let t = ((a >> j) ^ b) & mask;

                m[i] = Block128(a ^ (t << j));
                m[i + j] = Block128(b ^ t);
            }

            k += j << 1;
        }

        j >>= 1;
        mask ^= mask << j;
    }

    m
}

/// `(whole, ring)` master weights at `r'`, pairing with
/// `master_whole` and `master_bit` in the final check.
fn master_weights_at<F>(
    point: &[Flat<F>],
    r_row: &[Flat<F>],
    r_mix: &[Block128],
    eta_shift: Flat<F>,
    has_ring: bool,
    shifted_claims: bool,
) -> (Flat<F>, Flat<F>)
where
    F: HardwareField + Into<Block128> + From<u128>,
{
    let zero = Flat::from_raw(F::ZERO);
    let eq_at_r = TensorProduct::evaluate_eq_slice(point, r_row);

    if !has_ring && !shifted_claims {
        return (eq_at_r, zero);
    }

    let point_b: Vec<Block128> = point.iter().map(|f| f.to_tower().into()).collect();
    let r_row_b: Vec<Block128> = r_row.iter().map(|f| f.to_tower().into()).collect();

    let (a, a_next) = match has_ring {
        true => ring_switch_a_pair(&point_b, &r_row_b, r_mix, shifted_claims),
        false => (Block128::ZERO, Block128::ZERO),
    };

    let a_r = F::from(a.0).to_hardware();

    match shifted_claims {
        true => {
            let k_p_r = F::from(k_p_at(&point_b, &r_row_b).0).to_hardware();
            let a_next_r = F::from(a_next.0).to_hardware();

            (eq_at_r + eta_shift * k_p_r, a_r + eta_shift * a_next_r)
        }
        false => (eq_at_r, a_r),
    }
}

/// `Ã(r')` and the `K_P` carry chain `Ã_next(r')`.
/// Reverse iteration is safe: the per-variable
/// operators `I + L_{P_k} + R_{r'_k}` commute pairwise.
fn ring_switch_a_pair(
    point: &[Block128],
    r_final: &[Block128],
    r_mix: &[Block128],
    with_next: bool,
) -> (Block128, Block128) {
    let n = point.len();
    let one = Block128::ONE;

    let mut p_pref = vec![one; n + 1];
    let mut q_pref = vec![one; n + 1];

    for i in 0..n {
        p_pref[i + 1] = p_pref[i] * point[i];
        q_pref[i + 1] = q_pref[i] * (one + r_final[i]);
    }

    let mut e = [Block128::ZERO; NBITS];
    let mut h = [Block128::ZERO; NBITS];

    e[0] = one;

    for k in (0..n).rev() {
        if with_next {
            let alpha = p_pref[k] * (one + point[k]);
            let beta = q_pref[k] * r_final[k];

            let mut m = e;
            for cv in m.iter_mut() {
                *cv *= alpha;
            }

            let mut m_rows = transpose128(&m);
            for ru in m_rows.iter_mut() {
                *ru *= beta;
            }

            for (hv, mv) in h.iter_mut().zip(transpose128(&m_rows).iter()) {
                *hv += *mv;
            }
        }

        let mut col_scaled = e;
        for cv in col_scaled.iter_mut() {
            *cv *= point[k];
        }

        let mut row_scaled = transpose128(&e);
        for ru in row_scaled.iter_mut() {
            *ru *= r_final[k];
        }

        let row_scaled = transpose128(&row_scaled);

        for i in 0..NBITS {
            e[i] += col_scaled[i] + row_scaled[i];
        }
    }

    if with_next {
        let wrap_col = p_pref[n];
        let wrap_row = q_pref[n];

        for (v, hv) in h.iter_mut().enumerate() {
            if (wrap_row.0 >> v) & 1 == 1 {
                *hv += wrap_col;
            }
        }
    }

    let eq_mix = eq_tensor_b(r_mix);
    let e_rows = transpose128(&e);
    let h_rows = transpose128(&h);

    let mut a = Block128::ZERO;
    let mut a_next = Block128::ZERO;

    for u in 0..NBITS {
        a += eq_mix[u] * e_rows[u];
        a_next += eq_mix[u] * h_rows[u];
    }

    (a, a_next)
}

/// Σ_u eq(r'',u)·ŝ_u for one ring unit, ŝ_u = Σ_v bit_u(c_v)·2^v.
fn ring_batch_b(bit_claims: &[Block128], eq_mix: &[Block128]) -> Block128 {
    let mut acc = Block128::ZERO;
    for (u, &m) in eq_mix.iter().enumerate() {
        let mut shat = 0u128;
        for (v, cv) in bit_claims.iter().enumerate() {
            shat |= ((cv.0 >> u) & 1) << v;
        }

        acc += m * Block128(shat);
    }

    acc
}

/// Reconstructs the sumcheck's initial claim from the claimed
/// virtual evals, in the tower basis. Ring units contribute
/// `eta·Σ_u eq(r'',u) ŝ_u`; whole units contribute `eta·c'`.
fn ring_target<F>(
    plan: &RingSwitchPlan,
    claims: &[Flat<F>],
    eta_tower: F,
    r_mix: &[Block128],
    shifted_claims: bool,
) -> Block128
where
    F: HardwareField + Into<Block128>,
{
    let claim_halves = if shifted_claims { 2 } else { 1 };
    let half = claims.len() / claim_halves;
    let eq_mix = eq_tensor_b(r_mix);
    let eta: Block128 = eta_tower.into();

    let mut eta_pows = Vec::with_capacity(plan.num_units + 1);
    let mut e = Block128::ONE;

    for _ in 0..=plan.num_units {
        eta_pows.push(e);
        e *= eta;
    }

    let eta_shift = eta_pows[plan.num_units];

    let base = [(0usize, Block128::ONE)];
    let base_and_shift = [(0usize, Block128::ONE), (half, eta_shift)];
    let offsets: &[(usize, Block128)] = if shifted_claims {
        &base_and_shift
    } else {
        &base
    };

    let mut target = Block128::ZERO;
    for &(offset, shift_mul) in offsets {
        let half_claims = &claims[offset..offset + half];

        let mut ci = 0usize;
        for (unit_idx, &(is_ring, num_claims)) in plan.units.iter().enumerate() {
            let weight = eta_pows[unit_idx] * shift_mul;
            if is_ring {
                let bits: Vec<Block128> = half_claims[ci..ci + num_claims]
                    .iter()
                    .map(|f| f.to_tower().into())
                    .collect();

                target += weight * ring_batch_b(&bits, &eq_mix);
            } else {
                let c: Block128 = half_claims[ci].to_tower().into();
                target += weight * c;
            }

            ci += num_claims;
        }
    }

    target
}

/// Parses one opened grid-row: one symbol per committed column
/// at its `rs_field` width (sub-B32 columns are B32-wide).
fn parse_physical_row<F: TraceCompatibleField>(
    row_data: &[u8],
    phys_rs: &[ColumnType],
    out: &mut Vec<Flat<F>>,
) {
    let mut ptr = 0;
    for ct in phys_rs {
        let sz = ct.byte_size();

        out.push(ct.parse_from_bytes(&row_data[ptr..ptr + sz]));
        ptr += sz;
    }
}

/// K̃_P(r') in O(n): the K_P carry chain
/// `Σ_k Π_{i<k}(1+r'_i)P_i · r'_k(1+P_k) · Π_{i>k}(1+r'_i+P_i)`
/// plus the cyclic wrap `Π_i (1+r'_i)P_i`.
fn k_p_at(point: &[Block128], r_final: &[Block128]) -> Block128 {
    let n = point.len();
    let one = Block128::ONE;

    let mut suffix = vec![one; n + 1];
    for i in (0..n).rev() {
        suffix[i] = suffix[i + 1] * (one + r_final[i] + point[i]);
    }

    let mut acc = Block128::ZERO;
    let mut prefix = one;

    for k in 0..n {
        acc += prefix * r_final[k] * (one + point[k]) * suffix[k + 1];
        prefix *= (one + r_final[k]) * point[k];
    }

    acc + prefix
}

#[cfg(test)]
mod tests {
    use super::*;
    use hekate_core::poly::PolyVariant;
    use hekate_math::TowerField;

    fn elems(seed: u128, n: usize) -> Vec<Block128> {
        let g = Block128(0x2545F4914F6CDD1D_517CC1B727220A95);

        let mut x = Block128(seed | 1);
        let mut out = Vec::with_capacity(n);

        for _ in 0..n {
            x = x * g + Block128::ONE;
            out.push(x);
        }

        out
    }

    fn k_p_on_cube(point: &[Block128]) -> Vec<Block128> {
        let eq_p = eq_tensor_b(point);
        let n = eq_p.len();

        (0..n).map(|i| eq_p[(i + n - 1) & (n - 1)]).collect()
    }

    fn mle_at(values: &[Block128], r: &[Block128]) -> Block128 {
        let weights = eq_tensor_b(r);

        values
            .iter()
            .zip(weights.iter())
            .fold(Block128::ZERO, |acc, (&v, &w)| acc + v * w)
    }

    fn contract_bits(values: &[Block128], eq_mix: &[Block128]) -> Vec<Block128> {
        values
            .iter()
            .map(|v| {
                let mut acc = Block128::ZERO;
                for (u, &m) in eq_mix.iter().enumerate() {
                    if (v.0 >> u) & 1 == 1 {
                        acc += m;
                    }
                }

                acc
            })
            .collect()
    }

    /// `K_P` is only the right weight if its wrap agrees
    /// with `PolyVariant::Shifted`, which is what the AIR
    /// and the prover's fold read as the next row.
    #[test]
    fn k_p_contracts_to_the_polyvariant_next_row() {
        for num_vars in 1..=5 {
            let n = 1usize << num_vars;

            let point = elems(1289 + num_vars as u128, num_vars);
            let col_tower = elems(53 + num_vars as u128, n);
            let col: Vec<Flat<Block128>> = col_tower.iter().map(|v| v.to_hardware()).collect();

            let shifted = PolyVariant::Shifted(&col);
            let eq_p = eq_tensor_b(&point);
            let k_p = k_p_on_cube(&point);

            let mut via_variant = Block128::ZERO;
            let mut via_k_p = Block128::ZERO;

            for i in 0..n {
                via_variant += shifted.get_at(i).to_tower() * eq_p[i];
                via_k_p += col_tower[i] * k_p[i];
            }

            assert_eq!(via_variant, via_k_p, "n={num_vars}");
        }
    }

    #[test]
    fn k_p_closed_form_matches_materialized() {
        for num_vars in 1..=5 {
            let point = elems(3 + num_vars as u128, num_vars);
            let r_final = elems(101 + num_vars as u128, num_vars);

            let direct = mle_at(&k_p_on_cube(&point), &r_final);

            assert_eq!(k_p_at(&point, &r_final), direct, "n={num_vars}");
        }
    }

    #[test]
    fn a_closed_forms_match_materialized() {
        let kappa = NBITS.ilog2() as usize;

        for num_vars in 1..=5 {
            let point = elems(7 + num_vars as u128, num_vars);
            let r_final = elems(211 + num_vars as u128, num_vars);
            let r_mix = elems(919 + num_vars as u128, kappa);

            let eq_mix = eq_tensor_b(&r_mix);
            let a_cube = contract_bits(&eq_tensor_b(&point), &eq_mix);
            let a_next_cube = contract_bits(&k_p_on_cube(&point), &eq_mix);

            let (a, a_next) = ring_switch_a_pair(&point, &r_final, &r_mix, true);

            assert_eq!(a, mle_at(&a_cube, &r_final), "A n={num_vars}");
            assert_eq!(
                a_next,
                mle_at(&a_next_cube, &r_final),
                "A_next n={num_vars}"
            );

            let (a_only, skipped) = ring_switch_a_pair(&point, &r_final, &r_mix, false);

            assert_eq!(a_only, a, "A without the carry chain n={num_vars}");
            assert_eq!(skipped, Block128::ZERO, "n={num_vars}");
        }
    }

    #[test]
    fn transpose128_swaps_bit_indices() {
        let mut cols = [Block128::ZERO; NBITS];
        for (c, v) in cols.iter_mut().zip(elems(0x51, NBITS)) {
            *c = v;
        }

        let mut expected = [Block128::ZERO; NBITS];
        for (v, cv) in cols.iter().enumerate() {
            for (u, ru) in expected.iter_mut().enumerate() {
                ru.0 |= ((cv.0 >> u) & 1) << v;
            }
        }

        let rows = transpose128(&cols);

        assert_eq!(rows, expected);
        assert_eq!(transpose128(&rows), cols);
    }
}
