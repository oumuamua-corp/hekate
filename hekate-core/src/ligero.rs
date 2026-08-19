// SPDX-FileCopyrightText: 2026 Andrei Kochergin <andrei@oumuamua.dev>
// SPDX-FileCopyrightText: 2026 Oumuamua Labs <info@oumuamua.dev>
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::{Error, Result};
use crate::outer::OuterGeometry;
use crate::proofs::OuterOpening;
use alloc::vec;
use alloc::vec::Vec;
use hekate_crypto::Hasher;
use hekate_crypto::merkle::MerkleTree;
use hekate_math::fft::vanish_eval;
use hekate_math::{AdditiveFft, BinaryFieldExtras, Flat, HardwareField, TowerField};

const MAX_LOG: u32 = 63;

/// Mask of a product-code response: `low` covers
/// degrees `< k`, `high` rides `vanisher` for the rest.
pub struct ProductMask<'a, F> {
    pub low: usize,
    pub high: usize,
    pub vanisher: &'a [Flat<F>],
}

impl<F: TowerField + HardwareField> ProductMask<'_, F> {
    pub fn covers(&self, rows: usize) -> bool {
        self.low < rows && self.high < rows
    }

    pub fn at(&self, col: usize, values: &[Flat<F>]) -> Flat<F> {
        values[self.low] + self.vanisher[col] * values[self.high]
    }
}

pub struct RowEncoder<F> {
    message: AdditiveFft<F>,
    code: AdditiveFft<F>,
    code_shift: Flat<F>,
    code_len: usize,
    domain_len: usize,
}

impl<F: BinaryFieldExtras + HardwareField> RowEncoder<F> {
    pub fn new(geom: &OuterGeometry) -> Result<Self> {
        if !geom.code_len.is_power_of_two() || !geom.domain_len.is_power_of_two() {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "code and domain lengths must be powers of two",
            });
        }

        let log_k = geom.code_len.ilog2();
        let log_n = geom.domain_len.ilog2();

        if log_k < 1 || log_k >= log_n || log_n > MAX_LOG {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "require 1 <= log_k < log_n <= 63",
            });
        }

        // beta_{log_n} lies outside W_{log_n}
        let mut beta = F::ONE;
        for _ in 0..log_n {
            beta = F::solve_quadratic(beta).ok_or(Error::Protocol {
                protocol: "ligero",
                message: "Cantor chain has no next basis element",
            })?;
        }

        if vanish_eval(log_n as usize, beta) == F::ZERO {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "coset shift landed inside the message subspace",
            });
        }

        Ok(Self {
            message: AdditiveFft::new(log_k),
            code: AdditiveFft::new(log_n),
            code_shift: beta.to_hardware(),
            code_len: geom.code_len,
            domain_len: geom.domain_len,
        })
    }

    pub fn encode(&self, row: &mut [Flat<F>]) -> Result<()> {
        if row.len() != self.domain_len {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "row buffer must be domain_len long",
            });
        }

        self.message
            .inverse_scalar(&mut row[..self.code_len])
            .map_err(|_| Error::Protocol {
                protocol: "ligero",
                message: "message interpolation rejected its length",
            })?;

        row[self.code_len..].fill(Flat::from_raw(F::ZERO));

        self.code
            .forward_coset_scalar(row, self.code_shift)
            .map_err(|_| Error::Protocol {
                protocol: "ligero",
                message: "codeword evaluation rejected its length",
            })?;

        Ok(())
    }

    pub fn is_codeword(&self, values: &[Flat<F>]) -> Result<bool> {
        if values.len() != self.domain_len {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "codeword check needs a domain_len buffer",
            });
        }

        let mut buf = values.to_vec();

        self.code
            .inverse_coset_scalar(&mut buf, self.code_shift)
            .map_err(|_| Error::Protocol {
                protocol: "ligero",
                message: "codeword interpolation rejected its length",
            })?;

        Ok(buf[self.code_len..]
            .iter()
            .all(|c| *c == Flat::from_raw(F::ZERO)))
    }

    /// `Z_k` on the code domain.
    pub fn message_vanisher(&self) -> Result<Vec<Flat<F>>> {
        let zero = Flat::from_raw(F::ZERO);
        let mut buf = vec![zero; self.domain_len];

        buf[self.code_len] = Flat::from_raw(F::ONE);

        self.code
            .forward_coset_scalar(&mut buf, self.code_shift)
            .map_err(|_| Error::Protocol {
                protocol: "ligero",
                message: "vanisher evaluation rejected its length",
            })?;

        match self.message_evaluations(&buf)? {
            Some(evals) if evals[..self.code_len].iter().all(|v| *v == zero) => Ok(buf),
            _ => Err(Error::Protocol {
                protocol: "ligero",
                message: "novel basis element k does not vanish on the message domain",
            }),
        }
    }

    pub fn message_evaluations(&self, values: &[Flat<F>]) -> Result<Option<Vec<Flat<F>>>> {
        if values.len() != self.domain_len {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "response must be a domain_len buffer",
            });
        }

        let mut coeffs = values.to_vec();

        self.code
            .inverse_coset_scalar(&mut coeffs, self.code_shift)
            .map_err(|_| Error::Protocol {
                protocol: "ligero",
                message: "response interpolation rejected its length",
            })?;

        let product_len = 2 * self.code_len;

        // Products of two degree-<k rows and the mask
        // term `Z_k · u` both sit in dimension 2k
        if product_len > self.domain_len
            || coeffs[product_len..]
                .iter()
                .any(|c| *c != Flat::from_raw(F::ZERO))
        {
            return Ok(None);
        }

        let mut evals = coeffs[..product_len].to_vec();

        AdditiveFft::<F>::new(product_len.ilog2())
            .forward_scalar(&mut evals)
            .map_err(|_| Error::Protocol {
                protocol: "ligero",
                message: "response evaluation rejected its length",
            })?;

        Ok(Some(evals))
    }

    pub fn vanishes_on_message(&self, values: &[Flat<F>], message_len: usize) -> Result<bool> {
        Ok(match self.message_evaluations(values)? {
            None => false,
            Some(evals) => evals[..message_len]
                .iter()
                .all(|v| *v == Flat::from_raw(F::ZERO)),
        })
    }

    pub fn sum_on_message(&self, values: &[Flat<F>]) -> Result<Option<Flat<F>>> {
        Ok(self.message_evaluations(values)?.map(|evals| {
            evals[..self.code_len]
                .iter()
                .fold(Flat::from_raw(F::ZERO), |a, b| a + *b)
        }))
    }

    pub fn code_len(&self) -> usize {
        self.code_len
    }

    pub fn domain_len(&self) -> usize {
        self.domain_len
    }
}

pub struct Opening<F> {
    pub columns: Vec<(usize, Vec<Flat<F>>)>,
    pub siblings: Vec<[u8; 32]>,
}

impl<F: TowerField> Opening<F> {
    pub fn from_wire(wire: &OuterOpening<F>, rows: usize) -> Result<Self>
    where
        F: HardwareField,
    {
        if rows == 0 || wire.values.len() != wire.columns.len() * rows {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "opening values do not match columns × rows",
            });
        }

        let columns = wire
            .columns
            .iter()
            .zip(wire.values.chunks_exact(rows))
            .map(|(&col, values)| {
                (
                    col as usize,
                    values.iter().map(|v| v.to_hardware()).collect(),
                )
            })
            .collect();

        Ok(Self {
            columns,
            siblings: wire.siblings.clone(),
        })
    }

    pub fn to_wire(&self) -> OuterOpening<F>
    where
        F: HardwareField,
    {
        OuterOpening {
            columns: self.columns.iter().map(|(c, _)| *c as u32).collect(),
            values: self
                .columns
                .iter()
                .flat_map(|(_, v)| v.iter().map(|x| x.to_tower()))
                .collect(),
            siblings: self.siblings.clone(),
        }
    }

    /// The verifier's view of a [`Stack`]: the parts' openings
    /// at the same columns, values concatenated per column.
    pub fn stack(parts: &[&Opening<F>]) -> Result<Self> {
        let first = parts.first().ok_or(Error::Protocol {
            protocol: "ligero",
            message: "stack needs at least one opening",
        })?;

        let rows: usize = parts
            .iter()
            .map(|p| p.columns.first().map_or(0, |(_, v)| v.len()))
            .sum();

        let columns = first
            .columns
            .iter()
            .enumerate()
            .map(|(i, (col, _))| {
                let mut values = Vec::with_capacity(rows);
                for part in parts {
                    match part.columns.get(i) {
                        Some((c, v)) if c == col => values.extend_from_slice(v),
                        _ => {
                            return Err(Error::Protocol {
                                protocol: "ligero",
                                message: "stacked openings must cover the same columns",
                            });
                        }
                    }
                }

                Ok((*col, values))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            columns,
            siblings: Vec::new(),
        })
    }
}

pub fn verify_interleaved<F: BinaryFieldExtras + HardwareField + TowerField>(
    encoder: &RowEncoder<F>,
    response: &[Flat<F>],
    coeffs: &[Flat<F>],
    mask: usize,
    opening: &Opening<F>,
) -> bool {
    if response.len() != encoder.domain_len() || !matches!(encoder.is_codeword(response), Ok(true))
    {
        return false;
    }

    opening.columns.iter().all(|(col, values)| {
        if mask >= values.len() || coeffs.len() != values.len() - 1 {
            return false;
        }

        let mut acc = values[mask];
        let mut next = 0;

        for (r, v) in values.iter().enumerate() {
            if r == mask {
                continue;
            }

            acc += coeffs[next] * *v;
            next += 1;
        }

        acc == response[*col]
    })
}

/// Encodes each weight row in place.
pub fn encode_weights<F: BinaryFieldExtras + HardwareField + TowerField>(
    encoder: &RowEncoder<F>,
    mut weights: Vec<Vec<Flat<F>>>,
) -> Result<Vec<Vec<Flat<F>>>> {
    for row in weights.iter_mut() {
        if row.len() != encoder.domain_len() {
            return Err(Error::Protocol {
                protocol: "ligero",
                message: "weight row must be a domain_len buffer",
            });
        }

        encoder.encode(row)?;
    }

    Ok(weights)
}

pub fn verify_linear<F: BinaryFieldExtras + HardwareField + TowerField>(
    encoder: &RowEncoder<F>,
    response: &[Flat<F>],
    encoded_weights: &[Vec<Flat<F>>],
    rows_used: &[usize],
    mask: &ProductMask<'_, F>,
    target: Flat<F>,
    opening: &Opening<F>,
) -> bool {
    if response.len() != encoder.domain_len()
        || mask.vanisher.len() != encoder.domain_len()
        || encoded_weights.len() != rows_used.len()
    {
        return false;
    }

    match encoder.sum_on_message(response) {
        Ok(Some(sum)) if sum == target => {}
        _ => return false,
    }

    opening.columns.iter().all(|(col, values)| {
        if !mask.covers(values.len()) || rows_used.iter().any(|&r| r >= values.len()) {
            return false;
        }

        let mut acc = mask.at(*col, values);
        for (weights, &row) in encoded_weights.iter().zip(rows_used) {
            acc += weights[*col] * values[row];
        }

        acc == response[*col]
    })
}

pub fn verify_quadratic<F: BinaryFieldExtras + HardwareField + TowerField>(
    encoder: &RowEncoder<F>,
    response: &[Flat<F>],
    triples: &[[usize; 3]],
    r_quad: &[Flat<F>],
    mask: &ProductMask<'_, F>,
    message_len: usize,
    opening: &Opening<F>,
) -> bool {
    if response.len() != encoder.domain_len()
        || mask.vanisher.len() != encoder.domain_len()
        || r_quad.len() != triples.len()
    {
        return false;
    }

    if !matches!(encoder.vanishes_on_message(response, message_len), Ok(true)) {
        return false;
    }

    opening.columns.iter().all(|(col, values)| {
        if !mask.covers(values.len()) || triples.iter().flatten().any(|&r| r >= values.len()) {
            return false;
        }

        let mut acc = mask.at(*col, values);
        for (t, [x, y, z]) in triples.iter().enumerate() {
            acc += r_quad[t] * (values[*x] * values[*y] - values[*z]);
        }

        acc == response[*col]
    })
}

/// Checks the wire opening against `root`;
/// leaves are hashed from the wire's
/// tower bytes, as [`column_leaf`] does.
pub fn verify_opening<F: TowerField + HardwareField, H: Hasher>(
    root: &[u8; 32],
    domain_len: usize,
    rows: usize,
    opening: &OuterOpening<F>,
) -> bool {
    if rows == 0 || opening.values.len() != opening.columns.len() * rows {
        return false;
    }

    let leaves: Vec<(usize, [u8; 32])> = opening
        .columns
        .iter()
        .zip(opening.values.chunks_exact(rows))
        .map(|(&col, values)| {
            let mut hasher = H::new();
            hasher.update(&[0u8]);

            for v in values {
                hasher.update(&v.to_bytes());
            }

            (col as usize, hasher.finalize())
        })
        .collect();

    MerkleTree::<F, H>::verify_batch(root, domain_len, &leaves, &opening.siblings)
}

/// Leaf of one column, its rows top to bottom.
pub fn column_leaf<F: TowerField + HardwareField, H: Hasher>(
    column: impl Iterator<Item = Flat<F>>,
) -> [u8; 32] {
    let mut hasher = H::new();
    hasher.update(&[0u8]);

    for v in column {
        hasher.update(&v.to_tower().to_bytes());
    }

    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use alloc::vec;
    use alloc::vec::Vec;
    use hekate_math::{Block128, TowerField};

    const OPENED: [usize; 4] = [1, 9, 40, 77];

    /// A domain index outside [`OPENED`].
    const UNOPENED: usize = 5;

    type F = Block128;

    fn geometry() -> OuterGeometry {
        Config::prod().outer_geom(4_075, 2_384, 128).unwrap()
    }

    fn mix(seed: u128) -> Flat<F> {
        F::from(
            seed.wrapping_mul(0x9e37_79b9_7f4a_7c15)
                .wrapping_add(0x51ed_2701),
        )
        .to_hardware()
    }

    fn message(geom: &OuterGeometry, salt: u128) -> Vec<Flat<F>> {
        let mut row = vec![Flat::from_raw(F::ZERO); geom.domain_len];

        for (i, slot) in row[..geom.code_len].iter_mut().enumerate() {
            *slot = mix(i as u128 + salt);
        }

        row
    }

    fn opening_at(rows: &[Vec<Flat<F>>], columns: &[usize]) -> Opening<F> {
        Opening {
            columns: columns
                .iter()
                .map(|&c| (c, rows.iter().map(|r| r[c]).collect()))
                .collect(),
            siblings: Vec::new(),
        }
    }

    fn encoded(encoder: &RowEncoder<F>, geom: &OuterGeometry, salt: u128) -> Vec<Flat<F>> {
        let mut row = message(geom, salt);
        encoder.encode(&mut row).unwrap();

        row
    }

    /// Uniform message summing to zero over the code domain.
    fn zero_sum_row(encoder: &RowEncoder<F>, geom: &OuterGeometry, salt: u128) -> Vec<Flat<F>> {
        let mut row = vec![Flat::from_raw(F::ZERO); geom.domain_len];
        let mut acc = Flat::from_raw(F::ZERO);

        for (i, slot) in row[..geom.code_len - 1].iter_mut().enumerate() {
            *slot = mix(i as u128 + salt);
            acc += *slot;
        }

        row[geom.code_len - 1] = acc;
        encoder.encode(&mut row).unwrap();

        row
    }

    fn interleaved_response(
        rows: &[Vec<Flat<F>>],
        coeffs: &[Flat<F>],
        mask: usize,
        domain_len: usize,
    ) -> Vec<Flat<F>> {
        (0..domain_len)
            .map(|c| {
                let mut acc = rows[mask][c];
                for (r, k) in coeffs.iter().enumerate() {
                    acc += *k * rows[r][c];
                }

                acc
            })
            .collect()
    }

    #[test]
    fn code_domain_is_disjoint_from_message_domain() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();
        let log_n = geom.domain_len.ilog2() as usize;

        assert_ne!(vanish_eval(log_n, encoder.code_shift.to_tower()), F::ZERO);
    }

    #[test]
    fn encoding_is_linear() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();

        let mut a = message(&geom, 1);
        let mut b = message(&geom, 5_000);
        let mut sum: Vec<Flat<F>> = a.iter().zip(&b).map(|(x, y)| *x + *y).collect();

        encoder.encode(&mut a).unwrap();
        encoder.encode(&mut b).unwrap();
        encoder.encode(&mut sum).unwrap();

        for i in 0..geom.domain_len {
            assert_eq!(a[i] + b[i], sum[i]);
        }
    }

    #[test]
    fn zero_message_encodes_to_zero_codeword() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();
        let mut row = vec![Flat::from_raw(F::ZERO); geom.domain_len];

        encoder.encode(&mut row).unwrap();

        assert!(row.iter().all(|v| *v == Flat::from_raw(F::ZERO)));
    }

    #[test]
    fn encoding_agrees_with_coefficient_path() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();

        let coeffs: Vec<Flat<F>> = (0..geom.code_len).map(|i| mix(i as u128 + 77)).collect();

        let mut evals = vec![Flat::from_raw(F::ZERO); geom.domain_len];
        evals[..geom.code_len].copy_from_slice(&coeffs);

        AdditiveFft::<F>::new(geom.code_len.ilog2())
            .forward_scalar(&mut evals[..geom.code_len])
            .unwrap();

        let mut direct = vec![Flat::from_raw(F::ZERO); geom.domain_len];
        direct[..geom.code_len].copy_from_slice(&coeffs);

        AdditiveFft::<F>::new(geom.domain_len.ilog2())
            .forward_coset_scalar(&mut direct, encoder.code_shift)
            .unwrap();

        encoder.encode(&mut evals).unwrap();

        assert_eq!(evals, direct);
    }

    #[test]
    fn nonzero_message_is_far_from_zero() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();
        let mut row = message(&geom, 31);

        encoder.encode(&mut row).unwrap();

        let zeros = row
            .iter()
            .filter(|v| **v == Flat::from_raw(F::ZERO))
            .count();

        assert!(zeros < geom.code_len);
    }

    #[test]
    fn wrong_length_buffer_is_rejected() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();
        let mut row = vec![Flat::from_raw(F::ZERO); geom.domain_len - 1];

        assert!(encoder.encode(&mut row).is_err());
    }

    #[test]
    fn interleaved_test_rejects_row_off_code() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();

        let mut rows: Vec<Vec<Flat<F>>> = (0..4)
            .map(|i| encoded(&encoder, &geom, 100 * i + 1))
            .collect();

        let coeffs: Vec<Flat<F>> = (0..3).map(|i| mix(i as u128 + 7_000)).collect();
        let mask = 3;

        let honest = interleaved_response(&rows, &coeffs, mask, geom.domain_len);

        assert!(verify_interleaved(
            &encoder,
            &honest,
            &coeffs,
            mask,
            &opening_at(&rows, &OPENED),
        ));

        rows[0][UNOPENED] += Flat::from_raw(F::ONE);

        let off_code = interleaved_response(&rows, &coeffs, mask, geom.domain_len);

        assert!(!verify_interleaved(
            &encoder,
            &off_code,
            &coeffs,
            mask,
            &opening_at(&rows, &OPENED),
        ));
    }

    #[test]
    fn interleaved_test_rejects_column_that_misses_response() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();

        let rows: Vec<Vec<Flat<F>>> = (0..4)
            .map(|i| encoded(&encoder, &geom, 200 * i + 3))
            .collect();

        let coeffs: Vec<Flat<F>> = (0..3).map(|i| mix(i as u128 + 8_000)).collect();
        let mask = 3;

        let response = interleaved_response(&rows, &coeffs, mask, geom.domain_len);
        let mut opening = opening_at(&rows, &OPENED);

        opening.columns[0].1[0] += Flat::from_raw(F::ONE);

        assert!(!verify_interleaved(
            &encoder, &response, &coeffs, mask, &opening,
        ));
    }

    #[test]
    fn linear_test_rejects_wrong_target() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();
        let vanisher = encoder.message_vanisher().unwrap();

        let data_msgs: Vec<Vec<Flat<F>>> = (0..2).map(|i| message(&geom, 300 * i + 11)).collect();
        let weight_msgs: Vec<Vec<Flat<F>>> = (0..2)
            .map(|i| {
                let mut w = vec![Flat::from_raw(F::ZERO); geom.domain_len];
                for (c, slot) in w[..geom.message_len].iter_mut().enumerate() {
                    *slot = mix(c as u128 + 400 * i + 17);
                }

                w
            })
            .collect();

        let mut target = Flat::from_raw(F::ZERO);
        for (w, u) in weight_msgs.iter().zip(&data_msgs) {
            for c in 0..geom.message_len {
                target += w[c] * u[c];
            }
        }

        let mut rows: Vec<Vec<Flat<F>>> = data_msgs
            .iter()
            .map(|m| {
                let mut row = m.clone();
                encoder.encode(&mut row).unwrap();

                row
            })
            .collect();

        rows.push(zero_sum_row(&encoder, &geom, 991));
        rows.push(encoded(&encoder, &geom, 1_313));

        let weights = encode_weights(&encoder, weight_msgs).unwrap();
        let mask = ProductMask {
            low: 2,
            high: 3,
            vanisher: &vanisher,
        };

        let response: Vec<Flat<F>> = (0..geom.domain_len)
            .map(|c| {
                let mut acc = rows[2][c] + vanisher[c] * rows[3][c];
                for (w, u) in weights.iter().zip(&rows) {
                    acc += w[c] * u[c];
                }

                acc
            })
            .collect();

        let rows_used = [0usize, 1];
        let opening = opening_at(&rows, &OPENED);

        assert!(verify_linear(
            &encoder, &response, &weights, &rows_used, &mask, target, &opening,
        ));

        assert!(!verify_linear(
            &encoder,
            &response,
            &weights,
            &rows_used,
            &mask,
            target + Flat::from_raw(F::ONE),
            &opening,
        ));
    }

    #[test]
    fn quadratic_test_rejects_broken_triple() {
        let geom = geometry();
        let encoder = RowEncoder::<F>::new(&geom).unwrap();
        let vanisher = encoder.message_vanisher().unwrap();

        let build = |break_triple: bool| -> (Vec<Vec<Flat<F>>>, Vec<Flat<F>>) {
            let x = message(&geom, 501);
            let y = message(&geom, 607);

            let mut z = message(&geom, 709);
            for c in 0..geom.message_len {
                z[c] = x[c] * y[c];
            }

            if break_triple {
                z[0] += Flat::from_raw(F::ONE);
            }

            let mut rows: Vec<Vec<Flat<F>>> = [x, y, z]
                .into_iter()
                .map(|mut m| {
                    encoder.encode(&mut m).unwrap();

                    m
                })
                .collect();

            let mut low = vec![Flat::from_raw(F::ZERO); geom.domain_len];
            for (c, slot) in low[geom.message_len..geom.code_len].iter_mut().enumerate() {
                *slot = mix(c as u128 + 811);
            }

            encoder.encode(&mut low).unwrap();

            rows.push(low);
            rows.push(encoded(&encoder, &geom, 907));

            let r_quad = [mix(1_009)];
            let response: Vec<Flat<F>> = (0..geom.domain_len)
                .map(|c| {
                    let mut acc = rows[3][c] + vanisher[c] * rows[4][c];
                    acc += r_quad[0] * (rows[0][c] * rows[1][c] - rows[2][c]);

                    acc
                })
                .collect();

            (rows, response)
        };

        let mask = ProductMask {
            low: 3,
            high: 4,
            vanisher: &vanisher,
        };

        let triples = [[0usize, 1, 2]];
        let r_quad = [mix(1_009)];

        let (rows, response) = build(false);

        assert!(verify_quadratic(
            &encoder,
            &response,
            &triples,
            &r_quad,
            &mask,
            geom.message_len,
            &opening_at(&rows, &OPENED),
        ));

        let (rows, response) = build(true);

        assert!(!verify_quadratic(
            &encoder,
            &response,
            &triples,
            &r_quad,
            &mask,
            geom.message_len,
            &opening_at(&rows, &OPENED),
        ));
    }
}
