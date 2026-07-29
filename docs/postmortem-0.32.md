# Three unbound values: a soundness postmortem

Across 0.31.0 and 0.32.0 we fixed three soundness failures found in our own
prover. Two are total breaks: a malicious prover produces a proof for a false
statement and the real verifier accepts it. Both were confirmed with a
proof-of-concept prover against the shipped pipeline, not argued on paper.

## Summary

**1. The Brakedown row code delivered single-digit-bit soundness while the
configuration claimed 128.** A sparse expander's minimum distance is capped by the
column weight of its generator. A codeword-aware forgery against the real
prove/verify pipeline accepted at **up to 54% per attempt**. Affects every table,
including pure-AIR tables with no bus. Fixed by replacing the row code with MDS
Reed-Solomon over an additive binary-field FFT; the forgery harness now records
zero acceptances. Fixed in **0.31.0**.

**2. The LogUp fraction helper `h` was never committed.** A prover fits its
evaluation after the challenge is drawn, the final check collapses to `0 = 0`, and
every constraint on the table (AIR, boundary, bus) goes unenforced. Deterministic,
not probabilistic. Affects every table carrying a permutation or lookup bus: every
shipped circuit except the Fibonacci and arithmetic examples. Fixed by committing
`h` and binding each `h_eval` to its opening. Fixed in **0.32.0**.

**3. A table declaring no bus could inject an unbound `claimed_sums` entry into
cross-bus matching.** Forges bus cancellation in characteristic two. Our shipped
circuits declare a bus on every table and were not affected; the gap is live for
any program pairing a bus-free table with a real bus. Fixed verifier-side with no
change to proof bytes. Fixed in **0.32.0**.

## Affected versions

| Running            | Exposed to | Action                          |
|:-------------------|:-----------|:--------------------------------|
| 0.30.0 and earlier | all three  | Upgrade to 0.32.0 and re-prove. |
| 0.31.0             | 2 and 3    | Upgrade to 0.32.0 and re-prove. |
| 0.32.0             | none known | Current.                        |

0.31.0 replaced the row code and changed the transcript; 0.30.0 proofs and
bundles neither verify nor deserialize. 0.32.0 adds the `h` commitment and moves
the wire format to v3; v2 proofs are rejected. Both upgrades require re-proving.
The zero-bus fix is verifier-only and changes no proof bytes.

Upgrading is mandatory for any deployment relying on the 128-bit security claim.

This is written for people building proof systems. The bugs are ours, but the
class is not, and the first is a property of a code family several implementations
use.

## The common shape

Every one of the three has the same structure: a value entered the final verdict
and nothing bound it to the committed witness.

The reasons it was unbound differ, and that is the useful part:

1. The row code's minimum distance was assumed rather than derived. Its
   statistical binding was far weaker than the security parameter claimed.
2. `h_eval` was never committed at all.
3. `claimed_sums` was bound by code sitting behind a condition that did not hold.

None of these is a mistake in the underlying cryptography. Each was locally
reasonable. What was missing was an accounting discipline: for every quantity that
reaches the final check, be able to name the thing that binds it. We could not,
because we had never written the list down.

## 1. The row code's distance was a heuristic

*Fixed in 0.31.0.*

**Reach:** the proximity layer, and through it every table, including the pure-AIR
tables that the other two bugs do not touch.

Our Brakedown row code was a sparse expander. Its minimum distance is capped by
the column weight of the generator. That cap is a structural property of the
construction, not a matter of parameter tuning, and the proximity check
consequently delivered single-digit-bit soundness while the configuration claimed 128.

A codeword-aware forgery run against the real prove/verify pipeline accepted at up
to **54% per attempt**.

We replaced it with an MDS Reed-Solomon code over the additive binary-field FFT
subspace chain. Relative distance is now exact Singleton,
`δ = (encoded_width − support − grid_cols) / encoded_width`, and the proximity
bound `(1−δ)^q` holds with `num_queries = 176`. The security gate runs per table,
main trace and every chiplet at its own geometry, rejecting anything that delivers
under 128 bits before verification proceeds. The forgery harness now records zero
acceptances.

The change did not stay local, and this is the part worth knowing before you
attempt it. Our virtual bit-packing extracted bit-planes during the proximity
fold. Bit extraction is GF(2)-linear, which commutes with an expander's XOR fold
but not with Reed-Solomon twiddle scaling, which is GF(2^k)-linear. Under MDS an
honest prover would fail roughly δ of its own proximity queries. The bit-plane
collapse has to happen *before* the code layer, and that reduction is the
ring-switch of Diamond-Posen (eprint 2024/504, Construction 3.1): reduce each
packed column's bit-plane claims to one whole-column claim, then fold whole
physical columns, which does commute. The bit-mixing challenge is drawn after the
claims are absorbed, and Schwartz-Zippel over it binds every bit-plane to its
committed column, closing the lossy-collapse gap noted in Remark 3.3 of that
paper.

Zero-knowledge moved at the same time. The old scheme appended noise columns to a
systematic encode. The new encode is non-systematic and carries a random support
block of `ldt_support_size` symbols (default 200, floored at `num_queries`) inside
the message, at coordinates disjoint from the data. Any `num_queries` opened
columns are jointly uniform, and no committed column contains cleartext witness
symbols. The evaluation claim reads the data half alone, and the support cancels
without costing soundness.

## 2. The uncommitted LogUp helper

*Fixed in 0.32.0. Live in 0.31.0 and earlier.*

**Reach:** every table carrying at least one permutation or lookup bus. In our
tree that covers the entire general-purpose path (CPU↔RAM/ROM/Keccak/AES/IntArith
links, offline memory consistency, table range checks) and every shipped circuit
except raw Fibonacci and inline Keccak.

LogUp introduces a fraction helper `h[i] = s[i] / (γ + key[i])`. Our proof carried
no commitment to `h`. The verifier read each bus's `h_eval` as a raw scalar from
the proof and fed it into the bus contribution term, which is affine in `h_eval`
with coefficient `alpha_bus · ((γ + key)·eq_zc + eq_lookup)`, generically nonzero.
The entire verdict is one scalar equation, `val_final == expected_val`.

The ordering finished it. `h_evals` were absorbed into the transcript *after* the
sumcheck had drawn `r_final`. A prover picks `h_eval` with both `r_final` and
`val_final` already known, and solves the final check for it.

The forgery:

1. Commit an arbitrary false trace: bus relation violated, AIR still satisfied.
2. Report `claimed_sums = 0`; cross-bus matching then cancels trivially.
3. Send an all-zero sumcheck, giving `val_final = 0`.
4. Fit `h_eval = s_eff·eq_zc / ((γ + key)·eq_zc + 1)` from the committed trace
   evaluations at `r_final`. In characteristic two the contribution cancels as
   `A + A = 0`.
5. Open the honestly committed trace at `r_final`. The verifier accepts.

The consequence is wider than the multiset argument it was supposed to protect.
A free `h_eval` absorbs the whole gap between `val_final` and `expected_val`.
Every constraint on a bus-carrying table (AIR, boundary, bus) went unenforced, not
only the multiset relation. The bug reads like a lookup-argument problem and is
actually a complete loss of soundness across most of the circuit surface. Unlike
the proximity break above, this one is deterministic: the prover succeeds every
time.

There is no algebraic shortcut for the fix. `h(r_final)` is rational in the trace
(`s/(γ + key)`), and no recomputation from the opened trace evaluations exists. A
polynomial commitment is mandatory. We now commit `h` in a second round drawn
after γ and β, absorb its root before α, open `h` at `r_final`, and reject unless
every reported `h_eval` equals the opened value. Presence is validated against the
trusted bus specification, which stops the binding from being dropped:
`h_commitment` and `h_eval_proof` are present exactly when the table declares a
bus, and the commitment's dimensions must match the table height and bus count.

## 3. The zero-bus injection

*Fixed in 0.32.0. Live in 0.31.0 and earlier.*

**Reach:** any program pairing a table that declares no permutation bus with a
table that has a real one. Our shipped circuits declare a bus on every table and
were not affected. `Program::permutation_checks` defaults to empty, which makes
the vulnerable shape any AIR that does not override it: a range helper, a driver
main trace, a chiplet bound only by boundary constraints.

The LogUp auxiliary validation (length checks on `claimed_sums` and `h_evals`,
plus the per-endpoint `bus_id` ordering check) was gated behind
`if !bus_specs.is_empty()`. For a table with no declared bus those checks were
skipped. The same condition gated entry into the sumcheck initial claim and the
`r_final` consistency term, leaving `claimed_sums` bound to nothing on the trace.

But it was still absorbed into the transcript, and still harvested by cross-bus
matching, which groups endpoints by `bus_id` *string* and never checks that the
identifier was declared by the program.

Cross-bus cancellation requires the per-`bus_id` sum of every endpoint's
`claimed_sum` to be zero. A zero-bus table's unbound vector is a free term on that
sum. Forge an imbalance `δ` on the real bus, inject `(real_bus_id, δ)` through the
bus-free table, and in characteristic two the total cancels: `δ + δ = 0`.

The fix is one line of control flow: run the checks unconditionally, forcing a
zero-bus table to present empty vectors. Verifier-only; proof bytes and transcript
are unchanged and every existing proof still verifies.

This one matters because it is boring. The binding logic was correct and present.
It was skipped by a guard that looked like an optimization.

## What correctness cost

### 0.31.0, the MDS row code

Measured on the signed public cdylib 0.8.0, `table-math`, Apple M3 Max,
`-C target-cpu=native`. Peak memory is `phys_footprint_peak` rather than
`ru_maxrss`, because the macOS compressor caps the resident set under pressure.

Against the previous release:

- Proof size **+15-50%**, with AES at roughly **2.2x**, the most commit-bound
  workload with the largest chiplet tables.
- Peak memory **1.4-1.7x**, from the encoded matrix at rate 1/2.
- Prove time within **±12%**, except AES at **+32%**.

Three prover-internal optimizations landed in the same window and bought 15-29%;
the MDS encode spent most of it back where commit dominates. Verification stays
flat, 5.6 ms to 71 ms from 2^15 to 2^24 rows.

### 0.32.0, the `h` commitment

The binding adds a commitment and an opening per bus-carrying table. Proof growth
scales with bus count rather than trace width, and the opening is base-only, which
halves its row width. `h` is an all-`B128` table with no transition constraint, and
the verifier parses one value per committed column, dropping the next-row shift.
Peak memory is roughly flat. Full measurements ship with the release.

Those are the honest numbers. Some of our earlier published figures were faster
because the prover was skipping work that soundness requires. A benchmark from a
system that accepts forgeries at 54% is not a benchmark.

## For other implementers

Four things generalize beyond our tree.

**Derive code distance; do not inherit it.** If your PCS soundness rests on a
relative distance, that distance needs a bound you can state, not a construction
you assume is good. A sparse expander's minimum distance is capped by generator
column weight, and the gap between that cap and our intended security parameter
ran to roughly two orders of magnitude in bits.

**Enumerate what binds each value.** For every quantity entering the final check,
write down the mechanism that ties it to the committed witness: a commitment and
opening, a sumcheck claim, a transcript ordering constraint. If the entry is
blank, that value is free. Ours were blank in two places and neither was visible
without the list.

**Watch ordering against the transcript.** `h_eval` was fatal specifically because
it was absorbed after `r_final` was drawn. A value the prover supplies after
seeing the challenge that its check depends on is a solved equation, not a claim.

**Guards that skip validation are attack surface.** The empty-`bus_specs` case
looked like a table with nothing to check. It was a table whose checks were
skipped while its data still flowed into a global sum.

## Scope

This postmortem covers `hekate-verifier`, `hekate-core`, `hekate-program`,
`hekate-crypto` and the wire format, all of which are open. The prover-side encode
lives in a closed repository and reaches the open workspace as a signed cdylib.
Soundness is a property of the verifier and the protocol, both public, and the
forgeries above were run against the shipped pipeline end to end.
