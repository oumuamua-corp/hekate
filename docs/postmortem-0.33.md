# Shapes the honest prover never builds: a soundness postmortem

The 0.32.0 postmortem carried an affected-versions table whose last row read
`0.32.0 | none known | Current`. That was true of the protocol and false of the
circuits. Within the next two weeks we found seven soundness gaps across the
Keccak and AES chiplets, each one sufficient on its own to break the guarantee
the chiplet exists to provide.

Both chiplets computed their round functions correctly. Neither proved its cipher.

## Summary

| # | Chiplet | Gap                                      | Effect                                  |
|:--|:--------|:-----------------------------------------|:----------------------------------------|
| 1 | Keccak  | Round constants were a free witness      | The prover picks the schedule           |
| 2 | Keccak  | Nothing pinned where a chain may open    | A block starts from an invented state   |
| 3 | Keccak  | The bus key omitted emit direction       | The consumer reads keccak-f inverted    |
| 4 | AES     | A bare emit row needs no block behind it | The consumer's ciphertext is free       |
| 5 | AES     | The counter did not pin the round count  | Two-round blocks are AIR-valid          |
| 6 | AES     | The link key omitted emit direction      | The consumer reads AES inverted         |
| 7 | AES     | The S-box bus key had no clock           | `SBOX_OUT` is free when a block repeats |

Sixteen forgery tests were written against these, seven on Keccak and nine on
AES. Each one is a consistent witness rather than a tampered cell, laid out under
its own substitution and run through the real prove and verify pipeline. Six of
the nine AES forgeries were run against a pre-fix build and confirmed accepted by
the shipped prover and verifier. The other three, and all seven on Keccak, were
constructed alongside their fix and have only ever run against the fixed AIR.
Those demonstrate that the fix rejects the shape. They are not independent
confirmations that the shape was once accepted. All sixteen are rejected now and
none is `#[ignore]`. A seventeenth test holds the door open on purpose:
it builds a host carrying four of the five roots that pin the emit direction,
and that host still accepts.

## Affected versions

| Running                    | Exposed to                        | Action                          |
|:---------------------------|:----------------------------------|:--------------------------------|
| 0.32.0 and earlier, Keccak | 1, 2, 3                           | Upgrade to 0.33.0 and re-prove. |
| 0.32.0 and earlier, AES    | 4, 5, 6, 7                        | Upgrade to 0.33.0 and re-prove. |
| 0.33.0                     | Data plane and bus keys unchecked | Current.                        |

The wire format has moved three releases running: v2 in 0.31.0, v3 in 0.32.0, v4
here. Each rejects its predecessor. Whatever version you are on, reaching 0.33.0
means re-proving, and no proof crosses any of those boundaries.

That last row states coverage instead of absence, which is the one difference
between this table and the one it follows. Checked: the control-plane language of
both chiplets is enumerated and equals the honest automaton, and the host-side
direction pin is checked the same way. Not checked: the data plane is not
enumerated at all, and a bus key is examined only for clock ownership, where even
that examination accepts a written waiver in place of a clock. Nothing asks
whether two emissions can collide on a key, or whether a key distinguishes
emissions the AIR treats differently. Three of the seven gaps below sit in that
unchecked region and we found them by reading.

The Keccak gaps reach every SHA-3 and SHAKE statement proved against the
chiplet, which includes ML-KEM-768 and ML-DSA-65, both of which absorb through
it. The AES gaps reach every AES-128 and AES-256 statement. A counter-mode host
is the worst case for gap 4: the keystream is exactly what the chiplet exists to
prove and exactly what a bare emit row makes free.

Neither fix touches the wire format, `Config`, or transcript ordering. What
changes is the committed column layout on both chiplets and on the S-box ROM,
and with it `program_id` for any program embedding them. Existing proofs are
rejected and must be re-proved against a prover release built for the new
layout; the pinned prover cdylib release for 0.33.0 is 0.11.0.

0.33.0 carries one further change that is not a soundness fix and closes no gap
here: the Brakedown commitment layout, which moves the wire format to v4. It is
described with its measurements at the end of the cost section.

Upgrading the crates is not sufficient by itself. Both fixes have a host-side
half, and a host that takes the new crates without migrating its own AIR has
closed gaps 1, 2, 4, 5 and 7 and left 3 and 6 open. Some of that migration is
caught by the compiler and some of it is not: `CpuAes256Unit::linking_spec_at`
gains a third parameter, which will not build, while a Keccak host that neither
anchors its direction column nor writes it correctly compiles and proves and is
still forgeable. See **The half of the fix that lives in the host** below.

## What the seven have in common

Every value here was committed and opened, which is what puts these seven in a
different class from the previous three. Those were values reaching the verdict
with no commitment behind them at all. Here the commitments are real, the roots
fire, and the openings verify. What is missing is a constraint saying what a
committed column may hold, and a bus key rich enough to tell two emissions apart.
Naming the mechanism that binds each value entering the verdict, the discipline
the last postmortem ended on, returns a clean sheet on all seven of these.

Each AIR was a faithful description of a well-formed block, and a faithful
description of the honest witness is not a proof that every emission belongs to
one. That splits three ways:

**A constant living in a witness column is a free variable.** Keccak's iota
constants were 64 committed bit columns that the round equation read and no root
touched. AES's round counter is the same failure wearing different clothes: it
pinned a value on the final row rather than a count of rows, and a value has more
than one preimage.

**An AIR that constrains the interior of a block does not constrain its
boundary.** Both chiplets said what follows a round row and what precedes an emit
row. Neither said where a run may open, and AES did not say that a run must
close. A prover who may choose where a chain begins chooses its input; a prover
who may choose where it ends chooses its round count.

**A bus key is the whole interface.** Anything absent from the key is not proved
about the emission. Direction was absent twice. A clock was absent once, and in
characteristic two an even multiplicity is not a weak binding, it is a deletion:
the pair cancels before cross-bus matching runs and the columns it carried go
back to being free.

## 1. Keccak: the round schedule was a witness

`RC_BITS` was 64 committed bit columns. The Iota equation read them and nothing
pinned them to FIPS 202. The root count was `25 packing + 1600 round + 2 Ghost
Protocol + 2 selector boolean`, and none of those 1629 roots touched the column.
That was visible from a count, and we did not do the count.

The round constraint is `next_bit = chi + rc_bit` on lane (0,0), which puts the
constant on the output side. The last round row's constant therefore sets lane
(0,0) of the block's final state outright. Twenty-four free 64-bit constants give
1536 bits of freedom over a 1600-bit output. For SHA3-256 the digest is lanes 0
to 3, and lane 0 alone is enough: pick the target value, solve for the round-23
constant, lay an otherwise honest chain.

Fixed by replacing the constant column with a one-hot round index the AIR drives.
`ROUND_BITS: [Bit; 32]` expands from one committed `B32`. Iota reads it as a
coefficient sum: for each bit `z`, the rounds whose constant sets `z` contribute
their selector, and the constant never appears as a witness at all.

## 2. Keccak: a chain could open anywhere

Two constraints carried the whole chain discipline:

```rust
cs.constrain(s_round * (one + next_s_round + next_s_in_out));
cs.constrain(next_s_in_out * (one + next_s_round) * (one + s_round));
```

A round row is followed by a round row or an output row, and the row before an
output row is a round row. Neither says where a chain may open. A block could
begin on a bare round row from a state the prover picked, run forward, and put
its output on the bus with no input emit tying it to anything.

Cross-bus matching is a characteristic-two multiset check, which means a lone
emit has to be balanced by something. The prover has two ways to arrange that.
`REQUEST_IDX` is a free committed column, which lets two phantom blocks name the
same partner row and annihilate pairwise, dropping an honest block's tail off the
bus. Or aim the phantom block's output at a CPU row that expects a digest and let
the CPU's own emit cancel it. Two rows suffice for the second shape: one round
row carrying `round(23)` from a free state, then its output row.

The lever is stronger than the constant gap above, because the forged output
needs no algebraic work at all.

Fixed by three roots that ride with the one-hot index:

```rust
cs.assert_zero_when(not_round, weighted(0, 24));
cs.assert_zero_when(not_round, weighted_next(1, 24));
cs.constrain(round(0) * (one + s_in_out));
```

A row that is not a round row carries no round bit at all, and its successor
carries none above bit 0. The activity parity then pins `round(0)` on that
successor whenever it is active, and the third root forces `S_IN_OUT` on any row
carrying `round(0)`. Every chain announces its input. The two-row stub dies on
the first line: its `round(23)` bit cannot be set on a row whose predecessor is
not a round row.

## 3. Keccak: the bus key did not say which end of a block an emit was

The key was 25 lanes plus a request index. Both emit rows fire on `S_IN_OUT`;
`S_ROUND` told them apart inside the AIR and was not a bus source. Swap the two
request indices, run the block forward, and the consumer reads the result
backwards. Inverting keccak-f costs one keccak-f, which makes the substitution
free.

The chiplet proved its emitted multiset was closed under the 24-round map. It did
not prove that the consumer's output was the image of the consumer's input.
Pinning the round constants does not help here, because the block runs the
canonical schedule in canonical order. In a sponge each call flips independently,
which puts 2^calls digests within reach of one message.

Fixed by appending `KeccakColumns::IS_OUTPUT`, a committed `Bit`, to the key on
both endpoints, pinned on the chiplet side by two roots. The second one is not
optional:

```rust
cs.assert_zero_when(s_in_out, is_output + one + s_round);
cs.assert_zero_when(one + s_in_out, is_output);
```

Without it the column is free on non-emit rows, which is the one failure here
that a single-bit mutation harness does catch.

## 4. AES: a bare emit row needed no block behind it

One constraint carried the chain discipline:

```rust
cs.constrain(s_active * (cs.one() + next_s_active + next_s_in_out));
```

An active row must be followed by an active row or an emit row. Nothing
constrained a row that was neither. A row with `S_IN_OUT = 1` and every other
selector clear satisfied every equation in the chiplet: the round, key schedule
and counter constraints are gated on `S_ROUND`, `S_FINAL` and `S_INPUT`, and the
off-gate pins reached only the key-schedule witness columns. `STATE_IN` on that
row was free, and it is a bus source.

`REQUEST_IDX_LINK` is a free committed column, which again lets two such rows
carry the same state and the same partner index and annihilate pairwise. Four
rows are enough: one honest input emit, two decoys that cancel, and one carrying
the ciphertext of the prover's choice. The block runs zero rounds past its input.

## 5. AES: the round count was not pinned

`ROUND_NUM` started at 1 on the input row, doubled on every `S_ROUND` row, and
was pinned to `0x36` on the `S_FINAL` row. The comment above it claimed this
enforced exactly nine round rows before the final one. It did not, twice over.

A run need not reach `S_FINAL` at all. The chain constraint above lets an active
row be followed by a bare emit row, which makes a two-row block a complete,
AIR-valid witness computing `MixColumns(ShiftRows(SubBytes(W))) + K1` and putting
it on the bus as the ciphertext. One-round AES is trivially invertible, and a
prover who must hit a chosen ciphertext solves backwards for the plaintext.

The counter also wraps. `0x02` has multiplicative order 51 in GF(2^8) under the
FIPS 197 polynomial, which puts the AES-128 pin `0x36` at nine doublings and
every 51 after that, and the AES-256 pin `0x4D` at thirteen and every 51 after
that. A sixty-round AES-128 block satisfies the counter pins exactly as a
nine-round one does, and any chiplet trace tall enough for 61 rows admits it.

That height is not a hypothetical. Our own shipped AES-128 example runs 31250
blocks at 11 rows each, rounded up to a chiplet trace of 2^19 rows. A 61-row
block fits inside it about eight thousand times over. The wrap was reachable on
the geometry we ship, not only on a geometry an attacker would have to talk us
into.

The mirror case is a run that never starts. The `S_FINAL` pin is absolute, a lone
final row preceded by an idle row is valid, its `ROUND_KEY` is free because the
key cascade only fires on `S_ROUND` and `S_INPUT` rows, and the emit row after it
carries `ShiftRows(SBOX_OUT) + ROUND_KEY`.

Gaps 4 and 5 are fixed together by the same one-hot index that fixed Keccak.
`ROUND_NUM: B8` becomes `ROUND_IDX: B16`, expanded into 16 virtual bits. One pin
clears the bits above the active range and four identities make every selector a
function of the index:

```rust
cs.constrain(weighted(ACTIVE, 16));

cs.constrain(s_active + cs.sum(&(0..ACTIVE).map(round).collect::<Vec<_>>()));
cs.constrain(s_final + round(ACTIVE - 1));
cs.constrain(s_input + round(0));
cs.constrain(s_round + s_active + s_final);
```

Six more roots plus one shift per round carry the chain, and the induction
closes. An idle row carries no round bits, a row following one carries at most
bit 0, and the parity forces `rb(0) = 1` if that row is active. Each shift
carries the single bit forward and the parity forbids a second. An idle row
cannot absorb a shifted bit, which stops a run ending early. Every maximal active
run is exactly `ACTIVE` rows, opens on an input emit, closes on a final row, and
is followed by exactly one output emit. There is no bare emit row and no short or
long run. Rcon leaves the witness by the same route iota did.

We considered keeping the doubling counter and pinning `ROUND_NUM = 1` on input
rows. That needs an equality test on a `B8`, an inverse witness, three more
columns, and it is fragile against the next person who changes the round count.

## 6. AES: the link key did not say which end of a block an emit was

Identical in shape to gap 3, on a different chiplet, found after it. `link_spec`
sources were 16 `STATE_IN` bytes plus a request index. Both the input row and the
output row fire on `S_IN_OUT`. Swap the two request indices on a canonical block
and the consumer reads its ciphertext where it expects its whitened plaintext.

The chiplet proved its emitted pair was related by the round function. It did not
prove the direction. AES-128 is not an involution, at most one of the two
labellings holds, and the verifier accepted both.

Fixed by appending `S_INPUT` to the key under `AES_DIRECTION_LABEL` on both
levels. `S_INPUT` is a function of the one-hot index now, which is what stops it
floating.

## 7. AES: the S-box bus had no clock

The `aes_sbox` key was 16 state bytes plus 16 S-box bytes and nothing else.
Encrypt the same block twice and every S-box emission has multiplicity two, which
cancels the pair before cross-bus matching runs and leaves `SBOX_OUT` tied to
nothing. The round equations consume it as an input:

```rust
let body = cs.next(state_in + j) + cs.col(round_key + j) + cs.sum(&mc_terms);
cs.assert_zero_when(s_round, body);
```

XOR a delta into `SBOX_OUT[0]` on the final round row of both blocks and the same
delta into `STATE_IN[0]` of both output rows. `SHIFT_MAP[0] = 0` carries it into
ciphertext byte 0 unchanged. Every AIR equation holds, preflight reports zero
violations, and both forged emissions cancel against each other while the honest
ROM rows cancel among themselves. Two equal blocks in one proof is the entire
precondition, and the attacker chooses which blocks to submit.

Both endpoints carried a waiver from the clock-stitching enforcement work. Its
argument was that phantom blocks are caught at the link and key buses, which
gaps 4 and 5 disprove, and its citation was `hekate-chiplets/src/aes/aes128.rs`,
a path that had not existed since the crate was renamed.

Fixed with a real clock. The AES side appends `Source::RowIndexLeBytes(4)`, the
ROM commits a `REQUEST_IDX: B32` column and appends the matching
`Source::Column`, and trace generation fills it with the AES row index it is
already iterating. No `clock_waiver` remains anywhere in the crate, on either
level or on the ROM, and the cross-endpoint validator now sees a real clock
instead of an argument. The AES side emits at most once per row and carries that
row's index in the key, which makes its keys pairwise distinct. Each key must
then appear an odd number of times on the ROM side, and every ROM appearance
satisfies `OUTPUT = S(INPUT)`.

Lookup kind was the other candidate and it is worse here. It needs both endpoints
positionally aligned on the padded hypercube, and the ROM compacts active rows.

## The half of the fix that lives in the host

A direction source on the bus binds the chiplet's two emits to each other. It
says nothing about which row of the consumer's trace is the request. Leaving that
to convention reopens gaps 3 and 6 by a second route: rehome the key emit
alongside the swapped link indices and both buses balance again.

`CpuKeccakUnit::constrain` carries `IS_OUTPUT[next] = IS_OUTPUT + SELECTOR`,
which alternates input and output in trace order and pins every cell of the
column rather than only the off-selector rows. That recurrence is cyclic and the
complement of a valid column also satisfies it. The complement is precisely the
reversal, which is why `direction_boundary` anchors row 0 and why it is not
optional.

`CpuAes128Unit::constrain` and `CpuAes256Unit::{constrain, constrain_at}` do the
same job in five roots:

```rust
cs.assert_boolean(sel);
cs.assert_boolean(dir);
cs.constrain(dir * (one + sel));
cs.constrain(sel * (dir + next_dir + next_sel));
cs.constrain(next_sel * (one + sel) * (one + next_dir));
```

No boundary constraint is needed there, because the run-opener root anchors
through the trace-end wrap where Keccak's bare recurrence does not.

Leaving the direction column free on emit rows is the whole bug. A host that pins
direction from its own state can constrain it itself. A host that writes only the
receiving row has not fixed anything, and nothing at the API level forces a
caller of `linking_spec_at` to also call `constrain_at`, because the two live in
different trait methods and a host can always hand `permutation_checks` a
throwaway `ConstraintSystem`. That coupling is out of reach of the type system.
It is closed from the test side instead, by
`hekate_scribble::language::assert_direction_pinned`.

## Why the test suite was green

Thirty exploit tests in `hekate-aes/tests/aes_chiplet.rs` tested the constraint
evaluator and not the AIR. Every one of them tampered a cell inside an otherwise
honest trace:

```rust
set_bit_val(&mut traces[0], Aes128Columns::S_ROUND, 4, Bit::ZERO);
```

Clearing `S_ROUND` alone breaks `s_active = s_round | s_final`, which the AIR
already enforces. The test passes, and it reads as round-count coverage. It never
lays a witness that is consistent under the shortened schedule, which is the only
shape an attacker would ever build. The Keccak suite had the identical pattern:
`exploit_rc_tamper` flipped one constant bit and asserted rejection, which the
Iota constraint catches because the state chain stops matching, while a chain laid
consistently under a substituted schedule sailed through.

A tamper test that breaks a relation the AIR already enforces is evidence that
the AIR enforces that relation. It is not evidence that a column is bound.

The mutation harness was green for a related reason. `hekate-scribble`'s
`FlipSelector` strategy flips one selector at a time, and every single-bit flip
lands on an identity the AIR already carries. All seven gaps need two or more
coordinated changes to the witness.

The tamper helpers themselves were also wrong. `flip_b8` and `flip_b64` wrote
through `Flat::from_raw`, skipping the tower-to-flat basis map, which lands a
named delta on an unrelated value. A test that says it corrupts byte 0 and
actually corrupts something else still passes, for the wrong reason, and reports
coverage it does not have.

And the waiver. Our validator checks that waiver text starts with `"see "` and
runs at least 32 characters. It does not check that the citation resolves, and it
cannot check whether the argument is still true. The AES waiver failed both of
those and passed the one we automated.

## How the fix is checked

We stopped arguing about the language an AIR admits and started enumerating it.
The one-hot index itself is not new mathematics; the check around it is the part
worth copying.

`hekate-scribble` gained a `language` module. It holds every data column at zero,
evaluates only the roots whose column set lies entirely inside the control plane,
and returns the transition core after dropping states with no successor or no
predecessor. Roots that mix control and data are skipped, which makes the
enumerated relation a superset of the AIR's real one. A core that equals the
honest automaton therefore bounds the real language from above, which is the
direction that matters.

- AES-128, all 2^16 index values: 770 candidate row states, and the core is
  exactly `idle -> I R^8 F -> O -> idle`.
- AES-256, same enumeration at 14 active rows: 12290 candidates, same shape.
- Keccak: the index is 24 bits wide and the ordered pairs that come with it put
  exhaustion out of reach. The enumeration is bounded to Hamming weight 3, which
  covers the one-hot plus every single skipped or duplicated shift: 1797
  candidates, core equal to the honest automaton. That is a bound and not a
  proof, and the test states it as one.
- `assert_direction_pinned` rejects any host AIR admitting more than
  `idle -> request -> response -> idle`. Two deliberately weakened hosts sit in
  the suite and both are rejected, one carrying nothing but the two boolean roots
  and one missing the run opener.

That covers four of the seven gaps and one half of two more. The enumeration
catches 1, 2, 4 and 5, because a substituted schedule and a malformed run are
both properties of the transition relation and that relation is exactly what it
walks. `assert_direction_pinned` catches the host half of 3 and 6.

Nothing new catches the chiplet half of 3 and 6, or any part of 7. A source
missing from a bus key is not a property of the transition relation, and an
enumeration of the control language will happily report a perfect automaton for a
chiplet whose emissions are indistinguishable to the verifier. We found those
three by reading the key construction and asking what a second emission with the
same key would mean. That is not a method, it is an afternoon and a suspicious
mood, and it does not survive the next person or the next chiplet.

The tool that would catch them does not exist here yet. It would enumerate the
sources of each bus key against the properties that must be bound for that bus:
which endpoint owns the clock, whether two emissions from the same table can
collide on the key, whether the key distinguishes emissions the AIR treats
differently. Our validator already asks the first of those three, which is how
the clock waiver came to be written at all. It does not ask the other two.

Each AES forgery also pins attribution before the verdict. `assert_air_violated`
where the rejection must come from a constraint root, `assert_air_clean` where it
must come from the bus. Before the fix, all of them passed preflight with zero
constraint violations and zero boundary violations, which puts the acceptance on
the chain discipline and the bus rather than on a broken harness. Two were clean
on the preflight bus diagnostic as well: both endpoints emitted the same multiset
and even the product-based debug oracle saw nothing.

One test isolates a single root. `direction_pin.rs` builds a host carrying four
of the five roots `constrain` emits, and it accepts a proof in which two identical
blocks cancel their own input and key emits, handing the consumer a ciphertext
that no row of its trace bound a plaintext or a key to. The same witness under
the full five is rejected on a constraint root. Without that test the language
enumeration above would be a model with nothing anchoring it to exploitability.

## What correctness cost

|                              | before    | after     |
|:-----------------------------|:----------|:----------|
| Keccak physical / virtual    | 29 / 1692 | 30 / 1661 |
| Keccak row bytes             | 214       | 211       |
| Keccak constraint roots      | 1629      | 1662      |
| AES-128 physical / virtual   | 96 / 152  | 96 / 167  |
| AES-256 physical / virtual   | 122 / 150 | 120 / 163 |
| S-box ROM physical / virtual | 51 / 177  | 52 / 178  |
| AES-128 / AES-256 roots      | 196 / 183 | 207 / 191 |

Row width moves 3 bytes down on Keccak, 1 byte up on AES-128, 1 byte down on
AES-256, and 4 bytes up on the ROM. Trading 64 constant columns for a 32-bit
index made the Keccak row smaller while making it correct, which is the pleasant
case and not the general one.

End to end, against 0.32.0. Signed public cdylib 0.10.0, `table-math`, Apple
M3 Max, `-C target-cpu=native`, mean of three runs, peak memory as
`phys_footprint_peak`:

| Workload           | Prove 0.32.0 | Prove, fixes | Change | Proof, fixes | Peak, fixes |
|:-------------------|-------------:|-------------:|-------:|-------------:|------------:|
| ML-KEM-768         |       919 ms |       918 ms |     0% |    4,461 KiB |     556 MiB |
| ML-DSA-44          |       1.60 s |       1.58 s |    -1% |    5,821 KiB |     575 MiB |
| ML-DSA-65          |       1.66 s |       1.69 s |    +2% |    5,859 KiB |     621 MiB |
| ML-DSA-87          |       2.95 s |       2.84 s |    -4% |    7,890 KiB |   1,223 MiB |
| AES-128            |       2.08 s |       2.14 s |    +3% |    7,677 KiB |   1,632 MiB |
| AES-256            |       2.27 s |       2.34 s |    +3% |    8,387 KiB |   2,027 MiB |
| keccak_inline 2^15 |       323 ms |       341 ms |    +6% |    1,107 KiB |     164 MiB |
| keccak_inline 2^20 |       7.58 s |       8.06 s |    +6% |    5,484 KiB |   3,610 MiB |

Binding a round schedule is close to free, unlike the two fixes before it. Prove
time moves within 6%, every proof size lands within 1% of its 0.32.0 figure,
verify is unchanged at 6 to 36 ms, and peak memory is flat inside the variance of
a polled measurement. The two Keccak rows move most, and the reason is legible:
the chiplet gave up 3 bytes of row and took on 33 more constraint roots, and at
2^20 the roots cost more than the narrower row saves. AES pays 3% for 11 and 8
more roots.

Nothing in the wire format, `Config`, or transcript ordering moved for these two
fixes. The cost that matters is `program_id`: every program embedding either
chiplet gets a new one, and every existing proof has to be re-proved.

### The commitment layout, in the same release

The numbers above are the chiplet fixes measured alone. 0.33.0 also carries a
change to the Brakedown commitment layout, and the rest of this section is that
change rather than a soundness gap.

The commitment used to encode every physical column twice, once as-is and once
shifted by one row, because the evaluation argument had to open the shifted
polynomial at the same point. The second copy is gone. Shifted claims are now
proven through weights the verifier evaluates for itself: a carry-chain form of
`eq(prev(·), P)` paired with the whole-column master, and its ring-switch
counterpart paired with the bit-plane master. Same hash, same code, same Merkle
structure, half the codeword. The wire format moves to v4 and no 0.32.0 verifier
accepts a v4 proof.

Binding does not move with it. The second copy was another opening of data the
first copy already committed, never an independent constraint, and the weight
replacing it is transparent: the verifier evaluates it from the point and its own
sumcheck challenges, leaving the prover nothing to choose.

Measured the same way, signed public cdylib 0.11.0, peak memory as the larger of
`phys_footprint_peak` and `ru_maxrss`, because sampling misses a peak reached
between polls and the compressor caps the other under pressure:

| Workload           | Prove above | Prove now | Change | Proof now | Peak now  |
|:-------------------|------------:|----------:|-------:|----------:|----------:|
| ML-KEM-768         |      918 ms |    626 ms |   -32% | 3,576 KiB |   459 MiB |
| ML-DSA-44          |      1.58 s |    926 ms |   -41% | 4,403 KiB |   459 MiB |
| ML-DSA-65          |      1.69 s |    969 ms |   -43% | 4,436 KiB |   478 MiB |
| ML-DSA-87          |      2.84 s |    1.50 s |   -47% | 5,922 KiB |   869 MiB |
| AES-128            |      2.14 s |    1.44 s |   -33% | 5,628 KiB | 1,182 MiB |
| AES-256            |      2.34 s |    1.55 s |   -34% | 5,962 KiB | 1,480 MiB |
| keccak_inline 2^15 |      341 ms |    203 ms |   -40% |   793 KiB |   143 MiB |
| keccak_inline 2^20 |      8.06 s |    4.08 s |   -49% | 4,220 KiB | 2,486 MiB |

Proof size falls 20 to 29% and peak memory 13 to 31%, for one reason in three
places: a byte the commitment no longer carries is a byte not encoded, not
hashed into the tree, and not opened at a query. Verification stays flat at 6 to
32 ms, because the verifier trades two opened halves for two weight evaluations
it computes in `O(n)`.

The prove column is not the layout alone, and the proof column is. Nothing else
in this release moves proof bytes. Prove time carries two further changes landing
in the same window: `hekate-math` 0.10.0, whose NEON flat multiply kernels move
to the vector domain and take Block128 dependent-chain latency from 7.27 to
4.64 ns/mul with a 12% end-to-end gate, and prover-internal work that is not
described here, the prover being a closed-source cdylib. The three are not
separated by measurement, and reading the whole column as the commitment layout
would overstate it.

This is the first change in the sequence that gives cost back rather than
spending it. It is also the only one a reader should not treat as mandatory: the
three fixes before it bought soundness, and this one bought bytes.

### The bill for the whole sequence

The table above isolates one change. This one stacks all four. Against 0.29.1,
the last release measured before any of the protocol fixes, with a derived code
distance, a committed `h`, a bound schedule and the new layout all underneath
it:

| Circuit    | 0.29.1 | 0.33.0 | Change |
|:-----------|-------:|-------:|-------:|
| ML-KEM-768 | 945 ms | 626 ms |   -34% |
| ML-DSA-44  | 1.70 s | 926 ms |   -46% |
| ML-DSA-65  | 1.81 s | 969 ms |   -46% |
| ML-DSA-87  | 2.95 s | 1.50 s |   -49% |
| AES-128    | 1.68 s | 1.44 s |   -14% |
| AES-256    | 1.80 s | 1.55 s |   -14% |

All six prove faster today than they did before any of this existed, AES
included. Through 0.32.0 that was true of four, and AES ran 27 to 30% slower as
the most commit-bound workload in the set; halving the codeword is worth most
exactly where commit dominates.

Proof size did not come all the way back. Against 0.30.0, the smallest we ever
shipped, ML-KEM-768 is up about 27%, ML-DSA-65 26%, ML-DSA-87 34%, and AES-128
97%. Through 0.32.0 those same four stood at 58%, 67%, 79% and 169%. What
remains is the standing price of a proximity layer whose distance is derived
rather than assumed, and of a bus helper that is committed rather than reported.
We would rather pay it there than in the number it replaced, which was a 54%
acceptance rate against the real verifier.

Both cross-release comparisons are separately-taken measurement sets on the same
M3 Max rather than one controlled run, and the 0.29.1 figures were taken on an
older prover build.

## For other implementers

**Count your roots against your columns.** Keccak's root count was
`25 + 1600 + 2 + 2` and none of those roots touched the 64 columns holding the
round constants. That was arithmetic, available at any point over the life of the
chiplet, and nobody did it. A committed column that no root reads is an input
from the adversary.

**A constant in a witness column is a free variable.** Fold constants into
coefficients, which keeps them out of the trace entirely. Both chiplets now carry
their round constants as scalars multiplying a one-hot selector, and there is
nothing left for a prover to choose.

**Write down the property you assumed and never stated.** Three of these gaps are
a missing block boundary and three are a missing field in a bus key, and both
groups are that one omission. Transition constraints describe a well-formed block
from the inside, and where a run may open and that it must close are separate
statements you have to make. A bus key is the whole interface, and anything not
in it is not proved about the emission, where in characteristic two an emission
that collides with another is not weakly bound but deleted. In all six cases the
property was real, the designer knew it, and it never became a root or a source.

**Tamper tests are not soundness tests.** Breaking a relation the AIR enforces
demonstrates that the AIR enforces it. The witness an attacker builds is
*consistent* under the substitution, and it is more work to construct. Build that
one. If your suite has thirty exploit tests and every one of them mutates a single
cell of an honest trace, you have thirty tests of your constraint evaluator. The
same goes for any check whose form you automated and whose content you did not:
our clock waiver had to begin with `"see "` and run 32 characters, and it did,
while its citation pointed at a file deleted months earlier and its argument had
already been refuted by two other gaps in the same chiplet.

**Enumerate what you can, and publish what you cannot.** If the control plane of
your circuit is small, hold the data at zero, walk every state, and compare the
admitted transition relation against the automaton you meant to build. A superset
that matches the honest automaton is a real bound and it is a few hundred lines.
Then publish what it does not reach, in the same document that claims it. Ours
does not reach bus keys, which is where three of our seven gaps were.

## Scope

This postmortem covers `hekate-keccak`, `hekate-aes`, `hekate-pqc` and
`hekate-scribble`, all of which are open, along with the CPU-side interfaces
hosts build against. The wire format, transcript and verifier protocol are
unchanged from 0.32.0. The prover reaches this workspace as a signed cdylib from
a closed repository; soundness here is a property of the AIR and the bus, both
public, and every forgery above runs through the real prover and the real
verifier rather than against a mock oracle. Which of them were also run against a
pre-fix build is recorded in the summary.

The previous postmortem is at [postmortem-0.32](postmortem-0.32.md). Its four
lessons still hold, and this release adds a question they do not ask. That
document audited every value entering the final verdict and found three that
nothing bound. It never asked whether the witnesses satisfying our circuits were
the witnesses we meant to admit. Those are different questions, and the second
one needs a different tool.
