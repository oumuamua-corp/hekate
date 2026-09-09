# Liveness was a witness: a soundness postmortem

The 0.33.0 postmortem closed seven gaps across two chiplets. Three of them were one
shape: the prover decided whether a block existed at all, and the constraints that
would have policed that block were switched off by the same decision. We fixed those
three inside Keccak and AES, chiplet by chiplet.

The shape was never specific to those chiplets. It was a property of how every table
in the engine declared which of its rows were doing work. 0.34.0 removes the shape
from the engine instead of from a chiplet.

## Summary

| # | Gap                                                     | Effect                                             |
|:--|:--------------------------------------------------------|:---------------------------------------------------|
| 1 | Bus liveness was a witness column                        | The prover picks which rows run and which roots fire |
| 2 | The verifier never checked which circuit it verified     | A drifted build verifies a different statement      |
| 3 | Structural validators ran on the verify path             | Unrecognised program shapes were accepted           |

Gap 1 is the one that reaches statements. At 0.33.0 exactly one chiplet in the
workspace declared a fixed column of any kind, and it was not a bus selector.
Every other table left liveness in the witness, which is where the prover writes.

All chiplets were updated for this release: RAM, ROM, integer arithmetic, Keccak,
the AES round tables and the S-box ROM, NTT, twiddle ROM, base multiplication,
norm check, high bits, and both post-quantum control tables. Every example in the
workspace was updated with them, and the examples are now sound by construction in
the precise sense given in **What "sound by design" means** below.

## Affected versions

| Running            | Exposed to                              | Action                          |
|:-------------------|:----------------------------------------|:--------------------------------|
| 0.33.0 and earlier | 1, 2, 3                                 | Upgrade to 0.34.0 and re-prove. |
| 0.34.0             | Circuit semantics remain author's burden | Current.                        |

The proof wire format moves from v4 to v5 and the bundle format from v2 to v4.
Neither accepts its predecessor. `program_id` changes for every program in the
workspace, because a program's fixed columns are part of its identity and every
table gained some. Existing proofs are rejected and must be re-proved against a
prover release built for this layout; the pinned prover release for 0.34.0 is
0.12.0.

That last row states a limit rather than absence, following the practice this
series adopted in 0.33.0. Checked: no table lets the prover choose which of its
rows participate in a bus, and no verifier accepts a program it was not pinned to.
Not checked, and not checkable by any engine: whether a given circuit computes the
function its name claims. See **What this release does not promise**.

Upgrading the crates is not sufficient on its own. A host that takes the new crates
without pinning its own bus selectors is rejected by the predicate described in
gap 3, at circuit construction and again at verify entry. It fails closed at both,
which is deliberate: there is no path where an unpinned selector proves and
verifies quietly.

## What the three have in common

The three postmortems in this series sit at three different levels, and the
progression is the useful part.

0.32.0 was about values reaching the verdict with nothing binding them to the
committed witness. 0.33.0 was about committed columns that no constraint policed
and bus keys too poor to tell two emissions apart. Both are questions about a
circuit's contents.

This one is a question about the frame around the circuit. In both earlier cases
the verifier was doing the right arithmetic on the wrong inputs. Here the verifier
was doing arithmetic that was locally correct and then deferring, in three separate
places, to a party that cannot be deferred to: the program author for judgments
about structure the author writes, and the caller for the identity of the circuit
itself.

The rule that covers all three:

> A check on the verify path is safe if and only if its answer is a total function
> of data the verifier recomputes or compares by equality, with no case analysis
> over author-chosen structure.

Set membership is safe. Recompute-and-compare is safe. An MLE equality against a
commitment is safe. "Does some constraint in this program determine this cell" is
not, because it is a question about structure the adversary writes, and every
syntactic approximation of it maps the shapes it fails to recognise onto accept.

The tell is mechanical. If a verify-path check contains a `match` over expression
or declaration shapes with a default arm that does not reject, it is unsafe.

## 1. Bus liveness was a witness column

A bus endpoint declares an optional selector column. The bus weights each row's
contribution by that column, and the AIR roots that police the row are gated on the
same column, in the familiar `selector * body` form. Before this release that column
was an ordinary committed witness Bit.

One write therefore does two things at once. Clearing the selector on a row removes
the row from the bus and switches off every constraint gated on it. The row is still
committed and still opens correctly. It is simply no longer claiming anything.

The consequence for a published value is direct. A boundary constraint pins a
committed cell to a public input, and that check is sound: the opening is real and
the equality holds against the commitment. What the check does not establish is that
the row was live. If the prover chose liveness, it chose whether the constraints that
determine that cell ever fired, and a cell on a dead row is committed, opened, equal
to the published value, and free.

The same lever produces the empty-trace family generally: a table that appears to
have done work, whose rows are all switched off, satisfying every gated root
vacuously.

**Reach.** Every table with a bus, which at 0.33.0 was every table in the workspace
except the pure arithmetic examples. Keccak and AES were partially protected, not by
their selectors but by the chain roots and one-hot round indices added in 0.33.0,
which pin those two chiplets' activity from inside the AIR.

**Fix.** Liveness is a fixed column. Every bus selector is now either absent, meaning
the endpoint is unconditionally active on every row, or an index into that table's
own fixed column set. A fixed column is pinned to a shape determined by the row
index alone; the verifier evaluates the shape's multilinear extension at the point
where it opens the column and rejects on any mismatch. The prover has no freedom
left over which rows participate.

That mechanism already backed the other fixed shapes. What is new is that it now has
to express real activity schedules, which needed two shape variants:

```rust
FixedShape::Cadence { stride, count, origin, values }
FixedShape::Segments(Vec<CadenceSegment<F>>)
```

`Cadence` is a strided block placed anywhere, carrying a full per-period pattern,
which covers the common case of a dispatch table whose active rows sit at fixed
offsets inside a repeating block. `Segments` is a disjoint union of such blocks,
sorted by origin and non-overlapping, which covers schedules built from several runs
at different periods. Real schedules needed between one and roughly thirty blocks.
Validation rejects overlapping or unsorted segments rather than normalising them,
which keeps the encoding canonical and keeps a reordered declaration from hashing to
a different identity for the same shape.

Both are recompute-and-compare against a committed opening, which puts them in the
same category as the shapes that came before and squarely inside the rule above.

**Where the schedule comes from.** Circuit parameters, computed next to the code that
writes the trace. Not from the witness and not from the instance. A schedule that
disagrees with the generated trace is a loud failure before proving and a rejection
at verify. That is a completeness failure, which is the safe direction; the unsafe
direction would be a schedule the witness gets to influence.

**Data-dependent counts.** Where the number of active rows would depend on the
witness, the rule is to pin the selector on every row and fill the surplus with
canonical no-op events that cancel against matching no-ops on the partner endpoint.
The shape is then constant across every proof the circuit will ever produce. No
circuit in this workspace needs that today. It is written down because the tempting
alternative, publishing the count and deriving the shape from it, both leaks the
count and reintroduces an instance-dependent shape, and because leaving one witness
selector behind a local argument is precisely how this class survives.

## 2. The verifier did not check which circuit it verified

`program_id` existed before this release as a digest over a program's structure.
Nothing on the verify path read it. The verifier evaluated whichever `Program`
object the caller handed it, and the statement established was "the constraints of
this object are satisfied", with no link between that object and any reviewed
artifact.

This is not a forgery path, and calling it one would overstate it. It is a drift
path, and drift is what survives a careful team. A dependency bump, a merge, an edit
to a circuit definition, and a verifying node checks a different statement than the
one that was audited. Prover and verifier rebuilt from the same drifted tree agree
with each other perfectly. Nothing in the protocol noticed, because from the
protocol's point of view nothing was wrong.

**Fix.** `verify` takes the audited program id as its first argument, recomputes the
id from its own program object, and rejects on mismatch with a typed error carrying
both values. The id is also absorbed into the transcript. Verifying without a pinned
id is not expressible in the API.

The id deliberately does not travel in the proof or in the bundle. An identity
carried by the proof is a label the adversary chooses, and the bundle already carries
the program that the id is derived from, which makes an id alongside it a checksum
rather than a commitment. The pinned constant has to live where the drift cannot
reach it: in the verifying deployment, next to the code, the way a verifying key or
an image identifier does in other systems. This is the standard construction, and it
is the only one available, because "does this circuit really compute Keccak" is not
decidable by any engine.

## 3. Structural validators ran on the verify path

Before doing any algebra, the 0.33.0 verifier walked the program's own declarations:
a per-endpoint clock-stitching check, a cross-endpoint bus-set check, and a mutual
exclusion check that read the constraint syntax tree looking for a particular root
shape.

Those are gone from the verify path in 0.34.0.

Against an adversarial author they bought nothing. Each one asks a question about
structure the author writes, answers it by recognising the spellings it knows, and
falls through to accept on everything else. The set of spellings is not bounded by
anything, which makes the accepting default arm the whole behaviour of the check
rather than an edge case in it. A check like that costs completeness when it rejects
a legitimate shape and costs soundness when it accepts an illegitimate one, and its
success value reads to every downstream consumer as a guarantee it was never in a
position to make.

We deleted them rather than relocating them to an advisory report. A checker that
only helps an author who is already honest defends against nobody in this threat
model, and it is one more thing that can be wrong, one more thing to maintain, and
one more thing a reader mistakes for a guarantee.

**What replaces them is one predicate.** Every bus selector and receive-selector is
either absent or a member of that table's fixed column set, and a receive-selector
without a send-selector is rejected. Set membership over data the verifier already
holds, total, with no shape to misclassify. It runs both at authoring time and at
verify entry, and it fails closed.

Two authoring-time checks went with them and are worth naming, because their
disappearance is a consequence rather than a decision. With both selectors of a
paired bus pinned to fixed shapes, a row where both are high is public program
structure a reader can evaluate from the shapes alone, and booleanity of a selector
is the shape's bit-domain validation. The checks that used to argue those properties
from the constraint syntax had nothing left to argue.

The verify path now executes algebra and equality only: sumcheck, the commitment
openings, LogUp consistency and the cross-bus sum, the fixed-column MLE comparisons,
the boundary comparisons, the program identity comparison, and the membership
predicate above.

**Waivers.** Bus clock waivers still exist as authoring-time documentation, with a
lint on their citation format, and they run nowhere on the verify path. The 0.33.0
postmortem burned one whose citation pointed at a file deleted months earlier. A
waiver is an audit note attached to a human argument. It is not machinery, and this
release does not treat it as any.

## What changed for circuit authors

**Caught by the compiler.** `verify` gains a first parameter. Chiplet constructors
gain a count parameter where the schedule needs one, for example a ROM's instruction
count or a RAM's event count, letting the table derive its own activity shape from
its parameters.

**Caught by the predicate, not the compiler.** Every bus endpoint must name a fixed
column as its selector or omit the selector entirely. A host that keeps a witness
selector compiles and then fails closed at authoring and again at verify entry. A
wrong count fails the same way, at the fixed-column comparison, which is what makes
this migration mechanical rather than delicate: there is no configuration of counts
that is wrong and silent.

**ML-DSA circuits are per message length.** `MlDsaChiplet::new` takes it,
it lands in `program_id`, and a deployment pins one id per length it accepts.

**Not caught anywhere.** Whether the AIR determines the cell you publish. That was
true before this release and remains true.

## What "sound by design" means

Every example in this workspace that publishes a value does it through a boundary pin
on a row whose liveness is fixed. Three links are the engine's, each one algebra:

1. The published row is live, because a fixed column marks it and the verifier
   recomputes that column's shape for itself.
2. Every root gated on a fixed column fires on that row, because the prover does not
   write the gate.
3. The boundary pin ties the cell to the public input, checked by one commitment
   opening.

No bus carries a public input, no validator reads the author's structure, and no
author-supplied data appears in any of the three. That much is a property of
construction, which is the reason for the phrase: it holds without anyone reviewing
the example for it, and it cannot be lost by an edit that keeps compiling.

The fourth link is the author's. Whether an AIR contains roots that determine the
published cell at all is not something the engine checks, for any example or in
general, and the next section states that limit plainly.

## How the fix is checked

**A gauge, not an argument.** One test enumerates every shipped table and asserts
that each bus selector is absent or fixed. It reasons about nothing; it lists. When
the port was in progress its failure output was the work list, and it is now at
zero.

**A randomised corpus, in the ordinary test run.** A fixed-seed generator draws a
table geometry, a gate shape from four families, a bus topology, and a witness, then
proves and verifies through the real pipeline and asserts three things per sample:
the honest instance verifies, a forged public input is rejected, and a drifted
program identity is rejected. It sits in the ordinary test suite rather than in a
tool somebody remembers to run.

The generator is worth a paragraph of its own, because its existence is a
consequence of the fix rather than an addition to it. A randomised corpus is only
meaningful over a space it can cover. While liveness was a witness, the space of
expressible programs included every way an author might arrange activity, which is
not a space a generator explores usefully. Pinning liveness shrank it to schedules
drawn from a small set of shapes, and a generator covers that. Removing freedom made
the system testable in a way that checking for the absence of that freedom never
could have.

**A mutation harness that now has teeth.** The trace fuzzer's selector-flip strategy
flips one selector and asserts the proving oracle rejects. On most tables before this
release, flipping a selector was a legal prover move rather than a detectable
mutation, and the strategy was meaningful on the two chiplets whose AIRs pinned
activity from inside. With liveness fixed everywhere, a flipped selector is a
fixed-column mismatch on every table.

## What we removed that was not load-bearing

One post-quantum control table declared a bus whose two endpoints both selected on
columns that trace generation never wrote, alongside eleven further columns that
were never written either. The endpoints were inert: they contributed nothing to
cross-bus matching, and no proof changes meaning with their removal. Thirteen column
declarations and their roots are gone, 33 physical cells per row.

A declared bus that never fires is worse than no bus at all. It costs nothing at
runtime, which is why it survives, and it reads to a reviewer as a binding that
exists. The general form of that lesson is in the closing section.

The same table silently truncated its dispatch schedule when its trace was too
small, where the sibling table returned an error. Both now return an error, at the
point where the schedule is known rather than partway through writing rows.

## What this release does not promise

Stated plainly, because claiming a class was closed is how a series like this
acquires a fourth entry.

**Circuit semantics.** Pinning identity binds which circuit is being verified. It
does not certify that the circuit computes what its name claims. An author who
publishes a "SHA3" circuit with one round missing produces a verifier that correctly
answers yes about a statement nobody wanted. No engine decides this, and an engine
that claims to is running the kind of check gap 3 describes. The defense is that the
circuit is a reviewed, published artifact whose identity the verifier pins, exactly
as a contract address is pinned. Anything stronger is a claim this system cannot
back.

**Determination of the published cell.** The engine gives an author a construction in
which a published value is provably determined, and refuses to certify that any
particular circuit uses it correctly. That refusal is the subject of gap 3 and is
deliberate.

**Workload privacy.** Pinning liveness makes activity patterns public by
construction. In this workspace nothing new leaks: trace heights already implied
block counts and no shipped circuit hides how much work it did. A future circuit that
wants to hide its workload cannot express that as a witness selector under this rule,
and would need a different construction. That is a real constraint on the design
space and we would rather state it than have someone discover it.

**Independent audit.** This workspace has not had one.

## What correctness cost

The figures below are the currently published baselines, carried here unchanged. The
0.34.0 re-measurement lands with the release. Conditions as in the previous
postmortems: Apple M3 Max, `--release`, features `std parallel blake3 table-math`,
`-C target-cpu=native`, mean of at least three runs on an idle machine, peak memory
as the process peak physical footprint. Cells read zero-knowledge / base.

### Post-quantum and AES

|              | ML-KEM-768        | ML-DSA-44         | ML-DSA-65         | ML-DSA-87         | AES-128           | AES-256           |
|:-------------|:------------------|:------------------|:------------------|:------------------|:------------------|:------------------|
| Proving      | 686 / 608 ms      | 982 / 889 ms      | 1.04 / 0.95 s     | 1.55 / 1.44 s     | 1.42 / 1.35 s     | 1.54 / 1.53 s     |
| Verification | 46.0 / 22.0 ms    | 65.2 / 27.5 ms    | 66.1 / 28.7 ms    | 69.4 / 30.5 ms    | 23.1 / 17.9 ms    | 23.7 / 18.6 ms    |
| Proof size   | 3,948 / 3,335 KiB | 4,878 / 4,139 KiB | 4,897 / 4,148 KiB | 6,390 / 5,508 KiB | 5,901 / 5,242 KiB | 6,237 / 5,594 KiB |
| Peak memory  | 426 / 415 MiB     | 497 / 474 MiB     | 503 / 457 MiB     | 848 / 852 MiB     | 1,190 / 1,130 MiB | 1,484 / 1,425 MiB |

Both AES workloads prove 31,250 blocks per run.

### Keccak-f[1600], scaling

| Scale (rows) | Permutations | Proving       | Verify         | Proof size        | Peak memory       |
|:-------------|:-------------|:--------------|:---------------|:------------------|:------------------|
| 2^15         | 1,310        | 227 / 195 ms  | 16.8 / 5.3 ms  | 1,081 / 778 KiB   | 140 / 123 MiB     |
| 2^20         | 41,943       | 4.09 / 3.99 s | 25.3 / 12.9 ms | 4,507 / 3,986 KiB | 2,516 / 2,484 MiB |

### Fibonacci, 32-bit integer add, scaling

| Scale (rows) | Proving         | Verify         | Proof size        | Peak memory        |
|:-------------|:----------------|:---------------|:------------------|:-------------------|
| 2^20         | 441 / 388 ms    | 7.0 / 3.4 ms   | 1,297 / 739 KiB   | 228 / 144 MiB      |
| 2^24         | 6.66 / 6.17 s   | 12.6 / 7.0 ms  | 4,555 / 2,834 KiB | 3,318 / 2,018 MiB  |
| 2^26         | 29.24 / 24.45 s | 21.6 / 10.8 ms | 8,901 / 5,624 KiB | 13,312 / 7,840 MiB |

### Where the cost sits

This release is close to free, and the reasons are structural rather than measured.

**Proving is unchanged in shape.** A selector that becomes a fixed column is the same
committed Bit column it always was, in the same layout, encoded and opened the same
way. Nothing was added to the trace. Roots came off: the booleanity root on a pinned
selector is redundant against the shape's own bit-domain validation, and one control
table shed thirteen columns.

**Verification gains one shape evaluation per pinned column.** A small strided block
evaluates in about a microsecond and the cost is independent of table height, since
it scales with the number of variables and the stride rather than the number of rows.
A full composite's pins land under a millisecond against verifications measured in
tens of milliseconds. The one shape that would not have been affordable, a dense
per-row column, is exactly the one the new variants exist to avoid.

**Proof size is unaffected in structure.** No new committed columns, no new openings,
no change to the number of queries.

**The mandatory cost is re-proving.** A program's fixed columns are part of its
identity, every table gained some, and both wire formats moved. Nothing crosses that
boundary.

One workload was spot-checked through the shipped release against the table above,
at 2^24 in base mode. Proof size and peak memory land on their baselines. Prove time
is within noise of it on a machine that was not quiesced, which is why the full
re-measurement ships with the release rather than here.

## For other implementers

Four things generalise past this tree.

**Ask who writes the column that decides whether a constraint fires.** A gated root
is exactly as strong as its gate. If the gate is witness, the prover owns the
constraint, and the AIR you reviewed is not the AIR that runs. This is worth an
explicit pass: for every selector in your system, name the party that chooses its
value. Ours were nearly all the prover, and that was visible from a one-line
predicate we had not written down.

**A verify-path check that pattern-matches author structure fails open.** Decide
whether each check's answer is a total function of data you recompute or compare,
or a case analysis over syntax somebody else chose. The second kind cannot be made
safe by adding cases, because the cases are not bounded by anything, and it is worse
than absent because its success value gets read as a guarantee. The mechanical tell
is a default arm that does not reject.

**Bind the circuit, not just the witness.** A proof establishes a statement about a
circuit, which makes the circuit's identity part of the statement. Pin it where your
build drift cannot reach it, and do not accept it from the proof, since an identity
the prover supplies is a label rather than a commitment. This is settled practice
elsewhere and it is cheap: a digest, a constant, and one comparison.

**Removing freedom beats checking for its absence, and it is what makes testing
possible.** The second half is the part we underrated. A constraint enforced by
construction shrinks the space of programs your system admits, and a space small
enough to enforce is usually a space small enough to randomise over. We got a
generator out of this fix that would have had nothing to explore before it. A related
corollary: an inert declaration, a bus whose endpoints never fire or a column nothing
writes, costs nothing at runtime and reads to every reviewer as a binding that
exists. Delete it or wire it.

## Scope

This postmortem covers `hekate-program`, `hekate-verifier`, `hekate-core`, the
chiplet crates, the wire format and the examples, all of which are open. The prover
reaches this workspace as a signed shared library built from a closed repository;
soundness here is a property of the verifier, the AIR and the bus, all public, and
every test referenced above runs through the real prover and the real verifier.

The previous postmortems are at [postmortem-0.33](postmortem-0.33.md) and
[postmortem-0.32](postmortem-0.32.md). Their lessons still hold. The first asked
what binds each value entering the verdict. The second asked whether the witnesses
satisfying a circuit are the witnesses it meant to admit. This one asks who decides,
and answers that anything the prover decides is not a constraint and anything the
author declares is not a proof.