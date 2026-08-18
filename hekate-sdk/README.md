# hekate-sdk

[![Crates.io](https://img.shields.io/crates/v/hekate-sdk.svg)](https://crates.io/crates/hekate-sdk)
[![Docs.rs](https://docs.rs/hekate-sdk/badge.svg)](https://docs.rs/hekate-sdk)
[![CI](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml/badge.svg)](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](./LICENSE)

*Copyright (c) 2026 Andrei Kochergin and Oumuamua Labs.*

Bundling, wire-format, and preflight diagnostics for the Hekate ZK proving system.

Proving is driven through `hekate-prover-sys` (which links the signed cdylib).
Verification is `hekate_verifier::HekateVerifier::verify`. This crate owns the
serialization, identity, and preflight layers — not the prove/verify call sites.

## Preflight diagnostics

Evaluate constraints row-by-row on the concrete trace before proving. Catches
constraint, boundary, and bus violations without running the prover.

```rust
use hekate_sdk::preflight;

let report = preflight(&program, &instance, &witness)?;
assert!(report.is_clean());
```

## Bundle wire format

`build_bundle` / `serialize_bundle` / `deserialize_bundle` produce and parse the
internal program + instance + config + chiplet-defs payload. `serialize_bundle_header`
emits a witness-free bundle for the `hekate-prover-sys` ↔ cdylib boundary.

## Program identity

`program_id(program)` / `program_id_hex(program)` derive a stable 32-byte hash
over the program's structure (layout, constraints, chiplet defs, bus topology).

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Commercial licenses are available from Oumuamua Labs <info@oumuamua.dev>.