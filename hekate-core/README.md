# hekate-core

[![Crates.io](https://img.shields.io/crates/v/hekate-core.svg)](https://crates.io/crates/hekate-core)
[![Docs.rs](https://docs.rs/hekate-core/badge.svg)](https://docs.rs/hekate-core)
[![CI](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml/badge.svg)](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](./LICENSE)

*Copyright (c) 2026 Andrei Kochergin and Oumuamua Labs.*

Core primitives for the Hekate ZK proving system.

## Modules

| Module   | Description                                                  |
|----------|--------------------------------------------------------------|
| `poly`   | Zero-copy multilinear polynomial views and univariate rounds |
| `tensor` | Lazy `Eq(x, r)` with constant-time fold                      |
| `trace`  | Typed trace-column storage and builder                       |
| `proofs` | Wire-level proof and commitment types                        |
| `config` | LDT security parameters and relative-distance estimate       |

## Features

| Feature         | Default | Effect                                           |
|-----------------|---------|--------------------------------------------------|
| `std`           | yes     | Enable `std` (transitively through dependencies) |
| `parallel`      | yes     | Rayon-backed Merkle build                        |
| `blake3`        | yes     | Blake3 as `DefaultHasher`                        |
| `sha2`          | no      | SHA-256 as `DefaultHasher`                       |
| `sha3`          | no      | SHA-3-256 as `DefaultHasher`                     |
| `secure-memory` | no      | `ZeroizeOnDrop` on `TraceColumn`                 |

Exactly one of `blake3` / `sha2` / `sha3` must be enabled.

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Commercial licenses are available from Oumuamua Labs <info@oumuamua.dev>.
