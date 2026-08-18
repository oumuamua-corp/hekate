# hekate-program

[![Crates.io](https://img.shields.io/crates/v/hekate-program.svg)](https://crates.io/crates/hekate-program)
[![Docs.rs](https://docs.rs/hekate-program/badge.svg)](https://docs.rs/hekate-program)
[![CI](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml/badge.svg)](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](./LICENSE)

*Copyright (c) 2026 Andrei Kochergin and Oumuamua Labs.*

AIR program and chiplet definition API for the Hekate ZK proving system.

## Modules

| Module        | Description                                                        |
|---------------|--------------------------------------------------------------------|
| `constraint`  | Algebraic constraint DSL and arena-backed IR for AIR transitions   |
| `schema`      | Typed column layout declaration via macro                          |
| `expander`    | Wide physical columns expanded to virtual bit columns at eval time |
| `chiplet`     | Standalone AIR-table definition and composition                    |
| `permutation` | LogUp bus endpoint specification for cross-table wiring            |

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Commercial licenses are available from Oumuamua Labs <info@oumuamua.dev>.
