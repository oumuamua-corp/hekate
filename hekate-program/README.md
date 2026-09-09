# hekate-program

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
