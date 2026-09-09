# hekate-verifier

Analytical verifier for the Hekate ZK proving system.

## Modules

| Module      | Description                                               |
|-------------|-----------------------------------------------------------|
| `brakedown` | LDT query replay and Merkle path checks                   |
| `evaluator` | Multi-point evaluation argument against trace commitments |
| `sumcheck`  | Per-round Sumcheck verifier                               |
| `logup`     | Cross-table bus-sum matching                              |

Top-level `HekateVerifier::verify` replays Fiat-Shamir and chains the above into a single pass over the proof.

## Features

| Feature      | Default | Effect                                                                     |
|--------------|---------|----------------------------------------------------------------------------|
| `std`        | yes     | Standard library.                                                          |
| `blake3`     | yes     | Blake3 transcript and Merkle hashing.                                      |
| `parallel`   | yes     | Fan the LDT proximity check and Merkle path verification across CPU cores. |
| `table-math` | no      | Variable-time table-based basis conversion.                                |

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Commercial licenses are available from Oumuamua Labs <info@oumuamua.dev>.