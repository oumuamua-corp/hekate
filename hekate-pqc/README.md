# hekate-pqc

[![Crates.io](https://img.shields.io/crates/v/hekate-pqc.svg)](https://crates.io/crates/hekate-pqc)
[![Docs.rs](https://docs.rs/hekate-pqc/badge.svg)](https://docs.rs/hekate-pqc)
[![CI](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml/badge.svg)](https://github.com/oumuamua-labs/hekate/actions/workflows/ci.yml)
[![License: AGPL-3.0-only](https://img.shields.io/badge/License-AGPL--3.0--only-blue.svg)](LICENSE)

Post-quantum AIR chiplets for the [Hekate](https://github.com/oumuamua-labs/hekate) ZK proving system. Implements
ML-KEM (Kyber) decapsulation and ML-DSA (Dilithium) signature verification natively in binary fields, with supporting
NTT, basemul, high-bits, norm-check, and twiddle-ROM chiplets.

> **Experimental.** This crate exists to demonstrate that Hekate can prove
> lattice-based cryptography natively in binary fields. The circuits have no
> external audit and the statements they prove are fully public, which is the
> case where verifying the signature directly is cheaper. Treat it as a
> working example, not a production dependency.

```
Proving on Apple M3 Max:
  ML-KEM-768  : 626 ms, 459 MiB peak, 3,576 KiB proof, 23.2 ms verify
  ML-DSA-44   : 926 ms, 459 MiB peak, 4,403 KiB proof, 30.1 ms verify
  ML-DSA-65   : 969 ms, 478 MiB peak, 4,436 KiB proof, 30.5 ms verify
  ML-DSA-87   : 1.50 s, 869 MiB peak, 5,922 KiB proof, 32.0 ms verify
```

---

## ⚠️ Security Warning

This crate has not been audited and may contain bugs and security flaws.

USE AT YOUR OWN RISK!

### Proof soundness vs. PQC security level

Soundness is field-capped at **≈128 bits**: a proof binds at ~2⁻¹²⁸ regardless of parameter set, for
the higher levels (ML-KEM-768/1024, ML-DSA-65/87) the ZK proof is the weaker link, not the lattice scheme.
ML-KEM-512 and ML-DSA-44 are matched. The proven decapsulation and verification are still the full
FIPS 203 / 204 parameter sets.

---

## Examples

- [ML-KEM-768 decapsulation proof](https://github.com/oumuamua-labs/hekate/blob/main/hekate/examples/mlkem.rs)
- [ML-DSA signature verification proof](https://github.com/oumuamua-labs/hekate/blob/main/hekate/examples/mldsa.rs)

---

## License

AGPL-3.0-only. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
Commercial licenses are available from Oumuamua Labs <info@oumuamua.dev>.