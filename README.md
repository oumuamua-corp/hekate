<div align="center">
  <h1>Hekate Engine</h1>
  <h3>The Executioner of Monolithic ZK Architectures.</h3>
</div>

---

### THE MANIFESTO

The Zero-Knowledge industry is built on a lie. It sold scalable trust but delivered infrastructure debt.
It builds server-grade dinosaurs in an era that demands edge-native agility.

Current STARK and Binary-Field provers (Stone/Stwo, Winterfell, Miden, Binius) are architecturally obsolete. They suffer from the "Monolithic Trace Fallacy", the naive belief that the entire history of a computation must be materialized in RAM to be proven.

This architectural failure imposes a heavy "RAM Tax" on every rollup:
* It demands 128GB+ server nodes for real-world workloads.
* It centralizes proving into expensive SaaS silos.
* It makes client-side privacy a physics impossibility.

Hekate Engine is the end of that era. The mistake was not optimized. It was eradicated.

---

### THE WEAPON: EPHEMERAL STATE STREAMING

Hekate rejects history. It proves only the transition.

The proprietary Boundary-State Architecture fundamentally decouples proof capacity from memory capacity. The Engine does not store the execution trace. It generates segments JIT, proves the state transition, and instantly discards the ephemeral data.

The result is absolute linearity. Infinite execution streams proved with flat, O(1) RAM usage.

---

### THE KILL SHOT (BENCHMARKS)

Benchmarks conducted on a consumer-grade M3 Max Laptop.

### Binius64

> [!CAUTION]
> **The Workload:**
> Unlike the synthetic Fibonacci test bellow, this benchmark runs Keccak-f[1600] (Ethereum-native hashing). This is a real-world, heavy-duty cryptographic workload.

**The Reality Check:**
Binius is a specialized race car. It is incredibly fast on small, perfect tracks ($2^{15}$).
Hekate is an armored tank. It crushes industrial workloads ($2^{24}+$) where Binius engines melt down due to memory exhaustion.

![Benchmark Chart](https://github.com/oumuamua-corp/hekate/blob/main/hekate_vs_binius64_keccak_f1600.png?raw=true)

| Metric (Keccak) | Binius64 (Bit-Level Optimization) | **Hekate Engine** (Zero-Copy) | Kill Stats |
| :--- | :--- | :--- | :--- |
| **$2^{15}$ (1.3k Permutations)** | **147 ms** (~400 MB RAM) | 202 ms (**44 MB RAM**) | **~9x Less RAM Overhead** |
| **$2^{20}$ (41k Permutations)** | SWAP HELL (**72 GB RAM**) | **4.74 s** (1.4 GB RAM) | **50x Less RAM** |
| **$2^{24}$ (671k Permutations)** | **CRASH (Out of Memory)** | **88 s** (21.5 GB Peak) | **Operational vs Dead** |

*Note: Binius64 scales linearly in time but exponentially in memory cost due to massive allocation requirements for binary field extensions. Hekate maintains a flat memory profile via streaming.*

### Winterfell

> [!WARNING]
> **The Handicap:**
> * Winterfell: Configured in "Packed" mode (2 terms per row) to hide architectural latency.
> * Hekate: Configured in "Pure" mode (1 term per row). Hekate performs 2x the logical work per row and still dominates.

![Benchmark Chart](https://github.com/oumuamua-corp/hekate/blob/main/hekate_vs_winterfell_fibonacci.png?raw=true)

| Metric | Winterfell (Legacy / Miden Core) | **Hekate Engine** (Gen-5) | Kill Stats |
| :--- | :--- | :--- | :--- |
| **Security Level** | ~99 Bits (Proven <60) | **128 Bits** (Standard) | **Safer** |
| **$2^{20}$ (1M Rows)** | 792 ms (~1GB RAM) | **397 ms** (170 MB RAM) | **2.0x Faster / 6x Less RAM** |
| **$2^{24}$ (16M Rows)** | 18.34 s (**24 GB RAM**) | **6.39 s** (2.72 GB RAM) | **2.9x Faster / ~9x Less RAM** |
| **$2^{26}$ (67M Rows)** | **CRASH (Out of Memory)** | **28.2 s** (11.8 GB RAM) | **Infinite Scale vs Failure** |

*Note: Winterfell crashes because it attempts to materialize the entire execution trace + LDE in RAM (O(N log N)). Hekate streams the computation (O(N)), keeping memory usage flat.*

### STATUS: PROPRIETARY

Hekate Engine is a closed-source, proprietary binary designed for protocols requiring actual sovereignty and viable unit economics.
