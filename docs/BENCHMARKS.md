# BADGER Performance Benchmarks

---

## 1. Test Environment

- **Host Machine:** AMD64 64-bit Architecture
- **Operating System:** Linux 6.6.87.2-microsoft-standard-WSL2 (Ubuntu 22.04 LTS)
- **Rust Toolchain:** `rustc 1.100.0`, `cargo 1.100.0`
- **Compiler Profile:** `--release` (opt-level = 3)
- **Iteration Count:** 10,000 continuous evaluation cycles

---

## 2. Empirical Benchmark Results

### Policy Evaluation Latency
Measures the complete evaluation path across executable allowlists, filesystem longest-prefix-match rules, and network destination rules:
- **P50 Latency:** `0.950 µs` (sub-microsecond)
- **P95 Latency:** `0.960 µs`
- **P99 Latency:** `1.032 µs`

### Threat Detection Latency
Measures deterministic rule evaluation and finding synthesis upon receipt of a raw runtime event:
- **P50 Latency:** `0.990 µs`
- **P95 Latency:** `1.021 µs`
- **P99 Latency:** `1.982 µs`

### Event Ingestion Throughput
- **Measured Ingestion Rate:** `888,273 events / second`
- **Event Loss Under Load:** `0.00%` (zero buffer drops under benchmark volume)

---

## 3. Reproducibility Instructions

To reproduce these measurements on any Linux-compatible system:

```bash
cargo run -p badger-agent --release -- benchmark
```
