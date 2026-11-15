# M3 results (Blueprint §7)

Workload: 100 application events per run; 5 runs with the interceptor and 5 without, on the same scripted workload.

| Measure | Target | Measured | Result |
| --- | --- | --- | --- |
| Ordinary records, median per event (with interceptor) | under 15 ms | 1.914 ms | met |
| Same events without interceptor, median | — | 0.000180 ms | — |
| Interceptor cost per ordinary event (median with − median without), absolute | — | 1.913 ms | — |
| Anchor points, p50 (10 samples) | reported | 213.252 ms | — |
| Anchor points, p95 (10 samples) | reported | 956.164 ms | — |
| Average record size (exported row) | under 2048 bytes | 470.7 bytes | met |

The cost is reported as an absolute time per event, not as a ratio: the scripted tools are trivial, so the
baseline without the interceptor is close to zero by construction.

Spread of per-run medians: with interceptor 1.631–2.067 ms; without 0.000131–0.000280 ms.
Per-run medians with interceptor (ms): 1.940, 1.782, 1.898, 1.631, 2.067.
Per-run medians without interceptor (ms): 0.000188, 0.000280, 0.000133, 0.000131, 0.000258.

Time-stamp requests during the measurement: freetsa: 10.

| Environment | Value |
| --- | --- |
| Commit | 381e6a530d12b828572d3b33dc054c1cb06d2511 |
| CPU | 11th Gen Intel(R) Core(TM) i5-11300H @ 3.10GHz × 4 |
| Memory | 4 GiB |
| Kernel | Linux 6.6.87.2-microsoft-standard-WSL2 |
| Node.js | v24.22.3 |
| PostgreSQL | 16.15 (Ubuntu 16.15-0ubuntu0.24.04.1) |
| synchronous_commit | on |
| fsync | on |
| full_page_writes | on |
| wal_level | replica |
| Checkpoint filesystem (statfs type) | 0xef53 |
