# M3 results (Blueprint §7)

Workload: 100 application events per run; 5 runs with the interceptor and 5 without, on the same scripted workload.

| Measure | Target | Measured | Result |
| --- | --- | --- | --- |
| Ordinary records, median per event (with interceptor) | under 15 ms | 1.784 ms | met |
| Same events without interceptor, median | — | 0.000177 ms | — |
| Interceptor cost per ordinary event (median with − median without), absolute | — | 1.784 ms | — |
| Anchor points, p50 (10 samples) | reported | 211.650 ms | — |
| Anchor points, p95 (10 samples) | reported | 1194.550 ms | — |
| Average record size (exported row) | under 2048 bytes | 470.7 bytes | met |

The cost is reported as an absolute time per event, not as a ratio: the scripted tools are trivial, so the
baseline without the interceptor is close to zero by construction.

Spread of per-run medians: with interceptor 1.529–2.151 ms; without 0.000152–0.000306 ms.
Per-run medians with interceptor (ms): 2.148, 1.586, 2.151, 1.799, 1.529.
Per-run medians without interceptor (ms): 0.000172, 0.000153, 0.000154, 0.000306, 0.000152.

Time-stamp requests during the measurement: freetsa: 10.

| Environment | Value |
| --- | --- |
| Commit | b8fa2aca8dd8a8e2b2b50275ae4721d1c3b5304d |
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
