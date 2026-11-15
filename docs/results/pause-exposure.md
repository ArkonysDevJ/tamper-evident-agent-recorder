# Pause exposure window (experiment B)

The dataset is synthetic (experiments/dataset/). The exposure window is a property of the design (an automatic
anchor every 10 application events) measured on this workload; it is not a finding about agents or models.
Expected outcomes were predeclared before measurement (test/experiments/expected.ts).

## B1 · full dataset (1000 steps), offline test TSA

Application events recorded: 1695. Close: ANCHORED_FIRST_ATTEMPT (B2).

- Before close: 125 pauses; highest verified anchor 1880; 125 covered, 0 uncovered.
  - Exposure in events (covered pauses): min 0 · median 5 · max 8 events.
- After closeChain: 125 pauses; highest verified anchor 1883; 125 covered, 0 uncovered.
  - Exposure in events (covered pauses): min 0 · median 5 · max 8 events.

Truncation demonstration (copy of the pre-close export without rows after 1880): tear-verify exit 0; 3 rows and 0 pauses disappeared; output `VERIFIED_ANCHORED 0..1880`.

| Argument class | tool_call records | Mean exported row size | Median latency per tool_call event |
| --- | --- | --- | --- |
| small | 486 | 473.0 bytes | 1.481 ms |
| medium | 177 | 473.0 bytes | 1.451 ms |
| large | 32 | 472.3 bytes | 1.547 ms |

## B2 · first 150 application events, real TSAs (retained order: FreeTSA, then DigiCert on failure)

Application events: 150; rows after close: 168. Close: ANCHORED_FIRST_ATTEMPT. Time-stamp requests: freetsa 17; DigiCert was not used (no primary failure).
Exposure in time can be negative: FreeTSA signs genTime in whole seconds, so a token issued within the same second as the pause carries an earlier genTime (the §5.7 predicate allows down to -5 s).

- Before close: 11 pauses; highest verified anchor 160; 11 covered, 0 uncovered.
  - Exposure in events (covered pauses): min 0 · median 5 · max 8 events.
  - Exposure in time (covered pauses): min -1.428 · median -0.855 · max -0.138 s.
- After closeChain: 11 pauses; highest verified anchor 166; 11 covered, 0 uncovered.
  - Exposure in events (covered pauses): min 0 · median 5 · max 8 events.
  - Exposure in time (covered pauses): min -1.428 · median -0.855 · max -0.138 s.

## Predeclared expectations

| Check | Expected | Measured | Result |
| --- | --- | --- | --- |
| B1 exposure in events before close: min | 0 | 0 | matching |
| B1 exposure in events before close: max | ≤ 9 | 8 | matching |
| B1 exposure after the first anchor: max | ≤ 8 | 8 | matching |
| B1 tail pauses uncovered before close | pauses after the last anchor are uncovered | 0 uncovered, all after 1880 | matching |
| B1 all pauses covered after closeChain | all covered | 125/125 covered (ANCHORED_FIRST_ATTEMPT) | matching |
| B1 truncation: exit code | 0 | 0 | matching |
| B1 truncation: pauses removed = pauses after the last anchor | 0 | 0 | matching |
| B1 tool_call record size spread across argument classes | ≤ 16 bytes | 0.7 bytes | matching |
| B1 tool_call median latency, ~20 KB minus ~100 B | < 1 ms | 0.066 ms | matching |
| B2 exposure in time: lower bound | ≥ -5 s | -1.428 s | matching |
| B2 all pauses covered after closeChain | all covered | 11/11 | matching |
