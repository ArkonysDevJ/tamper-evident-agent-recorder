# Spec 005 — Interceptor and overhead (M3)

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the test
that proves it.

## 1. Objective

Wire the write-ahead interceptor between one agent and its tools so that every tool call, epistemic pause
and final answer is durably recorded before it takes effect, and measure the overhead.

## 2. Blueprint sections

§2, §5.4, §7 (M3).

## 3. Out of scope

- The chain, admission and storage themselves (§4, §5.3, §5.4 core) — spec 001.
- Anchoring (§5.7) — spec 003.
- Recovery and close (§5.6, §5.8) — spec 006.

## 4. Acceptance criteria

| ID | Criterion | Blueprint | Test |
| --- | --- | --- | --- |
| AC-1 | A tool runs only after its `tool_call` COMMIT is confirmed; if the write fails or its outcome is unknown, the tool does not run. | §2, §5.4 | `005 AC-1 call-before-tool` |
| AC-2 | A tool result and a final answer are delivered only after their COMMIT is confirmed; with an unknown outcome nothing is delivered. | §2, §5.4 | `005 AC-2 commit-before-delivery` |
| AC-3 | `args_hmac`, `result_digest` and `response_digest` are computed from JSON values at the adapter boundary; a textual value is hashed as a JSON string. | §4.4 | `005 AC-3 adapter-digests` |
| AC-4 | Adapter input outside the RFC 8785 domain fails `ADAPTER_JSON_INVALID` before the tool runs or the answer is delivered. | §4.3 | `005 AC-4 adapter-json-domain` |
| AC-5 | A rejected admission (`EVENT_REJECTED`) runs no tool and delivers nothing; `call_id` values are unique across the whole chain. | §5.4 | `005 AC-5 rejected-admission` |
| AC-6 | If the process dies after a tool ran and before its result was committed, the exported chain verifies with `INCOMPLETE_EXECUTION <call_seq>`, and the tool is not retried automatically. | §3.3 item 7, §6 Step 3 | `005 AC-6 incomplete-execution` |
| AC-7 | The pepper bytes never appear in the database, the export, the namespace or logs. | §5.3a | `005 AC-7 pepper-not-persisted` |
| AC-8 | A run with one agent produces a chain whose export verifies with exit 0. | §2, §6 | `005 AC-8 agent-end-to-end` |
| AC-9 | M3 reports the median latency of ordinary records, p50 and p95 at anchor points separately, and the average record size, each marked as met or not against its target. | §7 (M3) | `005 AC-9 m3-report` |

## 5. Dependencies

Specs 001, 002 and 003.
