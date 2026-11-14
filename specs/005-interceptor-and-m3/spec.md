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
| AC-7 | The pepper is read from the environment variable `TEAR_HMAC_PEPPER`; its bytes never appear in the database, the export, the namespace or logs. Only `pepper_id`, its public identifier, is recorded. A value that is not lowercase hex of at least 64 characters (32 bytes) is rejected before any write (implementation choice below). | §4.4, §5.3a | `005 AC-7 pepper-not-persisted` |
| AC-8 | A run of the reference agent (implementation choice below) produces a chain whose export verifies with exit 0, including one failed tool call. | §2, §6 | `005 AC-8 agent-end-to-end` |
| AC-9 | M3 reports the median latency of ordinary records, p50 and p95 at anchor points separately, and the average record size, each marked as met or not against its target, measured on the workload below with and without the interceptor. | §7 (M3) | `005 AC-9 m3-report` |
| AC-10 | The agent continues after an `epistemic_pause` or a `human_resolution` only once its COMMIT is confirmed (implementation choice below). | §5.4, §10 | `005 AC-10 pause-and-resolution-boundary` |
| AC-11 | When a tool fails, `result_digest` is computed over the error value defined below and `error_type` is non-null (implementation choice below). | §4.4, §10 | `005 AC-11 failed-tool-digest` |

## 5. Dependencies

Specs 001, 002 and 003.

## Implementation choices (not normative)

The Blueprint leaves these to the implementation (§10). They are recorded here and declared in the report of
the work package that implements them.

- **Commit boundary for `epistemic_pause` and `human_resolution`:** the same as for `tool_call`; the agent
  does not continue until the COMMIT is confirmed, and an unknown outcome stops it.
- **`result_digest` when a tool fails:** `result_json_value` is the JSON object
  `{"error_type": <error_type>, "message": <error message as a JSON string>}`, hashed under §4.4.
- **Reference agent:** a minimal scripted agent in TypeScript, with no framework and no LLM, that calls three
  deterministic local tools. One of them always fails, to exercise `result_digest` with an error.
- **M3 workload:** 100 events per run, measured with and without the interceptor; the measured latency is
  reported. If time runs short in this work package, Cut 1 of §8 applies and M3 is reported as unmeasured.
- **Pepper encoding:** `TEAR_HMAC_PEPPER` holds lowercase hex of at least 64 characters (32 bytes). The
  writer decodes it to bytes and rejects any other format.
