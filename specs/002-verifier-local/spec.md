# Spec 002 — Verifier: local chain and output

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the test
that proves it.

## 1. Objective

Build `tear-verify` up to Step 1 (local chain) and its canonical output, on top of the Step 1 core from spec
001, so that an exported log with no anchor packages is verified end to end.

## 2. Blueprint sections

§6 (invocation, exit behavior, Step 1), §6b.

## 3. Out of scope

- Step 2, Step 2b and Step 3 with anchor packages, and bundle grammar and loading (§6a) — spec 003.
- The tamper battery (§7 M1) — spec 004.
- SQL export (§5.3) — spec 001.

## 4. Acceptance criteria

| ID | Criterion | Blueprint | Test |
| --- | --- | --- | --- |
| AC-1 | Invocation follows §6; a namespace basename that is not a lowercase UUID, or a missing or unreadable log or namespace, prints `INPUT_UNAVAILABLE 0`, exits 2, with empty stderr; inputs load in the §6b order. | §6, §6b | `002 AC-1 invocation` |
| AC-2 | Framing vectors: zero-byte file, empty row 0, later empty row, missing final LF, BOM, invalid UTF-8; earlier defects keep precedence. | §6 Step 1, §7 (framing vectors) | `002 AC-2 framing` |
| AC-3 | Step 1.1 schema failures report `GENESIS_INVALID 0` at row 0 and `JCS_SCHEMA_INVALID` with the parameter chosen by the Step 1.1 rules at later rows. | §6 Step 1.1 | `002 AC-3 schema` |
| AC-4 | Step 1.2 genesis rules. | §6 Step 1.2 | `002 AC-4 genesis` |
| AC-5 | Step 1.3: genesis digest different from the bundle file digest → `TSA_BUNDLE_MISMATCH 0`. | §6 Step 1.3 | `002 AC-5 bundle-digest` |
| AC-6 | Step 1.4 → `TIME_FORMAT_INVALID <seq>`. | §6 Step 1.4, §4.2 | `002 AC-6 time-format` |
| AC-7 | Step 1.5 → `CHAIN_ID_MISMATCH <seq>`. | §6 Step 1.5 | `002 AC-7 chain-id` |
| AC-8 | Step 1.6 → `SEQ_DUPLICATE` / `SEQ_GAP` with their parameters. | §6 Step 1.6 | `002 AC-8 sequence` |
| AC-9 | Step 1.7 → `TS_REGRESSION <seq>`; ties pass. | §6 Step 1.7 | `002 AC-9 monotonicity` |
| AC-10 | Step 1.8 → `HASH_MISMATCH <seq>`. | §6 Step 1.8 | `002 AC-10 hash` |
| AC-11 | Step 1.9 → `PREV_HASH_MISMATCH <seq>`. | §6 Step 1.9 | `002 AC-11 link` |
| AC-12 | Step 1.10: orphan result, duplicate `call_id` and mismatched `task_id` → `CALL_CORRELATION_INVALID <seq>`; an earlier same-row defect prevails; a matching result closes its call. | §6 Step 1.10, §7 (call pairing) | `002 AC-12 call-pairing` |
| AC-13 | The verifier stops at the first failure in file order and Step 1 rule order. | §6 Step 1 | `002 AC-13 precedence` |
| AC-14 | Valid surrogate pairs are accepted; lone surrogates fail with the location-specific schema error. | §4.3, §7 | `002 AC-14 unicode` |
| AC-15 | On failure stdout is exactly `<CODE> <parameter>`, exit 1, empty stderr. On success the §6b groups appear in order with canonical integers and ranges; outputs are compared byte for byte. | §6b | `002 AC-15 output-format` |
| AC-16 | A valid log with no packages exits 0 with `VALID_UNANCHORED 0..<seq_final>`, one `INCOMPLETE_EXECUTION` line per unmatched `tool_call`, `MAX_ANCHOR_GAP 0` and `ANCHORED_CHECKPOINT_FAILURES 0`. | §6 Step 3, §6b | `002 AC-16 unanchored-success` |
| AC-17 | An export produced by spec 001 passes full offline framing; a physically malformed copy of it fails with its Step 1 framing diagnostic. | §5.3, §7 (SQL versus JSONL) | `002 AC-17 export-framing` |

## 5. Dependencies

Spec 001 (record format, JCS, hashing, Step 1 core, export).

## Implementation choices (not normative)

Recorded here and declared in the report of the work package that implements them.

- **Malformed command line:** a missing, repeated or unknown option is an invocation failure:
  `INPUT_UNAVAILABLE 0`, exit 2 (§6b).
- **Exit 3:** an internal error (an unclassified exception) exits 3 with empty stdout and the reason on stderr.
  Exit 3 is outside the §6b contract and is never a successful verification. Before spec 003, inputs that needed
  anchor verification also exited 3; spec 003 implements Steps 2, 2b and 3, so they no longer do.
- **First-failure placements left open (§10):** as recorded in spec 001; the verifier uses the same rule core.
- **Whitespace in the row envelope:** JSON whitespace around a row's object (spaces, tabs, and CR before the LF)
  is accepted, as RFC 8259 permits. The hash covers the canonical block, so this whitespace does not change the
  verification result. Spec 007 lists it as a known limit.
