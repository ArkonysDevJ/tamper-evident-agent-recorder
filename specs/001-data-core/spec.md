# Spec 001 — Data core

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the test
that proves it.

## 1. Objective

Build the local hash chain: record format and hashing, the Step 1 rule core, namespace provisioning and its
filesystem guard, the three exclusion layers, durable SQL storage, chain initialization (new namespace and
inspection), application append with writer admission, and canonical SQL export.

## 2. Blueprint sections

§4 (4.1–4.5), §5.1, §5.2, §5.3 (except the evidence package), §5.3a, §5.4, §6 Step 1 rules 1.1–1.10 (as a
library over row envelopes).

## 3. Out of scope

- The `tear-verify` CLI, physical JSONL framing and output (§6, §6b) — spec 002.
- Publish, durable delete and the durability barriers (§5.5) — spec 008.
- The anchor trigger and TSA flow (§5.7) — spec 003. This spec only provides the hook (AC-28).
- Anchor package validation (§6 Step 2) — spec 003, consumed through an interface.
- The E1–E10 classifier and start-up reconciliation (§5.6) — spec 006. This spec defines the classifier
  interface that `initializeChain` calls (AC-19).
- `closeChain` (§5.8) and the evidence package (§5.3) — spec 006.
- The agent adapter (§2) — spec 005.

## 4. Acceptance criteria

| ID | Criterion | Blueprint | Test |
| --- | --- | --- | --- |
| AC-1 | `entry_hash` of a block equals the §4.3 derivation; the JCS serializer matches the RFC 8785 test vectors. | §4.3 | `001 AC-1 jcs-and-entry-hash` |
| AC-2 | For each event type, the exact key set is accepted, and an extra key, a missing key, a wrong type or a `null` where not allowed is rejected. | §4.1, §4.4 | `001 AC-2 payload-schemas` |
| AC-3 | Duplicate keys at any depth, NaN/Infinity, and integers that are not safe nonnegative integers are rejected. | §4.1 | `001 AC-3 row-lexical-rules` |
| AC-4 | A lone surrogate is rejected before hashing or `jsonb` insertion; an escaped valid surrogate pair is accepted; U+0000 in a persisted payload string is rejected, and is accepted in transient tool arguments and results. | §4.3, §4.4 | `001 AC-4 unicode-domain` |
| AC-5 | The timestamp grammar and calendar limits accept and reject the §4.2/§5.7 vectors and convert to epoch nanoseconds as specified. | §4.2, §5.7 | `001 AC-5 timestamp-grammar` |
| AC-6 | After genesis, every appended row gets `ts = max(now_ms, ts[head])`; a backwards clock step yields a tie, never a regression. | §4.2 | `001 AC-6 writer-timestamps` |
| AC-7 | `tsa_ca_bundle_sha256`, `args_hmac`, `result_digest` and `response_digest` follow the §4.4 derivations; a textual value is hashed as a JSON string. | §4.4 | `001 AC-7 derivations` |
| AC-8 | Provisioning creates missing levels and fsyncs every parent unconditionally (checked by call order); a writer whose namespace is missing fails `NAMESPACE_NOT_PROVISIONED` before opening PostgreSQL. | §5.1 | `001 AC-8 provisioning` |
| AC-9 | `chain_id` is validated before any path is built; `statfs` accepts only `0xEF53` and `0x58465342` on the root and the namespace. | §5.1 | `001 AC-9 filesystem-guard` |
| AC-10 | A second writer on the same chain aborts at `flock`; the lock file is never deleted, renamed or truncated; its descriptor is not inherited by child processes. | §5.3 layer 1 | `001 AC-10 flock-exclusion` |
| AC-11 | The advisory lock is taken as an autocommit statement before any chain read; `false` aborts without inspecting state. | §5.3 layer 2 | `001 AC-11 advisory-lock` |
| AC-12 | Every chain read and mutation runs on the lock-owning backend (backend identity captured); pooled or secondary mutations, reconnects and prepared transactions are rejected; a successor cannot load or mutate state until the prior backend releases its lock, for both committed and rolled-back in-flight COMMITs. | §5.3, §7 (single-session handoff) | `001 AC-12 single-session` |
| AC-13 | Operations on one chain run in strict FIFO order through one serial queue. | §5.3 layer 3 | `001 AC-13 serial-queue` |
| AC-14 | A non-UTF8 database fails `DATABASE_ENCODING_UNSUPPORTED`, checked before the durability settings. | §5.3, §5.4 | `001 AC-14 encoding` |
| AC-15 | `full_page_writes=off`, `fsync=off`, `wal_level=minimal` or a mutation session without effective `synchronous_commit=on` each fail `DATABASE_DURABILITY_UNSUPPORTED` with no TEAR mutation; settings are rechecked before every mutating transaction; a loss detected after start-up invalidates the writer. | §5.4, §7 (SQL durability) | `001 AC-15 durability-settings` |
| AC-16 | Each isolated mirror discrepancy (payload, ts, prev_hash, seq, chain_id), a noncanonical or malformed `block_json` and a bad `entry_hash` fail `RECONCILIATION_STATE_INCONSISTENT`; a `jsonb` formatting difference with equal decoded values passes. | §5.3, §7 (SQL representation) | `001 AC-16 sql-representation` |
| AC-17 | `initializeChain` on an empty chain and namespace writes genesis and state in one transaction, contacts no TSA, and returns `INITIALIZED` only after a confirmed COMMIT. | §5.3a | `001 AC-17 initialize-new` |
| AC-18 | On an existing chain: an exact retry returns `ALREADY_INITIALIZED` (also when sealed, without changing `chain_closed`); a valid different genesis returns `CHAIN_INITIALIZATION_CONFLICT` before later rows are read; an invalid or mirror-corrupt genesis returns `RECONCILIATION_STATE_INCONSISTENT`; each partial SQL state returns `RECONCILIATION_STATE_INCONSISTENT`. Event rows, state row and namespace bytes are equal before and after every call. | §5.3a, §7 (initialization, inspection precedence) | `001 AC-18 initialize-existing` |
| AC-19 | Inspection calls the E1–E10 classifier through an interface and maps its result to `ALREADY_INITIALIZED`, `RECOVERY_REQUIRED` or `RECONCILIATION_STATE_INCONSISTENT` as §5.3a step 4 states for the active profile, without mutations. Tested here with a stub classifier; the real classifier is spec 006. | §5.3a | `001 AC-19 inspection-mapping` |
| AC-20 | A normal start with neither events nor state fails `CHAIN_NOT_INITIALIZED`, with only one fails `RECONCILIATION_STATE_INCONSISTENT`; an unknown initialization commit outcome returns no success and an exact retry resolves it. | §5.3a | `001 AC-20 startup-without-chain` |
| AC-21 | A candidate row that fails Step 1 rules 1.1–1.10 is rejected with `EVENT_REJECTED <code>`; nothing is committed and the writer stays available (duplicate `call_id`, result without call, empty `task_id`). | §5.4, §7 (writer admission) | `001 AC-21 writer-admission` |
| AC-22 | An append reports success only after a confirmed COMMIT and reports an unknown outcome as such. | §5.4 | `001 AC-22 durable-append` |
| AC-23 | On any `writerConn` error, end or timeout the writer is invalidated, admits no new work, and checks the guard before every mutation. | §5.3 (invalidation barrier) | `001 AC-23 invalidation` |
| AC-24 | Two chains run concurrently without sharing files; inventory and cleanup never leave their own namespace. | §5.2 | `001 AC-24 two-chains` |
| AC-25 | Export reads one read-only REPEATABLE READ snapshot, validates it, and emits the exact §5.3 rows with final LF; any failure leaves no successful partial file. | §5.3 (canonical export) | `001 AC-25 export` |
| AC-26 | Valid SQL tuples pass the logical Step 1 without LF bytes in `block_json`. | §5.3, §7 (SQL versus JSONL) | `001 AC-26 sql-logical-step1` |
| AC-27 | The Step 1 core applies rules 1.1–1.10 in their order to an ordered sequence of row envelopes and returns the first failure with its code and parameter. | §6 Step 1 | `001 AC-27 step1-core` |
| AC-28 | Append calls an anchor hook inside the transaction of each application record; in this spec the hook does nothing. | §5.7 | `001 AC-28 anchor-hook` |

## 5. Dependencies

None.

## Implementation choices (not normative)

The Blueprint leaves these to the implementation (§10). They are recorded here and declared in the report of
the work package that implements them.

- **Invalid `initializeChain` arguments** fail with `INITIALIZATION_ARGUMENT_INVALID`, before any SQL mutation.
- **Operation literals for application events:** `tool_call` and `tool_result` use `execute_tool`;
  `agent_final_response` uses `invoke_agent` (OpenTelemetry GenAI `gen_ai.operation.name` values).
  `epistemic_pause` uses `tear.epistemic_pause` and `human_resolution` uses `tear.human_resolution`, since
  OpenTelemetry defines no equivalent.
- **Cut profile selection:** the writer, the recoverer and `initializeChain` take the profile as a required
  explicit option (`base`, `cut1`, `cut1-2`, `cut1-3`, `cut1-4`), fixed for the life of a writer and never
  read from an environment variable.
