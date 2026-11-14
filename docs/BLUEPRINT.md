# TEAR — Tamper-Evident Action Recorder

Blueprint v1.3.1 · AI x Epistemics Research Sprint (Apart Research, 13–15 November 2026) · Track 2: Trust Infrastructure

This document says what this repository sets out to build in 48 hours, what the result will and will not prove, and how to check it. It was written before any code. The implementation is measured against it.

## 1. The problem

Activity logs of AI agents are usually mutable and self-reported. The operator who stores them is the same party that may want them to say something else after an incident, and they often contain only what the model chose to declare.

An external auditor reading such a log cannot tell:
- an intact history from a rewritten one;
- a complete history from one whose recent events were cut off.

## 2. What TEAR is

TEAR is a small recorder that sits between an agent and its tools. It makes later tampering with the record evident. It does not make tampering impossible.

It has three parts:
1. An interceptor. Every tool call, every epistemic pause and every final answer is written to the log before the action runs or the answer is delivered. If the write fails, the action does not happen.
2. A hash chain. Each record is hashed with SHA-256 over a canonical JSON envelope (RFC 8785) that includes the hash of the previous record.
3. External anchors. Whenever an application event is committed at a positive physical sequence number seq divisible by 10 (seq % 10 == 0), and when a chain is closed and its last application event is not yet anchored (section 5.8), the current head hash is submitted to an external RFC 3161 Time-Stamp Authority (TSA). A close can end without an anchor: B0, B3 without retry, or a failed attempt. Control events do not trigger automatic anchors. The operator does not hold that authority's private key.
A separate command-line verifier, tear-verify, reads a log and its anchors and reports which part of the chain is backed by external evidence, which part is only locally consistent, and where tampering is detected.

Stack: Node.js 24 (TypeScript), PostgreSQL, one Linux host with a local ext4 or xfs filesystem, OpenSSL ts.

## 3. What it guarantees, and what it does not

### 3.1 Adversaries

| Adversary | Assumed capability | What it attempts | What stops or reveals it |
| --- | --- | --- | --- |
| A1 · The agent | Calls tools, or answers without support | An action or answer that leaves no trace | Write-ahead interceptor with a durable commit before execution |
| A2a · Opportunistic operator | Direct edits to stored records without recomputing hashes | A single edit, interior deletion or insertion | prev_hash, seq, the local hash, and presented anchor commitments |
| A2b · Sophisticated operator | Full database control, chain recomputation, new timestamps | A coherent rewrite of history | RFC 3161 anchors, the time predicate, externally held receipts, and a bundle authenticated by the auditor as in section 3.3, item 9 |



### 3.2 Guarantees

- Against A2a: any edit, interior deletion or insertion made without recomputing the chain breaks the local chain and is detected. Truncating a suffix after the highest externally committed record may preserve a valid local prefix; detecting suffix truncation requires a presented external anchor whose k > seq_final. A retained checkpoint_anchored event whose package is missing is reported only as the informational ANCHOR_EVIDENCE_MISSING with exit code 0: it signals missing evidence, not truncation.
- Both guarantees against A2b below hold only when the auditor runs tear-verify with a --tsa-ca-bundle authenticated as in section 3.3, item 9.
- Against A2b keeping the original timestamps: re-timestamping an old block later violates the time predicate in section 5.7 whenever the new TSA token is issued outside the accepted [-5 s, +60 s] window relative to the block timestamp. A coherent rewrite re-stamped inside that window is not detected by the temporal predicate alone and requires earlier receipts retained outside the operator's control.
- Against A2b shifting timestamps and replacing receipts: detection depends on someone other than the operator keeping the earlier receipts.

### 3.3 Limits, stated up front

1. Unanchored tail. An anchor at k commits records 0..k. Everything after the last valid external anchor can be truncated or rewritten with recomputation without contradicting that anchor. The verifier labels that range VALID_UNANCHORED.
2. Receipt replacement. A TSA is stateless: it signs any digest at the current time. An operator who controls the only copy of the receipts can rewrite the chain, move timestamps to the present and obtain fresh valid receipts. Detecting this needs receipts held outside the operator's control. In this sprint the receipt directory simulates that external custodian.
3. What "anchored" means. VERIFIED_ANCHORED 0..max_k means the prefix is backed by a verified RFC 3161 token whose signed TSTInfo.genTime is the TSA's asserted time for that token. If TSTInfo.accuracy is present, the receipt itself supplies a numeric uncertainty bound and the latest receipt-derived bound is genTime + accuracy (RFC 3161 §2.4.2). If accuracy is absent, the receipt supplies no numeric accuracy bound; the verifier reports the signed genTime with accuracy unspecified rather than importing or guessing a TSA-policy value. This does not mean each event existed at its own ts. Coverage is cumulative. The operational acceptance predicate in section 5.7 evaluates genTime directly.
4. Absent, invalid and insufficient evidence. With no anchor packages present in the namespace, the verifier reports VALID_UNANCHORED, meaning no anchoring evidence was presented. If any presented anchor package is malformed, fails cryptographic verification or contradicts the log, verification fails with a non-zero exit code rather than degrading to VALID_UNANCHORED. If valid packages exist only up to max_k < seq_final, 0..max_k is VERIFIED_ANCHORED and the remainder is VALID_UNANCHORED.
5. Compromised interceptor. If the interceptor is modified before an event is captured, there is no record to protect.
6. Single host. All writers and recoverers of a chain run on the same Linux host and local filesystem.
7. Uncertain external effects. If the process dies after a tool ran and before its result was committed, the verifier reports INCOMPLETE_EXECUTION. Non-idempotent tools are not retried automatically.
8. Not in scope: client-side signing of events, cryptographic authentication of the human reviewer (reviewer_id is declarative), multi-host operation.
9. Root-bundle custody. tear-verify trusts exactly the roots in --tsa-ca-bundle. Step 1.3 checks that the bundle matches the digest declared in the genesis row; that is a consistency check, not authentication, because an operator who rewrites the chain can also rewrite that digest. An operator who supplies both the log and the bundle can create a self-issued root and a time-stamping signer that satisfy TEAR-TSA-01, pin them in the bundle, issue tokens whose genTime falls inside the time window of each original ts, rewrite the genesis digest and obtain VERIFIED_ANCHORED. Every guarantee against A2b therefore requires the auditor to authenticate the bundle independently of the operator, in two parts:
   - At the end of Phase 0, the SHA-256 of the complete bundle file (the same value as tsa_ca_bundle_sha256) is published, before the first anchor, through an authenticated channel that the operator cannot later change, for example a message to the auditor or the event's submission channel; a repository the operator controls does not qualify, since its history can be rewritten. Before relying on any result, the auditor compares the bundle received with that fingerprint. This binds the bundle to the exact signers and intermediates selected in Phase 0: a signature check alone would not, because a root can certify more than one time-stamping signer.
   - When the bundle is first published, each root's fingerprint is checked against the root published by the corresponding TSA, and each pinned signer's subject is checked to name that TSA.
   With a bundle that does not match the published fingerprint, or whose roots and signers were not checked this way, there is no guarantee against A2b.
10. Closing a stale chain. B2 anchors a row that already exists. Acceptance depends only on the token's signed genTime: if it falls more than 60 s after that row's ts, B2 records checkpoint_failed. The host clock at the moment of the call does not decide the outcome. In the base profile, B3 with retry:true then anchors the newer checkpoint_failed row; that retry succeeds only if its own token's genTime falls within the window of that row's ts, and otherwise records another checkpoint_failed. Under Cut 2 no route remains to anchor such a close. When the head is a checkpoint_failed row and max_anchored_seq < last_app_seq, closeChain without retry returns UNANCHORED_FAILURE without contacting a TSA; if application events followed the failure, B2 applies and a TSA is contacted.

11. Scope of what is specified. Edge cases of the formats and protocols this design touches (JSON, X.509, CMS, RFC 3161, POSIX filesystems) cannot all be named, and this document does not claim to. It covers the cases the 48-hour build needs, names the known open ones in section 10, and requires the final report to list what was not tested (section 9). A case that is neither specified nor listed is outside what this project claims.

### 3.4 Relation to existing transparency logs

TEAR is a lightweight sidecar for agent traces, not a global Merkle log. It combines a local chain that can be verified offline with standard RFC 3161 timestamping, and its verifier separates anchored coverage from the unanchored tail.

## 4. Record format

### 4.1 Row

Each line in an exported events.jsonl file is a UTF-8 JSON object terminated by \n (0x0A):
```json
{
  "block": O_i,
  "entry_hash": "<64 lowercase hex chars>"
}
```
Normative rules:
- Top-level keys are exactly "block" and "entry_hash".
- O_i is exactly the object containing "chain_id", "seq", "ts", "prev_hash", "payload".
- Duplicate keys anywhere in the row or nested payload → JCS_SCHEMA_INVALID.
- No NaN, Infinity or -Infinity.
- Integer fields (seq, anchored_seq, target_seq) are JSON numbers satisfying Number.isSafeInteger(x) and x >= 0.
- chain_id is a lowercase canonical UUID string matching ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$.
- entry_hash and prev_hash match ^[0-9a-f]{64}$.
- Genesis is seq = 0 with prev_hash equal to 64 ASCII zeros.

### 4.2 Timestamp O_i.ts

Required format: YYYY-MM-DDTHH:mm:ss.SSSZ.
- Literal Z (UTC), exactly three millisecond digits, valid proleptic Gregorian calendar date and time.
- No offsets and no permissive normalization. Date.parse() is not used as the validator.
- Converted to Unix epoch nanoseconds as BigInt(epoch_ms) * 1_000_000n.
- Invalid format or invalid calendar date → TIME_FORMAT_INVALID, checked before monotonicity.
- Monotonicity is ts[i] >= ts[i-1]; ties are valid.
- Writer timestamp assignment. For every row appended after genesis, application and control events alike (including rows inserted by E7 and E9), the writer sets ts = max(now_ms, ts[physical_head_seq]), where now_ms is the host wall clock truncated to whole milliseconds. A backwards clock step therefore produces a tie, never a regression. genesis_ts follows section 4.2 and is supplied to initializeChain; if it lies ahead of the clock, later rows tie with it. The time predicate in section 5.7 compares a token's genTime with the anchored row's own ts, so a clock or genesis_ts more than 5 s ahead of the TSA, or a clock more than 60 s behind it, makes anchors fail with TSA_TIME_INCONSISTENT, recorded as checkpoint_failed; it never corrupts the chain.

### 4.3 Hash

```text
B_i           = UTF8_ENCODE(JCS_SERIALIZE(O_i))
entry_hash[i] = HEX_LOWER(SHA256(B_i))
```
JCS_SERIALIZE is RFC 8785 canonical serialization. All JSON strings and object property names in rows, anchor packages and transient adapter values MUST contain only Unicode scalar values. An escaped UTF-16 surrogate pair representing a scalar value is permitted; an unpaired surrogate is rejected, never repaired or replaced. Apply this check before hashing or jsonb insertion. In tear-verify, invalid Unicode is a schema failure: GENESIS_INVALID 0 at row 0, JCS_SCHEMA_INVALID with the section 6 Step 1.1 parameter at later rows, and ANCHOR_PACKAGE_INCOMPLETE <k> in package JSON. Adapter inputs outside the RFC 8785 domain fail with ADAPTER_JSON_INVALID before tool execution or response delivery. The additional payload-only U+0000 exclusion in section 4.4 remains distinct.

### 4.4 Event types and normative payload schemas

O_i.payload is a JSON object containing event_type, operation, and the exact additional keys listed below. No extra keys are permitted. operation is always a non-empty string. Nullable fields must be present with null only where explicitly allowed. Every field described as a string is a non-empty JSON string unless the row explicitly permits null. Every string value persisted anywhere inside O_i.payload, including strings nested inside arrays, MUST NOT contain Unicode code point U+0000. This restriction defines the persistable payload domain and is enforced by both writer and verifier. It does not apply to tool arguments or tool results that are only canonicalized transiently to compute args_hmac, result_digest or response_digest and are not persisted as payload strings.

| event_type | Exact additional keys | Normative constraints |
| --- | --- | --- |
| chain_genesis | chain_version, pepper_id, tsa_ca_bundle_sha256 | chain_version literal "1.0.4"; pepper_id non-empty string; tsa_ca_bundle_sha256 <hex64> |
| tool_call | tool_name, call_id, task_id, args_hmac | tool_name, call_id, task_id non-empty strings; args_hmac <hex64> |
| tool_result | call_id, task_id, error_type, result_digest, summary | call_id, task_id, summary non-empty strings; error_type non-empty string or null; result_digest <hex64> |
| epistemic_pause | task_id, reason, missing_sources | task_id, reason non-empty strings; missing_sources JSON array of non-empty strings and may be empty |
| human_resolution | task_id, reviewer_id, decision | all three fields non-empty strings |
| agent_final_response | task_id, response_digest | task_id non-empty string; response_digest <hex64> |
| checkpoint_anchored | anchored_seq, tsr_sha256, tsa_gen_time | anchored_seq safe integer >= 1; tsr_sha256 <hex64>; tsa_gen_time is the exact ASCII TSTInfo.genTime lexical value extracted from the accepted .tsr, without reformatting, trimming or zero normalization |
| checkpoint_failed | target_seq, error_type | target_seq safe integer >= 1; error_type non-empty string |



Event categories:
- chain_genesis is permitted only at seq = 0.
- Application events (tool_call, tool_result, epistemic_pause, human_resolution, agent_final_response) are permitted only at seq >= 1.
- Control events (checkpoint_anchored, checkpoint_failed) are permitted only at seq >= 1.
- Writer operation literals: chain_genesis uses operation="tear.genesis"; checkpoint_anchored and checkpoint_failed both use operation="tear.checkpoint". The verifier's schema check requires only a non-empty string.
Control-event validation boundary. A conforming writer emits each checkpoint control at seq=k+1 for target k. The lexical schema checks in verifier Step 1 do not compare control targets with row position or receipt bytes. Those relational checks occur only after every presented package has passed Step 2, in Step 2b. This ordering is normative, including for renumbered adversarial exports. For checkpoint_anchored, Step 1 validates tsa_gen_time using the valid-calendar UTC grammar in section 5.7; invalid lexical time is JCS_SCHEMA_INVALID, not a TSA token-time error. checkpoint_failed has no tsa_gen_time field.

Cryptographic derivations:
```text
tsa_ca_bundle_sha256 = HEX_LOWER(SHA256(raw_bytes(tsa_roots.pem)))
args_hmac            = HEX_LOWER(HMAC_SHA256(pepper_bytes, UTF8_ENCODE(JCS_SERIALIZE(args_json_value))))
result_digest        = HEX_LOWER(SHA256(UTF8_ENCODE(JCS_SERIALIZE(result_json_value))))
response_digest      = HEX_LOWER(SHA256(UTF8_ENCODE(JCS_SERIALIZE(final_response_json_value))))
tsr_sha256           = HEX_LOWER(SHA256(raw_bytes(<k>.tsr)))
```
args_json_value, result_json_value and final_response_json_value are always JSON values at the adapter boundary. There is no alternate raw-string digest path. A textual result or final response is therefore a JSON string and RFC 8785 serializes it with JSON string quotes and escapes before hashing.

Operation names follow the OpenTelemetry GenAI semantic conventions where one exists.

epistemic_pause is recorded and chained like any other event. This sprint does not measure how reliably an agent emits it.

### 4.5 Anchor package <k>.anchor.json

```json
{
  "anchor_version": "1.0",
  "chain_id": "<uuid>",
  "anchored_seq": 10,
  "entry_hash": "<64 lowercase hex chars>",
  "block": O_k,
  "request_nonce_hex": "<16 lowercase hex chars>",
  "tsq_der_sha256": "<64 lowercase hex chars>"
}
```
Normative rules:
- Exactly the seven keys shown above are present.
- anchor_version is literal "1.0".
- chain_id is lowercase UUID.
- anchored_seq is safe integer k >= 1, matching the filename prefix <k>.
- entry_hash is <hex64>.
- block is exactly O_k.
- request_nonce_hex matches ^[4-7][0-9a-f]{15}$, representing a positive integer in [2^62, 2^63 - 1] and therefore a positive ASN.1 DER INTEGER with exactly 16 lowercase hex characters.
- tsq_der_sha256 is <hex64>.
Offline verification commits chain_id, k, entry_hash, block and the nonce. tsq_der_sha256 is checked for syntax only and is informational; it does not affect cryptographic acceptance.

## 5. Interceptor specification

### 5.1 Namespace provisioning

Each chain owns one directory: --checkpoints/<chain_id>/. It must exist durably before any writer or recoverer starts.

Creating it is the job of a separate provisioning step, never of the writer:
1. Create any missing ancestor, then <chain_id>.
2. For every level, open the parent with O_RDONLY | O_DIRECTORY | O_CLOEXEC, call fsync(parent_dir_fd), and close it in finally.
3. Do the fsync unconditionally, whether or not the entry already existed.
4. Do not start the writer until this completes.
The writer and recoverer do not create the namespace or its ancestors. If it is missing they fail with NAMESPACE_NOT_PROVISIONED before opening PostgreSQL, taking write locks or accepting traffic.

Deployment and start-up filesystem contract:
- Deployment precondition: the checkpoint namespace used by the sprint is on ext4 or xfs. Phase 0 records the effective filesystem as deployment evidence.
- validate chain_id as strict lowercase UUID before building a path;
- run Linux statfs(2) on both the checkpoint root and the effective --checkpoints/<chain_id>/ namespace after provisioning;
- accept runtime f_type only when it is 0xEF53 (the shared ext2/ext3/ext4 family magic) or 0x58465342 (xfs); reject any other magic number, including overlayfs, tmpfs and nfs;
- 0xEF53 is not represented as proof of ext4 specifically. Runtime statfs(2) is a guard against other filesystem families; the ext4-vs-ext2/ext3 distinction remains a deployment precondition evidenced separately.
The sprint does not claim generic bind-mount detection beyond these deterministic checks.

### 5.2 Contents and isolation

```text
--checkpoints/<chain_id>/.writer.lock
--checkpoints/<chain_id>/<k>.tsq
--checkpoints/<chain_id>/<k>.tsr
--checkpoints/<chain_id>/<k>.anchor.json
--checkpoints/<chain_id>/*.tmp
```
- Two chains never share files.
- Inventory, publication and cleanup stay inside the namespace.
- No glob acts on the parent or another chain.
- anchor.chain_id must match the namespace and loaded chain.

### 5.3 Mutual exclusion, serial queue and SQL schema

Layer 1 — flock. Open .writer.lock with O_CREAT | O_RDWR | O_CLOEXEC and call flock(fd, LOCK_EX | LOCK_NB).
- Lock file is never deleted, renamed or truncated.
- Descriptor stays open for the writer's lifetime and is not inherited by child processes.
- EWOULDBLOCK / EAGAIN → abort.
- Node.js core does not expose flock(2); a native binding is required.
Layer 2 — PostgreSQL. After flock:
```sql
SELECT pg_try_advisory_lock(hashtext(chain_id::text));
```
on writerConn, a dedicated TCP session outside the pool. hashtext collision can cause only a spurious refusal to start at this scale.

Single-session SQL invariant. All SQL reads of tear_events/tear_chain_state used to inspect, classify or operate a chain, and ALL mutations of those tables for that chain, execute exclusively on the same writerConn backend session that holds its session advisory lock. This includes initializeChain, recovery state loads/repairs, genesis insertion, application appends, pending updates, checkpoint control transactions and closeChain. Pooled/secondary mutation connections, transaction-pooling proxies, PREPARE TRANSACTION/two-phase prepared transactions, transparent reconnect and backend switching are forbidden. A disconnected writerConn is invalidated, never replaced within the same writer generation. Configuration/session setup and the lock-acquisition query may precede obtaining the advisory lock; loading chain data and beginning any chain mutation may not. Execute the advisory-lock acquisition as an autocommit statement, with no preexisting transaction/data snapshot. Start any subsequent chain inspection or mutation transaction only after successful acquisition so it cannot reuse a pre-lock snapshot. If pg_try_advisory_lock returns false, abort without inspecting chain state or mutating the namespace, and release flock normally.

Keep that session advisory lock for the generation's lifetime. Never explicitly release it while any chain operation or transaction is in flight; do not transfer unfinished work to another connection. On normal shutdown finish or roll back the transaction on writerConn before closing it, and drain filesystem mutations before releasing flock. On timeout, connection loss, unknown COMMIT outcome or process death, a rejected client promise, cancellation request or closed client socket is NOT evidence of server rollback. A successor first obtains flock and the advisory lock on its own fresh writerConn, and only then loads or classifies chain state. Because the only prior mutation backend also owns that advisory lock, its still-running transaction cannot outlive release of the session lock during backend termination. Until the server resolves that transaction and releases its session lock, a successor's lock attempt must fail; it must not bypass the lock or infer rollback from elapsed time.

The independent SQL exporter is the sole read-only exception: it may use its own read-only REPEATABLE READ connection under the export contract below. It never mutates chain data or namespace files, performs recovery, admits application traffic, or supplies its snapshot as the state for a writer/recoverer decision. A writer/recoverer cannot disguise a state load as an export to avoid the single-session invariant. Offline tear-verify uses no SQL connection. Schema provisioning is separate from per-chain operations and does not authorize secondary connections to mutate live chain rows.

Layer 3 — intra-process strict serial FIFO queue. All operations on a chain — application appends, automatic anchoring and closeChain() — execute through one strict serial queue.
- From the commit that sets pending_anchor_seq = k until the durable checkpoint transition clears pending_*, the writer does not begin any other application append or closeChain() transition.
- Subsequent callers wait in the queue, or are rejected if the writer aborts.
- Control events never trigger automatic anchoring, even if their sequence number is a multiple of 10.
PostgreSQL encoding precondition. The database used by TEAR MUST have server_encoding = 'UTF8'. The writer verifies this before accepting traffic and fails closed with DATABASE_ENCODING_UNSUPPORTED if it is not UTF8. Together with the U+0000 exclusion in section 4.4, this makes the public payload-string domain representable by the mandatory jsonb storage.

Tables:
```sql
CREATE TABLE tear_events (
  chain_id    uuid    NOT NULL,
  seq         bigint  NOT NULL,
  ts          text    NOT NULL,
  prev_hash   text    NOT NULL,
  payload     jsonb   NOT NULL,
  block_json  text    NOT NULL,
  entry_hash  text    NOT NULL,
  PRIMARY KEY (chain_id, seq),
  UNIQUE (chain_id, prev_hash)
);
```

```sql
CREATE TABLE tear_chain_state (
  chain_id            uuid        PRIMARY KEY,
  chain_closed        boolean     NOT NULL DEFAULT false,
  pending_anchor_seq  bigint      NULL,
  pending_entry_hash  text        NULL,
  pending_ts          text        NULL,
  pending_mode        text        NULL
);
```
writer_epoch is not part of this specification.

SQL representation authority and consistency. block_json is the authoritative serialized O_i; entry_hash is its stored commitment. The SQL columns chain_id, seq, ts, prev_hash and payload are mandatory indexed/typed mirrors, not independent sources of protocol truth. Every inserted row persists all mirrors, block_json=JCS_SERIALIZE(O_i), and entry_hash=HEX_LOWER(SHA256(UTF8_ENCODE(block_json))) together in the same durable SQL transaction.

For each loaded SQL row, strictly parse block_json under section 4 (including duplicate-key and Unicode rejection), require byte equality with its RFC 8785 reserialization, and verify entry_hash. Compare SQL chain_id with parsed block.chain_id as the same UUID, and SQL seq with block.seq as the same exact safe nonnegative integer (decode bigint without floating-point rounding). Require SQL ts and prev_hash to equal the respective strings exactly. Require SQL payload to be the same JSON value as block.payload, comparing RFC 8785 serializations of the decoded values, never the textual rendering of jsonb. Validate the mirrored payload under the same schema and Unicode domain; no silent replacement or repair is permitted. The primary-key/order columns are usable as protocol indices only after this correspondence is validated.

Any invalid canonical row, wrong commitment, missing mirror or mirror discrepancy is RECONCILIATION_STATE_INCONSISTENT for initialization inspection, writer/recoverer and SQL export. Do not silently prefer a valid-looking copy, regenerate a hash or overwrite a column. On startup and before admitting traffic, validate all loaded rows before using them for chain/head/pending decisions or any recovery mutation. A continuing conforming writer maintains the invariant on every append; direct SQL changes by other actors during its locked operation are outside the conforming-writer precondition. Adversarial SQL states presented to a subsequent inspection/recovery are checked and rejected as specified.

initializeChain applies this SQL-row check to genesis in inspection step 1, before its valid-genesis comparison; later rows are checked in step 2, preserving the published precedence of a valid different genesis over a later corruption. A mirror-corrupt genesis is inconsistent, not a valid conflicting genesis. Normal reconciliation applies the check in section 5.6 step 1 before any cleanup.

Canonical log export (SQL → events.jsonl):
```sql
SELECT block_json, entry_hash
FROM tear_events
WHERE chain_id = $1
ORDER BY seq ASC;
```
For each row emit exactly:
{"block":<block_json>,"entry_hash":"<entry_hash>"}\n
where block_json is the exact RFC 8785 canonical string persisted at write time. The exporter first loads every column needed for the SQL representation check in one read-only REPEATABLE READ transaction for this chain, validates the complete snapshot, and emits no output rows unless it passes that check and section 6 Step 1. The SELECT above describes the final projection and order from that validated snapshot, not permission to bypass mirror checks or reread a newer snapshot. Export failure emits no partial events.jsonl and returns RECONCILIATION_STATE_INCONSISTENT for a representation/chain violation; input/connection failure aborts export without a successful artifact. The standalone offline verifier receives only exported canonical rows, so its stages and diagnostics are unchanged; it cannot inspect SQL columns that were not supplied.

Evidence package for offline verification. To produce a consistent pair of events.jsonl and namespace copy while a writer may be running:
1. Copy from --checkpoints/<chain_id>/ only complete pairs <k>.tsr + <k>.anchor.json. Skip .writer.lock, every .tsq and every .tmp, and skip a .tsr whose .anchor.json is not yet present.
2. Only then run the SQL export above.
Every published package belongs to a row k that was committed before the package was written (the pending anchor is set in the same transaction as row k), so every copied package's row is in the later export. A control row whose package was published after step 1 is reported as the informational ANCHOR_EVIDENCE_MISSING, exit 0. With the writer stopped the same filter in step 1 still applies, because a writer that stopped by crashing can leave .tsq and .tmp files behind. Any other order may report an honest export as TRUNCATED_BELOW_ANCHOR or ANCHOR_PACKAGE_INCOMPLETE.

Invalidation and mutation barrier. On any error, end or timeout of writerConn, set writerInvalidated = true immediately and stop admitting new work. Every filesystem-mutating operation (publish, rename, durable delete, cleanup) and every SQL commit in writer/recoverer/initializeChain checks writerInvalidated == false and a connected writerConn before beginning the mutating operation. All filesystem mutations for the chain execute on the same strict serial queue and are tracked until completion. The single-session invariant above governs all SQL work even during invalidation. Closing a client session does not establish the outcome of an uncertain transaction; the successor resolves it only after acquiring both locks. If invalidation occurs while a filesystem syscall/libuv operation is already in flight, the process keeps flock held, admits no successor mutation, waits for every already-started mutation and continuation to settle, then closes writerConn, releases flock, and exits. A second writer therefore cannot acquire flock while the invalidated writer can still complete a namespace mutation.

SQL application of section 6 Step 1. At the validation points specified by initialization, reconciliation and export, check the SQL representation invariant above and apply Step 1 to the ordered in-memory sequence of canonical row envelopes built from block_json and entry_hash, with expected_seq equal to the zero-based row index. Apply all schema, genesis, bundle, time, identity, sequence, hash, link and call-pairing rules. The existing-chain inspection order in section 5.3a remains controlling: its step 1 checks only the stored genesis and its mirrors before the requested-genesis comparison; full-chain/mirror/Step 1 validation occurs only at its step 2 after genesis equality. This SQL adaptation does not introduce a pre-scan of later rows before that comparison. Do not apply physical JSONL byte framing (BOM, LF, empty physical line, final LF or EOF) to SQL tuples. A zero-row ordinary chain has the initialization/startup outcome specified in section 5.3a; it is not an accepted empty genesis. These online failures map to RECONCILIATION_STATE_INCONSISTENT as specified for their operation. The actual exported events.jsonl still must obey every section 4.1/section 6 framing rule and must pass standalone Step 1; skipping SQL byte-framing checks does not relax the export or offline format.

### 5.3a Chain initialization

The namespace provisioner only creates durable directories. A separate public initializeChain operation creates SQL genesis and state; ordinary start-up never implicitly creates either. All initialization, inspection and retries first satisfy sections 5.1, 5.3 and 5.4, including both locks, the queue and database encoding. No application traffic is admitted during initialization.

initializeChain takes chain_id, genesis_ts (section 4.2), pepper_id, and the pinned bundle bytes (section 6a). Validate these inputs before SQL mutation. The pepper bytes must be available to the writer under pepper_id; they are never persisted or exported. Build O_0 with prev_hash=64 zeros, operation="tear.genesis", event_type="chain_genesis", chain_version="1.0.4", pepper_id and the digest of the supplied bundle. Persist its JCS block_json and hash, plus tear_chain_state with chain_closed=false and all four pending_* fields NULL, in one durable SQL transaction. No TSA call is made for genesis.

Under exclusion, exactly these cases apply:
- No event rows and no state row, and namespace empty except .writer.lock: create atomically as above; return INITIALIZED only after confirmed COMMIT.
- Both exist: run only the ordered existing-chain inspection below. Do not execute section 5.6 cleanup, repair, durability barriers or TSA flow inside initializeChain. ALREADY_INITIALIZED, RECOVERY_REQUIRED, CHAIN_INITIALIZATION_CONFLICT and RECONCILIATION_STATE_INCONSISTENT in this branch are non-mutating outcomes, even if subsequent events exist or the chain is sealed.
- Exactly one exists, events exist without a genesis, or an uninitialized namespace contains any other entry: fail with RECONCILIATION_STATE_INCONSISTENT; do not repair by synthesizing genesis or state.

Existing-chain inspection (normative order):
1. Validate the stored genesis row on its own: section 4 envelope/payload/Unicode and timestamp rules, seq=0, zero prev_hash, chain_version="1.0.4", chain identity equal to the namespace, and its recomputed JCS hash. This check uses the stored bundle digest as data, not the requested bundle as an equality test. Missing or invalid stored genesis fails RECONCILIATION_STATE_INCONSISTENT. If valid, compare JCS(stored O_0) with JCS(requested O_0). A difference returns CHAIN_INITIALIZATION_CONFLICT immediately, before inspecting later rows, state contents or residue. Thus a valid different genesis has priority over a later corruption or recoverable residue; an invalid genesis never becomes an initialization conflict. Invocation preconditions and input validation still precede this comparison.
2. With identical genesis, read and validate the full existing chain using section 6 Step 1 and the state invariants below. Inventory the namespace using section 5.6 step 2's permitted names/types, but do not delete or synchronize anything. Invalid chain/state, unreadable required inputs, unknown names or disallowed entry types fail RECONCILIATION_STATE_INCONSISTENT. Validate all non-pending committed packages and bidirectional success-control correspondence as required by section 5.6 step 3, plus the applicable Step 2b control relations; any contradiction fails RECONCILIATION_STATE_INCONSISTENT. This is a writer-side inspection, not an invocation of tear-verify's offline inventory on .tsq/.tmp files. A pending partial/invalid package is classified by E8/E9 rather than rejected merely because that package alone would fail offline verification; committed non-pending invalid/missing evidence is never treated as repairable.
3. In memory only, form a view excluding the recognized regular temporary files that section 5.6 step 2 would delete. Retain the actual SQL rows, pending fields, requests and package files without modification. Classify this view using section 5.6 steps 3–5 and E1–E10 conditions only, not their actions. Use one captured now_ns for E8/E9 classification. A view matching E3, E6 or E10, or failing the preceding validation, is RECONCILIATION_STATE_INCONSISTENT even when temporary files are present. A .tmp file alone cannot establish recoverability. For E4/E5, validate the already present control relations; for E7–E9 do not demand a not-yet-created control at k+1. Never simulate a successful repair by inserting a control into the inspected chain.
4. If the actual namespace has no .tmp and the validated view is clean E1, return ALREADY_INITIALIZED. If the active profile permits automatic recovery and the validated view is E2, E4, E5, E7, E8 or E9, or is E1 with recognized .tmp files excluded from the view, return RECOVERY_REQUIRED without mutations. This result means that the contract authorizes a separate recovery attempt, not that future I/O, TSA access or recovery will succeed. With Cut 3 active, any .tmp, .tsq, pending state or non-clean-E1 view instead fails RECONCILIATION_STATE_INCONSISTENT; RECOVERY_REQUIRED is never returned under Cut 3. All other cases fail RECONCILIATION_STATE_INCONSISTENT.

RECOVERY_REQUIRED admits no application traffic and performs no automatic retry or repair. Release the inspection's locks/session normally. The caller must start the section 5.6 writer/recoverer separately under fresh exclusion, then may repeat initializeChain with identical inputs. Following a successful recovery to clean E1, that repetition returns ALREADY_INITIALIZED; a failed recovery remains a failure and is not reported as successful initialization. initializeChain never calls itself from reconciliation and reconciliation never invokes initializeChain to repair existing state.

Non-mutation here protects tear_events, tear_chain_state, genesis/timestamps, receipt/request/temporary-file bytes and namespace entries other than the control lock file. Normal lock acquisition/session setup/release remains governed by section 5.3; creating .writer.lock if absent is its explicit control-file exception, not evidence cleanup. Reads may update operating-system access metadata; the guarantee does not cover atime or transient OS/SQL lock bookkeeping. After acquiring exclusion, perform no insert/update/delete transaction, rename, unlink, publication, truncation, recovery fsync or network TSA request in the existing-chain branch, on any return path. Read/connection failures invalidate and abort under the existing barrier without cleanup. The genuinely new-chain branch retains its atomic initialization write.

An unknown initialization commit outcome invalidates the writer and returns no success; a caller retries the exact same inputs under fresh locks, resolving to one of the cases above. A normal start with neither events nor state fails CHAIN_NOT_INITIALIZED; with only one, it fails RECONCILIATION_STATE_INCONSISTENT. closeChain and application appends require an initialized chain.

The state row has all pending fields NULL together, or all non-NULL together with a safe positive pending_anchor_seq, hex64 pending_entry_hash, valid pending_ts, and pending_mode in {"auto","close","close_retry"}. A pending target must exist and its hash/time equal pending_entry_hash/pending_ts. pending_mode="close" or "close_retry" requires chain_closed=true. Violation fails reconciliation. Cut 2 retires close_retry for newly initiated operations; Cut 3 rejects any pending state.

### 5.4 Durable commit boundary

Mandatory SQL configuration: synchronous_commit = on for every mutating transaction on the exclusively authorized writerConn; server fsync = on, full_page_writes = on, wal_level in {replica, logical}; database server_encoding = UTF8. There is no implicit alternative to full_page_writes in this sprint contract. Before initialization, existing-chain inspection or recovery, and before accepting traffic, read effective settings from PostgreSQL and verify these requirements. Each newly created writerConn sets synchronous_commit=on and verifies its effective value before beginning mutating work; no mutation connection is acquired from a pool; transaction-local or role/database defaults must not override it. Recheck the effective durability settings before each mutating transaction. Missing/unreadable settings or a mismatch in the durability requirements fail closed with DATABASE_DURABILITY_UNSUPPORTED before that transaction performs TEAR writes or initiates recovery filesystem mutations. The independently specified encoding failure retains DATABASE_ENCODING_UNSUPPORTED; check encoding before the durability tuple if both fail. Inspection may query settings without changing persistent TEAR data.

These settings are deployment invariants throughout operation and crash recovery, not values a writer changes globally to repair an unsupported server. An observed loss of a requirement after startup invalidates the writer under section 5.3, admits no further mutation and drains existing operations before exit. Configuration must not be changed incompatibly while a conforming deployment is active. Phase 0 records the effective values and storage assumptions. PostgreSQL's WAL and full-page protection require the underlying storage stack to honor successful flush/synchronization requests and their ordering; the checkpoint filesystem has the corresponding dependency. Neither a configuration query nor call-order tests prove device/controller power-loss behavior. The guarantee is conditional on those deployment preconditions and does not survive an adversary disabling them during operation.
- tool_call needs a confirmed COMMIT before the tool runs. Unknown commit outcome → do not run; abort and reconcile.
- tool_result and agent_final_response need a confirmed COMMIT before delivery. Unknown outcome → do not deliver.
- Checkpoint events and clearing of pending_* happen in one atomic transaction.

Writer admission before commit. Before committing any row, the writer validates the candidate row against section 6 Step 1 rules 1.1 to 1.10, applied to the committed chain (held since start-up) extended by that row; this includes call_id uniqueness and call/result pairing. A candidate that fails is rejected with EVENT_REJECTED <code>, where <code> is the Step 1 diagnostic the verifier would emit for that row. Nothing is committed, the tool is not run and nothing is delivered; the chain is unchanged and the writer remains available. Adapters must therefore supply call_id values that are unique across the whole chain, not per turn.

### 5.5 Publishing and deleting files inside the namespace

Every operation in this section is a filesystem mutation governed by the invalidation barrier in section 5.3. The guard is checked before the operation begins; cleanup and durable deletes are not exempt.

Publish <name>:
1. open(<name>.tmp, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC)
2. write
3. fsync(file_fd)
4. close
5. rename(<name>.tmp, <name>)
6. open chain directory with O_RDONLY | O_DIRECTORY | O_CLOEXEC
7. fsync(dir_fd)
8. close in finally
Durable delete:
1. unlink each target (ignore ENOENT only where explicitly allowed)
2. open chain directory
3. fsync(dir_fd)
4. close in finally
This makes entries durable inside an already-provisioned namespace and does not replace section 5.1.

Recovered-package durability barrier. Before recovery confirms or retains a checkpoint success (E4 or E7), open each recovered .tsr and .anchor.json as a regular file without following symlinks, fsync each file, close in finally, then fsync the chain directory and close in finally. All calls are guarded by section 5.3. Only a successful barrier permits the SQL success transition; a failure aborts without clearing pending or admitting traffic. A readable, cryptographically valid filename alone is not proof of durable publication.

Mutation failures. Any filesystem mutation failure, including an unlink, file fsync, rename, directory fsync or close error, invalidates the writer, stops the queue and invokes the section 5.3 drain-and-exit protocol. Do not continue to another application append or another anchor and do not report success. This includes publication that may have become visible but whose durability is unknown. Keep the SQL pending state unchanged if its resolution transaction has not already committed, and leave residue for inspection/recovery. No cleanup is initiated after invalidation. With Cut 3, these states require operator intervention rather than automatic repair. ENOENT is ignored only for an explicitly optional cleanup target; other errors are never ignored.

### 5.6 Start-up reconciliation

Preconditions: namespace provisioned, flock held, advisory lock held.

Before accepting traffic:
1. Require both genesis/events and the state row as in section 5.3a; load state and every event column under exclusion, validate section 5.3 SQL representation consistency and the state invariants, and run section 6 Step 1. Invalid input fails RECONCILIATION_STATE_INCONSISTENT.
2. Inventory only this namespace, ignoring .writer.lock. Every other entry must be a regular file by lstat without following symlinks. Only canonical positive-decimal <m>.tsq, <m>.tsr, <m>.anchor.json and temporary files produced by section 5.5 (<m>.tsq.tmp, <m>.tsr.tmp, <m>.anchor.json.tmp) are allowed. Unknown names or entry types fail closed. In the base profile durably delete these temporary files before state selection; do not pre-delete .tsq. Cut 3 disables every deletion and rejects all .tmp/.tsq.
3. Let h=physical_head_seq and pending=pending_anchor_seq. For every m other than pending with either .tsr or .anchor.json present, require both files, full section 6 Step 2 validation against the committed log, and an exact matching checkpoint_anchored at m+1, including receipt digest and lexical genTime. Conversely, every committed checkpoint_anchored outside the pending transition must have its complete valid package on disk. Missing confirmed evidence is RECONCILIATION_STATE_INCONSISTENT in the writer/recoverer, including Cut 3. This is intentionally stricter than the offline verifier's X1 evidence-absence policy; no log or missing receipt is silently regenerated.
4. A confirmed foreign package means a valid pair for m != pending with the matching committed control at m+1. Such a pair is permitted and is not residue. After step 2 cleanup, foreign residue for a pending k means any entry other than .writer.lock, confirmed foreign packages, and the optional k.tsq/k.tsr/k.anchor.json. A .tsq for m != k is foreign residue even if a control for m is committed. Fail closed rather than deleting it speculatively. With no pending, exactly one resolved .tsq may be removed only by E2; multiple requests fail E3. No conforming writer advances past a failed request deletion: section 5.5 aborts it, and the next start resolves E2 before traffic.
5. Apply exactly one mutually exclusive state below. In this table a valid pending package means that both files pass section 6 Step 2 for k, including the temporal predicate against its target row. When a control already exists, its fields must also agree. Full relational control checks from Step 2b are required before successful completion, after any authorized repair.

| State | Mutually exclusive condition | Action |
| --- | --- | --- |
| E1 | pending IS NULL and no .tsq exists; all .tsr/.anchor.json on disk are confirmed valid committed packages | reconciled |
| E2 | pending IS NULL, exactly one <k>.tsq exists, h >= k+1, and record k+1 is a confirmed checkpoint_anchored(anchored_seq=k) or checkpoint_failed(target_seq=k) | durable-delete <k>.tsq; reconciled |
| E3 | pending IS NULL and not E1/E2, including unconfirmed residue, multiple .tsq, or committed-package contradiction | fail closed |
| E4 | pending=k, h=k+1, record k+1 is checkpoint_anchored(anchored_seq=k), package <k> is valid, and no foreign residue | run recovered-package durability barrier; clear pending_*; durable-delete <k>.tsq if present; reconciled |
| E5 | pending=k, h=k+1, record k+1 is checkpoint_failed(target_seq=k), and no foreign residue | durable-delete residue for k; clear pending_*; reconciled |
| E6 | pending=k, h=k+1, and neither E4 nor E5 holds, or foreign residue contradicts the pending transition | fail closed |
| E7 | pending=k, h=k, no foreign residue, and <k>.tsr + <k>.anchor.json form a complete valid package | run recovered-package durability barrier; insert checkpoint_anchored at k+1 and clear pending_* in one durable transaction; durable-delete <k>.tsq if present; reconciled |
| E8 | pending=k, h=k, no foreign residue, package missing/partial/invalid, and now_ns - pending_ts_ns <= 60_000_000_000n | durable-delete any <k>.tsq/.tsr/.anchor.json; repeat full TSA flow with a fresh nonce |
| E9 | same as E8 except now_ns - pending_ts_ns > 60_000_000_000n | durable-delete residue; insert checkpoint_failed(target_seq=k, error_type="anchor_window_expired") at k+1 and clear pending_* |
| E10 | anything not matched by E1–E9, including h < k, h > k+1, unknown file extensions, multiple foreign residues or DB/FS contradiction | fail closed with RECONCILIATION_STATE_INCONSISTENT |



Under this specification's writer, the checkpoint event and clearing of pending_* are one atomic SQL transaction. Therefore E4/E5 are defensive compatibility states, not ordinary outcomes of a conforming transaction: a confirmed atomic transition normally has pending IS NULL and is handled by E1/E2; a rolled-back transition retains pending=k and, when a complete package exists, is handled by E7. E4/E5 remain defined only to recover a coherent legacy/non-conforming residue rather than accepting it ambiguously.

Any filesystem or SQL error during an E2–E9 repair aborts recovery without accepting traffic.

Reconciliation succeeds only when pending_anchor_seq IS NULL, no .tmp or .tsq remains, every .tsr has a valid matching .anchor.json, and the local chain is valid. Before accepting traffic from any reconciled state, including E1, open the chain directory with O_RDONLY | O_DIRECTORY | O_CLOEXEC, fsync it and close it, under exclusion. This makes durable any earlier deletion whose directory fsync did not complete before a crash. If the barrier fails, start-up aborts without accepting traffic. Then chain_closed == false → accept application events; chain_closed == true → refuse application events with CHAIN_SEALED but keep the initialized writer available for explicit closeChain calls. No start-up close retry occurs automatically.

### 5.7 Anchoring with RFC 3161

Indexes:
- physical_head_seq: highest seq in tear_events (-1 if empty).
- last_app_seq: highest application-event seq (0 when only genesis exists).
- max_anchored_seq: highest anchored_seq referenced by a committed checkpoint_anchored (-1 when no anchors exist).
Automatic anchor trigger. Trigger only when committing an application event at seq = k where k > 0, k % 10 == 0, and k <= max_auto_anchor_seq (Infinity in production). Control events never trigger automatic anchors.

In the same SQL transaction as application record k:
pending_anchor_seq = k
pending_entry_hash = entry_hash[k]
pending_ts         = ts[k]
pending_mode       = "auto"
Because the per-chain queue is strict and serial, the writer immediately resolves that pending anchor before admitting another event.

Time rules:
- Network timeout: 5000 ms per TSA, separate from the acceptance predicate.
- TSTInfo.genTime must be valid UTC ASN.1 GeneralizedTime matching ^[0-9]{14}(\.[0-9]{1,9})?Z$, with a valid Gregorian date/time, years 0001..9999, seconds 00..59 and no leap-second normalization. Normalize to BigInt Unix nanoseconds by right-padding a present fraction to nine digits. No fraction means zero nanoseconds. No offsets, comma or empty fraction are accepted. The same calendar/year/second limits apply to O_i.ts. This profile does not accept leap-second tokens.
- Syntax error → TSA_TIME_FORMAT_INVALID.
- Acceptance predicate is inclusive:
-5_000_000_000n <= t_tsa_ns - t_block_ns <= 60_000_000_000n
Outside it → TSA_TIME_INCONSISTENT.

TSA flow for anchor k:
1. Nonce and request. Generate 8 random bytes via CSPRNG and force buf[0] = (buf[0] & 0x3f) | 0x40, so the big-endian integer lies in [2^62, 2^63 - 1]. Format as 16 lowercase hex chars (request_nonce_hex). Build the DER RFC 3161 TimeStampReq explicitly with version = 1, certReq = TRUE, SHA-256 OID 2.16.840.1.101.3.4.2.1, hashedMessage = HEX_DECODE(entry_hash[k]) (exactly 32 raw bytes), and nonce INTEGER(0x<request_nonce_hex>). The implementation contract is the ASN.1/DER structure just stated; no OpenSSL CLI flag is normative for injecting the nonce. Compute tsq_der_sha256 = HEX_LOWER(SHA256(tsq_der_bytes)); publish <k>.tsq durably.
2. Network and fallback. Retained TSAs: Phase 0 tests the intended TSAs in this order, freetsa.org then timestamp.digicert.com, and retains each one whose live responses and certificates pass TEAR-TSA-01; the bundle pins exactly the retained TSAs (section 6a). The first retained TSA is the primary and the other, if any, the secondary. If only one passes, the deployment runs with that one as under Cut 4. If none passes, no anchor can be produced: the frozen M1 fixture cannot be built with real receipts, phase 1 stops at that point and the final report states it; a test-only TSA must not be substituted into the deliverable fixture. POST the .tsq to the primary. The primary attempt fails when the request times out, the HTTP status is not 200, the body is not a decodable TimeStampResp, PKIStatus is not GRANTED or GRANTED_WITH_MODS, or any step 3 validation fails, including TSA_TIME_INCONSISTENT. Any such failure sends the same .tsq to the secondary, whose response is validated by the same step 3. Step 5 applies only after the last retained TSA has failed; under Cut 4 the primary is the last retained TSA. Writer invalidation, filesystem errors and SQL errors are not TSA failures and never trigger fallback.
3. Validation. Require writer still active; status GRANTED or GRANTED_WITH_MODS; parse a valid UTC TSTInfo.genTime; CMS signature valid; X.509 path valid under the pinned profile of section 6a; leaf certificate with critical timeStamping EKU; MessageImprint.hashAlgorithm == SHA-256; hashedMessage == HEX_DECODE(entry_hash[k]); nonce equality; and the time predicate.
4. On success. Publish <k>.tsr; publish <k>.anchor.json; in one durable SQL transaction insert checkpoint_anchored at k+1 and clear pending_*; durable-delete <k>.tsq.
5. On failure of the last retained TSA, before package publication. In one durable SQL transaction insert checkpoint_failed(target_seq=k) at k+1 and clear pending_*; durable-delete <k>.tsq. checkpoint_failed.error_type is an open descriptive vocabulary: any non-empty string satisfying the section 4 payload domain is valid, and tear-verify imposes no closed catalogue, case convention or additional length limit. Writers may use categories such as "tsa_unreachable", "tsa_rejected" or "tsa_validation_failed"; these examples are not required literals. The fixed "anchor_window_expired" in E9 and "tsa_timeout" in the T7 mutation remain required at those specified sites. This freedom does not change the transition, recovery or verifier diagnostic selected for a failure. Filesystem and SQL failures follow their abort rules rather than this TSA-failure continuation branch.
6. Publication / commit failure. If any filesystem mutation fails at any stage, follow section 5.5: invalidate, drain and exit without a new SQL resolution or cleanup. This includes a complete visible package whose directory fsync did not finish, a partial package, and a failed .tsq deletion after an already-confirmed SQL transition. If both files were durably published but the atomic checkpoint_anchored/clear-pending transaction fails or has unknown outcome, likewise invalidate and exit without deleting the package. On the next start, rollback leaves pending=k and a complete valid package for E7 (including its durability barrier); commit leaves pending=NULL and E2 removes one residual request, otherwise E1 applies. Partial/invalid packages use E8/E9 if the base recovery preconditions hold. E4/E5 are defensive states, not normal outcomes of this atomic transaction. No filesystem failure is reclassified as a TSA failure permitting continued traffic.
If both TSAs fail, the agent may continue after recording checkpoint_failed; the unanchored tail grows until a later successful anchor.

### 5.8 Closing a chain: closeChain({ retry?: boolean })

closeChain() is enqueued on the chain's serial FIFO queue and waits for any active pending anchor to finish. Every explicit close first sets chain_closed = true durably (or confirms that it is already true). From that commit on, application events are refused with CHAIN_SEALED.
Calling closeChain on an already sealed chain is permitted; CHAIN_SEALED applies to application appends, not idempotent close or an explicit retry. After reconciliation, B0–B3 are evaluated again. ANCHORED_* reports a committed anchoring transition with its package confirmed available at the latest reconciliation/publication boundary; it is not a promise that evidence cannot subsequently be deleted. Such loss is diagnosed by the offline verifier and blocks the next writer reconciliation. Namespace contents must not be modified by other actors while a conforming writer holds the lock; adversarial changes to a copied export are handled by tear-verify.


| Branch | Condition (with pending_anchor_seq IS NULL) | Result |
| --- | --- | --- |
| B0 | only genesis: physical_head_seq == 0, last_app_seq == 0, max_anchored_seq == -1 | no TSA call; CLOSED_NO_ANCHOR; coverage VALID_UNANCHORED 0..0 |
| B1 | physical_head_seq > 0 and max_anchored_seq >= last_app_seq | no TSA call; if the record at seq = max_anchored_seq has event_type == "checkpoint_failed", return ANCHORED_AFTER_PREVIOUS_FAILURE; otherwise ANCHORED_FIRST_ATTEMPT |
| B2 | max_anchored_seq < last_app_seq and head is not checkpoint_failed | set pending at k = physical_head_seq, mode "close"; run TSA flow; success → checkpoint_anchored(k+1, anchored_seq=k) and ANCHORED_FIRST_ATTEMPT; failure → checkpoint_failed(k+1,target_seq=k) and UNANCHORED_FAILURE |
| B3 | max_anchored_seq < last_app_seq and head h = physical_head_seq is checkpoint_failed | without retry:true → UNANCHORED_FAILURE; with retry → set pending at h, mode "close_retry"; success → checkpoint_anchored(h+1, anchored_seq=h) and ANCHORED_AFTER_PREVIOUS_FAILURE; failure, including TSA_TIME_INCONSISTENT, → checkpoint_failed(h+1,target_seq=h) and UNANCHORED_FAILURE |



B3 anchors h, not last_app_seq. Because O_h hashes the entire prefix 0..h, anchoring h commits all prior application records while using the fresher ts[h]. Temporal acceptance is determined exclusively by the signed TSTInfo.genTime against ts[h] using the section 5.7 predicate. The 5000 ms network timeout is a separate transport bound and does not create a local completion deadline relative to ts[h]. A retry may finish after ts[h] + 60 s and still be accepted if the TSA signed the token with genTime <= ts[h] + 60 s and the response otherwise satisfies the network timeout; a token whose signed genTime is outside the predicate fails with TSA_TIME_INCONSISTENT.

## 6. The verifier: tear-verify

```text
tear-verify \
  --log events.jsonl \
  --checkpoints ./tsr_receipts/<chain_id>/ \
  --tsa-ca-bundle ./certs/tsa_roots.pem
```
--checkpoints must be the chain's own namespace and its directory basename is the expected lowercase UUID chain id.

Exit behavior:
- Any Step 1, Step 2 or Step 2b failure prints the primary code (with sequence parameter where applicable) and exits 1.
- If Steps 1, 2 and 2b succeed, Step 3 coverage and informational warnings are printed and exit code is 0.

#### Step 1 — local chain

The file is one or more LF-terminated physical rows. A single final LF terminates the last row and does not create another row; an additional LF is an empty row. Scan in file order, without a pre-scan for later empty rows. A zero-byte file or empty physical row 0 → GENESIS_INVALID 0. A later empty row fails Step 1.1 with JCS_SCHEMA_INVALID <expected_seq>. A nonempty last row lacking its required LF is a schema failure at that row, with the Step 1.1 parameter rules; earlier failures retain precedence. No UTF-8 BOM is permitted. UTF-8 decoding is strict, never replacement-based.

Rows are scanned in file order with expected_seq = index. The verifier stops at the first failure. Exact precedence:
1. JSON / outer-envelope schema. UTF-8 JSON object; no duplicate keys; exact row keys; entry_hash <hex64>; exact O_i keys and payload schema, including the section 4.4 prohibition on U+0000 in every persisted payload string. Step 1.1 also enforces every lexical rule of section 4.1 on O_i: chain_id matches the lowercase UUID pattern, prev_hash matches <hex64>, ts is a JSON string, and the integer rules. Steps 1.4, 1.5 and 1.9 apply only to values that passed Step 1.1: the format and calendar grammar of the ts string, chain-id equality, and prev_hash equality. At physical row index expected_seq = 0, any JSON/schema/genesis-structure failure is reported as GENESIS_INVALID 0. At later rows, if JSON is malformed, seq is absent/non-integer, or schema cannot supply a valid O_i.seq, report JCS_SCHEMA_INVALID <expected_seq>; otherwise schema failure reports JCS_SCHEMA_INVALID <O_i.seq>.
2. Genesis. At index 0: seq=0, 64-zero prev_hash, event_type="chain_genesis", chain_version="1.0.4"; else GENESIS_INVALID 0. At later rows, chain_genesis → JCS_SCHEMA_INVALID <seq>.
3. TSA verification bundle. Genesis tsa_ca_bundle_sha256 must equal the SHA-256 digest of --tsa-ca-bundle; mismatch → TSA_BUNDLE_MISMATCH 0. This binds the log to the supplied bundle; it does not authenticate the bundle (section 3.3, item 9).
4. Local time format. Strict section 4.2; else TIME_FORMAT_INVALID <seq>.
5. Identity. O_i.chain_id equals genesis chain id and checkpoint namespace basename; else CHAIN_ID_MISMATCH <seq>.
6. Sequence. If O_i.seq < expected_seq → SEQ_DUPLICATE <O_i.seq>; if O_i.seq > expected_seq → SEQ_GAP <expected_seq>.
7. Monotonicity. For i>=1, if ts[i] < ts[i-1] → TS_REGRESSION <O_i.seq>.
8. Hash. Recompute RFC 8785 SHA-256; mismatch → HASH_MISMATCH <O_i.seq>.
9. Link. For i>=1, prev_hash != previous.entry_hash → PREV_HASH_MISMATCH <O_i.seq>.
10. Call pairing. tool_call.call_id is globally unique in the chain. tool_result requires a prior unmatched call with the same call_id and same task_id. Otherwise CALL_CORRELATION_INVALID <O_i.seq>.
Let seq_final be the last O_i.seq.

#### Step 2 — anchor packages

Inventory only inside --checkpoints/<chain_id>/; .writer.lock is ignored. The caller supplies a stable offline snapshot: directory entries and file bytes do not change during verification. This is a consistency precondition, not protection against a privileged concurrent operator. If an input becomes unreadable, report the error assigned below; do not silently omit it.

Canonical inventory. After ignoring .writer.lock, the only permitted package filenames are those matching exactly:
```text
^([1-9][0-9]*)\.(tsr|anchor\.json)$
```
For every parsed positive decimal k, both <k>.tsr and <k>.anchor.json must exist exactly once as filesystem directory entries. Each must be a readable regular file, checked with lstat without following symlinks and opened without following symlinks. A directory, symlink, FIFO, socket, device or unreadable permitted entry is an inventory failure, before the package loop. Filename integers and ordering use arbitrary-precision decimal arithmetic, never floating-point rounding; the package schema still restricts anchored_seq to a safe integer. A later read failure of package JSON maps to ANCHOR_PACKAGE_INCOMPLETE <k>; of the .tsr maps to TSA_SIGNATURE_INVALID <k>. Any other entry, or any unpaired permitted entry, is an inventory failure evaluated before the per-package loop. Its diagnostic parameter is derived as follows: if the filename begins with ^([1-9][0-9]*)\., use that decimal integer; otherwise use 0. If several inventory failures exist, report the numerically smallest derived value, with 0 ordered first, as ANCHOR_PACKAGE_INCOMPLETE <k> and exit 1.

After inventory succeeds, evaluate complete packages in ascending k and stop at the first failure in this exact precedence:
1. Package JSON schema and identity → ANCHOR_PACKAGE_INCOMPLETE <k>. Require valid UTF-8 JSON with no duplicate keys, exact section 4.5 schema, anchor.chain_id equal to the verified log/namespace chain id, anchor.anchored_seq == k, anchor.block.seq == k, and HEX_LOWER(SHA256(UTF8_ENCODE(JCS_SERIALIZE(anchor.block)))) == anchor.entry_hash. Any failure here is package incompleteness/identity failure.
2. TimeStampResp/CMS/TSTInfo structure and signed-time syntax. Enforce section 6a structural rules at this stage. Decode the .tsr as ASN.1 DER TimeStampResp; require PKIStatus GRANTED or GRANTED_WITH_MODS, a present timeStampToken of CMS SignedData, and a decodable RFC 3161 TSTInfo. If ASN.1/CMS structure, status, token presence or TSTInfo decoding fails → TSA_SIGNATURE_INVALID <k>. After successful structural decoding, require TSTInfo.genTime to match the UTC ASN.1 GeneralizedTime grammar from section 5.7 and convert it deterministically to epoch nanoseconds; invalid genTime syntax → TSA_TIME_FORMAT_INVALID <k>. Structural DER decoding checks only the DER encoding rules of GeneralizedTime, not calendar validity. Edge cases:
   - any non-digit character where GeneralizedTime requires digits → DER violation → TSA_SIGNATURE_INVALID <k>;
   - time-zone offset instead of Z → DER violation → TSA_SIGNATURE_INVALID <k>;
   - fraction with trailing zeros, or a present empty fraction → DER violation → TSA_SIGNATURE_INVALID <k>;
   - DER-valid value with more than nine fractional digits → grammar failure → TSA_TIME_FORMAT_INVALID <k>;
   - DER-valid value with an impossible date or time (for example February 30) → calendar failure → TSA_TIME_FORMAT_INVALID <k>, even if the ASN.1 library would reject it during decoding.
3. CMS signature and X.509 → TSA_SIGNATURE_INVALID <k>. Enforce section 6a cryptographic, signer-identity and certificate-path rules at this stage. Validate the CMS signature and the certificate path exactly as section 6a "Path acceptance" specifies: the signer certificate comes from SignedData.certificates of that .tsr and every other path certificate comes from --tsa-ca-bundle. Do not consult the operating-system trust store, AIA downloads, any other local certificate/intermediate store, OCSP, CRLs or any network source. Revocation is not evaluated in this sprint profile. Certificate validity is evaluated at the parsed TSTInfo.genTime. Require the signing certificate's critical timeStamping EKU.
4. RFC 3161 commitment → ANCHOR_COMMITMENT_MISMATCH <k>. Require TSTInfo.messageImprint.hashAlgorithm == SHA-256, hashedMessage == HEX_DECODE(anchor.entry_hash), and TSTInfo.nonce == INTEGER(0x<anchor.request_nonce_hex>).
5. Log range → TRUNCATED_BELOW_ANCHOR <k>. If k > seq_final, fail here before comparing to a nonexistent log row.
6. Log commitment → CHECKPOINT_DIVERGENCE <k>. Require anchor.entry_hash == log[k].entry_hash and JCS_SERIALIZE(anchor.block) == JCS_SERIALIZE(log[k].block).
7. Temporal predicate → TSA_TIME_INCONSISTENT <k>. Evaluate the inclusive [-5 s,+60 s] predicate against log row k timestamp using the signed genTime parsed in step 2.
Any invalid package fails verification with non-zero exit. Invalid evidence is not treated as absent evidence.

The offline profile is intentionally closed over the supplied inputs: the verifier's cryptographic decision depends only on events.jsonl, the checkpoint namespace, --tsa-ca-bundle, and certificates embedded in each .tsr. tsa_roots.pem is the sole trust store. If no acceptable path can be formed from the embedded signer and the bundle certificates, verification fails with TSA_SIGNATURE_INVALID <k>; the verifier does not search for missing certificates elsewhere. If TSTInfo.accuracy is absent, verification does not import a policy-derived numeric accuracy from the environment; coverage may still be VERIFIED_ANCHORED, but the reported receipt accuracy is unspecified.

#### Step 2b — control relations, after ALL presented packages pass Step 2

Scan control events in increasing physical row order. Require anchored_seq == seq-1 for checkpoint_anchored and target_seq == seq-1 for checkpoint_failed; the target must be >=1 and present. Otherwise CONTROL_EVENT_INVALID <seq>, exit 1. These are relational checks, not Step 1 schema checks. For a checkpoint_anchored whose package k is present, compare tsr_sha256 to SHA-256 of the exact .tsr bytes and tsa_gen_time to its exact decoded ASCII TSTInfo.genTime value. Mismatch → CHECKPOINT_METADATA_MISMATCH <seq>, exit 1. At a row, target/position failure precedes metadata failure. If package k is absent, skip only receipt equality and retain ANCHOR_EVIDENCE_MISSING <k> for successful reporting. A valid presented package does not require a control row to be present: an export may end at its anchored target k. Coverage derives from the package, not from a claim in a control event. This ordering preserves M1 package divergences before relational defects introduced by adversarial renumbering.

#### Step 3 — coverage

Reached only if Steps 1, 2 and 2b have zero errors:
- zero anchor packages → VALID_UNANCHORED 0..seq_final;
- highest valid anchor max_k → VERIFIED_ANCHORED 0..max_k; if max_k < seq_final, also VALID_UNANCHORED max_k+1..seq_final;
- unmatched tool_call at end → warning INCOMPLETE_EXECUTION <call_seq> without changing coverage or exit code.
Informational diagnostics
These do not change coverage or exit code:
- ANCHOR_EVIDENCE_MISSING <k> when the log contains checkpoint_anchored(anchored_seq=k) but package k is absent;
- largest gap between valid anchors;
- count of checkpoint_failed events inside the anchored range.

## 6a. Mandatory cryptographic profile TEAR-TSA-01

This fixed profile applies to the writer, recoverer and offline verifier in every cut. It is selected by this document, not by an environment variable, OpenSSL configuration file or provider default. A different profile requires a new declared specification/profile; it must not silently widen acceptance. OpenSSL 3.5 is a reference backend, not a substitute for these requirements. Phase 0 records the exact implementation/backend version, checks the intended TSAs against this profile, retains those that pass (section 5.7) and pins their certificates in the bundle; service compatibility is not assumed.

Structural rules (Step 2.2): require complete DER decoding with no trailing bytes, a TimeStampResp status of 0 or 1 with a token, SignedData with encapsulated id-ct-TSTInfo content (not detached), exactly one SignerInfo, and TSTInfo version=1. Require the RFC 3161 field types and constraints, a positive serialNumber, a syntactically valid policy OID, and accuracy, if present, with nonnegative seconds and millis/micros in 1..999. TEAR-TSA-01 admits no critical TSTInfo extension: any extension with critical=TRUE fails Step 2.2 with TSA_SIGNATURE_INVALID <k>, even if the backend recognizes it. A noncritical TSTInfo extension (critical absent or FALSE) is ignored after valid DER Extension decoding. Duplicate extnID values are rejected at Step 2.2 regardless of criticality. No external extension registry or backend feature changes these decisions. ordering has its ASN.1 default false and is not a coverage guarantee. genTime is decoded then checked separately for the section 5.7 grammar, yielding TSA_TIME_FORMAT_INVALID rather than a generic structure error when only that lexical/calendar rule fails. GeneralizedTime canonical encodings permitted by DER are required; the application grammar does not waive DER rules. No requested TSA policy OID is imposed: any valid policy OID is accepted and no external policy document is consulted. The TimeStampReq sets no reqPolicy and no extensions.

CMS digest-set rule (Step 2.2, before checking genTime syntax): SignedData.digestAlgorithms MUST contain exactly one AlgorithmIdentifier, equivalent to SignerInfo.digestAlgorithm of the sole signer. Empty sets, extra entries (including a second encoding of the same digest), a missing signer digest, or an unsupported/malformed digest identifier fail structurally with TSA_SIGNATURE_INVALID <k>. This rule concerns the CMS container digest, not the potentially different TSTInfo.messageImprint algorithm checked at Step 2.4.

For these two CMS fields the only allowed digest OIDs are SHA-256 = 2.16.840.1.101.3.4.2.1, SHA-384 = 2.16.840.1.101.3.4.2.2 and SHA-512 = 2.16.840.1.101.3.4.2.3. Parameters MUST be either absent or ASN.1 NULL; other parameter values fail. Two such identifiers are equivalent if and only if their OIDs match, treating absent parameters and NULL as equivalent, as specified for SHA-2 CMS identifiers in RFC 5754 §2. New CMS generation uses absent parameters. This does not change signature-scheme parameter rules or RSA signature padding requirements. A structural digest-set failure takes precedence over TSA_TIME_FORMAT_INVALID when both occur; signature mathematics, digest/signature-scheme agreement and signed attributes remain at Step 2.3.

Signature and identity rules (Step 2.3): require CMS signed attributes with exactly one content-type matching id-ct-TSTInfo and exactly one message-digest matching the encapsulated TSTInfo bytes, and verify the signature over the DER SignedAttributes representation required by CMS. Require a SigningCertificate (ESSCertID, SHA-1 certificate identifier) or SigningCertificateV2 (ESSCertIDv2, SHA-256/384/512; omitted hashAlgorithm means SHA-256) binding the first certificate reference to the actual signer. Validate issuerSerial when present. If both attributes are present both must agree with the signer; duplicate attributes are rejected. SHA-1 is permitted only for the legacy ESS certificate identifier, not for CMS signatures or non-root certificate signatures. Enforce RFC 3161 as updated by RFC 5816 for this binding. If TSTInfo.tsa is present, it must identify the signer certificate by a DER-byte-identical subject directoryName or a DER-byte-identical subjectAltName GeneralName; no hostname/network lookup is performed.

Allowed CMS digest algorithms are SHA-256, SHA-384 and SHA-512. Allowed signature schemes for SignerInfo and every non-trust-anchor certificate are RSA PKCS#1 v1.5 with one of these digests, and ECDSA with one of these digests. RSA keys must be at least 2048 bits; ECDSA uses named NIST P-256, P-384 or P-521 curves only. RSA-PSS, DSA, EdDSA, explicit EC parameters and other algorithms are outside this profile and rejected. RSA signature parameters accept NULL or absent where the governing algorithm definition permits; ECDSA signature parameters are absent. CMS digestAlgorithm and signatureAlgorithm must agree on the digest, including when rsaEncryption identifies PKCS#1 v1.5. Certificate inner and outer signatureAlgorithm identifiers must agree. Invalid encodings or algorithm/key mismatch fail. Root self-signatures are not checked and do not grant permission for weak non-root signatures. The same allowed public-key families and strengths apply to root keys used to validate a path.

Bundle file grammar. --tsa-ca-bundle (tsa_roots.pem) is a sequence of one or more PEM blocks in the strict textual encoding of RFC 7468, each labelled CERTIFICATE and each decoding to exactly one DER X.509 certificate. Outside the blocks only line breaks (LF or CRLF) are permitted: no explanatory text, comments, other labels or private keys before, between or after blocks. The whole file is consumed. An empty file, a block with another label, text outside blocks or a block that does not decode as one DER certificate fails loading. tsa_ca_bundle_sha256 is always computed over the raw file bytes.

Pinned profile. The bundle holds the roots and every signer and intermediate certificate of each retained TSA, exactly as recorded in Phase 0. Each certificate's role is derived from its bytes alone, in this order:
1. Self-issued (subject and issuer Names DER-byte-identical): it is a root. It must have basicConstraints CA=true and keyCertSign when keyUsage is present; otherwise loading fails. A self-issued certificate is never an intermediate, so a TSA hierarchy that needs a self-issued intermediate (for example a CA key rollover certificate) cannot be pinned and that TSA is not retained.
2. Not self-issued with basicConstraints CA=true: it is an intermediate. It must have keyCertSign when keyUsage is present.
3. Not self-issued without CA=true (basicConstraints absent or CA=false): it is a signer. It must satisfy the signer requirements in "Path acceptance".
The bundle must contain at least one root and at least one signer.
Each bundle certificate must decode as DER, use the allowed key families and strengths above, and carry no critical extension outside this allowlist: keyUsage (2.5.29.15), basicConstraints (2.5.29.19), extendedKeyUsage (2.5.29.37) and subjectAltName (2.5.29.17). These four extensions are always decoded and applied by the role, path and identity rules of this profile, whether they are marked critical or not; where a rule requires criticality (the signer's extendedKeyUsage) that requirement stands. Every other noncritical extension is ignored after valid DER Extension decoding. Duplicate extnID values fail. Any loading failure produces INPUT_UNAVAILABLE 0, exit 2, before Step 1. Loading contacts no network and imports no system trust store. Root self-signatures are not checked; trust in the roots and pins comes from out-of-band provisioning (section 3.3, item 9).

Path acceptance (Step 2.3). The token must embed its signer certificate in SignedData.certificates (section 5.7 requests it with certReq = TRUE). The embedded certificate identified by the ESS binding is the signer, and it must be DER-byte-identical to a pinned signer in the bundle. A token that does not embed the certificate identified by the ESS binding fails. A path is the sequence signer, then zero or more pinned intermediates, then one bundle root, in which each certificate's issuer Name is DER-byte-identical to the next certificate's subject Name. Only bundle certificates form paths; embedded certificates other than the signer are ignored, never rejected. Acceptance requires at least one path in which: every signature below the root verifies under the algorithm rules above; every certificate on the path, including the root, is within its validity interval at signed genTime (not at local wall clock); every intermediate satisfies the intermediate requirements; pathLenConstraint values on the path are respected; and the signer has a critical extendedKeyUsage containing only id-kp-timeStamping and, when keyUsage is present, digitalSignature or contentCommitment. Acceptance does not depend on the order in which candidate paths are tried. No name-constraint, certificate-policy or revocation processing is performed: certificates that would require it cannot be pinned, because their critical extensions fall outside the allowlist.

Name equality. Everywhere in this profile (self-issuance, issuer/subject chaining, ESS issuerSerial and a TSTInfo.tsa directoryName) two Names are equal if and only if their DER encodings are byte-identical. No string preparation, case folding, Unicode normalization or attribute whitelist applies. Names that differ only in string type or case are unequal.

Re-pinning is needed when a TSA starts signing with a certificate that is not pinned, or when no acceptable path through the bundle remains (for example after an intermediate rotation); until then its tokens fail Step 2.3. A change in the intermediates a TSA embeds does not matter while a bundle path exists, because embedded non-signer certificates are ignored. A re-pinned bundle has a different digest and therefore belongs to a new chain. Signature, ESS binding, unsupported algorithms, tsa-name and path failures all map to TSA_SIGNATURE_INVALID <k> at Step 2.3. A critical TSTInfo extension instead fails Step 2.2, before token-time syntax or certificate validation. MessageImprint and nonce comparisons remain exclusively at Step 2.4 and use ANCHOR_COMMITMENT_MISMATCH <k>. The writer and recoverer enforce the same profile rules without a weaker acceptance mode.

Digest-identifier representation outside the CMS set. For MessageImprint.hashAlgorithm (SHA-256 only) and an explicit ESSCertIDv2.hashAlgorithm (SHA-256/384/512 only), accept absent or ASN.1 NULL parameters as equivalent for the same digest OID, following RFC 4055 §2.1; no other parameter value is accepted. MessageImprint OID/parameter/content mismatch is ANCHOR_COMMITMENT_MISMATCH <k> at Step 2.4. An ESSCertIDv2 OID/parameter/binding mismatch is TSA_SIGNATURE_INVALID <k> at Step 2.3; an omitted ESSCertIDv2 hashAlgorithm still means SHA-256. ASN.1 that cannot be decoded structurally continues to fail at Step 2.2. These comparisons do not move ahead of JSON identity, structural decoding, genTime syntax or certificate validation, and do not expand the allowed digest/signature algorithms or extension catalogue.

## 6b. Canonical verifier output

For a completed verification, stdout is UTF-8 without BOM, each line ends with LF, and contains only the lines below. stderr is empty. Integers are canonical base-10 without leading zeros (except 0); ranges have literal two dots and no added spaces. The primary failure is the only stdout line on exit 1: <CODE> <parameter>. The parameter is the row/anchor parameter defined in Steps 1, 2 or 2b. No coverage or informational lines are emitted on failure.

On exit 0 print these groups, in this order:
1. VERIFIED_ANCHORED 0..<max_k> if any valid package exists.
2. VALID_UNANCHORED <start>..<seq_final> if any uncovered tail exists; start=0 with no packages, otherwise max_k+1. Omit empty ranges.
3. INCOMPLETE_EXECUTION <call_seq> for each unmatched tool_call, increasing call_seq.
4. ANCHOR_EVIDENCE_MISSING <k> for each distinct missing declared anchor, increasing k.
5. MAX_ANCHOR_GAP <n>: n=max(k[j]-k[j-1]) over consecutive presented valid anchors; 0 with fewer than two. Genesis is not an anchor.
6. ANCHORED_CHECKPOINT_FAILURES <n>: count checkpoint_failed rows with seq<=max_k; 0 without an anchor.
7. For each valid package, increasing k: ANCHOR_TIME <k> <genTime> ACCURACY_NS <a|unspecified> LATEST_BOUND_NS <b|unspecified>. genTime is the token's exact ASCII lexical value; a=seconds*1000000000+millis*1000000+micros*1000 with absent accuracy subfields treated as zero. If accuracy is present, b=parsed genTime epoch nanoseconds+a, otherwise both a and b are the literal unspecified. Signed epoch integers use a minus only for negative values, never + or negative zero. The bound describes that receipt's asserted time, not each local event timestamp.

Invocation/input access failures are separate from completed verification: missing/unreadable log, namespace or CA bundle, invalid namespace UUID, or a bundle that fails the section 6a grammar or loading rules emit exactly INPUT_UNAVAILABLE 0 on stdout and exit 2; stderr remains empty. Load/validate these top-level inputs before Step 1 in this order: namespace identity/access, log access, CA bundle parsing/profile checks. Invalid row bytes belong to Step 1 rather than input loading. Per-entry access/type failures belong to Step 2. There is no successful verification after an unclassified I/O exception.

## 7. How the result is judged

#### M1 · Tamper-detection matrix (the deliverable)

Frozen fixture:
- exported events.jsonl plus copied --checkpoints/<chain_id>/ with real frozen TSA receipts;
- genesis at seq=0;
- application events at all positions except checkpoint-control rows;
- seq=22,23,24,25,26 are specifically epistemic_pause application events with valid distinct non-empty task_id values; none participates in tool_call/`tool_result` correlation;
- each of those five rows has a valid reason string and missing_sources array; specifically, O_25.payload.reason is the literal "baseline";
- every application position not otherwise fixed is also an epistemic_pause with a valid non-empty task_id and reason and missing_sources=[]; this M1 fixture has no tool calls/results and therefore no INCOMPLETE_EXECUTION warnings. Adapter call pairing is exercised separately, not inferred from this fixture;
- all frozen and replacement receipts and the root bundle satisfy TEAR-TSA-01; record exact bytes, serials, genTime and accuracy in the fixture manifest, never regenerate frozen receipts during verification;
- automatic anchors at physical application-event sequence numbers 10, 20, 30, 40;
- checkpoint_anchored events at 11, 21, 31, 41;
- automatic anchoring capped at max_auto_anchor_seq=40, so 50 is not anchored;
- strictly increasing timestamps across rows, with at least 100 ms between consecutive timestamps, including ts[22] < ts[23];
- original fixture timestamps are more than 10 minutes old when T6a requests fresh receipts;
- baseline coverage: VERIFIED_ANCHORED 0..40, VALID_UNANCHORED 41..50.
Adversary mechanics:
- M1 mutations operate on a copy of the exported events.jsonl and copied checkpoint namespace, not on the live PostgreSQL primary-key constrained table.
- A2a edits exported rows without recomputing entry_hash/`prev_hash` and leaves packages unchanged unless the test explicitly says otherwise.
- A2b recomputes prev_hash and entry_hash from the first affected row through the tail and modifies packages where explicitly stated.

| ID | Exact mutation | A2a result | A2b result |
| --- | --- | --- | --- |
| T1 | At seq=25, replace the fixture literal O_25.payload.reason = "baseline" with literal "tampered", preserving every other field and valid schema. A2a leaves hashes; A2b recomputes 25..50, packages unchanged. | HASH_MISMATCH 25 | CHECKPOINT_DIVERGENCE 30 |
| T2 | Delete row seq=25. A2a leaves former 26..50 unchanged; A2b renumbers former 26..50 to 25..49 and recomputes, packages unchanged. | SEQ_GAP 25 | CHECKPOINT_DIVERGENCE 30 |
| T3a | Delete rows 35..50, leaving 0..34; packages 10,20,30,40 remain. | TRUNCATED_BELOW_ANCHOR 40 | TRUNCATED_BELOW_ANCHOR 40 |
| T3b | Delete rows 45..50, leaving 0..44; packages remain. | not detected: anchored 0..40, tail 41..44 | same |
| T4 | A2a inserts immediately after existing row 25 a duplicate of that valid epistemic_pause row retaining seq=25, producing consecutive 25s. A2b instead inserts at seq=25 a valid new epistemic_pause with non-correlating fresh task_id, reason="inserted", missing_sources=[], and ts = O_24.ts; former rows 25..50 are shifted to 26..51, their seq values updated, and the chain recomputed; packages remain unchanged. | SEQ_DUPLICATE 25 | CHECKPOINT_DIVERGENCE 30 |
| T5 | Swap only the (ts,payload) contents of rows 22 and 23, keeping their seq values. A2a keeps hashes; A2b recomputes hashes from 22 onward. Fixture guarantees original ts[22] < ts[23], so after swap ts[23] < ts[22]. | HASH_MISMATCH 22 | TS_REGRESSION 23 |
| T6a | A2b replaces only the fixture literal O_25.payload.reason = "baseline" with "tampered", recomputes the tail while keeping every row timestamp unchanged, and requests fresh valid receipts for 30 and 40 whose signed genTime is more than 60 s after the corresponding block timestamp. It replaces 30.tsr/30.anchor.json and 40.tsr/40.anchor.json consistently, and in rows 31 and 41 changes only payload.tsr_sha256 to the SHA-256 of the replacement .tsr and payload.tsa_gen_time to that replacement token's exact TSTInfo.genTime; event_type, operation, anchored_seq, row ts and all other fields remain unchanged. Then it recomputes the affected chain so Step 1 remains valid. | n/a | TSA_TIME_INCONSISTENT 30 |
| T6b | A2b replaces only the fixture literal O_25.payload.reason = "baseline" with "tampered", shifts timestamps 25..50 into the current issuance window while preserving strict monotonicity and event schemas/correlations, recomputes the tail, and replaces packages 30/40 with fresh valid receipts whose signed genTime values satisfy the temporal predicate against the rewritten rows 30 and 40. In rows 31 and 41 it also changes payload.tsr_sha256 to the SHA-256 of the corresponding replacement .tsr and payload.tsa_gen_time to that replacement token's exact TSTInfo.genTime; event_type, operation, anchored_seq and all other payload fields remain unchanged, while the row envelope timestamps are the already shifted fixture timestamps. The chain is then recomputed through the tail so Step 1 remains valid. | n/a | not detected without external custody: anchored 0..40, tail 41..50 |
| T7 | A2b replaces only the fixture literal O_25.payload.reason = "baseline" with "tampered", removes 30.tsr/30.anchor.json and 40.tsr/40.anchor.json, and replaces the payloads at rows 31 and 41 with exact checkpoint_failed payloads: row 31 uses event_type="checkpoint_failed", operation="tear.checkpoint", target_seq=30, error_type="tsa_timeout"; row 41 uses the same literals with target_seq=40. Their envelope ts values remain the original O_31.ts and O_41.ts; chain_id, seq and prev_hash are then recomputed as required from the first affected row through the tail so Step 1 remains valid. | n/a | degraded coverage: anchored 0..20, tail 21..50 |



Acceptance: npm run test:tamper produces all 15 primary results exactly as listed: 6 under A2a and 9 under A2b. The successful cases also obey section 6b output in full; expected ANCHOR_TIME lines are derived from the frozen or explicitly replaced receipt bytes. T3b, T6b, T7 and X1 have no INCOMPLETE_EXECUTION lines under the fixed pause-only fixture. The matrix is a required test contract, not a claim of tests already executed. "Not detected" and degraded-coverage rows are expected results and therefore declared limits, not hidden failures.

Additional cases outside the 15:

| ID | Mutation | Expected |
| --- | --- | --- |
| X1 | Delete 30.tsr, 30.anchor.json, 40.tsr, 40.anchor.json from disk with no events.jsonl change | exit 0; coverage drops to VERIFIED_ANCHORED 0..20, VALID_UNANCHORED 21..50; diagnostics ANCHOR_EVIDENCE_MISSING 30 and 40 |
| X2 | Replace --tsa-ca-bundle with a bundle created by the tester (a root and a pinned time-stamping signer) that satisfies TEAR-TSA-01 and rewrite the genesis tsa_ca_bundle_sha256, keeping every original ts. In ascending k = 10, 20, 30, 40: recompute the chain up to row k, replace <k>.tsr with a token from that root over the recomputed entry_hash[k] whose genTime lies inside the window of ts[k], rebuild <k>.anchor.json from the recomputed row, and in row k+1 change only payload.tsr_sha256 and payload.tsa_gen_time to the values of the replacement token. Recompute the chain through the tail. | exit 0; VERIFIED_ANCHORED 0..40, VALID_UNANCHORED 41..50. Expected and not a detection: it demonstrates section 3.3, item 9 |



#### Additional acceptance vectors (outside M1's 15 results, X1 and X2)

The implementation must cover these boundaries and record outcomes separately; they do not replace M1 or imply that this document has executed tests:
- Initialization: empty/empty, existing/existing exact retry and conflicting retry, each partial SQL state, and unknown commit outcome followed by exact retry. Assert INITIALIZED for a confirmed first creation and ALREADY_INITIALIZED for the exact retry on clean E1; a sealed clean chain also permits the latter without modifying chain_closed.
- Existing-chain inspection: exact genesis on E2, E7, and clean E1 plus a recognized .tmp returns RECOVERY_REQUIRED in Base, Cut 1 and Cuts 1–2. Snapshot event rows, state row, namespace entries and every application-file byte before/after the call; assert equality and no repair/cleanup/TSA calls. Separately run a successful section 5.6 recovery and then repeat initializeChain: expect ALREADY_INITIALIZED. Under Cuts 1–3 and 1–4 those initial dirty states instead fail RECONCILIATION_STATE_INCONSISTENT, without mutations. Cover the same classification for defensive E4/E5 and E8/E9; do not claim that a later TSA attempt must succeed.
- Inspection error precedence: valid different genesis plus recoverable residue or later invalid row returns CHAIN_INITIALIZATION_CONFLICT; invalid genesis returns RECONCILIATION_STATE_INCONSISTENT. Identical genesis plus an invalid local chain, invalid/missing committed package, foreign residue or E3/E6/E10 returns RECONCILIATION_STATE_INCONSISTENT, even with recognized .tmp files. A pending invalid package satisfying E8/E9 is RECOVERY_REQUIRED only where automatic recovery remains active. Unknown temporary filenames and nonregular entries are not eligible for the virtual cleanup view. Verify every error path leaves the inspected data unchanged, subject only to the stated lock/OS-metadata exception.
- Call pairing, outside pause-only M1: an orphan tool_result, a duplicate tool_call.call_id, and a result with a mismatched task_id each produce CALL_CORRELATION_INVALID <offending_seq> at Step 1.10 when that row passes rules 1.1–1.9. A matching result closes its call; an otherwise valid unmatched final call produces INCOMPLETE_EXECUTION at exit 0. With an earlier same-row schema/hash defect, that earlier diagnostic must prevail.
- SQL durability configuration: assert DATABASE_DURABILITY_UNSUPPORTED and no TEAR mutation for full_page_writes=off, fsync=off, wal_level=minimal or a mutation session not effectively using synchronous_commit=on after setup. Test failed settings inspection, correct setup on every fresh writerConn, rejection of pooled/secondary mutation attempts and acceptance with the required tuple. Observe the runtime fail-closed rule when a mismatch is detected; test encoding-before-durability precedence. These checks establish configuration handling, not physical crash resistance.
- SQL representation: independently alter only payload, ts, prev_hash, seq or chain_id mirrors while retaining canonical block_json/entry_hash, using a state where SQL constraints permit that isolated edit. Each discrepancy must fail RECONCILIATION_STATE_INCONSISTENT before traffic, repair or export. Test noncanonical block_json, malformed/duplicate-key block_json, bad entry_hash, and a valid-looking mirror alongside a corrupt canonical row. A jsonb textual formatting/key-order difference with equal decoded values must pass the correspondence check. Cover a mirror-corrupt genesis versus a valid different requested genesis (inconsistent takes precedence), and a valid matching/correctly mirrored genesis followed by a later discrepancy. Export failure must leave no successful partial artifact; the offline verifier on an unchanged prior export cannot detect a later mirror-only database edit.
- Root loading: construct otherwise conforming self-issued CA roots (with the required pinned certificates) with correct and mathematically incorrect self-signatures; both must pass root loading, irrespective of a backend option to check self-signatures. Update the genesis bundle digest to match the actual test bundle and keep all downstream signatures consistent. Assert INPUT_UNAVAILABLE 0, exit 2, for a self-issued certificate without CA=true, a bundle with no root or no signer, disallowed keys or critical extensions, or invalid DER. A deliberately bad signature below an accepted root must instead fail at Step 2.3 with TSA_SIGNATURE_INVALID <k>. Root loading must not contact a network or import a system trust store.
- Single-session handoff: capture backend identity and assert all chain-state loads and mutations in initializeChain/writer/recoverer use the lock-owning writerConn; reject pooled/secondary mutations, backend switching, transparent reconnect and prepared transactions. In a controlled test, crash/disconnect the client while its writerConn COMMIT is in flight. A successor may obtain flock after process death, but cannot load/classify E1–E10 or mutate until it obtains the advisory lock after the prior backend resolves the transaction and releases that lock. Exercise both committed and rolled-back outcomes, and delayed server detection of disconnect; a rejected promise or cancellation request alone cannot satisfy the barrier. Under Cut 3 the same lock acquisition precedes inspection even though repair is retired. The independent read-only exporter remains permitted and cannot be used to mutate or decide writer state.
- SQL versus JSONL validation: matching canonical SQL tuples pass logical Step 1 without requiring LF bytes inside block_json; empty/missing SQL genesis uses the initialization/startup codes. The generated export must include each required final LF and pass full offline framing. A physically malformed JSONL copy must still fail with the existing Step 1 framing diagnostic; the SQL adaptation cannot accept malformed exports or skip logical schema/hash/pairing checks.
- Pinned-profile vectors: a token whose embedded signer is not pinned, and a token that does not embed its signer, fail TSA_SIGNATURE_INVALID <k> at Step 2.3. With the same embedded signer: an intermediate present only in the bundle passes Step 2.3; an intermediate needed for the path but present only in the token fails TSA_SIGNATURE_INVALID <k>. Issuer/subject Names with the same text in different string types are unequal and break the path. An unused extra embedded certificate is ignored. A bundle certificate with a critical extension outside the allowlist (for example nameConstraints or certificatePolicies) fails loading with INPUT_UNAVAILABLE 0, exit 2. A token from a rotated, unpinned signer fails at Step 2.3.
- Bundle grammar vectors: text before the first block, text between blocks, a block with another label, an empty file and a block that is not one DER certificate each fail loading with INPUT_UNAVAILABLE 0, exit 2; LF and CRLF line breaks between blocks both load.
- Writer admission: a duplicate tool_call.call_id, a tool_result without its call and an empty task_id are each rejected with EVENT_REJECTED <code> before commit; the tool is not run, nothing is delivered and the exported chain still verifies.
- Bundle custody (auditor procedure, outside tear-verify): two valid bundles with identical roots and different pinned signers; only the one whose SHA-256 matches the fingerprint published at the end of Phase 0 passes the custody check.
- E1 durability barrier: kill the process between unlink(<k>.tsq) and the directory fsync after a confirmed transition; the successor must fsync the chain directory before accepting traffic, and an injected barrier failure aborts start-up.
- E7: kill after anchor.json rename but before directory fsync; recover with file+directory barriers before success commit. Inject failure at each barrier and at request deletion; confirm no next append and no success acknowledgment after failure.
- Missing committed package: writer/recoverer fails closed in base and Cut 3; the copied offline X1 export still exits 0 with reduced coverage.
- Control metadata: a baseline valid package and altered final control metadata with recalculated tail, no later contradicting anchor, produces CHECKPOINT_METADATA_MISMATCH at that control; impossible target/position produces CONTROL_EVENT_INVALID only after packages pass. Renumbered T2 must still fail CHECKPOINT_DIVERGENCE 30 first.
- Empty-file, empty-row-0, later empty-row and missing-final-LF vectors; earlier row defects retain first-failure precedence. Valid Unicode surrogate pairs are accepted; lone surrogates fail with the location-specific schema error.
- Directory, symlink, FIFO, unreadable entry, noncanonical filename and oversized decimal filename vectors use the deterministic inventory error parameter and precedence.
- TEAR-TSA-01 vectors include accepted legacy ESS and ESSv2 bindings; wrong binding, wrong signed digest/content type, multiple signers, weak/disallowed keys or algorithms, unavailable intermediate, expired-at-genTime signer, invalid/unknown-critical extensions and two candidate paths where only one validates. Check the assigned structural/signature/commitment diagnostic stage.
- Non-container digest identifiers: MessageImprint SHA-256 with absent versus NULL parameters must pass Step 2.4 when all other fields agree; explicit ESSCertIDv2 SHA-256/384/512 identifiers accept both forms at Step 2.3, with omitted hashAlgorithm separately testing default SHA-256. A DER-decodable but inadmissible parameter value yields ANCHOR_COMMITMENT_MISMATCH at Step 2.4 for MessageImprint or TSA_SIGNATURE_INVALID at Step 2.3 for ESS. Invalid genTime syntax precedes both semantic failures; nondecodable ASN.1 fails at Step 2.2. Keep signer signatures and ESS binding internally consistent when constructing these cases.
- CMS digest-set vectors: each permitted digest with absent/absent, NULL/NULL and mixed absent/NULL parameters must pass this structural rule. Empty set, extra digest, duplicate-equivalent entry, missing/mismatched signer digest and non-NULL parameters fail TSA_SIGNATURE_INVALID <k> at Step 2.2. Combine a digest-set failure with invalid genTime to prove structural precedence. Keep MessageImprint SHA-256 separate from a permitted SHA-384 or SHA-512 CMS signer digest.
- Extension vectors: each of the four allowlisted extensions has a valid and a violating case on a pinned certificate, in both critical and noncritical form. In particular, an intermediate with critical CA=true and a noncritical keyUsage without keyCertSign fails loading with INPUT_UNAVAILABLE 0 even if no path uses it, while its pair with keyCertSign loads. A critical TSTInfo extension, recognized or not, fails at Step 2.2. Other noncritical extensions are ignored; duplicate extnIDs fail.
- When both a new profile defect and a later commitment, range or control defect occur in one package, assert the published first-failure stage; no new check is inserted before the existing JSON/package identity stage. Revalidate the frozen and replacement receipt bytes against the clarified profile before using them for M1/X1. No newly excluded receipt is presumed compatible from a successful mathematical signature alone.
- Canonical success and failure output byte comparisons, accuracy absent/present, zero/one/multiple anchors, and repeated close after restart on a sealed chain. Profile-specific vectors confirm Cut 2 never starts B3 and Cut 3 performs no cleanup or repair.

#### M3 · Overhead

- Ordinary records: median under 15 ms/event.
- Anchor points: p50 and p95 reported separately.
- Average record size under 2 KB.
These are targets and are reported as measured, met or not.

## 8. Plan, cut order, and normative cut profiles

| Phase | Window | Deliverable |
| --- | --- | --- |
| 0 | Friday, before implementation | Durable provisioning; Node 24 flock binding; both TSAs tested with openssl ts; actual root, intermediate and signer certificates of each intended TSA checked against TEAR-TSA-01; retained TSAs recorded and their certificates pinned in the bundle (sections 5.7 and 6a) |
| 1 | Friday night | JCS + chain, locks, namespace check, durable SQL, reconciliation, frozen fixture, verifier |
| 2 | Saturday AM | M1 15/15, fault injection, two concurrent chains |
| 3 | Saturday PM | Interceptor wired to an agent; M3 |
| 4 | Sunday AM | Recovery, time rules, B0–B3, regressions |
| 5 | Sunday PM | Report, repository cleanup, demo |



If time runs short, apply cuts in this order and activate the corresponding Normative Cut Profile:
1. Cut 1 — Drop M3 measurements. Omit benchmark harness; final report marks M3 unmeasured. No protocol change.
2. Cut 2 — Minimal Close Profile. Retire B3 retry and the return literal ANCHORED_AFTER_PREVIOUS_FAILURE. Keep B0 and one single-attempt B2. Under this profile B1 remains the idempotent max_anchored_seq >= last_app_seq branch but always returns ANCHORED_FIRST_ATTEMPT, regardless of historical checkpoint-failure records. If the current head is checkpoint_failed while max_anchored_seq < last_app_seq, return UNANCHORED_FAILURE without retry. The delivered contract removes every claim tied to the retired B3 branch or retired return literal. Under this profile a close whose token genTime falls more than 60 s after ts[head] cannot be anchored (section 3.3, item 10); the final report states it.
3. Cut 3 — Fail-Closed Recovery Profile. Replace section 5.6 automatic cleanup/repair with a strict inspection-only start-up gate. The preliminary *.tmp deletion in section 5.6 step 2 is disabled under this profile. After ignoring only .writer.lock, any .tmp, .tsq, unconfirmed .tsr/`.anchor.json`, pending_anchor_seq IS NOT NULL, unknown entry, incomplete package or DB/filesystem contradiction fails immediately with RECONCILIATION_STATE_INCONSISTENT. Only a state equivalent to clean E1 — initialized genesis and state, pending IS NULL, no .tmp/`.tsq`, every package already confirmed valid and committed, and every committed checkpoint_anchored having its matching complete valid package — starts normally. Missing confirmed evidence is a DB/filesystem contradiction and fails this gate. Section 5.3a explicit atomic initialization remains available for a genuinely empty provisioned namespace; this exception does not permit repair or residue cleanup. Mid-anchor crash recovery and automatic residue cleanup are explicitly retired. The section 5.6 directory durability barrier before accepting traffic still applies: it is a durability barrier, not a repair.
4. Cut 4 — Drop the second TSA. Phase 0 tests only the retained primary TSA against TEAR-TSA-01, and section 5.7 uses only that primary TSA; primary failure transitions directly to checkpoint_failed with no fallback. If Cut 4 is activated on a chain whose bundle already pins a secondary TSA, those pins stay in the bundle unused.
Never dropped: hash chain, tear-verify, and M1 15/15. Whatever profile is activated is declared in the final report and replaces the corresponding normative clauses; removed functionality must not remain simultaneously promised elsewhere.

## 9. What the final report must state

- M1 table as measured, including "not detected" and degraded-coverage rows.
- VERIFIED_ANCHORED means the prefix is backed by an RFC 3161 token with signed TSTInfo.genTime. If the token includes accuracy, report the receipt-derived numeric bound; if it omits accuracy, report accuracy as unspecified rather than importing a policy value. It does not prove each event existed at its own ts.
- Deleting anchor packages can reduce coverage to VALID_UNANCHORED; if the log still carries the matching checkpoint_anchored event, emit ANCHOR_EVIDENCE_MISSING. Corrupt evidence is a hard verification failure, not silent degradation.
- Receipt directory simulates an external custodian; T6b and T7 depend on external custody assumptions. Offline X.509 verification uses only the pinned bundle of section 6a; it does not use system/environmental certificate sources and does not evaluate revocation in this sprint profile.
- Report the design and the tests actually performed on one host, without implying execution from this specification alone. State the effective SQL durability settings (including full_page_writes), storage flush/ordering assumptions and section 5.4 deployment invariants. Real power-loss resistance depends on protocol/implementation order and the actual storage stack; CI checks call ordering and configuration handling, not storage-device physics.
- The published fingerprint of the bundle used by tear-verify, the channel through which it was published, and the root and signer checks of section 3.3, item 9; without them no result holds against A2b.
- Any Normative Cut Profile activated under section 8.
- Every requirement of this specification not exercised by an executed test, listed as "not tested", together with the Known debt below. Being absent from that list means a test was run, not that the property is proven in general. A test that was run and failed is reported as failed, not as not tested.

## 10. Known debt

- chain_version in genesis ties the genesis hash to a document version; to be decoupled later.
- No independent external record proves that anchor packages existed and were later lost.
- Measuring how reliably agents emit epistemic_pause is outside this sprint.
- Offline TSA certificate revocation is not evaluated; reproducibility is prioritized over live revocation status for the frozen sprint evidence.
- A TSA certificate rotation requires re-pinning the bundle and starting a new chain.
- The ESSCertIDv2 acceptance vector with an explicitly encoded default SHA-256 identifier conflicts with DER and is to be corrected.
- Handling of optional CMS SignedData fields (other CertificateChoices, crls, unsignedAttrs, sid form) is not enumerated beyond ignoring unused embedded certificates.
- Some first-failure placements are not fully pinned: the diagnostic parameter of a row with duplicate seq keys, a later row with seq=0 carrying an application event, and schema checks of anchor.block at Step 2.1 versus 2.6.
- The integer rule is by value: lexical forms such as 10.0 or 1e1 are not distinguished.
- Left to the implementation: transport details per TSA (URL, content type), the commit boundary for epistemic_pause and human_resolution, result_digest when a tool fails, operation literals for application events, arbitrary-precision decoding of Accuracy.seconds and the error code for invalid initializeChain arguments.
- The A1 guarantee assumes complete mediation: every tool call passes through the interceptor.
- pathLenConstraint handling does not state whether a root's own value counts.
- A TSA serving with more than one signer certificate at a time is only partly covered: certificates not pinned in Phase 0 make anchors fail. Phase 0 records whether the retained TSAs' receipts carry crls, unsignedAttrs or other optional SignedData fields.

## 11. References

- RFC 3161 — Internet X.509 Public Key Infrastructure Time-Stamp Protocol: https://datatracker.ietf.org/doc/html/rfc3161
- RFC 8785 — JSON Canonicalization Scheme: https://datatracker.ietf.org/doc/html/rfc8785
- RFC 6962 — Certificate Transparency: https://datatracker.ietf.org/doc/html/rfc6962
- OpenSSL ts; Linux fsync(2), rename(2), flock(2), statfs(2)
- PostgreSQL 17 — WAL configuration and explicit locking
- RFC 5280 — X.509 path validation: https://www.rfc-editor.org/rfc/rfc5280.html
- RFC 7468 — Textual encodings of PKIX structures (PEM): https://www.rfc-editor.org/rfc/rfc7468.html
- RFC 5652 — CMS: https://www.rfc-editor.org/rfc/rfc5652.html
- RFC 5754 — SHA-2 identifiers and parameters in CMS: https://www.rfc-editor.org/rfc/rfc5754.html
- RFC 4055 §2.1 — SHA-2 digest AlgorithmIdentifier representations: https://www.rfc-editor.org/rfc/rfc4055.html#section-2.1
- RFC 5816 — RFC 3161 ESSCertIDv2 update: https://www.rfc-editor.org/rfc/rfc5816.html
- OpenSSL 3.5 verification options (backend reference; TEAR-TSA-01 controls acceptance): https://docs.openssl.org/3.5/man1/openssl-verification-options/
- OpenTelemetry GenAI Semantic Conventions: https://opentelemetry.io/docs/specs/semconv/gen-ai/
- Forethought — Design sketches: collective epistemics: https://www.forethought.org/research/design-sketches-collective-epistemics
