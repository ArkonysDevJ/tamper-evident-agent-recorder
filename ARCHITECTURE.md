# Architecture

This file describes what exists in the repository. Each spec updates it with the modules and files it adds.
The design itself is in `docs/BLUEPRINT.md`.

## Components (Blueprint §2)

```text
           agent
             │  tool calls, epistemic pauses, final answers
             ▼
      ┌─────────────┐   durable commit before the action runs
      │ interceptor │─────────────────────────────┐
      └─────────────┘                             ▼
                                         ┌──────────────────┐
                                         │ hash chain       │
                                         │ (PostgreSQL)     │
                                         └──────────────────┘
                                            │            │
                          head hash at      │            │  export
                          seq % 10 == 0     ▼            ▼
                                 ┌──────────────┐   ┌───────────────┐
                    RFC 3161 TSA │ anchors      │   │ events.jsonl  │
                    ◄───────────►│ (checkpoint  │   └───────────────┘
                                 │  namespace)  │           │
                                 └──────────────┘           │
                                         │                  │
                                         ▼                  ▼
                                      ┌──────────────────────────┐
                                      │ tear-verify (offline)    │◄── certs/tsa_roots.pem
                                      └──────────────────────────┘
```

| Component | Blueprint | Spec | Status |
| --- | --- | --- | --- |
| Hash chain: record format, hashing, Step 1 core, SQL storage, locks, initialization, append, export | §4, §5.1–§5.4, §5.3a, §6 Step 1 | 001 | implemented |
| Verifier: CLI, framing and output | §6 Step 1, §6b | 002 | implemented |
| Durable file primitives | §5.5 | 008 | implemented; used by the anchor flow |
| Anchors: RFC 3161 client, TEAR-TSA-01 profile, package checks, coverage, frozen fixture | §5.7, §6 Steps 2–3, §6a, §7 | 003 | implemented; recovery of interrupted anchors is spec 006 |
| Tamper battery | §7 | 004 | implemented: 15/15 primary results, X1 and X2 match §7 |
| Interceptor wired to one agent; overhead | §2, §5.4, §7 M3 | 005 | implemented with a scripted reference agent; M3 measured |
| Recovery, close, evidence package | §5.6, §5.8, §5.3 | 006 | not implemented |
| Final report | §8, §9 | 007 | not written |

## Data core (spec 001)

```text
initializeChain / ChainWriter.open
  └─ acquireExclusion: namespace exists → statfs guard → flock(.writer.lock) → writerConn
       └─ WriterConn.open: SET synchronous_commit=on → encoding + durability check → pg_try_advisory_lock
  └─ loadChain (one read-only snapshot on writerConn)
       └─ checkSqlRow (block_json authority, mirrors) → Step1Checker (rules 1.1–1.10) → validateState
  └─ RecoveryClassifier (interface; spec 006)       ← default: "not implemented"
ChainWriter.append (serial queue)
  └─ build block (ts = max(now, head ts)) → Step1Checker.check (admission, EVENT_REJECTED)
  └─ writerConn.mutate: recheck durability → INSERT → AnchorHook (automatic trigger, spec 003) → COMMIT
  └─ pending anchor set? → TSA flow in the same queue slot (spec 003, below)
exportChain (own read-only REPEATABLE READ connection) → checkSqlRow + Step 1 → events.jsonl
```

| Module | What it does | Blueprint |
| --- | --- | --- |
| `src/json/strict-json.ts` | Strict JSON parser: duplicate keys, lone surrogates, non-finite numbers rejected | §4.1, §4.3 |
| `src/json/jcs.ts` | RFC 8785 canonical serialization | §4.3 |
| `src/crypto/digests.ts` | `entry_hash`, bundle digest, `args_hmac`, `result_digest`, `response_digest` | §4.3, §4.4 |
| `src/time/timestamps.ts` | `O_i.ts` and GeneralizedTime grammars, epoch nanoseconds, writer timestamp rule | §4.2, §5.7 |
| `src/chain/ids.ts` | UUID and hex64 forms, zero hash, chain version | §4.1 |
| `src/chain/schema.ts` | Row envelope and the eight payload schemas, U+0000 and Unicode domain | §4.1, §4.4 |
| `src/chain/step1.ts` | Step 1 rule core, incremental (`check` for admission, `accept` for loading) | §6 Step 1 |
| `src/chain/sql-rows.ts` | SQL representation check: `block_json` authority, commitment, mirrors | §5.3 |
| `src/chain/state.ts` | Snapshot load on writerConn, full validation, state invariants | §5.3, §5.3a |
| `src/chain/exclusion.ts` | Start-up order: namespace, statfs, flock, writerConn and advisory lock | §5.1, §5.3 |
| `src/chain/initialize.ts` | `initializeChain`: atomic creation, non-mutating inspection, step 4 mapping | §5.3a |
| `src/chain/writer.ts` | `ChainWriter`: start-up, admission, durable append | §5.3, §5.4 |
| `src/chain/export.ts` | Canonical SQL → `events.jsonl` export | §5.3 |
| `src/chain/interfaces.ts` | `RecoveryClassifier` (default: not implemented) and `AnchorHook` (writer default: the automatic trigger) | §5.6, §5.7 |
| `src/chain/profile.ts` | Cut profiles and whether automatic recovery applies | §8 |
| `src/db/writer-conn.ts` | The single writer session: never pooled, never reconnected, commit outcome | §5.3, §5.4 |
| `src/db/settings.ts` | Encoding and durability preconditions | §5.3, §5.4 |
| `src/db/schema.ts` | `tear_events` and `tear_chain_state`, provisioned separately | §5.3 |
| `src/fs/namespace.ts` | Provisioning with unconditional parent fsync, statfs guard | §5.1, §5.2 |
| `src/fs/writer-lock.ts` | `flock(2)` on `.writer.lock` through `fs-ext` (native binding, see below) | §5.3 |
| `src/fs/inventory.ts` | Read-only namespace inventory under §5.6 step 2 names and types | §5.6 |
| `src/util/serial-queue.ts` | Strict FIFO queue per chain | §5.3 |

## Durable file primitives (spec 008)

```text
DurableNamespace(nsPath, guard: MutationGuard, { fsOps?, onFatal? })     one per writer generation
  every call → FIFO mutation queue → guard check → operation
  publish(name, bytes)           open <name>.tmp → write → fsync → close → rename → fsync dir
  durableDelete([{name, optional}]) unlink each (ENOENT ignored only if optional) → fsync dir
  recoveredPackageBarrier(names) open O_NOFOLLOW → regular file? → fsync → close; then fsync dir
  any failure → guard.invalidate() → refuse all later work → drain → onFatal(cause); no cleanup
```

| Module | What it does | Blueprint |
| --- | --- | --- |
| `src/fs/durable.ts` | The three primitives, their mutation queue, the guard checks and fail-stop handling | §5.3, §5.5 |

`WriterConn` is a `MutationGuard`: it is invalidated on any error, end or timeout of the session, so a namespace
mutation never starts once writerConn is lost. The guard is checked before each operation starts and again before
each mutating system call. Entry names are plain names inside the namespace; `.writer.lock` is never published,
renamed or deleted. Closing writerConn, releasing flock and exiting after `onFatal` are the owner's job.

## Anchoring (spec 003)

```text
append of application record k (k > 0, k % 10 == 0, k <= max_auto_anchor_seq)
  └─ same transaction: pending_* = (k, entry_hash[k], ts[k], "auto")              src/anchor/trigger.ts
  └─ after COMMIT, same queue slot: runAnchorFlow                                 src/anchor/flow.ts
       1. nonce (CSPRNG, top bits forced) → DER TimeStampReq → publish <k>.tsq     src/tsa/request.ts
       2. POST to FreeTSA, then DigiCert on any TSA failure (5000 ms each)         src/tsa/transport.ts
       3. checkReceipt (2.2 → 2.4, TEAR-TSA-01) + time predicate                   src/tsa/receipt.ts
       4. publish <k>.tsr → publish <k>.anchor.json → INSERT checkpoint_anchored + clear pending (one COMMIT)
          → durable-delete <k>.tsq
       5. last TSA failed: INSERT checkpoint_failed + clear pending → durable-delete <k>.tsq
       6. filesystem or SQL failure, or invalidation: no fallback, no resolution, no cleanup;
          invalidate → drain → close writerConn → release flock → exit
```

| Module | What it does | Blueprint |
| --- | --- | --- |
| `src/asn1/der.ts` | Strict DER reader: TLV elements and byte ranges only, with size and depth limits | §6a |
| `src/asn1/types.ts` | DER rules of INTEGER, BOOLEAN, NULL, OID, BIT STRING, OCTET STRING and the time types | §6a |
| `src/asn1/encode.ts` | Minimal DER encoder for the TimeStampReq | §5.7 |
| `src/pki/oids.ts` | Object identifiers of the profile | §6a |
| `src/pki/algorithms.ts` | Allowed digests, signature schemes and keys; signature checks through `node:crypto` | §6a |
| `src/pki/certificate.ts` | X.509 decoding: Names as DER bytes, the four decoded extensions, duplicates rejected | §6a |
| `src/pki/bundle.ts` | `--tsa-ca-bundle`: strict PEM grammar, roles from the bytes, loading checks | §6a |
| `src/pki/path.ts` | Path acceptance at genTime through bundle certificates only | §6a |
| `src/tsa/request.ts` | Nonce and DER TimeStampReq, `tsq_der_sha256` | §5.7 step 1 |
| `src/tsa/transport.ts` | HTTP POST per retained TSA with a 5000 ms timeout | §5.7 step 2 |
| `src/tsa/receipt.ts` | Receipt checks shared by the writer and the verifier: structure, genTime, signature and path, commitment, time predicate | §5.7 step 3, §6 Steps 2.2–2.4, §6a |
| `src/anchor/package.ts` | `<k>.anchor.json` bytes and the Step 2.1 check | §4.5, §6 Step 2.1 |
| `src/anchor/trigger.ts` | Automatic trigger in the append transaction | §5.7 |
| `src/anchor/flow.ts` | The TSA flow for anchor k on the durable primitives | §5.5, §5.7 |

**Own trust surface: the DER reader.** Certificates, CMS and RFC 3161 structures are read by a DER reader written
in this repository, not by a library: `node:crypto` does not expose DER Names, extension criticality or CMS
structure. The reader accepts only definite, minimal lengths and single-byte identifiers, rejects trailing bytes
and out-of-bounds reads, and limits size (1 MiB) and depth (32). It is tested with negative vectors for every
rejection rule and checked against `openssl` on every real receipt and certificate (`npm run test:local`). It has
had no external review. No cryptographic primitive is implemented here: hashes, signatures and key loading use
`node:crypto`.

## Interceptor and M3 (spec 005)

```text
Interceptor.start: readPepper(TEAR_HMAC_PEPPER) → ChainWriter.initializeAndOpen (new chain, same session)
agent step                      record (confirmed COMMIT first)                    then
  tool call      → beginCall    tool_call  {tool_name, call_id, task_id, args_hmac} → the tool runs
                 → completeCall tool_result {call_id, task_id, error_type, result_digest, summary} → result delivered
  pause          → epistemicPause   epistemic_pause                                  → the agent continues
  resolution     → humanResolution  human_resolution                                 → the agent continues
  final answer   → finalResponse    agent_final_response {response_digest}           → answer delivered
any failed or unknown COMMIT: the step stops; nothing runs, nothing is delivered, nothing is retried
```

| Module | What it does | Blueprint |
| --- | --- | --- |
| `src/interceptor/pepper.ts` | `TEAR_HMAC_PEPPER`: lowercase hex, at least 32 bytes; never echoed | §4.4 |
| `src/interceptor/interceptor.ts` | Write-ahead recording, adapter JSON domain, digests, failed-tool value, start-up order | §2, §4.3, §4.4, §5.4 |
| `src/chain/writer.ts` (`initializeAndOpen`) | Writer start in the session that created the chain (provisional until spec 006) | §5.3a |

| File | What it does |
| --- | --- |
| `test/agent/scripted-agent.ts` | Scripted reference agent (a test instrument, no LLM): three deterministic tools, one always fails |
| `test/m3/run-m3.ts`, `test/m3/report.ts` | M3 harness and its results table (`npm run m3`; local PostgreSQL, TSAs, `TEAR_HMAC_PEPPER`) |

## Tamper battery (spec 004)

```text
npm run test:tamper
  for each §7 case: Evidence (copy of test/fixtures/frozen-m1) → exact mutation (A2a / A2b) → temp dir
    → verifyOffline → compare with the §7 result copied into the case → test-results/tamper-results.md
```

| File | What it does |
| --- | --- |
| `test/tamper/model.ts` | The in-memory copy of the exported log and namespace, and the A2a/A2b operations |
| `test/tamper/cases.ts` | T1–T7 under A2a and A2b, X1 and X2, with their §7 results |
| `test/tamper/receipts.ts` | Stored real receipts for T6a and T6b |
| `test/tamper/battery.test.ts` | The runner, the additional vectors and the results table |
| `test/fixture-tools/build-tamper-receipts.ts` | One-time request of the T6a and T6b receipts (`npm run tamper:receipts`) |

## Local verifier (spec 002, Steps 2–3 from spec 003)

```text
tear-verify (src/cli/tear-verify.ts) → parseArgs → verifyOffline
  1. namespace: basename is a lowercase UUID, directory readable     ┐ any failure:
  2. log: readable                                                    │ INPUT_UNAVAILABLE 0, exit 2
  3. bundle: readable → loadBundle (PEM grammar, TEAR-TSA-01 loading) ┘
  Step 1: logRows (LF framing, strict UTF-8, no BOM) → Step1Checker   (the writer's own rule core)
  Step 2: inventory (lstat, O_NOFOLLOW) → per package, ascending k: 2.1 … 2.7
  Step 2b: control relations → Step 3: coverage and informational lines (§6b groups)
```

| Module | What it does | Blueprint |
| --- | --- | --- |
| `src/cli/tear-verify.ts` | Command entry point and `bin` target (shebang on line 1); writes stdout/stderr and sets the exit code | §6, §6b |
| `src/verify/args.ts` | The three options, each exactly once | §6 |
| `src/verify/verify.ts` | Input loading order, Step 1 over the log, extensions, Step 3 | §6, §6b |
| `src/verify/framing.ts` | JSONL rows: final LF, empty rows, unterminated last row, strict UTF-8, BOM | §6 Step 1 |
| `src/verify/output.ts` | Canonical failure, success and `INPUT_UNAVAILABLE` lines | §6b |
| `src/verify/extensions.ts` | `BundleLoader` and `AnchorVerifier` extension points, set to the TEAR-TSA-01 implementations | §6, §6a |
| `src/verify/anchors.ts` | Step 2 inventory and packages, Step 2b, `ANCHOR_TIME` lines | §6 Steps 2–3, §6b |

The verifier and the writer share `src/chain/step1.ts` and `src/tsa/receipt.ts`. Exit 3 (outside the §6b
contract) remains only for an internal error.

## Native binding

Node.js core does not expose `flock(2)` (Blueprint §5.3), so the writer lock uses `fs-ext@2.1.1`, a native
addon (with `nan@2.30.0`) compiled by `node-gyp` at install time. Its install script is the only one approved in
`package.json` `allowScripts`, pinned to that exact version; npm reports any other version, or any other package
with an install script, as unreviewed. Building it needs a C/C++ toolchain and Python.

## Files

| Path | What it is |
| --- | --- |
| `docs/BLUEPRINT.md` | Normative design, hash-pinned |
| `certs/tsa_roots.pem` | Pinned TSA bundle from Phase 0, hash-pinned |
| `specs/` | One spec per work package |
| `src/` | Modules listed above |
| `test/unit/` | Tests without PostgreSQL (`npm test`, run in CI) |
| `test/pg/` | Tests against a local PostgreSQL (`npm run test:pg`) |
| `test/helpers/` | Chain builder, PostgreSQL helpers, verifier input files, a recording and fault-injecting `fs` double, child processes for lock and handoff tests, a test PKI that builds certificates and RFC 3161 receipts, in-process test TSAs |
| `test/fixtures/frozen-m1/` | The frozen M1 fixture: `events.jsonl`, the copied namespace with real FreeTSA and DigiCert receipts, and `manifest.json` (digests, serials, genTime, accuracy, optional fields) |
| `test/fixture-tools/` | One-time builders: the fixture (`npm run fixture:build`; local PostgreSQL and both TSAs) and the T6a/T6b receipts (`npm run tamper:receipts`; both TSAs) |
| `test/fixtures/tamper-receipts/` | The stored real receipts for T6a and T6b, with their manifest and the T6b base time |
| `test/tamper/` | The tamper battery (`npm run test:tamper`; offline) |
| `test/agent/`, `test/m3/` | The scripted reference agent and the M3 harness (`npm run m3`, `npm run m3:render`) |
| `test/local/` | Local checks with external tools (`npm run test:local`): the DER reader against `openssl` |
