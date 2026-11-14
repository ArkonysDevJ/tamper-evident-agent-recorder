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
| Verifier: CLI, framing and output | §6 Step 1, §6b | 002 | implemented for logs without anchors |
| Durable file primitives | §5.5 | 008 | not implemented |
| Anchors: RFC 3161 client, TEAR-TSA-01 profile, package checks, coverage, frozen fixture | §5.7, §6 Steps 2–3, §6a, §7 | 003 | not implemented |
| Tamper battery | §7 | 004 | not implemented |
| Interceptor wired to one agent; overhead | §2, §5.4, §7 M3 | 005 | not implemented |
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
  └─ writerConn.mutate: recheck durability → INSERT → AnchorHook (interface; spec 003) → COMMIT
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
| `src/chain/interfaces.ts` | `RecoveryClassifier` (default: not implemented) and `AnchorHook` (default: no-op) | §5.6, §5.7 |
| `src/chain/profile.ts` | Cut profiles and whether automatic recovery applies | §8 |
| `src/db/writer-conn.ts` | The single writer session: never pooled, never reconnected, commit outcome | §5.3, §5.4 |
| `src/db/settings.ts` | Encoding and durability preconditions | §5.3, §5.4 |
| `src/db/schema.ts` | `tear_events` and `tear_chain_state`, provisioned separately | §5.3 |
| `src/fs/namespace.ts` | Provisioning with unconditional parent fsync, statfs guard | §5.1, §5.2 |
| `src/fs/writer-lock.ts` | `flock(2)` on `.writer.lock` through `fs-ext` (native binding, see below) | §5.3 |
| `src/fs/inventory.ts` | Read-only namespace inventory under §5.6 step 2 names and types | §5.6 |
| `src/util/serial-queue.ts` | Strict FIFO queue per chain | §5.3 |

## Local verifier (spec 002)

```text
tear-verify (src/cli/tear-verify.ts) → parseArgs → verifyOffline
  1. namespace: basename is a lowercase UUID, directory readable     ┐ any failure:
  2. log: readable                                                    │ INPUT_UNAVAILABLE 0, exit 2
  3. bundle: readable → BundleLoader (extension; spec 003)            ┘
  Step 1: logRows (LF framing, strict UTF-8, no BOM) → Step1Checker   (the writer's own rule core)
  Steps 2, 2b → AnchorVerifier (extension; spec 003)
  Step 3 → successOutput (§6b groups)
```

| Module | What it does | Blueprint |
| --- | --- | --- |
| `src/cli/tear-verify.ts` | Command entry point and `bin` target (shebang on line 1); writes stdout/stderr and sets the exit code | §6, §6b |
| `src/verify/args.ts` | The three options, each exactly once | §6 |
| `src/verify/verify.ts` | Input loading order, Step 1 over the log, extensions, Step 3 | §6, §6b |
| `src/verify/framing.ts` | JSONL rows: final LF, empty rows, unterminated last row, strict UTF-8, BOM | §6 Step 1 |
| `src/verify/output.ts` | Canonical failure, success and `INPUT_UNAVAILABLE` lines | §6b |
| `src/verify/extensions.ts` | `BundleLoader` and `AnchorVerifier` extension points and their current defaults | §6, §6a |

The verifier and the writer share `src/chain/step1.ts`. The default `AnchorVerifier` handles only a namespace
without entries (besides `.writer.lock`) and a log without control events; anything else exits 3 with the
reason on stderr, outside the §6b contract. The default `BundleLoader` only requires readable bytes.

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
| `test/helpers/` | Chain builder, PostgreSQL helpers, verifier input files, child processes for lock and handoff tests |
