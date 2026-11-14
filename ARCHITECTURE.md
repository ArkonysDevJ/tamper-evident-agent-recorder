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
| Hash chain: record format, hashing, Step 1 core, SQL storage, locks, initialization, append, export | §4, §5.1–§5.4, §5.3a, §6 Step 1 | 001 | not implemented |
| Verifier: CLI, framing and output | §6 Step 1, §6b | 002 | not implemented |
| Durable file primitives | §5.5 | 008 | not implemented |
| Anchors: RFC 3161 client, TEAR-TSA-01 profile, package checks, coverage, frozen fixture | §5.7, §6 Steps 2–3, §6a, §7 | 003 | not implemented |
| Tamper battery | §7 | 004 | not implemented |
| Interceptor wired to one agent; overhead | §2, §5.4, §7 M3 | 005 | not implemented |
| Recovery, close, evidence package | §5.6, §5.8, §5.3 | 006 | not implemented |
| Final report | §8, §9 | 007 | not written |

## Files

| Path | What it is |
| --- | --- |
| `docs/BLUEPRINT.md` | Normative design, hash-pinned |
| `certs/tsa_roots.pem` | Pinned TSA bundle from Phase 0, hash-pinned |
| `specs/` | One spec per work package |
| `src/index.ts` | Placeholder so the compiler has an input; no code yet |
