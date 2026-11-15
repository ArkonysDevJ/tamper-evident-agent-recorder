# TEAR — Tamper-Evident Action Recorder

A small recorder that sits between an AI agent and its tools and makes later tampering with the record
evident, using a SHA-256 hash chain over RFC 8785 canonical JSON and RFC 3161 time-stamp anchors.

**Status:** three parts exist today. The local data core (spec 001) records events in a PostgreSQL hash chain
and exports them as `events.jsonl`. Anchoring (spec 003) time-stamps every tenth application record with RFC 3161,
first through FreeTSA and then DigiCert, under the fixed TEAR-TSA-01 profile. The offline verifier `tear-verify`
(specs 002 and 003) checks an exported log and its anchor packages against the pinned bundle
`certs/tsa_roots.pem`. A frozen fixture with real receipts from both TSAs is in `test/fixtures/frozen-m1/`, and the §7 tamper battery
runs on copies of it (`npm run test:tamper`). A write-ahead interceptor (spec 005) records every tool call,
epistemic pause, human resolution and final answer before it takes effect; it is exercised by a scripted
reference agent, a test instrument with no LLM. Start-up reconciliation (spec 006) recovers an interrupted
anchor or fails closed, `closeChain` seals a chain with its final anchor, and `buildEvidencePackage` produces a
consistent log and namespace copy for offline verification.

- What will be built, and what it will and will not prove: [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md)
  (the only normative source).
- How the work is split: [`specs/`](specs/).
- What exists so far: [`ARCHITECTURE.md`](ARCHITECTURE.md).
- Rules for contributors and agents: [`AGENTS.md`](AGENTS.md).

> **Reading the Blueprint.** `docs/BLUEPRINT.md` uses angle-bracket placeholders such as `<k>` and `<chain_id>`.
> GitHub's renderer hides some of them. Use the **Raw** view to read the normative text exactly as hashed.

Requires Node.js 24 (see `.nvmrc`).

## Verifying an exported log

```sh
npm ci && npm run build
npm exec -- tear-verify \
  --log events.jsonl \
  --checkpoints ./tsr_receipts/<chain_id>/ \
  --tsa-ca-bundle ./certs/tsa_roots.pem
```

`tear-verify` is the package's `bin` entry (`dist/src/cli/tear-verify.js`); `node dist/src/cli/tear-verify.js`
works the same. The verifier reads only those three inputs: no database, no network. The directory name must be
the chain id.
Output and exit codes follow Blueprint §6b:

| Exit | stdout |
| --- | --- |
| 0 | Coverage and informational lines, for example `VERIFIED_ANCHORED 0..40` then `VALID_UNANCHORED 41..50` |
| 1 | One line with the first failure, for example `HASH_MISMATCH 7` |
| 2 | `INPUT_UNAVAILABLE 0`: an input is missing or unreadable, or the command line is malformed |

Exit 3, with an explanation on stderr and nothing on stdout, means an internal error occurred. It never reports
a log as verified.

The guarantees against an operator who controls both the log and the bundle hold only when the bundle's SHA-256
matches the fingerprint published before the first anchor (Blueprint §3.3 item 9).

## Tests

| Command | Needs |
| --- | --- |
| `npm test` | Nothing else; runs in CI, including the frozen fixture without network |
| `npm run test:pg` | A local PostgreSQL (`PGHOST`, `PGDATABASE`, `PGUSER`) |
| `npm run test:local` | The `openssl` command: checks the DER reader against OpenSSL on the real receipts |
| `npm run test:tamper` | Nothing else: the §7 tamper battery on copies of the frozen fixture, offline |

## Measuring the overhead (M3)

```sh
export TEAR_HMAC_PEPPER=...   # lowercase hex, at least 64 characters; never written anywhere by TEAR
npm run m3                    # local PostgreSQL and network access to the TSAs
cat test-results/m3-results.md
```

The run uses 100 events per run, 5 runs with and 5 without the interceptor, and new chains that anchor at 10 and
20 (10 time-stamp requests). `npm run m3:render` re-renders the table from the saved samples without measuring
again.

## Reproducing the tamper battery

```sh
npm ci
npm run test:tamper
cat test-results/tamper-results.md
```

The battery applies each §7 mutation (T1–T7 under both adversaries, X1 and X2) to a copy of
`test/fixtures/frozen-m1/`, runs the offline verifier and compares the result with the one §7 specifies. It writes
the table "specified → measured" to `test-results/tamper-results.md`; two runs give the same table. T6a and T6b use
real receipts stored once in `test/fixtures/tamper-receipts/`; X2 generates its own root and signer at run time.

## License

`AGPL-3.0-or-later`. See [`LICENSE`](LICENSE).
