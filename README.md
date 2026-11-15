# TEAR — Tamper-Evident Action Recorder

A small recorder that sits between an AI agent and its tools and makes later tampering with the record
evident, using a SHA-256 hash chain over RFC 8785 canonical JSON and RFC 3161 time-stamp anchors.

**Status:** three parts exist today. The local data core (spec 001) records events in a PostgreSQL hash chain
and exports them as `events.jsonl`. Anchoring (spec 003) time-stamps every tenth application record with RFC 3161,
first through FreeTSA and then DigiCert, under the fixed TEAR-TSA-01 profile. The offline verifier `tear-verify`
(specs 002 and 003) checks an exported log and its anchor packages against the pinned bundle
`certs/tsa_roots.pem`. A frozen fixture with real receipts from both TSAs is in `test/fixtures/frozen-m1/`.

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

## License

`AGPL-3.0-or-later`. See [`LICENSE`](LICENSE).
