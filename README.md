# TEAR — Tamper-Evident Action Recorder

A small recorder that sits between an AI agent and its tools and makes later tampering with the record
evident, using a SHA-256 hash chain over RFC 8785 canonical JSON and RFC 3161 time-stamp anchors.

**Status:** two parts exist today. The local data core (spec 001) records events in a PostgreSQL hash chain
and exports them as `events.jsonl`. The local verifier `tear-verify` (spec 002) checks an exported log offline
when the log has no anchor packages or checkpoint events.

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
node dist/src/cli/tear-verify.js \
  --log events.jsonl \
  --checkpoints ./tsr_receipts/<chain_id>/ \
  --tsa-ca-bundle ./certs/tsa_roots.pem
```

The verifier reads only those three inputs: no database, no network. The directory name must be the chain id.
Output and exit codes follow Blueprint §6b:

| Exit | stdout |
| --- | --- |
| 0 | Coverage and informational lines, for example `VALID_UNANCHORED 0..25` |
| 1 | One line with the first failure, for example `HASH_MISMATCH 7` |
| 2 | `INPUT_UNAVAILABLE 0`: an input is missing or unreadable, or the command line is malformed |

Exit 3, with an explanation on stderr and nothing on stdout, means the input needs anchor verification, which
this version does not perform, or an internal error occurred. It never reports such a log as verified.

## License

`AGPL-3.0-or-later`. See [`LICENSE`](LICENSE).
