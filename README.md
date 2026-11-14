# TEAR — Tamper-Evident Action Recorder

A small recorder that sits between an AI agent and its tools and makes later tampering with the record
evident, using a SHA-256 hash chain over RFC 8785 canonical JSON and RFC 3161 time-stamp anchors.

**Status:** pre-implementation. Nothing of the protocol is implemented yet.

- What will be built, and what it will and will not prove: [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md)
  (the only normative source).
- How the work is split: [`specs/`](specs/).
- What exists so far: [`ARCHITECTURE.md`](ARCHITECTURE.md).
- Rules for contributors and agents: [`AGENTS.md`](AGENTS.md).

> **Reading the Blueprint.** `docs/BLUEPRINT.md` uses angle-bracket placeholders such as `<k>` and `<chain_id>`.
> GitHub's renderer hides some of them. Use the **Raw** view to read the normative text exactly as hashed.

Requires Node.js 24 (see `.nvmrc`).

## License

`AGPL-3.0-or-later`. See [`LICENSE`](LICENSE).
