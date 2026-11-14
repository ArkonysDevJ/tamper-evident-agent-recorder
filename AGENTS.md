# AGENTS.md

Rules for any agent or person working in this repository.

## Before you start

1. Run `node --version`. It must print `v24.x`. If it does not, **stop and report it**. Do not continue on
   another Node version.
2. Environment: Linux, with the repository and the checkpoint namespace on a local ext4 or xfs filesystem
   (Blueprint §5.1), and PostgreSQL configured for durability as Blueprint §5.4 requires.
3. Install with `npm ci`.

## The normative source

- `docs/BLUEPRINT.md` is the only normative source. It is never edited. Its SHA-256 is
  `b394d3341b05bbfbb66688e7aacc99dfa3cddfba41dbde51198179413d28826d`; check it with
  `sha256sum docs/BLUEPRINT.md`.
- `certs/tsa_roots.pem` is the pinned bundle (Blueprint §6a). It is never edited either. Its SHA-256 is
  `10335e1e5d816b98665e5f4cb21ed92dd0637d2957658e0c34d55c365240ccfd`.
- The specs in `specs/` and `ARCHITECTURE.md` point to Blueprint sections. They do not restate or extend its
  rules. If the Blueprint and a spec seem to disagree, the Blueprint wins and the spec is wrong.
- If the Blueprint is ambiguous or contradictory for what you are building, **stop and report it, quoting
  the section**. Do not invent the rule, in code or in a spec.

## How to work

- One spec at a time, on its own branch. Never push to `main`.
- A spec is done when every acceptance criterion has a passing test with the name the spec gives it.
- After each spec, update `ARCHITECTURE.md` with the modules and files that now exist. Describe what exists,
  not what is planned.
- No secrets in the repository. The HMAC pepper (Blueprint §4.4, §5.3a) is supplied through the
  environment variable `TEAR_HMAC_PEPPER` and is never written to a file, a log or the database. Only its
  public identifier, `pepper_id`, is recorded. The value is lowercase hex of at least 64 characters
  (32 bytes); the writer decodes it to bytes and rejects any other format (implementation choice, not
  normative; see spec 005).
- Work order: 001 → 002 → 008 → 003 → 004 → 006 → 005 → 007. Each spec lists its dependencies.

## Commands

| Command | What it does | Available from |
| --- | --- | --- |
| `npm ci` | Install exact dependencies | now |
| `npx tsc --noEmit` | Type-check | now |
| `npm test` | Run the test suite | spec 001 |
| `npm run test:tamper` | Run the tamper battery (M1 + X1 + X2, Blueprint §7) | spec 004 |
| `tear-verify --log <events.jsonl> --checkpoints <dir>/<chain_id>/ --tsa-ca-bundle certs/tsa_roots.pem` | Verify an exported log offline (Blueprint §6) | spec 002 |

When you run tests, report the summary (passed, failed, skipped) and each failure. Do not paste the full
output. Only report counts from a run you actually made.
