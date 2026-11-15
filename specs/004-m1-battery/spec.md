# Spec 004 — Tamper battery (M1, X1, X2)

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the test
that proves it.

## 1. Objective

Run the §7 tamper matrix against the frozen fixture with `npm run test:tamper` and obtain every expected
result, including the declared limits.

## 2. Blueprint sections

§7 (M1 matrix, adversary mechanics, acceptance, X1, X2).

## 3. Out of scope

- Building the frozen fixture — spec 003.
- The additional acceptance vectors of §7 — the specs that own each mechanism.

## 4. Acceptance criteria

The criteria are the §7 rows as written there. Mutations act on copies of the exported log and namespace
(§7, adversary mechanics). Every mutation must change bytes of a block or of an `entry_hash`, never only
whitespace in the row envelope: that whitespace does not change the verification result (spec 002,
implementation choice; spec 007, known limits). Exit-0 cases match the full §6b output, with `ANCHOR_TIME` lines derived from the
frozen or explicitly replaced receipt bytes.

| ID | §7 row | Adversary | Expected (§7) | Test |
| --- | --- | --- | --- | --- |
| AC-1 | T1 | A2a | `HASH_MISMATCH 25` | `004 AC-1 T1-A2a` |
| AC-2 | T1 | A2b | `CHECKPOINT_DIVERGENCE 30` | `004 AC-2 T1-A2b` |
| AC-3 | T2 | A2a | `SEQ_GAP 25` | `004 AC-3 T2-A2a` |
| AC-4 | T2 | A2b | `CHECKPOINT_DIVERGENCE 30` | `004 AC-4 T2-A2b` |
| AC-5 | T3a | A2a | `TRUNCATED_BELOW_ANCHOR 40` | `004 AC-5 T3a-A2a` |
| AC-6 | T3a | A2b | `TRUNCATED_BELOW_ANCHOR 40` | `004 AC-6 T3a-A2b` |
| AC-7 | T3b | A2a | not detected: anchored 0..40, tail 41..44 | `004 AC-7 T3b-A2a` |
| AC-8 | T3b | A2b | same as A2a | `004 AC-8 T3b-A2b` |
| AC-9 | T4 | A2a | `SEQ_DUPLICATE 25` | `004 AC-9 T4-A2a` |
| AC-10 | T4 | A2b | `CHECKPOINT_DIVERGENCE 30` | `004 AC-10 T4-A2b` |
| AC-11 | T5 | A2a | `HASH_MISMATCH 22` | `004 AC-11 T5-A2a` |
| AC-12 | T5 | A2b | `TS_REGRESSION 23` | `004 AC-12 T5-A2b` |
| AC-13 | T6a | A2b | `TSA_TIME_INCONSISTENT 30` | `004 AC-13 T6a-A2b` |
| AC-14 | T6b | A2b | not detected without external custody: anchored 0..40, tail 41..50 | `004 AC-14 T6b-A2b` |
| AC-15 | T7 | A2b | degraded coverage: anchored 0..20, tail 21..50 | `004 AC-15 T7-A2b` |
| AC-16 | X1 | — | exit 0; `VERIFIED_ANCHORED 0..20`, `VALID_UNANCHORED 21..50`; `ANCHOR_EVIDENCE_MISSING 30` and `40` | `004 AC-16 X1` |
| AC-17 | X2 | — | exit 0; `VERIFIED_ANCHORED 0..40`, `VALID_UNANCHORED 41..50` | `004 AC-17 X2` |
| AC-18 | Acceptance | — | `npm run test:tamper` produces all 15 primary results (6 A2a, 9 A2b); T3b, T6b, T7 and X1 print no `INCOMPLETE_EXECUTION` lines | `004 AC-18 matrix-15-of-15` |

## 5. Dependencies

Specs 001, 002 and 003 (frozen fixture closed).

## Implementation choices (not normative)

Recorded here and declared in the report of the work package that implements them.

- **Runner:** `npm run test:tamper` runs `test/tamper/battery.test.ts` offline. Each case builds an in-memory copy of
  the frozen fixture, applies its exact operation, writes the copy to a temporary directory and runs the offline
  verifier. The frozen files are checked unchanged after the run. The table "specified → measured" is written to
  `test-results/tamper-results.md` (not committed); two runs write the same bytes.
- **Copies:** an unchanged copy serializes to the exact exported bytes; mutated rows are written as canonical
  `{"block":…,"entry_hash":…}` lines. Each case except X1 is checked to change block or `entry_hash` bytes; X1
  leaves `events.jsonl` byte-identical.
- **A2b recomputation:** `prev_hash` and `entry_hash` are recomputed from the first affected row through the tail.
  For T3a and T3b nothing follows the cut, so the A2b copy equals the A2a copy.
- **T4 under A2b:** the inserted row uses `task_id` `inserted-fresh-task`.
- **T6a and T6b receipts:** real receipts, requested once by `npm run tamper:receipts` (network) and stored in
  `test/fixtures/tamper-receipts/` with a manifest. The receipt for 30 comes from FreeTSA and the one for 40 from
  DigiCert. The battery never requests receipts; it refuses a stored receipt whose request no longer matches the
  recomputed row.
- **T6b timestamps:** rows 25..50 get `base + (seq − 25) × 150 ms`, with the base time stored in the manifest
  (three seconds before the requests).
- **X2:** the tester's root (RSA 2048) and pinned signer (P-256) are generated at run time and never stored. Each
  token's genTime is the row's whole second plus one second, and the nonce is fixed, so the output is
  deterministic.
- **ANCHOR_TIME lines** in expected outputs are derived from the bytes of the frozen or replaced receipts.

## Additional §7 vectors: where each one runs

| Vector (§7) | Where |
| --- | --- |
| Initialization | spec 001 (`npm run test:pg`) |
| Existing-chain inspection (E2, E7, `.tmp`, defensive E4/E5, E8/E9) | spec 006 |
| Inspection error precedence | spec 001 for genesis conflicts and invalid chains; E3/E6/E10 parts in spec 006 |
| Call pairing, outside the pause-only M1 fixture | specs 001 and 002 (Step 1); adapter pairing in spec 005 |
| SQL durability configuration, SQL representation, single-session handoff | spec 001 |
| SQL versus JSONL validation; empty-file and row vectors | spec 002 |
| Root loading; pinned-profile, bundle grammar, inventory, TEAR-TSA-01, digest identifiers, digest-set, extension and stage-precedence vectors | spec 003 (the explicit default SHA-256 `ESSCertIDv2` vector is known debt) |
| Writer admission | spec 001 |
| Bundle custody (auditor procedure) | this battery |
| Control metadata (final control, impossible target, renumbered T2) | this battery and spec 003 |
| Revalidation of frozen and replacement receipts | this battery |
| E1 durability barrier, E7 crash, missing committed package in the writer | spec 006 (the offline X1 part runs here) |
| Repeated close after restart; Cut 2 and Cut 3 profile vectors | spec 006 |
| Canonical output; accuracy absent and present; zero, one and several anchors | specs 002 and 003 |
