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
(§7, adversary mechanics). Exit-0 cases match the full §6b output, with `ANCHOR_TIME` lines derived from the
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
