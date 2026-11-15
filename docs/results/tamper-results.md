# Tamper battery results (Blueprint §7)

Frozen fixture chain: `890c1d36-1e29-45ac-8efc-bdc18c2a34c1`. Bundle: `10335e1e5d816b98665e5f4cb21ed92dd0637d2957658e0c34d55c365240ccfd`.

| Case | Adversary | Specified (§7) | Measured | Result |
| --- | --- | --- | --- | --- |
| T1 | A2a | HASH_MISMATCH 25 | HASH_MISMATCH 25 | match |
| T1 | A2b | CHECKPOINT_DIVERGENCE 30 | CHECKPOINT_DIVERGENCE 30 | match |
| T2 | A2a | SEQ_GAP 25 | SEQ_GAP 25 | match |
| T2 | A2b | CHECKPOINT_DIVERGENCE 30 | CHECKPOINT_DIVERGENCE 30 | match |
| T3a | A2a | TRUNCATED_BELOW_ANCHOR 40 | TRUNCATED_BELOW_ANCHOR 40 | match |
| T3a | A2b | TRUNCATED_BELOW_ANCHOR 40 | TRUNCATED_BELOW_ANCHOR 40 | match |
| T3b | A2a | not detected: anchored 0..40, tail 41..44 | exit 0; VERIFIED_ANCHORED 0..40; VALID_UNANCHORED 41..44 | match |
| T3b | A2b | same | exit 0; VERIFIED_ANCHORED 0..40; VALID_UNANCHORED 41..44 | match |
| T4 | A2a | SEQ_DUPLICATE 25 | SEQ_DUPLICATE 25 | match |
| T4 | A2b | CHECKPOINT_DIVERGENCE 30 | CHECKPOINT_DIVERGENCE 30 | match |
| T5 | A2a | HASH_MISMATCH 22 | HASH_MISMATCH 22 | match |
| T5 | A2b | TS_REGRESSION 23 | TS_REGRESSION 23 | match |
| T6a | A2b | TSA_TIME_INCONSISTENT 30 | TSA_TIME_INCONSISTENT 30 | match |
| T6b | A2b | not detected without external custody: anchored 0..40, tail 41..50 | exit 0; VERIFIED_ANCHORED 0..40; VALID_UNANCHORED 41..50 | match |
| T7 | A2b | degraded coverage: anchored 0..20, tail 21..50 | exit 0; VERIFIED_ANCHORED 0..20; VALID_UNANCHORED 21..50 | match |
| X1 | — | exit 0; coverage drops to VERIFIED_ANCHORED 0..20, VALID_UNANCHORED 21..50; diagnostics ANCHOR_EVIDENCE_MISSING 30 and 40 | exit 0; VERIFIED_ANCHORED 0..20; VALID_UNANCHORED 21..50; ANCHOR_EVIDENCE_MISSING 30; ANCHOR_EVIDENCE_MISSING 40 | match |
| X2 | — | exit 0; VERIFIED_ANCHORED 0..40, VALID_UNANCHORED 41..50. Expected and not a detection: it demonstrates section 3.3, item 9 | exit 0; VERIFIED_ANCHORED 0..40; VALID_UNANCHORED 41..50 | match |

Primary M1 results matched: 15/15 (A2a 6/6, A2b 9/9). X1: match. X2: match.

## Additional §7 vectors run on the frozen fixture

| Vector | Specified | Measured | Result |
| --- | --- | --- | --- |
| control-metadata: final control altered, tail recomputed | CHECKPOINT_METADATA_MISMATCH at that control (41) | CHECKPOINT_METADATA_MISMATCH 41 | match |
| control-metadata: impossible target at the final control | CONTROL_EVENT_INVALID only after packages pass (41) | CONTROL_EVENT_INVALID 41 | match |
| control-metadata: renumbered T2 still fails divergence first | CHECKPOINT_DIVERGENCE 30 | CHECKPOINT_DIVERGENCE 30 | match |
| receipt revalidation: frozen and replacement receipts under the profile | every receipt passes TEAR-TSA-01 Steps 2.2–2.4 | frozen 10: ok; frozen 20: ok; frozen 30: ok; frozen 40: ok; T6a-30: ok; T6a-40: ok; T6b-30: ok; T6b-40: ok | match |
| T6a precondition: original timestamps more than 10 minutes old when the fresh receipts were issued | genTime - ts > 10 min for 30 and 40 | 30: +2352 s; 40: +2350 s | match |
| bundle custody (auditor procedure, outside tear-verify) | only the bundle matching the published fingerprint passes | pinned: pass; variant: fail | match |
