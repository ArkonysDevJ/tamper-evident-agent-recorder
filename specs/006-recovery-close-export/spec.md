# Spec 006 — Recovery, close and evidence package

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the test
that proves it.

## 1. Objective

Make the namespace durable under crashes: durable publish and delete, start-up reconciliation E1–E10,
`closeChain` B0–B3, the evidence package for offline verification, and fault injection at each barrier.

## 2. Blueprint sections

§5.5, §5.6, §5.8, §5.3 (evidence package for offline verification), §8 (Cut 2 and Cut 3 profiles).

## 3. Out of scope

- The TSA flow itself (§5.7) — spec 003.
- `initializeChain` (§5.3a) and SQL export (§5.3) — spec 001.
- The final report — spec 007.

## 4. Acceptance criteria

| ID | Criterion | Blueprint | Test |
| --- | --- | --- | --- |
| AC-1 | Publish and durable delete follow the §5.5 call sequence, each guarded by the invalidation barrier. | §5.5 | `006 AC-1 publish-and-delete` |
| AC-2 | Any filesystem mutation failure invalidates, drains and exits; pending state is unchanged and no cleanup starts. | §5.5 | `006 AC-2 mutation-failure` |
| AC-3 | The recovered-package durability barrier runs before an E4 or E7 success transition; its failure aborts without clearing pending. | §5.5 | `006 AC-3 recovered-package-barrier` |
| AC-4 | Reconciliation steps 1–2: full validation, namespace inventory by `lstat`, temporary files deleted in the base profile; unknown names or entry types fail closed. | §5.6 steps 1–2 | `006 AC-4 inventory-and-cleanup` |
| AC-5 | Steps 3–4: every package outside the pending one matches a committed control and vice versa; missing committed evidence fails closed in base and Cut 3. | §5.6 steps 3–4, §7 (missing committed package) | `006 AC-5 committed-packages` |
| AC-6 | Each state E1–E10 is reached by a constructed case and produces exactly its §5.6 action. | §5.6 step 5 | `006 AC-6 states-E1-E10` |
| AC-7 | The chain directory is fsynced before traffic is accepted from any reconciled state; an injected failure aborts start-up. | §5.6, §7 (E1 durability barrier) | `006 AC-7 startup-dir-barrier` |
| AC-8 | Kill after `anchor.json` rename and before the directory fsync; recovery runs the file and directory barriers before the success commit; a failure injected at each barrier and at request deletion produces no next append and no success. | §5.6, §7 (E7) | `006 AC-8 e7-crash` |
| AC-9 | A sealed chain refuses application events with `CHAIN_SEALED` and still accepts `closeChain`. | §5.6, §5.8 | `006 AC-9 sealed-chain` |
| AC-10 | `closeChain` waits for a pending anchor, seals durably, and returns the B0–B3 result for each branch; a repeated close after restart on a sealed chain is accepted. | §5.8, §7 | `006 AC-10 close-branches` |
| AC-11 | B2 and B3 acceptance depends only on the signed `genTime` against the anchored row's `ts`, not on the host clock. | §5.8, §3.3 item 10 | `006 AC-11 close-time-predicate` |
| AC-12 | The evidence package copies only complete `.tsr` + `.anchor.json` pairs before the export; a package published after the copy yields `ANCHOR_EVIDENCE_MISSING`, exit 0. | §5.3 (evidence package) | `006 AC-12 evidence-package` |
| AC-13 | Under Cut 2 B3 never starts; under Cut 3 no cleanup or repair runs and only a clean-E1-equivalent state starts. | §8, §7 | `006 AC-13 cut-profiles` |

## 5. Dependencies

Specs 001 and 003.
