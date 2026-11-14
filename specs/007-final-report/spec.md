# Spec 007 — Final report

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the check
that proves it.

## 1. Objective

Write the final report that states what was built, what was measured and what was not tested, as §9 requires.

## 2. Blueprint sections

§9, §8 (cut profiles applied).

## 3. Out of scope

- Producing the results it reports — specs 001 to 006.

## 4. Acceptance criteria

Each check confirms that the report contains the item; it does not judge the results.

| ID | The report states | Blueprint | Check |
| --- | --- | --- | --- |
| AC-1 | The M1 table as measured, including "not detected" and degraded-coverage rows. | §9, §7 | `007 AC-1 m1-table` |
| AC-2 | What VERIFIED_ANCHORED means, with the receipt-derived accuracy bound or "unspecified". | §9, §3.3 item 3 | `007 AC-2 anchored-meaning` |
| AC-3 | That deleting packages can reduce coverage and emits `ANCHOR_EVIDENCE_MISSING`, and that corrupt evidence is a hard failure. | §9 | `007 AC-3 evidence-loss` |
| AC-4 | The external-custodian simulation, the custody assumptions of T6b and T7, and the offline-only, no-revocation certificate profile. | §9 | `007 AC-4 custody` |
| AC-5 | The tests performed on one host, the effective SQL durability settings (including `full_page_writes`), the storage assumptions and the §5.4 deployment invariants. | §9, §5.4 | `007 AC-5 host-and-durability` |
| AC-6 | The published bundle fingerprint, its channel, and the root and signer checks. | §9, §3.3 item 9 | `007 AC-6 bundle-custody` |
| AC-7 | Every cut profile activated. | §9, §8 | `007 AC-7 cut-profiles` |
| AC-8 | Every requirement not exercised by an executed test, listed as "not tested", with the §10 known debt; failed tests listed as failed. | §9, §10 | `007 AC-8 not-tested` |
| AC-9 | M3 as measured, met or not, or "unmeasured" under Cut 1. | §7 (M3), §8 | `007 AC-9 m3` |
| AC-10 | Under "not tested / known debt", at least: the `ESSCertIDv2` vector with an explicitly encoded default SHA-256 identifier (excluded from the battery because it conflicts with DER); whether a root's own `pathLenConstraint` counts; optional CMS SignedData fields (other CertificateChoices, crls, unsignedAttrs, sid form); the three unpinned first-failure placements (duplicate `seq` keys, a later row with seq=0 carrying an application event, `anchor.block` schema at Step 2.1 versus 2.6); the integer rule by value (`10.0`, `1e1`). | §10 | `007 AC-10 known-debt-entries` |
| AC-11 | Every implementation choice recorded in the specs for points §10 leaves open, marked as not normative. | §10 | `007 AC-11 implementation-choices` |
| AC-12 | Under "not tested", at least these partly exercised spec 001 criteria, each with the part that was tested: **001 AC-9** — the xfs magic (`0x58465342`) is accepted only through a stubbed `statfs` (tested: real `statfs` on ext4 accepted, tmpfs rejected, stubbed overlayfs and nfs rejected); **001 AC-12** — rejection of pooled or secondary mutations, transparent reconnect and prepared transactions holds by construction, with no test that attempts them (tested: every statement on the lock-owning backend, no reconnect after the session ends, successor blocked until the prior backend releases its lock, for committed and rolled-back in-flight work); **001 AC-15** — loss of `fsync`, `full_page_writes` or `wal_level` is tested only in the decision function, since the server settings are not changed in tests (tested: the decision for each setting, and a live session with `synchronous_commit` turned off refused before any write and invalidated). | §9, §5.1, §5.3, §5.4 | `007 AC-12 partly-tested-data-core` |
| AC-13 | Under "not tested", at least this partly exercised spec 002 criterion, with the part that was tested: **002 AC-1** — the §6b input loading order is only partly observable, because every invocation or access failure prints the same `INPUT_UNAVAILABLE 0`; bundle grammar and profile loading are not applied by the local verifier (tested: an invalid namespace fails even when the log is also missing; missing, non-directory or misnamed namespace, missing, unreadable or directory log, and missing bundle each give `INPUT_UNAVAILABLE 0`, exit 2, empty stderr). | §9, §6b | `007 AC-13 partly-tested-verifier` |
| AC-14 | Under known limits: the hash covers the canonical block; whitespace in the row envelope (including CR before LF) does not change the verification result. | §9, §4.3, §6 Step 1 | `007 AC-14 envelope-whitespace` |
| AC-15 | Under "not tested", at least these partly exercised spec 008 points, each with the part that was tested: real power loss and the device flush order (tested: the call order of each primitive and its fault handling on ext4); real disk I/O errors (tested: failures injected through an `fs` double at every mutating call); `O_CLOEXEC` on namespace files, which Node.js sets through libuv without exposing the flag (tested: descriptor inheritance for the writer lock only); process exit after a mutation failure: the writer's default exit is not run by any test, which injects the exit step instead (tested: invalidation, refusal of later work, a single call to the drain-and-exit handler, and release of writerConn and flock before it). | §9, §5.4, §5.5 | `007 AC-15 partly-tested-file-primitives` |
| AC-16 | A mandatory statement that the ASN.1 DER reader is written in this repository and is a trust surface of its own: tested with negative vectors for every rejection rule and checked against `openssl` on every real receipt and certificate, with no external review. | §9, §6a | `007 AC-16 der-reader-trust-surface` |
| AC-17 | Under "not tested", at least these partly exercised spec 003 points, each with the part that was tested: real TSA failures (timeouts, HTTP errors, rejections) are produced only by test TSAs and a local HTTP server (tested: every §5.7 step 2 and step 3 failure and the fallback order); the fallback to DigiCert with real receipts happened only after a primary failure forced locally while building the fixture; the 5000 ms timeout is exercised only with a shorter timeout against a local server; accuracy and GRANTED_WITH_MODS appear only in constructed receipts, since the real receipts omit accuracy and were granted; the recoverer's use of the profile (spec 006) is not tested yet (tested: the writer and the verifier share the same receipt checks). | §9, §5.7, §6a | `007 AC-17 partly-tested-anchoring` |
| AC-18 | Under known limits: the DER order of the SignedData certificate set is not enforced, because the real DigiCert receipts carry that set out of DER order; every other SET OF, including the signed attributes whose DER encoding the signature covers, must be in DER order. | §9, §6a | `007 AC-18 certificate-set-order` |
| AC-19 | That the real receipts of the frozen fixture (FreeTSA and DigiCert) carry no `accuracy`, so the reported receipt accuracy is "accuracy unspecified" rather than a policy value. | §9, §3.3 item 3 | `007 AC-19 accuracy-unspecified` |

## 5. Dependencies

Specs 001 to 006 and 008.
