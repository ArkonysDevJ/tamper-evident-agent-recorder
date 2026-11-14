# Spec 003 — Anchoring and the TEAR-TSA-01 profile

Normative source: `docs/BLUEPRINT.md`. This spec only points to it. Each acceptance criterion names the test
that proves it.

## 1. Objective

Anchor the chain with RFC 3161 under the fixed TEAR-TSA-01 profile, verify anchor packages offline (Steps 2,
2b and 3), and build the frozen M1 fixture with real receipts.

## 2. Blueprint sections

§5.7, §6 (Step 2, Step 2b, Step 3), §6a, §7 (frozen fixture).

## 3. Out of scope

- Publish, durable delete and the durability barriers (§5.5) — spec 008.
- Recovery of interrupted anchors (§5.6) and `closeChain` (§5.8) — spec 006.
- Running the tamper matrix (§7 M1, X1, X2) — spec 004.
- The §7 vector with an explicitly encoded default SHA-256 `ESSCertIDv2` identifier: §10 declares that it
  conflicts with DER, so it is not part of the test battery. Spec 007 lists it as known debt.

## 4. Acceptance criteria

| ID | Criterion | Blueprint | Test |
| --- | --- | --- | --- |
| AC-1 | The nonce is 8 CSPRNG bytes with the §5.7 bit forcing, in range, formatted as 16 lowercase hex. | §5.7 step 1, §4.5 | `003 AC-1 nonce` |
| AC-2 | The TimeStampReq DER has exactly the §5.7 fields, no `reqPolicy` and no extensions; `tsq_der_sha256` is its digest. | §5.7 step 1, §6a | `003 AC-2 request-der` |
| AC-3 | Connected to the spec 001 anchor hook, pending fields are set in the same transaction as application record k only when k > 0, k % 10 == 0 and k <= `max_auto_anchor_seq`; control events never trigger. | §5.7 | `003 AC-3 auto-trigger` |
| AC-4 | While an anchor is pending, no other append or close starts. | §5.3 layer 3, §5.7 | `003 AC-4 pending-blocks-queue` |
| AC-5 | Each §5.7 step 2 failure condition moves the same `.tsq` to the secondary; writer, filesystem and SQL errors never trigger fallback; with one retained TSA there is no fallback. | §5.7 step 2 | `003 AC-5 fallback` |
| AC-6 | On success the `.tsr` and `.anchor.json` are published, the control row and pending clear commit atomically, then the `.tsq` is durably deleted, in that order. | §5.7 step 4 | `003 AC-6 success-path` |
| AC-7 | When the last retained TSA fails, `checkpoint_failed` and pending clear commit atomically; any non-empty `error_type` in the payload domain is accepted. | §5.7 step 5 | `003 AC-7 failure-path` |
| AC-8 | A filesystem or SQL failure at any stage invalidates and exits without a new resolution or cleanup, and is never reclassified as a TSA failure. | §5.7 step 6, §5.5 | `003 AC-8 publication-failure` |
| AC-9 | `genTime` grammar and the inclusive `[-5 s, +60 s]` predicate give `TSA_TIME_FORMAT_INVALID` and `TSA_TIME_INCONSISTENT` at the boundaries; the 5000 ms network timeout is independent of the predicate. | §5.7 | `003 AC-9 time-rules` |
| AC-10 | Bundle grammar vectors fail loading with `INPUT_UNAVAILABLE 0`, exit 2; LF and CRLF between blocks both load. | §6a, §7 (bundle grammar) | `003 AC-10 bundle-grammar` |
| AC-11 | Role derivation and loading checks; roots with correct and incorrect self-signatures both load; loading fails for a self-issued certificate without CA=true, no root or no signer, disallowed keys, disallowed critical extensions or invalid DER. Loading uses no network and no system trust store. | §6a, §7 (root loading) | `003 AC-11 bundle-loading` |
| AC-12 | Inventory vectors (directory, symlink, FIFO, unreadable entry, noncanonical and oversized filenames, unpaired files) give `ANCHOR_PACKAGE_INCOMPLETE` with the deterministic parameter. | §6 Step 2, §7 (inventory) | `003 AC-12 inventory` |
| AC-13 | Step 2.1 package schema and identity failures → `ANCHOR_PACKAGE_INCOMPLETE <k>`. | §6 Step 2.1, §4.5 | `003 AC-13 package-schema` |
| AC-14 | Step 2.2 structural rules, including the DER `genTime` edge cases, the CMS digest-set vectors and a critical TSTInfo extension, with structural precedence over `genTime` syntax. | §6 Step 2.2, §6a, §7 (digest-set, extension) | `003 AC-14 structure` |
| AC-15 | Step 2.3 signature, ESS binding (legacy and v2), signer identity and path acceptance, including the pinned-profile, TEAR-TSA-01 and extension vectors → `TSA_SIGNATURE_INVALID <k>`. | §6 Step 2.3, §6a, §7 | `003 AC-15 signature-and-path` |
| AC-16 | Step 2.4 `messageImprint` and nonce → `ANCHOR_COMMITMENT_MISMATCH <k>`; absent and NULL parameters are equivalent for SHA-256. | §6 Step 2.4, §6a, §7 | `003 AC-16 commitment` |
| AC-17 | Steps 2.5, 2.6 and 2.7 → `TRUNCATED_BELOW_ANCHOR`, `CHECKPOINT_DIVERGENCE`, `TSA_TIME_INCONSISTENT`. | §6 Step 2.5–2.7 | `003 AC-17 log-relations` |
| AC-18 | Step 2b runs only after all packages pass Step 2: `CONTROL_EVENT_INVALID` before `CHECKPOINT_METADATA_MISMATCH`; a missing package skips receipt equality. | §6 Step 2b, §7 (control metadata) | `003 AC-18 control-relations` |
| AC-19 | Step 3 coverage and informational lines for zero, one and several anchors; `ANCHOR_TIME` with accuracy present and absent. | §6 Step 3, §6b | `003 AC-19 coverage` |
| AC-20 | Verification uses only the log, the namespace, the bundle and certificates embedded in each `.tsr`: no network, OS trust store, AIA, OCSP or CRL. | §6 Step 2.3, §6a | `003 AC-20 closed-inputs` |
| AC-21 | When a profile defect and a later defect occur in one package, the first-failure stage is reported. | §7 | `003 AC-21 stage-precedence` |
| AC-22 | The writer and recoverer accept a receipt only under the same profile rules as the verifier. | §6a | `003 AC-22 writer-profile` |
| AC-23 | The frozen fixture meets every §7 fixture bullet, is built only from real retained TSAs, records exact bytes, serials, `genTime` and accuracy in its manifest, and verifies to `VERIFIED_ANCHORED 0..40`, `VALID_UNANCHORED 41..50`. Receipts are never regenerated during verification. | §7 (frozen fixture), §5.7 step 2 | `003 AC-23 frozen-fixture` |

## 5. Dependencies

Specs 001, 002 and 008.

## Implementation choices (not normative)

The Blueprint leaves these to the implementation (§10). They are recorded here and declared in the report of
the work package that implements them.

- **Transport per TSA:** HTTP POST of the DER `.tsq` with `Content-Type: application/timestamp-query`
  (RFC 3161 §3.4). Primary `https://freetsa.org/tsr`, secondary `http://timestamp.digicert.com`, in the
  §5.7 order. The URLs were checked on 2026-11-14: both answered a request with a granted response. The response
  `Content-Type` plays no part in acceptance; only the §5.7 step 2 and step 3 checks do.
- **`Accuracy.seconds`:** decoded from its DER INTEGER as a `BigInt`; `ACCURACY_NS` and `LATEST_BOUND_NS`
  are computed in `BigInt`, never through `Number`.
- **DER reader:** the ASN.1 DER reader is written in this repository (`src/asn1/der.ts`). It accepts only
  definite lengths in minimal form and single-byte identifiers, and rejects indefinite lengths, non-minimal
  lengths, high tag numbers, end-of-contents octets, trailing bytes and reads outside bounds, with explicit size
  (1 MiB) and depth (32) limits. It returns elements and byte ranges only; each structure is interpreted in its
  own module. Every hash, signature check and key load uses `node:crypto`. It is tested with negative vectors for
  each rejection rule and checked against `openssl` on every real receipt and certificate
  (`npm run test:local`). It is a trust surface of its own, with no external review.
- **SET OF ordering:** the DER ordering of SET OF elements is not enforced. The certificate set of the real
  DigiCert receipts is not in DER order, and signed attributes are verified over their received bytes.
- **Request encoding:** the SHA-256 AlgorithmIdentifier in the TimeStampReq has absent parameters (RFC 5754 §2).
  Both TSAs accepted it.
- **`anchor.block` placement (§10):** Step 2.1 checks `block` only as a JSON object with `seq == k` whose canonical
  hash is `entry_hash`. Its full row schema is checked at Step 2.6, through byte equality with log row k, which
  already passed Step 1.
- **Root `pathLenConstraint` (§10):** a root's own value is not applied; intermediates' values are.
- **Signer keyUsage:** when present, it must set digitalSignature or contentCommitment and no other bit.
- **ESS binding:** the signer is the embedded certificate that every present ESS reference (v1 and v2) identifies
  by its first certificate hash. `issuerSerial`, when present, must carry the signer serial and a directoryName
  equal to the signer's issuer Name. An explicitly encoded SHA-256 `ESSCertIDv2.hashAlgorithm` is accepted, as §6a
  states, although DER would omit it (known debt in §10). The SignerInfo `sid` must identify the same certificate,
  by issuer and serial or by subjectKeyIdentifier.
- **Signed attributes:** required at Step 2.3; any duplicate attribute type is rejected; content-type and
  message-digest must each carry exactly one value.
- **Optional SignedData fields (§10):** other CertificateChoices, `crls` and `unsignedAttrs` are decoded
  structurally and then ignored. The receipts in the frozen fixture carry none of them (see its manifest).
- **DEFAULT values encoded explicitly:** `ordering FALSE`, an Extension `critical FALSE`, basicConstraints
  `cA FALSE` and certificate version v1 break DER and fail decoding.
- **SubjectPublicKeyInfo:** RSA keys must use rsaEncryption with NULL parameters; EC keys must name P-256, P-384 or
  P-521 by OID.
- **Transport limits:** redirects are not followed; responses over 256 KiB are a TSA failure.
- **`checkpoint_failed.error_type`:** `tsa_unreachable` (timeout or network), `tsa_rejected` (HTTP status or PKIStatus
  not granted) or `tsa_validation_failed` (any other step 3 failure), named after the last retained TSA's failure.
- **Append and its anchor:** the append of record k resolves only after its anchor settled (anchored or
  `checkpoint_failed`). If the anchor flow aborts (filesystem or SQL failure, or writer invalidation), that append
  rejects although row k is committed; the caller treats it as unconfirmed (the tool is not run, nothing is
  delivered).
- **Drain-and-exit:** after a fatal anchor failure the writer invalidates writerConn, waits for started namespace
  mutations, closes writerConn, releases flock and exits the process with code 70. The exit step is injectable.
- **Writer start-up:** a bundle that fails loading stops `ChainWriter.open` with `TSA_BUNDLE_UNLOADABLE`.
- **Frozen fixture with both TSAs:** built once by `npm run fixture:build` through the real writer, export and
  evidence-package steps. For anchors 20 and 40 the primary (FreeTSA) is made to fail locally with HTTP 503,
  without contacting it, so the writer's own fallback obtains real DigiCert receipts; anchors 10 and 30 come from
  FreeTSA. Writer start-up uses the clean-E1 test classifier until spec 006. The tool refuses to overwrite an
  existing fixture.
