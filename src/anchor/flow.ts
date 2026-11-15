// SPDX-License-Identifier: AGPL-3.0-or-later
// TSA flow for anchor k (Blueprint §5.7 steps 1–6), run by the writer inside
// the queue slot of the append that set the pending anchor, so no other append
// or close starts until the pending fields are cleared (§5.3 layer 3).
//
// TSA failures (timeout, network, HTTP status, undecodable or not granted
// response, any step 3 check) move the same .tsq to the next retained TSA.
// Writer invalidation, filesystem errors and SQL errors are never TSA
// failures: they abort through the drain-and-exit protocol (§5.5, §5.7 step 6).

import { TearError } from '../errors.js';
import type { PendingAnchor } from '../chain/interfaces.js';
import { INSERT_EVENT_SQL } from '../chain/initialize.js';
import type { Block } from '../chain/schema.js';
import type { Step1Checker } from '../chain/step1.js';
import { entryHashOf, sha256Hex } from '../crypto/digests.js';
import type { WriterConn } from '../db/writer-conn.js';
import type { DurableNamespace } from '../fs/durable.js';
import { canonicalize } from '../json/jcs.js';
import { newJsonObject } from '../json/strict-json.js';
import type { JsonObject } from '../json/strict-json.js';
import type { LoadedBundle } from '../pki/bundle.js';
import { parseTimestampNs, writerTimestamp } from '../time/timestamps.js';
import { checkReceipt, timePredicate } from '../tsa/receipt.js';
import { newTimeStampRequest } from '../tsa/request.js';
import type { TsaEndpoint } from '../tsa/transport.js';
import { anchorPackageBytes } from './package.js';

export const CLEAR_PENDING_SQL = `UPDATE tear_chain_state
  SET pending_anchor_seq = NULL, pending_entry_hash = NULL, pending_ts = NULL, pending_mode = NULL
  WHERE chain_id = $1::uuid AND pending_anchor_seq = $2::bigint
  RETURNING chain_id`;

/** Why one TSA attempt failed (§5.7 step 2 and step 3). */
export type TsaFailureKind = 'unreachable' | 'rejected' | 'validation_failed';

export interface TsaAttempt {
  readonly tsa: string;
  readonly outcome: 'accepted' | TsaFailureKind;
  readonly detail: string;
}

export type AnchorOutcome =
  | { readonly kind: 'anchored'; readonly k: number; readonly tsa: string; readonly attempts: readonly TsaAttempt[] }
  | { readonly kind: 'failed'; readonly k: number; readonly errorType: string; readonly attempts: readonly TsaAttempt[] };

/**
 * Implementation choice (not normative; §5.7 step 5 leaves the vocabulary
 * open): error_type names the failure of the last retained TSA.
 */
export const ERROR_TYPE: Readonly<Record<TsaFailureKind, string>> = {
  unreachable: 'tsa_unreachable',
  rejected: 'tsa_rejected',
  validation_failed: 'tsa_validation_failed',
};

export interface AnchorFlowDeps {
  readonly chainId: string;
  readonly conn: WriterConn;
  readonly files: DurableNamespace;
  readonly checker: Step1Checker;
  readonly bundle: LoadedBundle;
  readonly tsas: readonly TsaEndpoint[];
  readonly clock: () => number;
  /** Starts drain-and-exit after an SQL failure (filesystem failures start it in DurableNamespace). */
  readonly fatal: (cause: unknown) => void;
  readonly random?: (n: number) => Uint8Array;
}

function requireActive(conn: WriterConn): void {
  if (conn.invalidated) throw new TearError('WRITER_INVALIDATED', 'writer invalidated during the TSA flow');
}

/** Builds the control row at k+1, admits it under Step 1 and commits it with the pending clear (one transaction). */
export async function commitControl(d: AnchorFlowDeps, k: number, payload: JsonObject): Promise<void> {
  const head = d.checker.head;
  if (head === undefined || head.block.seq !== k) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'head moved');
  const block = newJsonObject() as Block;
  block['chain_id'] = d.chainId;
  block['seq'] = k + 1;
  block['ts'] = writerTimestamp(d.clock(), head.block.ts);
  block['prev_hash'] = head.entryHash;
  block['payload'] = payload;
  const entryHash = entryHashOf(block);
  const envelope = newJsonObject();
  envelope['block'] = block;
  envelope['entry_hash'] = entryHash;
  const rejection = d.checker.check({ kind: 'json', value: envelope });
  if (rejection !== null) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', `control row ${rejection.code}`);
  requireActive(d.conn);
  let cleared = 0;
  const outcome = await d.conn.mutate(async () => {
    await d.conn.query(INSERT_EVENT_SQL, [
      d.chainId,
      String(k + 1),
      block.ts,
      block.prev_hash,
      canonicalize(payload),
      canonicalize(block),
      entryHash,
    ]);
    cleared = (await d.conn.query(CLEAR_PENDING_SQL, [d.chainId, String(k)])).length;
    if (cleared !== 1) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'pending anchor not set');
  });
  if (outcome !== 'committed') {
    const cause = new TearError(
      outcome === 'unknown' ? 'COMMIT_OUTCOME_UNKNOWN' : 'COMMIT_ROLLED_BACK',
      `checkpoint transition for anchor ${String(k)}`,
    );
    d.fatal(cause);
    throw cause;
  }
  if (d.checker.accept({ kind: 'json', value: envelope }) !== null) {
    const cause = new TearError('RECONCILIATION_STATE_INCONSISTENT', 'committed control row failed Step 1');
    d.fatal(cause);
    throw cause;
  }
}

/** Runs the whole flow for the pending anchor; resolves with its outcome or rejects after an abort. */
export async function runAnchorFlow(d: AnchorFlowDeps, pending: PendingAnchor): Promise<AnchorOutcome> {
  const k = pending.seq;
  const blockTsNs = parseTimestampNs(pending.ts);
  if (blockTsNs === null) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'pending ts');

  // Step 1: nonce, DER request, durable <k>.tsq.
  const req = newTimeStampRequest(pending.entryHash, d.random);
  requireActive(d.conn);
  await d.files.publish(`${String(k)}.tsq`, req.der);

  // Steps 2 and 3: primary, then secondary on any TSA failure.
  const attempts: TsaAttempt[] = [];
  let accepted: { tsr: Uint8Array; genTime: string; tsa: string } | null = null;
  for (const tsa of d.tsas) {
    requireActive(d.conn);
    const res = await tsa.request(req.der);
    requireActive(d.conn);
    if (res.kind === 'failure') {
      attempts.push({
        tsa: tsa.name,
        outcome: res.reason === 'http_status' ? 'rejected' : 'unreachable',
        detail: `${res.reason} ${res.detail}`,
      });
      continue;
    }
    const check = checkReceipt(res.body, d.bundle, pending.entryHash, req.nonceHex);
    if (!check.ok) {
      const decodeOrStatus = check.code === 'TSA_SIGNATURE_INVALID' && check.reason.startsWith('PKIStatus');
      attempts.push({ tsa: tsa.name, outcome: decodeOrStatus ? 'rejected' : 'validation_failed', detail: `${check.code} ${check.reason}` });
      continue;
    }
    if (!timePredicate(check.genTimeNs, blockTsNs)) {
      attempts.push({ tsa: tsa.name, outcome: 'validation_failed', detail: 'TSA_TIME_INCONSISTENT' });
      continue;
    }
    attempts.push({ tsa: tsa.name, outcome: 'accepted', detail: check.receipt.tstInfo.genTime });
    accepted = { tsr: res.body, genTime: check.receipt.tstInfo.genTime, tsa: tsa.name };
    break;
  }

  if (accepted !== null) {
    // Step 4: publish .tsr, then .anchor.json, then the atomic checkpoint transition, then delete .tsq.
    requireActive(d.conn);
    await d.files.publish(`${String(k)}.tsr`, accepted.tsr);
    const block = d.checker.accepted[k]?.block;
    if (block === undefined) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'anchored row missing');
    await d.files.publish(
      `${String(k)}.anchor.json`,
      anchorPackageBytes({
        chainId: d.chainId,
        anchoredSeq: k,
        entryHash: pending.entryHash,
        block,
        nonceHex: req.nonceHex,
        tsqSha256: req.derSha256,
      }),
    );
    const payload = newJsonObject();
    payload['event_type'] = 'checkpoint_anchored';
    payload['operation'] = 'tear.checkpoint';
    payload['anchored_seq'] = k;
    payload['tsr_sha256'] = sha256Hex(accepted.tsr);
    payload['tsa_gen_time'] = accepted.genTime;
    await commitControl(d, k, payload);
    await d.files.durableDelete([{ name: `${String(k)}.tsq`, optional: false }]);
    return { kind: 'anchored', k, tsa: accepted.tsa, attempts };
  }

  // Step 5: the last retained TSA failed, before any package publication.
  const last = attempts[attempts.length - 1];
  const errorType = last === undefined ? ERROR_TYPE.unreachable : ERROR_TYPE[last.outcome as TsaFailureKind];
  const payload = newJsonObject();
  payload['event_type'] = 'checkpoint_failed';
  payload['operation'] = 'tear.checkpoint';
  payload['target_seq'] = k;
  payload['error_type'] = errorType;
  await commitControl(d, k, payload);
  await d.files.durableDelete([{ name: `${String(k)}.tsq`, optional: false }]);
  return { kind: 'failed', k, errorType, attempts };
}
