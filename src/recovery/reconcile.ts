// SPDX-License-Identifier: AGPL-3.0-or-later
// Start-up reconciliation (Blueprint §5.6), run by the writer under exclusion
// before it accepts traffic. Step 1 (full validation) has already run. This
// module performs step 2 (inventory, .tmp deletion in the base profile), the
// classification and exactly the action §5.6 assigns to the state; E3, E6 and
// E10 fail closed. Nothing else is cleaned or repaired. Any filesystem or SQL
// failure aborts start-up without accepting traffic. The directory durability
// barrier runs before traffic in every profile, including from E1.

import { commitControl, runAnchorFlow } from '../anchor/flow.js';
import type { AnchorFlowDeps } from '../anchor/flow.js';
import type { ChainView, RecoveryClassifier, RecoveryState } from '../chain/interfaces.js';
import { permitsAutomaticRecovery } from '../chain/profile.js';
import type { CutProfile } from '../chain/profile.js';
import type { ChainState } from '../chain/state.js';
import { TearError } from '../errors.js';
import { inventoryNamespace } from '../fs/inventory.js';
import type { NamespaceEntry } from '../fs/inventory.js';
import { newJsonObject } from '../json/strict-json.js';
import { validPackage } from './classifier.js';

export const CLEAR_PENDING_ONLY_SQL = `UPDATE tear_chain_state
  SET pending_anchor_seq = NULL, pending_entry_hash = NULL, pending_ts = NULL, pending_mode = NULL
  WHERE chain_id = $1::uuid AND pending_anchor_seq = $2::bigint
  RETURNING chain_id`;

export interface ReconcileDeps extends AnchorFlowDeps {
  readonly nsPath: string;
  readonly profile: CutProfile;
  readonly classifier: RecoveryClassifier;
  /** The validated state row; updated by the caller after reconciliation. */
  readonly state: ChainState;
  readonly view: (state: ChainState, entries: readonly NamespaceEntry[]) => ChainView;
  /** Reloads the state row on writerConn after a repair. */
  readonly reloadState: () => Promise<ChainState>;
}


export interface ReconcileResult {
  /** The state found at start-up (after .tmp deletion). */
  readonly from: RecoveryState;
  /** The state row after reconciliation (pending cleared). */
  readonly state: ChainState;
}

function inconsistent(reason: string): TearError {
  return new TearError('RECONCILIATION_STATE_INCONSISTENT', reason);
}

async function classify(d: ReconcileDeps, state: ChainState, entries: readonly NamespaceEntry[]): Promise<RecoveryState> {
  const c = await d.classifier.classify(d.view(state, entries));
  if (c.kind === 'inconsistent') throw inconsistent(c.reason);
  return c.state;
}

async function clearPending(d: ReconcileDeps, k: number): Promise<void> {
  if (d.conn.invalidated) throw new TearError('WRITER_INVALIDATED');
  let cleared = 0;
  const outcome = await d.conn.mutate(async () => {
    cleared = (await d.conn.query(CLEAR_PENDING_ONLY_SQL, [d.chainId, String(k)])).length;
    if (cleared !== 1) throw inconsistent('pending anchor not set');
  });
  if (outcome !== 'committed') {
    const cause = new TearError(outcome === 'unknown' ? 'COMMIT_OUTCOME_UNKNOWN' : 'COMMIT_ROLLED_BACK', `clear pending ${String(k)}`);
    d.fatal(cause);
    throw cause;
  }
}

const present = (entries: readonly NamespaceEntry[], names: string[]): string[] =>
  names.filter((n) => entries.some((e) => e.name === n));

/**
 * Runs §5.6 for the current namespace and state. Returns the state found;
 * throws on a fail-closed state or on any failure (start-up is then aborted).
 */
export async function reconcile(d: ReconcileDeps): Promise<ReconcileResult> {
  let entries = inventoryNamespace(d.nsPath);
  const automatic = permitsAutomaticRecovery(d.profile);

  // Step 2: .tmp files. Base: durable delete before state selection. Cut 3: any .tmp or .tsq fails.
  const tmp = entries.filter((e) => e.temporary);
  if (!automatic) {
    if (tmp.length > 0 || entries.some((e) => e.kind === 'tsq') || d.state.pending !== null) {
      throw inconsistent(`${d.profile}: residue or a pending anchor needs operator intervention`);
    }
  } else if (tmp.length > 0) {
    await d.files.durableDelete(tmp.map((e) => ({ name: e.name, optional: false })));
    entries = inventoryNamespace(d.nsPath);
  }

  const from = await classify(d, d.state, entries);
  if (!automatic && from !== 'E1') throw inconsistent(`${d.profile}: only a clean E1 state starts`);

  const pending = d.state.pending;
  const k = pending?.anchorSeq ?? 0;
  const kNames = [`${String(k)}.tsq`, `${String(k)}.tsr`, `${String(k)}.anchor.json`];
  switch (from) {
    case 'E1':
      break;
    case 'E2': {
      const tsq = entries.find((e) => e.kind === 'tsq')!;
      await d.files.durableDelete([{ name: tsq.name, optional: false }]);
      break;
    }
    case 'E4':
      await d.files.recoveredPackageBarrier([`${String(k)}.tsr`, `${String(k)}.anchor.json`]);
      await clearPending(d, k);
      await d.files.durableDelete(present(entries, [`${String(k)}.tsq`]).map((name) => ({ name, optional: false })));
      break;
    case 'E5':
      await d.files.durableDelete(present(entries, kNames).map((name) => ({ name, optional: false })));
      await clearPending(d, k);
      break;
    case 'E7': {
      const pkg = validPackage(d.view(d.state, entries), BigInt(k));
      if (pkg === null) throw inconsistent('E7 package no longer valid');
      await d.files.recoveredPackageBarrier([`${String(k)}.tsr`, `${String(k)}.anchor.json`]);
      const payload = newJsonObject();
      payload['event_type'] = 'checkpoint_anchored';
      payload['operation'] = 'tear.checkpoint';
      payload['anchored_seq'] = k;
      payload['tsr_sha256'] = pkg.tsrSha256;
      payload['tsa_gen_time'] = pkg.genTime;
      await commitControl(d, k, payload);
      await d.files.durableDelete(present(entries, [`${String(k)}.tsq`]).map((name) => ({ name, optional: false })));
      break;
    }
    case 'E8':
      await d.files.durableDelete(present(entries, kNames).map((name) => ({ name, optional: false })));
      await runAnchorFlow(d, { seq: k, entryHash: pending!.entryHash, ts: pending!.ts });
      break;
    case 'E9': {
      await d.files.durableDelete(present(entries, kNames).map((name) => ({ name, optional: false })));
      const payload = newJsonObject();
      payload['event_type'] = 'checkpoint_failed';
      payload['operation'] = 'tear.checkpoint';
      payload['target_seq'] = k;
      payload['error_type'] = 'anchor_window_expired';
      await commitControl(d, k, payload);
      break;
    }
    default:
      throw inconsistent(`state ${from}`);
  }

  // Success requires a clean E1 afterwards: no pending, no .tmp or .tsq, every package confirmed.
  const after = inventoryNamespace(d.nsPath);
  if (after.some((e) => e.temporary || e.kind === 'tsq')) throw inconsistent('residue after reconciliation');
  const finalState = from === 'E1' || from === 'E2' ? d.state : await d.reloadState();
  if (finalState.pending !== null) throw inconsistent('pending anchor after reconciliation');
  if ((await classify(d, finalState, after)) !== 'E1') throw inconsistent('not E1 after reconciliation');

  // Directory durability barrier before accepting traffic, from every state including E1.
  await d.files.directoryBarrier();
  return { from, state: finalState };
}
