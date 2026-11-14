// SPDX-License-Identifier: AGPL-3.0-or-later
// Automatic anchor trigger (Blueprint §5.7): in the same SQL transaction as
// application record k, with k > 0, k % 10 == 0 and k <= max_auto_anchor_seq,
// set the pending fields with mode "auto". The writer calls the hook for
// application events only, so control events never trigger.

import { TearError } from '../errors.js';
import type { AnchorHook } from '../chain/interfaces.js';

export const SET_PENDING_SQL = `UPDATE tear_chain_state
  SET pending_anchor_seq = $2::bigint, pending_entry_hash = $3, pending_ts = $4, pending_mode = $5
  WHERE chain_id = $1::uuid AND pending_anchor_seq IS NULL
  RETURNING chain_id`;

export function triggersAutoAnchor(seq: number, maxAutoAnchorSeq: number): boolean {
  return seq > 0 && seq % 10 === 0 && seq <= maxAutoAnchorSeq;
}

/** The writer's default hook. maxAutoAnchorSeq is Infinity in production; the frozen fixture caps it at 40. */
export function autoAnchorHook(maxAutoAnchorSeq: number = Number.POSITIVE_INFINITY): AnchorHook {
  return {
    async onApplicationCommit(ctx) {
      if (!triggersAutoAnchor(ctx.seq, maxAutoAnchorSeq)) return null;
      const rows = await ctx.query(SET_PENDING_SQL, [ctx.chainId, String(ctx.seq), ctx.entryHash, ctx.ts, 'auto']);
      if (rows.length !== 1) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'pending anchor already set');
      return { seq: ctx.seq, entryHash: ctx.entryHash, ts: ctx.ts };
    },
  };
}
