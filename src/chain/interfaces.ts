// SPDX-License-Identifier: AGPL-3.0-or-later
// Interfaces this package defines and later packages implement.
// - RecoveryClassifier: the E1–E10 classification of Blueprint §5.6, used by
//   initializeChain inspection (§5.3a steps 2–4) and by writer start-up. Its
//   implementation is src/recovery/classifier.ts.
// - AnchorHook: called inside the SQL transaction of every application append,
//   where §5.7 sets the pending anchor. The writer's default is the automatic
//   trigger of src/anchor/trigger.ts; noAnchorHook never sets one.

import type { NamespaceEntry } from '../fs/inventory.js';
import type { LoadedBundle } from '../pki/bundle.js';
import type { ChainState } from './state.js';
import type { CutProfile } from './profile.js';
import type { AcceptedRow } from './step1.js';

export type RecoveryState = 'E1' | 'E2' | 'E3' | 'E4' | 'E5' | 'E6' | 'E7' | 'E8' | 'E9' | 'E10';

/** The validated chain, its state row and a namespace view, as §5.3a step 3 describes. */
export interface ChainView {
  readonly chainId: string;
  readonly nsPath: string;
  readonly rows: readonly AcceptedRow[];
  readonly state: ChainState;
  /** Namespace entries in the view (recognized .tmp files already excluded by inspection). */
  readonly entries: readonly NamespaceEntry[];
  readonly nowNs: bigint;
  readonly profile: CutProfile;
  /** The loaded bundle, to validate packages under TEAR-TSA-01 (§5.6 step 3). */
  readonly bundle: LoadedBundle;
}

export type Classification =
  | { readonly kind: 'state'; readonly state: RecoveryState }
  | { readonly kind: 'inconsistent'; readonly reason: string };

export interface RecoveryClassifier {
  /**
   * Classifies a view without mutating anything. Includes validation of
   * committed packages (§5.3a step 2, §5.6 step 3).
   */
  classify(view: ChainView): Promise<Classification>;
}


export interface AnchorHookContext {
  readonly chainId: string;
  readonly seq: number;
  readonly entryHash: string;
  readonly ts: string;
  /** Runs a statement inside the append transaction on writerConn. */
  readonly query: (text: string, values?: unknown[]) => Promise<unknown[]>;
}

/** The pending anchor a hook set in the append transaction. */
export interface PendingAnchor {
  readonly seq: number;
  readonly entryHash: string;
  readonly ts: string;
}

export interface AnchorHook {
  /** Returns the pending anchor it set in this transaction, or null. */
  onApplicationCommit(ctx: AnchorHookContext): Promise<PendingAnchor | null>;
}

export const noAnchorHook: AnchorHook = {
  onApplicationCommit: async () => null,
};
