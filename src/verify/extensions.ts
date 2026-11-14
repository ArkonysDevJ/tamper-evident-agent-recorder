// SPDX-License-Identifier: AGPL-3.0-or-later
// Extension points of tear-verify and their implementations:
// - BundleLoader: bundle grammar and TEAR-TSA-01 loading (§6a). A loading
//   failure makes tear-verify print INPUT_UNAVAILABLE 0 (exit 2).
// - AnchorVerifier: Step 2 inventory and packages, Step 2b control relations,
//   and the anchored part of Step 3.

import type { AcceptedRow } from '../chain/step1.js';
import { loadBundle } from '../pki/bundle.js';
import type { LoadedBundle } from '../pki/bundle.js';
import { anchorTimeLine, checkControls, checkPackage, inventoryPackages } from './anchors.js';
import type { ValidPackage } from './anchors.js';

export interface BundleLoader {
  /** Throws if the bundle fails loading. */
  load(rawBytes: Uint8Array): LoadedBundle;
}

export const profileBundleLoader: BundleLoader = { load: loadBundle };

export interface AnchorInput {
  readonly nsPath: string;
  readonly chainId: string;
  /** Namespace entry names, .writer.lock excluded. */
  readonly entries: readonly string[];
  readonly rows: readonly AcceptedRow[];
  readonly bundle: LoadedBundle;
}

export interface AnchorCoverage {
  /** Highest valid anchored k, or null with no valid package. */
  readonly maxK: number | null;
  readonly evidenceMissing: readonly number[];
  readonly maxAnchorGap: number;
  readonly anchoredCheckpointFailures: number;
  readonly anchorTimes: readonly string[];
}

export type AnchorResult =
  | { readonly kind: 'ok'; readonly coverage: AnchorCoverage }
  | { readonly kind: 'failure'; readonly code: string; readonly param: bigint };

export interface AnchorVerifier {
  verify(input: AnchorInput): AnchorResult;
}

export const NO_ANCHORS: AnchorCoverage = {
  maxK: null,
  evidenceMissing: [],
  maxAnchorGap: 0,
  anchoredCheckpointFailures: 0,
  anchorTimes: [],
};

export const profileAnchorVerifier: AnchorVerifier = {
  verify(input) {
    const ks = inventoryPackages(input.nsPath, input.entries);
    if (!Array.isArray(ks)) return { kind: 'failure', ...ks };
    const valid = new Map<number, ValidPackage>();
    for (const k of ks) {
      const r = checkPackage(input.nsPath, k, input.chainId, input.rows, input.bundle);
      if ('code' in r) return { kind: 'failure', ...r };
      valid.set(r.k, r);
    }
    const controls = checkControls(input.rows, valid);
    if ('code' in controls) return { kind: 'failure', ...controls };

    const sorted = [...valid.values()].sort((a, b) => a.k - b.k);
    const maxK = sorted.length === 0 ? null : sorted[sorted.length - 1]!.k;
    let maxAnchorGap = 0;
    for (let i = 1; i < sorted.length; i++) maxAnchorGap = Math.max(maxAnchorGap, sorted[i]!.k - sorted[i - 1]!.k);
    const anchoredCheckpointFailures =
      maxK === null
        ? 0
        : input.rows.filter((r) => r.block.payload['event_type'] === 'checkpoint_failed' && r.block.seq <= maxK).length;
    return {
      kind: 'ok',
      coverage: {
        maxK,
        evidenceMissing: controls.evidenceMissing,
        maxAnchorGap,
        anchoredCheckpointFailures,
        anchorTimes: sorted.map(anchorTimeLine),
      },
    };
  },
};

export interface VerifierExtensions {
  readonly bundleLoader: BundleLoader;
  readonly anchorVerifier: AnchorVerifier;
}

export const defaultExtensions: VerifierExtensions = {
  bundleLoader: profileBundleLoader,
  anchorVerifier: profileAnchorVerifier,
};
