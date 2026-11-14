// SPDX-License-Identifier: AGPL-3.0-or-later
// Extension points of tear-verify for the anchoring work package (spec 003):
// - BundleLoader: bundle grammar and TEAR-TSA-01 loading (§6a). The default
//   only requires readable bytes; it does not check the grammar yet.
// - AnchorVerifier: Step 2 inventory and packages, Step 2b control relations,
//   and the anchored part of Step 3. The default supports exactly the case with
//   nothing to verify: no namespace entries besides .writer.lock and no control
//   events in the log. Anything else is reported as not implemented, never as
//   VALID_UNANCHORED.

import type { AcceptedRow } from '../chain/step1.js';

export interface BundleLoader {
  /** Throws if the bundle fails loading; tear-verify then prints INPUT_UNAVAILABLE 0 (exit 2). */
  load(rawBytes: Uint8Array): void;
}

export const rawBytesBundleLoader: BundleLoader = {
  load: () => undefined,
};

export interface AnchorInput {
  readonly nsPath: string;
  /** Namespace entry names, .writer.lock excluded. */
  readonly entries: readonly string[];
  readonly rows: readonly AcceptedRow[];
  readonly bundleBytes: Uint8Array;
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
  | { readonly kind: 'failure'; readonly code: string; readonly param: number }
  | { readonly kind: 'not_implemented'; readonly reason: string };

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

export const unanchoredOnlyVerifier: AnchorVerifier = {
  verify(input) {
    if (input.entries.length > 0) {
      return { kind: 'not_implemented', reason: 'anchor package verification (Step 2) is not implemented yet' };
    }
    const control = input.rows.find((r) => {
      const t = r.block.payload['event_type'];
      return t === 'checkpoint_anchored' || t === 'checkpoint_failed';
    });
    if (control !== undefined) {
      return { kind: 'not_implemented', reason: 'control relations (Step 2b) are not implemented yet' };
    }
    return { kind: 'ok', coverage: NO_ANCHORS };
  },
};

export interface VerifierExtensions {
  readonly bundleLoader: BundleLoader;
  readonly anchorVerifier: AnchorVerifier;
}

export const defaultExtensions: VerifierExtensions = {
  bundleLoader: rawBytesBundleLoader,
  anchorVerifier: unanchoredOnlyVerifier,
};
