// SPDX-License-Identifier: AGPL-3.0-or-later
// Predeclared expected outcomes (committed before any measurement code runs).
// Every value below is derived from docs/BLUEPRINT.md; a measured value that
// differs is reported as "not matching", never adjusted.

// ---------------------------------------------------------------------------
// Experiment A — layer ladder over the 17 cases of spec 004 (15 primary, X1, X2)
// ---------------------------------------------------------------------------
//
// Outcome per layer:
//   detected          the layer rejects the evidence (non-zero exit, or the L3 auditor comparison fails)
//   reduced coverage  exit 0, but the highest VERIFIED_ANCHORED bound is lower than for the unmutated fixture
//                     at the same layer
//   accepted          any other exit 0
//
// L0  plain log: every row is readable JSON. All mutations keep rows readable → accepted everywhere.
// L1  tear-verify with an empty namespace: Step 1 and Step 2b (control positions) run; no package is presented,
//     so VERIFIED_ANCHORED never appears and coverage cannot be reduced (baseline bound: none).
//       T1/T5 A2a: hash rules; T2 A2a: SEQ_GAP; T4 A2a: SEQ_DUPLICATE; T5 A2b: TS_REGRESSION (§6 Step 1).
//       T2 A2b: rows renumbered, the control formerly at 31 (anchored_seq 30) sits at 30 → CONTROL_EVENT_INVALID (Step 2b).
//       T4 A2b: rows shifted, the control formerly at 31 sits at 32 with anchored_seq 30 → CONTROL_EVENT_INVALID.
//       T1 A2b, T3a, T3b, T6a, T6b, T7, X1, X2: a recomputed or truncated chain with consistent controls → accepted.
// L2  full tear-verify (as in M1): the §7 results. T3b, T6b, X2 accepted (T3b and T6b keep 0..40);
//     T7 and X1 reduced coverage (0..20 < 0..40); every other case detected.
// L3  L2 plus the auditor procedure (§3.3 item 9, outside tear-verify): the bundle SHA-256 must equal the
//     retained fingerprint, and every presented .tsr must equal the retained receipt for the same k. The
//     retained manifest is a simulation of the external custodian, built by the test from the original fixture.
//       T6b: replaced receipts 30 and 40 differ from the retained ones → detected.
//       X2:  the tester's bundle differs from the retained fingerprint → detected.
//       T3b: nothing presented differs (truncation above the last anchor) → accepted.
//       T7, X1: the presented receipts 10 and 20 match; 30 and 40 are not presented → reduced coverage stays.

export type LayerOutcome = 'detected' | 'accepted' | 'reduced coverage';
export type Layer = 'L0' | 'L1' | 'L2' | 'L3';

const D = 'detected' as const;
const A = 'accepted' as const;
const R = 'reduced coverage' as const;

export const EXPECTED_LADDER: Readonly<Record<string, Readonly<Record<Layer, LayerOutcome>>>> = {
  'T1-A2a': { L0: A, L1: D, L2: D, L3: D },
  'T1-A2b': { L0: A, L1: A, L2: D, L3: D },
  'T2-A2a': { L0: A, L1: D, L2: D, L3: D },
  'T2-A2b': { L0: A, L1: D, L2: D, L3: D },
  'T3a-A2a': { L0: A, L1: A, L2: D, L3: D },
  'T3a-A2b': { L0: A, L1: A, L2: D, L3: D },
  'T3b-A2a': { L0: A, L1: A, L2: A, L3: A },
  'T3b-A2b': { L0: A, L1: A, L2: A, L3: A },
  'T4-A2a': { L0: A, L1: D, L2: D, L3: D },
  'T4-A2b': { L0: A, L1: D, L2: D, L3: D },
  'T5-A2a': { L0: A, L1: D, L2: D, L3: D },
  'T5-A2b': { L0: A, L1: D, L2: D, L3: D },
  'T6a-A2b': { L0: A, L1: A, L2: D, L3: D },
  'T6b-A2b': { L0: A, L1: A, L2: A, L3: D },
  'T7-A2b': { L0: A, L1: A, L2: R, L3: R },
  X1: { L0: A, L1: A, L2: R, L3: R },
  X2: { L0: A, L1: A, L2: A, L3: D },
};

/** Totals per layer implied by the table above (detected / accepted / reduced coverage). */
export const EXPECTED_LADDER_TOTALS: Readonly<Record<Layer, Readonly<Record<LayerOutcome, number>>>> = {
  L0: { detected: 0, accepted: 17, 'reduced coverage': 0 },
  L1: { detected: 7, accepted: 10, 'reduced coverage': 0 },
  L2: { detected: 11, accepted: 4, 'reduced coverage': 2 },
  L3: { detected: 13, accepted: 2, 'reduced coverage': 2 },
};

// ---------------------------------------------------------------------------
// Experiment B — exposure window of an epistemic pause
// ---------------------------------------------------------------------------
//
// Automatic anchors are set on application records k with k % 10 == 0 (§5.7); the control row of anchor k
// sits at k+1 and anchoring k commits records 0..k (§3.3 item 1). Application records therefore follow at
// 1..10, then k+2..k+10 after each anchor.
//
// Exposure in events of a pause at seq s = application events after s up to and including the first anchored
// record k >= s.
//   - Before close: min 0 (a pause that is itself an anchored record), max 9 (a pause at seq 1: records 2..10);
//     after the first anchor, at most 8 (records k+3..k+10). Pauses after the last automatic anchor are not
//     covered (they belong to the VALID_UNANCHORED tail).
//   - After closeChain: B2 anchors the head h (§5.8), so every pause is covered; the tail pauses' exposure is
//     at most the number of application events between the last automatic anchor and h.
// Exposure in time (B2 only) = signed genTime of the covering anchor minus ts[s]. The Blueprint fixes only a
// lower bound: genTime >= ts[k] - 5 s (§5.7 predicate) and ts[k] >= ts[s] (§4.2 monotonic writer timestamps),
// so the value is >= -5 s. No upper bound follows from the Blueprint (it depends on the pace of the run).
//
// Truncation demonstration (§3.2, §3.3 item 1): deleting the unanchored tail of an export taken before close
// still verifies with exit 0, and every pause in that tail disappears; the count equals the number of pauses
// after the last anchored record.
//
// Record size by argument size: a tool_call row stores args_hmac (64 hex characters), never the arguments
// (§4.4). Expected: the mean exported tool_call row size differs by at most 16 bytes between the ~100 B,
// ~2 KB and ~20 KB argument classes (only identifiers vary in length).
// Latency by argument size: the extra cost is one RFC 8785 serialization and one HMAC over the arguments.
// Expected: the median per-event latency of tool_call records differs by less than 1 ms between the ~100 B
// and ~20 KB classes.

export const EXPECTED_EXPOSURE = {
  eventsBeforeClose: { min: 0, max: 9, maxAfterFirstAnchor: 8 },
  tailUncoveredBeforeClose: true,
  allCoveredAfterClose: true,
  timeLowerBoundSeconds: -5,
  truncation: { exitCode: 0, removedEqualsPausesAfterLastAnchor: true },
  recordSizeMaxSpreadBytes: 16,
  latencyMaxSpreadMs: 1,
} as const;
