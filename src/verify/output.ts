// SPDX-License-Identifier: AGPL-3.0-or-later
// Canonical verifier output (Blueprint §6b): UTF-8 without BOM, LF line ends,
// canonical base-10 integers, ranges written as a..b.

import type { AnchorCoverage } from './extensions.js';

export const EXIT_OK = 0;
export const EXIT_FAILED = 1;
export const EXIT_INPUT_UNAVAILABLE = 2;

export function failureOutput(code: string, param: number): string {
  return `${code} ${String(param)}\n`;
}

export const INPUT_UNAVAILABLE_OUTPUT = 'INPUT_UNAVAILABLE 0\n';

/** The exit-0 groups of §6b, in order. */
export function successOutput(seqFinal: number, unmatchedCalls: readonly number[], c: AnchorCoverage): string {
  const lines: string[] = [];
  if (c.maxK !== null) lines.push(`VERIFIED_ANCHORED 0..${String(c.maxK)}`);
  const start = c.maxK === null ? 0 : c.maxK + 1;
  if (start <= seqFinal) lines.push(`VALID_UNANCHORED ${String(start)}..${String(seqFinal)}`);
  for (const s of [...unmatchedCalls].sort((a, b) => a - b)) lines.push(`INCOMPLETE_EXECUTION ${String(s)}`);
  for (const k of [...new Set(c.evidenceMissing)].sort((a, b) => a - b)) lines.push(`ANCHOR_EVIDENCE_MISSING ${String(k)}`);
  lines.push(`MAX_ANCHOR_GAP ${String(c.maxAnchorGap)}`);
  lines.push(`ANCHORED_CHECKPOINT_FAILURES ${String(c.anchoredCheckpointFailures)}`);
  lines.push(...c.anchorTimes);
  return lines.map((l) => `${l}\n`).join('');
}
