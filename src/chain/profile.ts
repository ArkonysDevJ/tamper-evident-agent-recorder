// SPDX-License-Identifier: AGPL-3.0-or-later
// Normative cut profiles (Blueprint §8).
// Implementation choice (not normative): the profile is a required explicit
// option of the writer, the recoverer and initializeChain, fixed for the life
// of a writer and never read from an environment variable.

export type CutProfile = 'base' | 'cut1' | 'cut1-2' | 'cut1-3' | 'cut1-4';

export const CUT_PROFILES: readonly CutProfile[] = ['base', 'cut1', 'cut1-2', 'cut1-3', 'cut1-4'];

/** Automatic recovery is retired from Cut 3 on (§8). */
export function permitsAutomaticRecovery(profile: CutProfile): boolean {
  return profile === 'base' || profile === 'cut1' || profile === 'cut1-2';
}

/** Cut 2 retires the B3 retry and ANCHORED_AFTER_PREVIOUS_FAILURE (§8). */
export function retiresCloseRetry(profile: CutProfile): boolean {
  return profile === 'cut1-2' || profile === 'cut1-3' || profile === 'cut1-4';
}
