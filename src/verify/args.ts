// SPDX-License-Identifier: AGPL-3.0-or-later
// Command-line parsing for tear-verify (Blueprint §6). Each of the three
// options must appear exactly once, followed by its value.
// Implementation choice: a malformed command line (missing, repeated or unknown
// option) is an invocation failure: INPUT_UNAVAILABLE 0, exit 2 (§6b).

import type { VerifyInputs } from './verify.js';

const OPTIONS = { '--log': 'logPath', '--checkpoints': 'checkpointsPath', '--tsa-ca-bundle': 'bundlePath' } as const;

export function parseArgs(argv: readonly string[]): VerifyInputs | null {
  const found: Partial<Record<keyof VerifyInputs, string>> = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i];
    const value = argv[i + 1];
    if (flag === undefined || !Object.prototype.hasOwnProperty.call(OPTIONS, flag) || value === undefined) return null;
    const key = OPTIONS[flag as keyof typeof OPTIONS];
    if (found[key] !== undefined) return null;
    found[key] = value;
  }
  if (found.logPath === undefined || found.checkpointsPath === undefined || found.bundlePath === undefined) return null;
  return { logPath: found.logPath, checkpointsPath: found.checkpointsPath, bundlePath: found.bundlePath };
}
