// SPDX-License-Identifier: AGPL-3.0-or-later
// tear-verify command line (Blueprint §6):
//   node dist/src/cli/tear-verify.js --log events.jsonl \
//     --checkpoints ./tsr_receipts/<chain_id>/ --tsa-ca-bundle ./certs/tsa_roots.pem

import { parseArgs } from '../verify/args.js';
import { EXIT_INPUT_UNAVAILABLE, INPUT_UNAVAILABLE_OUTPUT } from '../verify/output.js';
import { EXIT_OUTSIDE_CONTRACT, verifyOffline } from '../verify/verify.js';
import type { VerifyResult } from '../verify/verify.js';

function main(): void {
  const inputs = parseArgs(process.argv.slice(2));
  if (inputs === null) {
    process.stdout.write(INPUT_UNAVAILABLE_OUTPUT);
    process.exitCode = EXIT_INPUT_UNAVAILABLE;
    return;
  }
  let result: VerifyResult;
  try {
    result = verifyOffline(inputs);
  } catch (err) {
    // There is no successful verification after an unclassified exception (§6b).
    process.stderr.write(`tear-verify: internal error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = EXIT_OUTSIDE_CONTRACT;
    return;
  }
  process.stdout.write(result.stdout);
  if (result.stderr.length > 0) process.stderr.write(result.stderr);
  process.exitCode = result.exitCode;
}

main();
