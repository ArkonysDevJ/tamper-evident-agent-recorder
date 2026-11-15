// SPDX-License-Identifier: AGPL-3.0-or-later
// Review finding 9: the report states where the only e-mail addresses in the repository come from.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { test } from 'node:test';

test('review H9: the report states that the only e-mail addresses are TSA certificate contact fields', () => {
  assert.match(fs.readFileSync('docs/REPORT.md', 'utf8'), /only e-mail addresses in the repository are contact fields inside the public TSA certificates/);
});
