// SPDX-License-Identifier: AGPL-3.0-or-later
// Review finding 7: anchors are triggered on application records at physical sequence numbers divisible by 10
// (Blueprint §2, §5.7); the sequence includes control rows, so the wording "every 10 application events" is wrong.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { test } from 'node:test';

// Skipped until docs/REPORT.md is rendered after the final run, like the report checks.
const opts = { skip: fs.existsSync('docs/REPORT.md') ? false : 'no docs/REPORT.md yet' };

test('review H7: the anchor trigger is described with the words of Blueprint §2', opts, () => {
  for (const file of ['docs/REPORT.md', 'README.md']) {
    const text = fs.readFileSync(file, 'utf8');
    assert.doesNotMatch(text, /every 10 application\s+events/, file);
  }
  assert.match(fs.readFileSync('docs/REPORT.md', 'utf8'), /positive physical sequence number seq divisible by 10/);
});
