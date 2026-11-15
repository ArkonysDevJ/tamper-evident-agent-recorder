// SPDX-License-Identifier: AGPL-3.0-or-later
// Review finding 8: byte-exact fixtures and artifacts must never have their line endings converted by a clone,
// and the report must not say that the published commit only adds generated files.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import { test } from 'node:test';

// Skipped until docs/REPORT.md is rendered after the final run, like the report checks.
const opts = { skip: fs.existsSync('docs/REPORT.md') ? false : 'no docs/REPORT.md yet' };

const BYTE_EXACT = [
  'test/fixtures/frozen-m1/events.jsonl',
  'test/fixtures/frozen-m1/manifest.json',
  'test/fixtures/tamper-receipts/manifest.json',
  'experiments/b2/pre-close/events.jsonl',
  'experiments/b2/meta.json',
  'experiments/dataset/traces.jsonl',
];

test('review H8: byte-exact files are never converted on checkout', () => {
  const out = execFileSync('git', ['check-attr', 'text', '--', ...BYTE_EXACT], { encoding: 'utf8' });
  for (const line of out.trim().split('\n')) assert.match(line, /: text: unset$/, line);
});

test('review H8: the report does not say the published commit only adds generated files', opts, () => {
  assert.doesNotMatch(fs.readFileSync('docs/REPORT.md', 'utf8'), /published commit only adds the generated files/);
});
