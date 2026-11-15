// SPDX-License-Identifier: AGPL-3.0-or-later
// Review finding 1: the report must show the measured B2 exposure in time and give the reasons it is not
// interpreted, instead of a fixed explanation that the data contradict.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { test } from 'node:test';

const report = fs.readFileSync('docs/REPORT.md', 'utf8');
const raw = fs.readFileSync('docs/results/pause-exposure.md', 'utf8');

test('review H1: B2 exposure in time is shown as measured, with the reasons it is not interpreted', () => {
  const m = /^## B2[\s\S]*?Exposure in time \(covered pauses\): min (\S+) · median \S+ · max (\S+) s\./m.exec(raw);
  assert.ok(m !== null, 'the generated file holds the B2 time line');
  assert.ok(report.includes(m[1]!) && report.includes(m[2]!), 'the measured minimum and maximum are shown');
  assert.match(report, /clock/);
  assert.doesNotMatch(report, /within the same second as the\s+pause/);
});
