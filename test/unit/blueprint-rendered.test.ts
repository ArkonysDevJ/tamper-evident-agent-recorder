// SPDX-License-Identifier: AGPL-3.0-or-later
// docs/BLUEPRINT.rendered.md is a reading copy of the normative docs/BLUEPRINT.md in which each <placeholder>
// is wrapped in backticks so that GitHub shows it. Removing those backticks must give back the normative bytes,
// so the reading copy cannot diverge from the normative text.

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import { test } from 'node:test';
import { sha256Hex } from '../../src/crypto/digests.js';

const NORMATIVE_SHA256 = 'b394d3341b05bbfbb66688e7aacc99dfa3cddfba41dbde51198179413d28826d';
const RENDERED_SHA256 = '3c8fef0fd6e9ac294203c6d8be17c720ddfa72c34d8f83b018008744679a41a1';

test('the readable Blueprint copy matches the normative text', async (t) => {
  const rendered = fs.readFileSync('docs/BLUEPRINT.rendered.md');
  await t.test('both files have their pinned digests', () => {
    assert.equal(sha256Hex(fs.readFileSync('docs/BLUEPRINT.md')), NORMATIVE_SHA256);
    assert.equal(sha256Hex(rendered), RENDERED_SHA256);
  });
  await t.test('removing the backticks around each <placeholder> gives the normative bytes exactly', () => {
    const restored = rendered.toString('utf8').replace(/`(<[^`<>\n]*>)`/g, '$1');
    assert.equal(sha256Hex(Buffer.from(restored, 'utf8')), NORMATIVE_SHA256);
  });
});
