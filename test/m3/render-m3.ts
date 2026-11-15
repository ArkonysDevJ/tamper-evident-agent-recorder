// SPDX-License-Identifier: AGPL-3.0-or-later
// Re-renders test-results/m3-results.md from the raw samples in
// test-results/m3-results.json, without measuring again (no requests, no writes
// to the database). Run: npm run m3:render

import * as fs from 'node:fs';
import * as path from 'node:path';
import { renderM3 } from './report.js';
import type { M3Input } from './report.js';

const dir = path.resolve('test-results');
const input = JSON.parse(fs.readFileSync(path.join(dir, 'm3-results.json'), 'utf8')) as M3Input;
fs.writeFileSync(path.join(dir, 'm3-results.md'), renderM3(input));
process.stdout.write(renderM3(input));
