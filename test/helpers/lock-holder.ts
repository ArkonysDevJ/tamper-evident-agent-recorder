// SPDX-License-Identifier: AGPL-3.0-or-later
// Child process for lock tests: takes the writer lock on argv[2], reports on
// stdout, and holds it until killed.

import { WriterLock } from '../../src/fs/writer-lock.js';

const ns = process.argv[2];
if (ns === undefined) throw new Error('namespace path required');
WriterLock.acquire(ns);
process.stdout.write('locked\n');
setInterval(() => undefined, 1000);
