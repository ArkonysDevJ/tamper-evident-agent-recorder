// SPDX-License-Identifier: AGPL-3.0-or-later
// Namespace inventory under the names and types of Blueprint §5.6 step 2.
// .writer.lock is ignored. Every other entry must be a regular file (lstat,
// symlinks not followed) with a permitted canonical name; anything else fails
// closed. This module only reads: it never deletes or synchronizes.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { TearError } from '../errors.js';
import { WRITER_LOCK_NAME } from './names.js';

export type EntryKind = 'tsq' | 'tsr' | 'anchor.json';

export interface NamespaceEntry {
  readonly name: string;
  readonly seq: bigint;
  readonly kind: EntryKind;
  readonly temporary: boolean;
}

const ENTRY_RE = /^([1-9][0-9]*)\.(tsq|tsr|anchor\.json)(\.tmp)?$/;

export function inventoryNamespace(nsPath: string): NamespaceEntry[] {
  const out: NamespaceEntry[] = [];
  for (const name of fs.readdirSync(nsPath)) {
    if (name === WRITER_LOCK_NAME) continue;
    const m = ENTRY_RE.exec(name);
    if (m === null) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', `unknown namespace entry ${name}`);
    if (!fs.lstatSync(path.join(nsPath, name)).isFile()) {
      throw new TearError('RECONCILIATION_STATE_INCONSISTENT', `namespace entry is not a regular file: ${name}`);
    }
    out.push({ name, seq: BigInt(m[1]!), kind: m[2] as EntryKind, temporary: m[3] !== undefined });
  }
  return out;
}
