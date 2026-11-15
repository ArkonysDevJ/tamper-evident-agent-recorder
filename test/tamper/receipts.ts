// SPDX-License-Identifier: AGPL-3.0-or-later
// Stored replacement receipts for T6a and T6b (real TSA receipts requested
// once by test/fixture-tools/build-tamper-receipts.ts). The battery reads them
// offline; it never requests receipts.

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ReceiptSource } from './cases.js';

export const TAMPER_RECEIPTS_DIR = path.resolve('test/fixtures/tamper-receipts');

export interface StoredReceipt {
  readonly tsa: string;
  readonly file: string;
  readonly entry_hash: string;
  readonly nonce_hex: string;
  readonly tsr_sha256: string;
  readonly gen_time: string;
  readonly serial_hex: string;
}

export interface TamperReceiptsManifest {
  readonly description: string;
  readonly t6b_base_ms: number;
  readonly receipts: Record<string, StoredReceipt>;
}

export function readManifest(): TamperReceiptsManifest {
  return JSON.parse(fs.readFileSync(path.join(TAMPER_RECEIPTS_DIR, 'manifest.json'), 'utf8')) as TamperReceiptsManifest;
}

export class StoredReceipts implements ReceiptSource {
  private loaded: TamperReceiptsManifest | null = null;

  private get m(): TamperReceiptsManifest {
    this.loaded ??= readManifest();
    return this.loaded;
  }

  t6bBaseMs(): number {
    return this.m.t6b_base_ms;
  }

  async obtain(id: 'T6a' | 'T6b', k: 30 | 40, entryHash: string): Promise<{ tsr: Uint8Array; nonceHex: string }> {
    const r = this.m.receipts[`${id}-${String(k)}`];
    if (r === undefined) throw new Error(`no stored receipt ${id}-${String(k)}`);
    // The mutation is deterministic: the recomputed row must be the one the stored receipt was requested for.
    if (r.entry_hash !== entryHash) throw new Error(`${id}-${String(k)}: the mutation no longer reproduces the stored request`);
    return { tsr: new Uint8Array(fs.readFileSync(path.join(TAMPER_RECEIPTS_DIR, r.file))), nonceHex: r.nonce_hex };
  }
}
