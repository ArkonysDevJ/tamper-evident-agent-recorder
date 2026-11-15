// SPDX-License-Identifier: AGPL-3.0-or-later
// The §7 matrix (T1–T7 under A2a and A2b), X1 and X2, each as an exact,
// reproducible operation on a copy of the frozen fixture. The "specified"
// text and the expected output are copied from Blueprint §7 before running.

import { sha256Hex } from '../../src/crypto/digests.js';
import { pem, certificate, cn, ext, genTimeOf, issuerAndSerial, key, timeStampResp, tstInfo } from '../helpers/pki.js';
import { OID } from '../../src/pki/oids.js';
import { formatTimestamp, parseTimestampMs } from '../../src/time/timestamps.js';
import { Evidence, successStdout } from './model.js';

/** Fresh receipts for T6a and T6b: real TSA receipts, requested once and stored. */
export interface ReceiptSource {
  /** Base time of the shifted T6b timestamps (epoch ms), fixed when the receipts were requested. */
  t6bBaseMs(): number;
  obtain(id: 'T6a' | 'T6b', k: 30 | 40, entryHash: string): Promise<{ tsr: Uint8Array; nonceHex: string }>;
}

export interface Expected {
  readonly exitCode: number;
  readonly stdout: string;
}

export interface TamperCase {
  readonly id: string;
  readonly row: string;
  readonly adversary: 'A2a' | 'A2b' | '—';
  /** The §7 result column, literally. */
  readonly specified: string;
  /** One of the 15 primary M1 results. */
  readonly primary: boolean;
  readonly build: (src: ReceiptSource) => Promise<Evidence>;
  readonly expected: (e: Evidence) => Expected;
}

const fail = (line: string) => (): Expected => ({ exitCode: 1, stdout: `${line}\n` });

/** T1, T6a, T6b, T7: replace only the fixture literal O_25.payload.reason "baseline" with "tampered". */
function tamperReason(e: Evidence): void {
  if (e.payload(25)['reason'] !== 'baseline') throw new Error('fixture literal O_25.payload.reason is not "baseline"');
  e.setPayloadField(25, 'reason', 'tampered');
}

/** T6b: timestamps 25..50 moved into the issuance window, strictly increasing and 150 ms apart. */
export const T6B_STEP_MS = 150;
export function shiftedTs(baseMs: number, seq: number): string {
  return formatTimestamp(baseMs + (seq - 25) * T6B_STEP_MS);
}

/** Replaces packages 30 and 40 in order, keeping the chain consistent (§7 T6a and T6b). */
async function replace30and40(e: Evidence, src: ReceiptSource, id: 'T6a' | 'T6b'): Promise<void> {
  for (const k of [30, 40] as const) {
    const { tsr, nonceHex } = await src.obtain(id, k, e.rows[k]!.entry_hash);
    e.replacePackage(k, tsr, nonceHex);
    e.setControlMetadata(k, tsr);
    e.recompute(k + 1);
  }
}

// ---------- X2: the tester's own bundle (keys generated at run time, never stored) ----------

export interface TesterPki {
  readonly bundle: Uint8Array;
  readonly signer: Uint8Array;
  readonly signerKey: ReturnType<typeof key>;
}

export function testerPki(): TesterPki {
  const rootKey = key('rsa2048', 900);
  const signerKey = key('p256', 901);
  const rootName = cn('X2 tester root');
  const root = certificate({ subject: rootName, issuer: rootName, subjectKey: rootKey, issuerKey: rootKey, extensions: [ext.bc(true), ext.ku([5, 6])] });
  const signer = certificate({
    subject: cn('X2 tester time-stamping signer'),
    issuer: rootName,
    subjectKey: signerKey,
    issuerKey: rootKey,
    extensions: [ext.ku([0]), ext.eku([OID.kpTimeStamping])],
    notBefore: new Date(Date.UTC(2020, 0, 1)),
  });
  return { bundle: pem([root, signer]), signer, signerKey };
}

const X2_NONCE = 0x5a5a5a5a5a5a5a5an;

function x2Token(p: TesterPki, entryHash: string, ts: string): Uint8Array {
  // genTime one second after the row timestamp: inside the [-5 s, +60 s] window of ts[k].
  const genTime = genTimeOf(new Date(Math.floor(parseTimestampMs(ts)! / 1000) * 1000 + 1000));
  const { issuer, serial } = issuerAndSerial(p.signer);
  return timeStampResp({
    tst: tstInfo({ hashedMessage: Buffer.from(entryHash, 'hex'), genTime, nonce: X2_NONCE }),
    signerCert: p.signer,
    signerKey: p.signerKey,
    signerIssuer: issuer,
    signerSerial: serial,
  });
}

const BASE_TAIL = ['MAX_ANCHOR_GAP 10', 'ANCHORED_CHECKPOINT_FAILURES 0'];

export const CASES: readonly TamperCase[] = [
  {
    id: 'T1-A2a', row: 'T1', adversary: 'A2a', specified: 'HASH_MISMATCH 25', primary: true,
    build: async () => {
      const e = new Evidence();
      tamperReason(e);
      return e;
    },
    expected: fail('HASH_MISMATCH 25'),
  },
  {
    id: 'T1-A2b', row: 'T1', adversary: 'A2b', specified: 'CHECKPOINT_DIVERGENCE 30', primary: true,
    build: async () => {
      const e = new Evidence();
      tamperReason(e);
      e.recompute(25);
      return e;
    },
    expected: fail('CHECKPOINT_DIVERGENCE 30'),
  },
  {
    id: 'T2-A2a', row: 'T2', adversary: 'A2a', specified: 'SEQ_GAP 25', primary: true,
    build: async () => {
      const e = new Evidence();
      e.deleteRows(25, 25);
      return e;
    },
    expected: fail('SEQ_GAP 25'),
  },
  {
    id: 'T2-A2b', row: 'T2', adversary: 'A2b', specified: 'CHECKPOINT_DIVERGENCE 30', primary: true,
    build: async () => {
      const e = new Evidence();
      e.deleteRows(25, 25);
      e.renumber(25);
      e.recompute(25);
      return e;
    },
    expected: fail('CHECKPOINT_DIVERGENCE 30'),
  },
  {
    id: 'T3a-A2a', row: 'T3a', adversary: 'A2a', specified: 'TRUNCATED_BELOW_ANCHOR 40', primary: true,
    build: async () => {
      const e = new Evidence();
      e.deleteRows(35, 50);
      return e;
    },
    expected: fail('TRUNCATED_BELOW_ANCHOR 40'),
  },
  {
    id: 'T3a-A2b', row: 'T3a', adversary: 'A2b', specified: 'TRUNCATED_BELOW_ANCHOR 40', primary: true,
    // A suffix deletion leaves nothing after the cut to recompute: the A2b operation is the same deletion.
    build: async () => {
      const e = new Evidence();
      e.deleteRows(35, 50);
      e.recompute(35);
      return e;
    },
    expected: fail('TRUNCATED_BELOW_ANCHOR 40'),
  },
  {
    id: 'T3b-A2a', row: 'T3b', adversary: 'A2a', specified: 'not detected: anchored 0..40, tail 41..44', primary: true,
    build: async () => {
      const e = new Evidence();
      e.deleteRows(45, 50);
      return e;
    },
    expected: (e) => ({ exitCode: 0, stdout: successStdout(e, ['VERIFIED_ANCHORED 0..40', 'VALID_UNANCHORED 41..44', ...BASE_TAIL], [10, 20, 30, 40]) }),
  },
  {
    id: 'T3b-A2b', row: 'T3b', adversary: 'A2b', specified: 'same', primary: true,
    build: async () => {
      const e = new Evidence();
      e.deleteRows(45, 50);
      e.recompute(45);
      return e;
    },
    expected: (e) => ({ exitCode: 0, stdout: successStdout(e, ['VERIFIED_ANCHORED 0..40', 'VALID_UNANCHORED 41..44', ...BASE_TAIL], [10, 20, 30, 40]) }),
  },
  {
    id: 'T4-A2a', row: 'T4', adversary: 'A2a', specified: 'SEQ_DUPLICATE 25', primary: true,
    build: async () => {
      const e = new Evidence();
      const dup = structuredClone(e.rows[25]!);
      e.rows.splice(26, 0, dup);
      return e;
    },
    expected: fail('SEQ_DUPLICATE 25'),
  },
  {
    id: 'T4-A2b', row: 'T4', adversary: 'A2b', specified: 'CHECKPOINT_DIVERGENCE 30', primary: true,
    build: async () => {
      const e = new Evidence();
      const o24 = e.rows[24]!.block;
      const inserted = {
        block: Object.assign(Object.create(null) as Record<string, unknown>, {
          chain_id: o24['chain_id'],
          seq: 25,
          ts: o24['ts'],
          prev_hash: e.rows[24]!.entry_hash,
          payload: Object.assign(Object.create(null) as Record<string, unknown>, {
            event_type: 'epistemic_pause',
            operation: 'tear.epistemic_pause',
            task_id: 'inserted-fresh-task',
            reason: 'inserted',
            missing_sources: [],
          }),
        }),
        entry_hash: '',
      } as unknown as Evidence['rows'][number];
      e.rows.splice(25, 0, inserted);
      e.renumber(25);
      e.recompute(25);
      return e;
    },
    expected: fail('CHECKPOINT_DIVERGENCE 30'),
  },
  {
    id: 'T5-A2a', row: 'T5', adversary: 'A2a', specified: 'HASH_MISMATCH 22', primary: true,
    build: async () => {
      const e = new Evidence();
      const a = e.rows[22]!.block;
      const b = e.rows[23]!.block;
      [a['ts'], b['ts']] = [b['ts']!, a['ts']!];
      [a['payload'], b['payload']] = [b['payload']!, a['payload']!];
      return e;
    },
    expected: fail('HASH_MISMATCH 22'),
  },
  {
    id: 'T5-A2b', row: 'T5', adversary: 'A2b', specified: 'TS_REGRESSION 23', primary: true,
    build: async () => {
      const e = new Evidence();
      const a = e.rows[22]!.block;
      const b = e.rows[23]!.block;
      [a['ts'], b['ts']] = [b['ts']!, a['ts']!];
      [a['payload'], b['payload']] = [b['payload']!, a['payload']!];
      e.recompute(22);
      return e;
    },
    expected: fail('TS_REGRESSION 23'),
  },
  {
    id: 'T6a-A2b', row: 'T6a', adversary: 'A2b', specified: 'TSA_TIME_INCONSISTENT 30', primary: true,
    build: async (src) => {
      const e = new Evidence();
      tamperReason(e);
      e.recompute(25);
      await replace30and40(e, src, 'T6a');
      return e;
    },
    expected: fail('TSA_TIME_INCONSISTENT 30'),
  },
  {
    id: 'T6b-A2b', row: 'T6b', adversary: 'A2b', specified: 'not detected without external custody: anchored 0..40, tail 41..50', primary: true,
    build: async (src) => {
      const e = new Evidence();
      tamperReason(e);
      const base = src.t6bBaseMs();
      for (let seq = 25; seq <= 50; seq++) e.rows[seq]!.block['ts'] = shiftedTs(base, seq);
      e.recompute(25);
      await replace30and40(e, src, 'T6b');
      return e;
    },
    expected: (e) => ({ exitCode: 0, stdout: successStdout(e, ['VERIFIED_ANCHORED 0..40', 'VALID_UNANCHORED 41..50', ...BASE_TAIL], [10, 20, 30, 40]) }),
  },
  {
    id: 'T7-A2b', row: 'T7', adversary: 'A2b', specified: 'degraded coverage: anchored 0..20, tail 21..50', primary: true,
    build: async () => {
      const e = new Evidence();
      tamperReason(e);
      e.deletePackage(30);
      e.deletePackage(40);
      for (const [seq, target] of [[31, 30], [41, 40]] as const) {
        e.rows[seq]!.block['payload'] = Object.assign(Object.create(null) as Record<string, unknown>, {
          event_type: 'checkpoint_failed',
          operation: 'tear.checkpoint',
          target_seq: target,
          error_type: 'tsa_timeout',
        }) as never;
      }
      e.recompute(25);
      return e;
    },
    expected: (e) => ({ exitCode: 0, stdout: successStdout(e, ['VERIFIED_ANCHORED 0..20', 'VALID_UNANCHORED 21..50', ...BASE_TAIL], [10, 20]) }),
  },
  {
    id: 'X1', row: 'X1', adversary: '—',
    specified: 'exit 0; coverage drops to VERIFIED_ANCHORED 0..20, VALID_UNANCHORED 21..50; diagnostics ANCHOR_EVIDENCE_MISSING 30 and 40',
    primary: false,
    build: async () => {
      const e = new Evidence();
      e.deletePackage(30);
      e.deletePackage(40);
      return e;
    },
    expected: (e) => ({
      exitCode: 0,
      stdout: successStdout(
        e,
        ['VERIFIED_ANCHORED 0..20', 'VALID_UNANCHORED 21..50', 'ANCHOR_EVIDENCE_MISSING 30', 'ANCHOR_EVIDENCE_MISSING 40', ...BASE_TAIL],
        [10, 20],
      ),
    }),
  },
  {
    id: 'X2', row: 'X2', adversary: '—',
    specified: 'exit 0; VERIFIED_ANCHORED 0..40, VALID_UNANCHORED 41..50. Expected and not a detection: it demonstrates section 3.3, item 9',
    primary: false,
    build: async () => {
      const e = new Evidence();
      const p = testerPki();
      e.bundle = p.bundle;
      e.setPayloadField(0, 'tsa_ca_bundle_sha256', sha256Hex(p.bundle));
      e.recompute(0);
      for (const k of [10, 20, 30, 40]) {
        const row = e.rows[k]!;
        const tsr = x2Token(p, row.entry_hash, row.block['ts'] as string);
        e.replacePackage(k, tsr, X2_NONCE.toString(16));
        e.setControlMetadata(k, tsr);
        e.recompute(k + 1);
      }
      return e;
    },
    expected: (e) => ({ exitCode: 0, stdout: successStdout(e, ['VERIFIED_ANCHORED 0..40', 'VALID_UNANCHORED 41..50', ...BASE_TAIL], [10, 20, 30, 40]) }),
  },
];
