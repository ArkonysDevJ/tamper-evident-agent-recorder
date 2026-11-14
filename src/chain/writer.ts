// SPDX-License-Identifier: AGPL-3.0-or-later
// Chain writer: start-up under exclusion and application appends with writer
// admission and a confirmed durable COMMIT (Blueprint §5.3, §5.4, §4.2).
// Start-up reconciliation (§5.6) enters through the RecoveryClassifier
// interface; only a clean E1 view is accepted until that is implemented.

import type { ClientConfig } from 'pg';
import { bundleSha256, entryHashOf } from '../crypto/digests.js';
import { TearError } from '../errors.js';
import { inventoryNamespace } from '../fs/inventory.js';
import { fsyncDirectory } from '../fs/namespace.js';
import type { StatfsType } from '../fs/namespace.js';
import { CanonicalizationError, canonicalize } from '../json/jcs.js';
import { newJsonObject } from '../json/strict-json.js';
import type { JsonObject } from '../json/strict-json.js';
import { writerTimestamp } from '../time/timestamps.js';
import { SerialQueue } from '../util/serial-queue.js';
import { acquireExclusion, releaseExclusion } from './exclusion.js';
import type { Exclusion } from './exclusion.js';
import { ZERO_HASH } from './ids.js';
import { INSERT_EVENT_SQL } from './initialize.js';
import { noAnchorHook, notImplementedClassifier } from './interfaces.js';
import type { AnchorHook, RecoveryClassifier } from './interfaces.js';
import type { CutProfile } from './profile.js';
import { isApplicationEventType } from './schema.js';
import type { Block } from './schema.js';
import { loadChain, validateEvents, validateState } from './state.js';
import type { Step1Checker, Step1Failure } from './step1.js';

export interface WriterOptions {
  readonly checkpointsRoot: string;
  readonly chainId: string;
  readonly bundleBytes: Uint8Array;
  readonly pg: ClientConfig;
  readonly profile: CutProfile;
  readonly classifier?: RecoveryClassifier;
  readonly anchorHook?: AnchorHook;
  /** Wall clock in milliseconds; injectable to test clock steps (§4.2). */
  readonly clock?: () => number;
  readonly statfsType?: StatfsType;
}

export interface AppendResult {
  readonly seq: number;
  readonly entryHash: string;
  readonly ts: string;
}

/** Writer admission failure (§5.4): carries the Step 1 diagnostic the verifier would emit. */
export class EventRejectedError extends TearError {
  readonly rejection: Step1Failure;
  constructor(rejection: Step1Failure) {
    super('EVENT_REJECTED', `${rejection.code} ${rejection.param}`);
    this.rejection = rejection;
  }
}

export class ChainWriter {
  private readonly queue = new SerialQueue();
  private sealed: boolean;

  private constructor(
    private readonly ex: Exclusion,
    private readonly checker: Step1Checker,
    private readonly opts: WriterOptions,
    chainClosed: boolean,
  ) {
    this.sealed = chainClosed;
  }

  static async open(opts: WriterOptions): Promise<ChainWriter> {
    const ex = await acquireExclusion(opts);
    try {
      const loaded = await loadChain(ex.conn, opts.chainId);
      if (loaded.events.length === 0 && loaded.stateRow === null) {
        throw new TearError('CHAIN_NOT_INITIALIZED', opts.chainId);
      }
      if (loaded.events.length === 0 || loaded.stateRow === null) {
        throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'only one of events and state exists');
      }
      const checker = validateEvents(loaded.events, opts.chainId, bundleSha256(opts.bundleBytes));
      const state = validateState(loaded.stateRow, checker);
      const entries = inventoryNamespace(ex.nsPath);
      const classifier = opts.classifier ?? notImplementedClassifier;
      const classification = await classifier.classify({
        chainId: opts.chainId,
        nsPath: ex.nsPath,
        rows: checker.accepted,
        state,
        entries,
        nowNs: BigInt((opts.clock ?? Date.now)()) * 1_000_000n,
        profile: opts.profile,
      });
      if (classification.kind === 'not_implemented') {
        throw new TearError('RECOVERY_CLASSIFIER_NOT_IMPLEMENTED', 'E1–E10 classification is not implemented yet');
      }
      if (classification.kind === 'inconsistent') {
        throw new TearError('RECONCILIATION_STATE_INCONSISTENT', classification.reason);
      }
      if (classification.state !== 'E1' || entries.length > 0 || state.pending !== null) {
        throw new TearError('RECONCILIATION_NOT_IMPLEMENTED', `start-up from ${classification.state} needs §5.6 repair`);
      }
      // Directory durability barrier before accepting traffic (§5.6).
      if (ex.conn.invalidated) throw new TearError('WRITER_INVALIDATED');
      fsyncDirectory(ex.nsPath);
      return new ChainWriter(ex, checker, opts, state.chainClosed);
    } catch (err) {
      await releaseExclusion(ex);
      throw err;
    }
  }

  get invalidated(): boolean {
    return this.ex.conn.invalidated;
  }

  get backendPid(): number {
    return this.ex.conn.backendPid;
  }

  get observedPids(): readonly number[] {
    return this.ex.conn.observedPids;
  }

  get headSeq(): number {
    return this.checker.head?.block.seq ?? -1;
  }

  /** Test access to the writer session, used only to simulate faults. */
  get connForTests(): Exclusion['conn'] {
    return this.ex.conn;
  }

  /** Appends one application event. Resolves only after a confirmed COMMIT. */
  append(payload: JsonObject): Promise<AppendResult> {
    return this.queue.run(() => this.appendNow(payload));
  }

  private async appendNow(payload: JsonObject): Promise<AppendResult> {
    if (this.ex.conn.invalidated) throw new TearError('WRITER_INVALIDATED');
    if (this.sealed) throw new TearError('CHAIN_SEALED');
    if (!isApplicationEventType(payload['event_type'])) {
      throw new TearError('EVENT_TYPE_NOT_APPLICATION', 'append accepts application events only');
    }
    const head = this.checker.head;
    if (head === undefined) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'empty chain');

    const block = newJsonObject() as Block;
    block['chain_id'] = this.opts.chainId;
    block['seq'] = head.block.seq + 1;
    block['ts'] = writerTimestamp((this.opts.clock ?? Date.now)(), head.block.ts);
    block['prev_hash'] = head.entryHash;
    block['payload'] = payload;
    let entryHash: string;
    try {
      entryHash = entryHashOf(block);
    } catch (err) {
      // Not serializable (for example a lone surrogate): the schema check below rejects it.
      if (!(err instanceof CanonicalizationError)) throw err;
      entryHash = ZERO_HASH;
    }
    const envelope = newJsonObject();
    envelope['block'] = block;
    envelope['entry_hash'] = entryHash;
    const rejection = this.checker.check({ kind: 'json', value: envelope });
    if (rejection !== null) throw new EventRejectedError(rejection);

    const hook = this.opts.anchorHook ?? noAnchorHook;
    const conn = this.ex.conn;
    const outcome = await conn.mutate(async () => {
      await conn.query(INSERT_EVENT_SQL, [
        block.chain_id,
        String(block.seq),
        block.ts,
        block.prev_hash,
        canonicalize(payload),
        canonicalize(block),
        entryHash,
      ]);
      await hook.onApplicationCommit({
        chainId: block.chain_id,
        seq: block.seq,
        entryHash,
        ts: block.ts,
        query: (text, values) => conn.query(text, values),
      });
    });
    if (outcome === 'unknown') throw new TearError('COMMIT_OUTCOME_UNKNOWN', `seq ${block.seq}`);
    if (outcome === 'rolled_back') {
      conn.invalidate();
      throw new TearError('COMMIT_ROLLED_BACK', `seq ${block.seq}`);
    }
    const accepted = this.checker.accept({ kind: 'json', value: envelope });
    if (accepted !== null) {
      conn.invalidate();
      throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'committed row failed Step 1');
    }
    return { seq: block.seq, entryHash, ts: block.ts };
  }

  /** Drains the queue, then closes writerConn and releases flock. */
  async close(): Promise<void> {
    await this.queue.drain();
    await releaseExclusion(this.ex);
  }
}
