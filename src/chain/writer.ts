// SPDX-License-Identifier: AGPL-3.0-or-later
// Chain writer: start-up under exclusion, application appends with writer
// admission and a confirmed durable COMMIT (Blueprint §5.3, §5.4, §4.2), and
// automatic RFC 3161 anchoring (§5.7). Start-up reconciliation (§5.6) enters
// through the RecoveryClassifier interface; only a clean E1 view is accepted
// until that is implemented.

import type { ClientConfig } from 'pg';
import { runAnchorFlow } from '../anchor/flow.js';
import type { AnchorOutcome } from '../anchor/flow.js';
import { autoAnchorHook } from '../anchor/trigger.js';
import { DurableNamespace } from '../fs/durable.js';
import type { DurableFsOps } from '../fs/durable.js';
import { loadBundle } from '../pki/bundle.js';
import type { LoadedBundle } from '../pki/bundle.js';
import { retainedTsas } from '../tsa/transport.js';
import type { TsaEndpoint } from '../tsa/transport.js';
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
import { INSERT_EVENT_SQL, initializeUnderExclusion, requestedGenesis } from './initialize.js';
import type { InitializeOptions } from './initialize.js';
import { notImplementedClassifier } from './interfaces.js';
import type { AnchorHook, PendingAnchor, RecoveryClassifier } from './interfaces.js';
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
  /** Default: the automatic trigger of §5.7 with maxAutoAnchorSeq. */
  readonly anchorHook?: AnchorHook;
  /** max_auto_anchor_seq (§5.7): Infinity in production. */
  readonly maxAutoAnchorSeq?: number;
  /** Retained TSAs in §5.7 order. Default: FreeTSA, then DigiCert. */
  readonly tsas?: readonly TsaEndpoint[];
  /** Wall clock in milliseconds; injectable to test clock steps (§4.2). */
  readonly clock?: () => number;
  readonly statfsType?: StatfsType;
  /** Test seam for namespace fault injection (§5.5). */
  readonly fsOps?: DurableFsOps;
  /**
   * Last step of drain-and-exit (§5.3), after already-started mutations settled
   * and writerConn and flock were released. Default: exit the process with code 70.
   */
  readonly exit?: (cause: unknown) => void;
}

export interface AppendResult {
  readonly seq: number;
  readonly entryHash: string;
  readonly ts: string;
  /** Set when this append triggered an anchor; the append resolves only after it settled. */
  readonly anchor?: AnchorOutcome;
}

const defaultExit = (cause: unknown): void => {
  process.stderr.write(`tear writer: drain-and-exit: ${cause instanceof Error ? cause.message : String(cause)}\n`);
  process.exit(70);
};

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
  private readonly files: DurableNamespace;
  private fatalStarted = false;
  private released = false;

  private constructor(
    private readonly ex: Exclusion,
    private readonly checker: Step1Checker,
    private readonly opts: WriterOptions,
    private readonly bundle: LoadedBundle,
    chainClosed: boolean,
  ) {
    this.sealed = chainClosed;
    this.files = new DurableNamespace(ex.nsPath, ex.conn, {
      ...(opts.fsOps !== undefined ? { fsOps: opts.fsOps } : {}),
      onFatal: (cause) => void this.exitAfterDrain(cause),
    });
  }

  /** Starts drain-and-exit once: invalidate, let started file mutations settle, release, exit. */
  private fatal(cause: unknown): void {
    if (this.fatalStarted) return;
    this.fatalStarted = true;
    this.ex.conn.invalidate();
    if (this.files.failed) return; // DurableNamespace calls onFatal itself after draining.
    void this.files.drain().then(() => this.exitAfterDrain(cause));
  }

  private async exitAfterDrain(cause: unknown): Promise<void> {
    this.fatalStarted = true;
    await this.release();
    (this.opts.exit ?? defaultExit)(cause);
  }

  private async release(): Promise<void> {
    if (this.released) return;
    this.released = true;
    await releaseExclusion(this.ex);
  }

  static async open(opts: WriterOptions): Promise<ChainWriter> {
    let bundle: LoadedBundle;
    try {
      bundle = loadBundle(opts.bundleBytes);
    } catch (err) {
      throw new TearError('TSA_BUNDLE_UNLOADABLE', (err as Error).message);
    }
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
      return new ChainWriter(ex, checker, opts, bundle, state.chainClosed);
    } catch (err) {
      await releaseExclusion(ex);
      throw err;
    }
  }

  /**
   * Creates the chain in a new, empty namespace and starts the writer in the
   * same session (same flock and writerConn) when initializeChain returns
   * INITIALIZED.
   *
   * Implementation choice (not normative), provisional until spec 006: the
   * writer accepts events only in the session that created the chain. Any
   * existing chain (ALREADY_INITIALIZED, RECOVERY_REQUIRED or an inspection
   * error) is refused: opening it needs the §5.6 start-up of spec 006.
   */
  static async initializeAndOpen(opts: WriterOptions & Omit<InitializeOptions, keyof WriterOptions | 'classifier'>): Promise<ChainWriter> {
    const initOpts: InitializeOptions = { ...opts, classifier: notImplementedClassifier };
    const requested = requestedGenesis(initOpts);
    let bundle: LoadedBundle;
    try {
      bundle = loadBundle(opts.bundleBytes);
    } catch (err) {
      throw new TearError('TSA_BUNDLE_UNLOADABLE', (err as Error).message);
    }
    const ex = await acquireExclusion(opts);
    try {
      const result = await initializeUnderExclusion(ex, initOpts, requested);
      if (result !== 'INITIALIZED') {
        throw new TearError('WRITER_START_NOT_IMPLEMENTED', `${result}: opening an existing chain needs the §5.6 start-up`);
      }
      // Same session: load and validate exactly what this session committed.
      const loaded = await loadChain(ex.conn, opts.chainId);
      if (loaded.stateRow === null) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'state row missing after creation');
      const checker = validateEvents(loaded.events, opts.chainId, bundleSha256(opts.bundleBytes));
      const state = validateState(loaded.stateRow, checker);
      if (checker.length !== 1 || state.pending !== null || state.chainClosed || inventoryNamespace(ex.nsPath).length > 0) {
        throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'a newly created chain must hold only its genesis');
      }
      if (ex.conn.invalidated) throw new TearError('WRITER_INVALIDATED');
      fsyncDirectory(ex.nsPath);
      return new ChainWriter(ex, checker, opts, bundle, false);
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

    const hook = this.opts.anchorHook ?? autoAnchorHook(this.opts.maxAutoAnchorSeq);
    const conn = this.ex.conn;
    const hooked: { pending: PendingAnchor | null } = { pending: null };
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
      hooked.pending = await hook.onApplicationCommit({
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
    const result = { seq: block.seq, entryHash, ts: block.ts };
    const pending = hooked.pending;
    if (pending === null) return result;
    // The pending anchor is resolved in this queue slot, before any other append or close (§5.3, §5.7).
    // Implementation choice: if the flow aborts, this append rejects although row k is committed;
    // the caller treats it as unconfirmed (the tool is not run, nothing is delivered).
    try {
      const anchor = await runAnchorFlow(
        {
          chainId: this.opts.chainId,
          conn,
          files: this.files,
          checker: this.checker,
          bundle: this.bundle,
          tsas: this.opts.tsas ?? retainedTsas(),
          clock: this.opts.clock ?? Date.now,
          fatal: (cause) => this.fatal(cause),
        },
        pending,
      );
      return { ...result, anchor };
    } catch (err) {
      this.fatal(err);
      throw err;
    }
  }

  /** True once drain-and-exit started; the writer admits nothing more. */
  get failed(): boolean {
    return this.fatalStarted;
  }

  /** Drains the queue, then closes writerConn and releases flock. */
  async close(): Promise<void> {
    await this.queue.drain();
    await this.files.drain();
    await this.release();
  }
}
