// SPDX-License-Identifier: AGPL-3.0-or-later
// Chain writer: start-up under exclusion, application appends with writer
// admission and a confirmed durable COMMIT (Blueprint §5.3, §5.4, §4.2), and
// automatic RFC 3161 anchoring (§5.7). Start-up reconciliation (§5.6) enters
// through the RecoveryClassifier interface; only a clean E1 view is accepted
// until that is implemented.

import type { ClientConfig } from 'pg';
import { runAnchorFlow } from '../anchor/flow.js';
import type { AnchorFlowDeps, AnchorOutcome } from '../anchor/flow.js';
import { SET_PENDING_SQL, autoAnchorHook } from '../anchor/trigger.js';
import { stateClassifier } from '../recovery/classifier.js';
import { reconcile } from '../recovery/reconcile.js';
import type { ReconcileDeps } from '../recovery/reconcile.js';
import { DurableNamespace } from '../fs/durable.js';
import type { DurableFsOps } from '../fs/durable.js';
import { loadBundle } from '../pki/bundle.js';
import type { LoadedBundle } from '../pki/bundle.js';
import { retainedTsas } from '../tsa/transport.js';
import type { TsaEndpoint } from '../tsa/transport.js';
import { bundleSha256, entryHashOf } from '../crypto/digests.js';
import { TearError } from '../errors.js';
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
import type { AnchorHook, PendingAnchor, RecoveryClassifier, RecoveryState } from './interfaces.js';
import { retiresCloseRetry } from './profile.js';
import type { CutProfile } from './profile.js';
import { isApplicationEventType } from './schema.js';
import type { Block } from './schema.js';
import { loadChain, validateEvents, validateState } from './state.js';
import type { ChainState } from './state.js';
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

export type CloseLiteral = 'CLOSED_NO_ANCHOR' | 'ANCHORED_FIRST_ATTEMPT' | 'ANCHORED_AFTER_PREVIOUS_FAILURE' | 'UNANCHORED_FAILURE';

export interface CloseResult {
  readonly result: CloseLiteral;
  readonly branch: 'B0' | 'B1' | 'B2' | 'B3';
  /** Set when the close contacted a TSA. */
  readonly anchor?: AnchorOutcome;
}

const SEAL_SQL = 'UPDATE tear_chain_state SET chain_closed = true WHERE chain_id = $1::uuid RETURNING chain_id';

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
    let writer: ChainWriter | null = null;
    try {
      // §5.6 step 1: state and every event column, loaded and validated on writerConn under exclusion.
      const loaded = await loadChain(ex.conn, opts.chainId);
      if (loaded.events.length === 0 && loaded.stateRow === null) {
        throw new TearError('CHAIN_NOT_INITIALIZED', opts.chainId);
      }
      if (loaded.events.length === 0 || loaded.stateRow === null) {
        throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'only one of events and state exists');
      }
      const checker = validateEvents(loaded.events, opts.chainId, bundleSha256(opts.bundleBytes));
      const state = validateState(loaded.stateRow, checker);
      writer = new ChainWriter(ex, checker, opts, bundle, state.chainClosed);
      const result = await reconcile(writer.reconcileDeps(state));
      writer.startedFrom = result.from;
      return writer;
    } catch (err) {
      if (writer !== null) await writer.release();
      else await releaseExclusion(ex);
      throw err;
    }
  }

  /** The §5.6 state found at start-up (after .tmp deletion). */
  startedFrom: RecoveryState | null = null;

  private flowDeps(): AnchorFlowDeps {
    return {
      chainId: this.opts.chainId,
      conn: this.ex.conn,
      files: this.files,
      checker: this.checker,
      bundle: this.bundle,
      tsas: this.opts.tsas ?? retainedTsas(),
      clock: this.opts.clock ?? Date.now,
      fatal: (cause) => this.fatal(cause),
    };
  }

  private reconcileDeps(state: ChainState): ReconcileDeps {
    return {
      ...this.flowDeps(),
      nsPath: this.ex.nsPath,
      profile: this.opts.profile,
      classifier: this.opts.classifier ?? stateClassifier,
      state,
      view: (st, entries) => ({
        chainId: this.opts.chainId,
        nsPath: this.ex.nsPath,
        rows: this.checker.accepted,
        state: st,
        entries,
        nowNs: BigInt((this.opts.clock ?? Date.now)()) * 1_000_000n,
        profile: this.opts.profile,
        bundle: this.bundle,
      }),
      reloadState: async () => {
        const loaded = await loadChain(this.ex.conn, this.opts.chainId);
        if (loaded.stateRow === null) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'state row missing');
        return validateState(loaded.stateRow, this.checker);
      },
    };
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
      const anchor = await runAnchorFlow(this.flowDeps(), pending);
      return { ...result, anchor };
    } catch (err) {
      this.fatal(err);
      throw err;
    }
  }

  /**
   * closeChain (§5.8): enqueued behind any pending anchor; seals the chain
   * durably (or confirms it is sealed), then evaluates B0–B3.
   */
  closeChain(opts: { retry?: boolean } = {}): Promise<CloseResult> {
    return this.queue.run(() => this.closeNow(opts.retry === true));
  }

  private async closeNow(retry: boolean): Promise<CloseResult> {
    if (this.ex.conn.invalidated) throw new TearError('WRITER_INVALIDATED');
    if (!this.sealed) {
      const outcome = await this.ex.conn.mutate(async () => {
        const rows = await this.ex.conn.query(SEAL_SQL, [this.opts.chainId]);
        if (rows.length !== 1) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'state row missing');
      });
      if (outcome !== 'committed') {
        const cause = new TearError(outcome === 'unknown' ? 'COMMIT_OUTCOME_UNKNOWN' : 'COMMIT_ROLLED_BACK', 'sealing the chain');
        this.fatal(cause);
        throw cause;
      }
      this.sealed = true;
    }
    const rows = this.checker.accepted;
    const h = rows.length - 1;
    let lastApp = 0;
    let maxAnchored = -1;
    for (const r of rows) {
      const t = r.block.payload['event_type'];
      if (isApplicationEventType(t)) lastApp = r.block.seq;
      if (t === 'checkpoint_anchored') maxAnchored = Math.max(maxAnchored, r.block.payload['anchored_seq'] as number);
    }
    // B0: only genesis.
    if (h === 0) return { result: 'CLOSED_NO_ANCHOR', branch: 'B0' };
    // B1: already anchored up to the last application event.
    if (maxAnchored >= lastApp) {
      const afterFailure = rows[maxAnchored]?.block.payload['event_type'] === 'checkpoint_failed' && !retiresCloseRetry(this.opts.profile);
      return { result: afterFailure ? 'ANCHORED_AFTER_PREVIOUS_FAILURE' : 'ANCHORED_FIRST_ATTEMPT', branch: 'B1' };
    }
    const head = rows[h]!;
    const headFailed = head.block.payload['event_type'] === 'checkpoint_failed';
    // B3 without retry (or with B3 retired under Cut 2): no TSA call.
    if (headFailed && (!retry || retiresCloseRetry(this.opts.profile))) return { result: 'UNANCHORED_FAILURE', branch: 'B3' };
    const mode = headFailed ? 'close_retry' : 'close';
    const outcome = await this.ex.conn.mutate(async () => {
      const set = await this.ex.conn.query(SET_PENDING_SQL, [this.opts.chainId, String(h), head.entryHash, head.block.ts, mode]);
      if (set.length !== 1) throw new TearError('RECONCILIATION_STATE_INCONSISTENT', 'pending anchor already set');
    });
    if (outcome !== 'committed') {
      const cause = new TearError(outcome === 'unknown' ? 'COMMIT_OUTCOME_UNKNOWN' : 'COMMIT_ROLLED_BACK', `close pending ${String(h)}`);
      this.fatal(cause);
      throw cause;
    }
    let anchor: AnchorOutcome;
    try {
      anchor = await runAnchorFlow(this.flowDeps(), { seq: h, entryHash: head.entryHash, ts: head.block.ts });
    } catch (err) {
      this.fatal(err);
      throw err;
    }
    const branch = headFailed ? 'B3' : 'B2';
    if (anchor.kind === 'failed') return { result: 'UNANCHORED_FAILURE', branch, anchor };
    return { result: headFailed ? 'ANCHORED_AFTER_PREVIOUS_FAILURE' : 'ANCHORED_FIRST_ATTEMPT', branch, anchor };
  }

  get sealedChain(): boolean {
    return this.sealed;
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
