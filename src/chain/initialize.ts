// SPDX-License-Identifier: AGPL-3.0-or-later
// initializeChain (Blueprint §5.3a): atomic creation in a new namespace, and a
// non-mutating inspection of an existing chain. Recovery classification
// (§5.6) enters through the RecoveryClassifier interface.

import type { ClientConfig } from 'pg';
import { bundleSha256, entryHashOf } from '../crypto/digests.js';
import { TearError } from '../errors.js';
import { inventoryNamespace } from '../fs/inventory.js';
import type { StatfsType } from '../fs/namespace.js';
import { canonicalize } from '../json/jcs.js';
import { newJsonObject } from '../json/strict-json.js';
import { parseTimestampMs } from '../time/timestamps.js';
import { acquireExclusion, releaseExclusion } from './exclusion.js';
import type { Exclusion } from './exclusion.js';
import { CHAIN_VERSION, ZERO_HASH, isChainId } from './ids.js';
import { loadBundle } from '../pki/bundle.js';
import type { LoadedBundle } from '../pki/bundle.js';
import { stateClassifier } from '../recovery/classifier.js';
import type { RecoveryClassifier } from './interfaces.js';
import { permitsAutomaticRecovery } from './profile.js';
import type { CutProfile } from './profile.js';
import { checkSqlRow } from './sql-rows.js';
import type { SqlEventRow } from './sql-rows.js';
import type { Block } from './schema.js';
import { loadChain, validateEvents, validateState } from './state.js';
import { Step1Checker } from './step1.js';

export interface InitializeOptions {
  readonly checkpointsRoot: string;
  readonly chainId: string;
  readonly genesisTs: string;
  readonly pepperId: string;
  /** Raw bytes of the pinned bundle (certs/tsa_roots.pem). */
  readonly bundleBytes: Uint8Array;
  readonly pg: ClientConfig;
  readonly profile: CutProfile;
  readonly classifier?: RecoveryClassifier;
  readonly now?: () => bigint;
  readonly statfsType?: StatfsType;
  /** Test seam: runs inside the creation transaction, just before COMMIT. */
  readonly beforeCreateCommitForTests?: (backendPid: number) => Promise<void>;
}

export type InitializeResult = 'INITIALIZED' | 'ALREADY_INITIALIZED' | 'RECOVERY_REQUIRED';

function argumentInvalid(reason: string): TearError {
  // Implementation choice (not normative): §10 leaves this code to the implementation.
  return new TearError('INITIALIZATION_ARGUMENT_INVALID', reason);
}

function inconsistent(reason: string): TearError {
  return new TearError('RECONCILIATION_STATE_INCONSISTENT', reason);
}

export function buildGenesisBlock(chainId: string, genesisTs: string, pepperId: string, bundleDigest: string): Block {
  const payload = newJsonObject();
  payload['event_type'] = 'chain_genesis';
  payload['operation'] = 'tear.genesis';
  payload['chain_version'] = CHAIN_VERSION;
  payload['pepper_id'] = pepperId;
  payload['tsa_ca_bundle_sha256'] = bundleDigest;
  const block = newJsonObject() as Block;
  block['chain_id'] = chainId;
  block['seq'] = 0;
  block['ts'] = genesisTs;
  block['prev_hash'] = ZERO_HASH;
  block['payload'] = payload;
  return block;
}

export const INSERT_EVENT_SQL = `INSERT INTO tear_events (chain_id, seq, ts, prev_hash, payload, block_json, entry_hash)
  VALUES ($1::uuid, $2::bigint, $3, $4, $5::jsonb, $6, $7)`;

/** Validates the initialization arguments and builds the requested genesis; no SQL work. */
export function requestedGenesis(opts: InitializeOptions): Block {
  if (!isChainId(opts.chainId)) throw argumentInvalid('chain_id');
  if (parseTimestampMs(opts.genesisTs) === null) throw argumentInvalid('genesis_ts');
  if (opts.pepperId.length === 0 || !opts.pepperId.isWellFormed() || opts.pepperId.includes('\u0000')) {
    throw argumentInvalid('pepper_id');
  }
  if (opts.bundleBytes.length === 0) throw argumentInvalid('bundle');
  return buildGenesisBlock(opts.chainId, opts.genesisTs, opts.pepperId, bundleSha256(opts.bundleBytes));
}

export async function initializeChain(opts: InitializeOptions): Promise<InitializeResult> {
  // Input validation precedes any SQL work.
  const requested = requestedGenesis(opts);
  const ex = await acquireExclusion(opts);
  try {
    return await initializeUnderExclusion(ex, opts, requested);
  } finally {
    await releaseExclusion(ex);
  }
}

/** §5.3a on an exclusion already held; the caller releases it. */
export async function initializeUnderExclusion(ex: Exclusion, opts: InitializeOptions, requested: Block): Promise<InitializeResult> {
  const loaded = await loadChain(ex.conn, opts.chainId);
  const entries = inventoryNamespace(ex.nsPath);
  const hasEvents = loaded.events.length > 0;
  const hasState = loaded.stateRow !== null;

  if (!hasEvents && !hasState) {
    if (entries.length > 0) throw inconsistent('uninitialized namespace is not empty');
    return createChain(ex, requested, opts.beforeCreateCommitForTests);
  }
  if (!hasEvents || !hasState) throw inconsistent('only one of events and state exists');
  return inspectExisting(ex, opts, requested, loaded.events, loaded.stateRow!, entries);
}

async function createChain(
  ex: Exclusion,
  requested: Block,
  beforeCommit?: (backendPid: number) => Promise<void>,
): Promise<InitializeResult> {
  const blockJson = canonicalize(requested);
  const entryHash = entryHashOf(requested);
  const outcome = await ex.conn.mutate(async () => {
    await ex.conn.query(INSERT_EVENT_SQL, [
      requested.chain_id,
      '0',
      requested.ts,
      requested.prev_hash,
      canonicalize(requested.payload),
      blockJson,
      entryHash,
    ]);
    await ex.conn.query(
      `INSERT INTO tear_chain_state (chain_id, chain_closed, pending_anchor_seq, pending_entry_hash, pending_ts, pending_mode)
       VALUES ($1::uuid, false, NULL, NULL, NULL, NULL)`,
      [requested.chain_id],
    );
    if (beforeCommit !== undefined) await beforeCommit(ex.conn.backendPid);
  });
  if (outcome === 'committed') return 'INITIALIZED';
  if (outcome === 'unknown') throw new TearError('COMMIT_OUTCOME_UNKNOWN', 'initialization commit outcome unknown');
  throw new TearError('COMMIT_ROLLED_BACK', 'initialization was rolled back');
}

async function inspectExisting(
  ex: Exclusion,
  opts: InitializeOptions,
  requested: Block,
  events: readonly SqlEventRow[],
  stateRow: NonNullable<Awaited<ReturnType<typeof loadChain>>['stateRow']>,
  entries: ReturnType<typeof inventoryNamespace>,
): Promise<InitializeResult> {
  // Step 1: the stored genesis on its own, using its stored bundle digest as data.
  const genesisRow = events[0];
  if (genesisRow === undefined || genesisRow.seq !== '0') throw inconsistent('missing genesis');
  const genesisCheck = checkSqlRow(genesisRow);
  if (!genesisCheck.ok) throw inconsistent(`genesis: ${genesisCheck.reason}`);
  const storedDigest = genesisCheck.block.payload['tsa_ca_bundle_sha256'];
  const genesisChecker = new Step1Checker({
    bundleSha256: typeof storedDigest === 'string' ? storedDigest : '',
    namespaceChainId: opts.chainId,
  });
  const genesisFailure = genesisChecker.accept({ kind: 'json', value: genesisCheck.envelope });
  if (genesisFailure !== null) throw inconsistent(`genesis: ${genesisFailure.code}`);
  if (canonicalize(genesisCheck.block) !== canonicalize(requested)) {
    throw new TearError('CHAIN_INITIALIZATION_CONFLICT', 'stored genesis differs from the requested genesis');
  }

  // Step 2: full chain and state, with identical genesis.
  const checker = validateEvents(events, opts.chainId, requested.payload['tsa_ca_bundle_sha256'] as string);
  const state = validateState(stateRow, checker);

  // Step 3: in-memory view without recognized temporary files, classified through the interface.
  const hasTmp = entries.some((e) => e.temporary);
  let bundle: LoadedBundle;
  try {
    bundle = loadBundle(opts.bundleBytes);
  } catch (err) {
    throw new TearError('TSA_BUNDLE_UNLOADABLE', (err as Error).message);
  }
  const classifier = opts.classifier ?? stateClassifier;
  const classification = await classifier.classify({
    chainId: opts.chainId,
    nsPath: ex.nsPath,
    rows: checker.accepted,
    state,
    entries: entries.filter((e) => !e.temporary),
    nowNs: (opts.now ?? (() => BigInt(Date.now()) * 1_000_000n))(),
    profile: opts.profile,
    bundle,
  });
  if (classification.kind === 'inconsistent') throw inconsistent(classification.reason);

  // Step 4: map the classification for the active profile.
  const s = classification.state;
  if (!permitsAutomaticRecovery(opts.profile)) {
    const hasTsq = entries.some((e) => e.kind === 'tsq');
    if (s === 'E1' && !hasTmp && !hasTsq && state.pending === null) return 'ALREADY_INITIALIZED';
    throw inconsistent(`state ${s} under ${opts.profile}`);
  }
  if (s === 'E1' && !hasTmp) return 'ALREADY_INITIALIZED';
  if (s === 'E1' || s === 'E2' || s === 'E4' || s === 'E5' || s === 'E7' || s === 'E8' || s === 'E9') {
    return 'RECOVERY_REQUIRED';
  }
  throw inconsistent(`state ${s}`);
}
