// SPDX-License-Identifier: AGPL-3.0-or-later
// Write-ahead interceptor between one agent and its tools (Blueprint §2, §5.4).
// Every tool call, epistemic pause, human resolution and final answer is
// committed durably before it takes effect:
//   tool_call             → confirmed COMMIT → the tool runs
//   tool_result           → confirmed COMMIT → the result (or error) is delivered
//   epistemic_pause,
//   human_resolution      → confirmed COMMIT → the agent continues
//   agent_final_response  → confirmed COMMIT → the answer is delivered
// Any failure or unknown outcome of a write stops that step: the tool does not
// run, nothing is delivered and the agent does not continue. Nothing is retried.

import { TearError } from '../errors.js';
import { initializeChain } from '../chain/initialize.js';
import type { InitializeOptions, InitializeResult } from '../chain/initialize.js';
import { ChainWriter } from '../chain/writer.js';
import type { AppendResult, WriterOptions } from '../chain/writer.js';
import { readPepper } from './pepper.js';
import { argsHmac, resultDigest, responseDigest } from '../crypto/digests.js';
import { canonicalize } from '../json/jcs.js';
import { newJsonObject } from '../json/strict-json.js';
import type { JsonObject, JsonValue } from '../json/strict-json.js';

/**
 * Implementation choice (not normative; §10 leaves operation literals for
 * application events open). They follow the OpenTelemetry GenAI operation
 * names where one exists.
 */
export const OPERATION = {
  toolCall: 'execute_tool',
  toolResult: 'execute_tool',
  epistemicPause: 'tear.epistemic_pause',
  humanResolution: 'tear.human_resolution',
  finalResponse: 'invoke_agent',
} as const;

/** A tool failure the agent sees; error_type is recorded in tool_result. */
export class ToolError extends Error {
  readonly errorType: string;
  constructor(errorType: string, message: string) {
    super(message);
    this.name = 'ToolError';
    this.errorType = errorType;
  }
}

export type Tool = (args: JsonValue) => Promise<JsonValue> | JsonValue;

const MAX_ADAPTER_DEPTH = 512;

function inDomain(v: unknown, depth: number, seen: Set<object>): boolean {
  if (v === null || typeof v === 'boolean') return true;
  if (typeof v === 'number') return Number.isFinite(v);
  if (typeof v === 'string') return v.isWellFormed();
  if (typeof v !== 'object' || depth > MAX_ADAPTER_DEPTH || seen.has(v)) return false;
  seen.add(v);
  try {
    if (Array.isArray(v)) {
      if (Object.getPrototypeOf(v) !== Array.prototype) return false;
      for (let i = 0; i < v.length; i++) if (!(i in v) || !inDomain(v[i], depth + 1, seen)) return false;
      return Object.keys(v).length === v.length;
    }
    const proto: unknown = Object.getPrototypeOf(v);
    if (proto !== Object.prototype && proto !== null) return false; // Date, Map, class instances…
    if (Object.getOwnPropertySymbols(v).length > 0) return false;
    for (const key of Object.getOwnPropertyNames(v)) {
      const d = Object.getOwnPropertyDescriptor(v, key)!;
      if (!d.enumerable || !('value' in d) || !key.isWellFormed()) return false;
      if (!inDomain(d.value, depth + 1, seen)) return false;
    }
    return true;
  } finally {
    seen.delete(v);
  }
}

/**
 * Checks that an adapter value is a JSON value in the RFC 8785 domain (§4.3):
 * null, booleans, finite numbers, well-formed strings, dense arrays and plain
 * objects with data properties. Anything else (undefined, NaN, BigInt,
 * functions, symbols, Date, Map, cycles, lone surrogates) is ADAPTER_JSON_INVALID.
 */
export function adapterJson(value: unknown, what: string): JsonValue {
  if (!inDomain(value, 0, new Set())) throw new TearError('ADAPTER_JSON_INVALID', what);
  canonicalize(value as JsonValue);
  return value as JsonValue;
}

function deepFreeze<T>(v: T): T {
  if (v !== null && typeof v === 'object') {
    for (const k of Object.keys(v)) deepFreeze((v as Record<string, unknown>)[k]);
    Object.freeze(v);
  }
  return v;
}

/**
 * The adapter value as an immutable snapshot, taken on entry: the snapshot is what is canonicalized and hashed,
 * and what the tool receives or the caller is given, never the caller's original reference (review finding 3).
 */
export function snapshotJson(value: unknown, what: string): JsonValue {
  return deepFreeze(structuredClone(adapterJson(value, what)));
}

/**
 * Implementation choice (not normative; §10 leaves result_digest for a failed
 * tool open): the result value of a failed tool is
 * {"error_type": <error_type>, "message": <error message>}.
 */
export function failedToolValue(errorType: string, message: string): JsonObject {
  const o = newJsonObject();
  o['error_type'] = errorType;
  o['message'] = message;
  return o;
}

export interface ToolCallHandle {
  readonly callId: string;
  readonly taskId: string;
  readonly toolName: string;
  readonly call: AppendResult;
  /** The recorded arguments: the immutable snapshot that was hashed. */
  readonly args: JsonValue;
}

export type ToolOutcome = { readonly ok: true; readonly value: JsonValue } | { readonly ok: false; readonly errorType: string; readonly message: string };

function payload(fields: Record<string, JsonValue>): JsonObject {
  const o = newJsonObject();
  for (const [k, v] of Object.entries(fields)) o[k] = v;
  return o;
}

export class Interceptor {
  private readonly tools = new Map<string, Tool>();

  /** The pepper is decoded by the caller (readPepper) before the writer starts, so a bad one writes nothing. */
  constructor(
    private readonly writer: ChainWriter,
    private readonly pepper: Uint8Array,
  ) {}

  /**
   * Start-up: the pepper is read and checked first, so a missing or invalid
   * TEAR_HMAC_PEPPER refuses before anything is written. Then initializeChain
   * (§5.3a) creates the chain or inspects the existing one without mutation,
   * and the writer starts under fresh exclusion, running §5.6 reconciliation
   * before it accepts traffic.
   */
  static async start(
    opts: WriterOptions & Pick<InitializeOptions, 'genesisTs' | 'pepperId'>,
    env: NodeJS.ProcessEnv = process.env,
  ): Promise<{ interceptor: Interceptor; writer: ChainWriter; initialized: InitializeResult }> {
    const pepper = readPepper(env);
    const initialized = await initializeChain(opts);
    const writer = await ChainWriter.open(opts);
    return { interceptor: new Interceptor(writer, pepper), writer, initialized };
  }

  register(name: string, tool: Tool): void {
    this.tools.set(name, tool);
  }

  /** Records tool_call; resolves only after its COMMIT is confirmed. The tool has not run. */
  async beginCall(taskId: string, toolName: string, callId: string, args: unknown): Promise<ToolCallHandle> {
    const json = snapshotJson(args, 'tool arguments');
    const call = await this.writer.append(
      payload({
        event_type: 'tool_call',
        operation: OPERATION.toolCall,
        tool_name: toolName,
        call_id: callId,
        task_id: taskId,
        args_hmac: argsHmac(this.pepper, json),
      }),
    );
    return { callId, taskId, toolName, call, args: json };
  }

  /** Records tool_result; resolves only after its COMMIT is confirmed. */
  async completeCall(h: Pick<ToolCallHandle, 'callId' | 'taskId' | 'toolName'>, outcome: ToolOutcome): Promise<AppendResult> {
    const value = outcome.ok ? snapshotJson(outcome.value, 'tool result') : failedToolValue(outcome.errorType, outcome.message);
    return this.writer.append(
      payload({
        event_type: 'tool_result',
        operation: OPERATION.toolResult,
        call_id: h.callId,
        task_id: h.taskId,
        error_type: outcome.ok ? null : outcome.errorType,
        result_digest: resultDigest(value),
        summary: outcome.ok ? `${h.toolName} succeeded` : `${h.toolName} failed: ${outcome.errorType}`,
      }),
    );
  }

  /**
   * The whole call: tool_call committed → tool runs → tool_result committed →
   * the value is returned, or the ToolError is thrown to the agent.
   */
  async callTool(taskId: string, toolName: string, callId: string, args: unknown): Promise<JsonValue> {
    const tool = this.tools.get(toolName);
    if (tool === undefined) throw new TearError('TOOL_UNKNOWN', toolName);
    const handle = await this.beginCall(taskId, toolName, callId, args);
    let outcome: ToolOutcome;
    try {
      outcome = { ok: true, value: snapshotJson(await tool(handle.args), 'tool result') };
    } catch (err) {
      if (!(err instanceof ToolError)) throw err; // An adapter fault, not a tool result: nothing is delivered.
      outcome = { ok: false, errorType: err.errorType, message: err.message };
    }
    await this.completeCall(handle, outcome);
    if (!outcome.ok) throw new ToolError(outcome.errorType, outcome.message);
    return outcome.value;
  }

  /** Records epistemic_pause; the agent continues only after the COMMIT is confirmed. */
  async epistemicPause(taskId: string, reason: string, missingSources: readonly string[]): Promise<AppendResult> {
    return this.writer.append(
      payload({ event_type: 'epistemic_pause', operation: OPERATION.epistemicPause, task_id: taskId, reason, missing_sources: [...missingSources] }),
    );
  }

  /** Records human_resolution; the agent continues only after the COMMIT is confirmed. */
  async humanResolution(taskId: string, reviewerId: string, decision: string): Promise<AppendResult> {
    return this.writer.append(
      payload({ event_type: 'human_resolution', operation: OPERATION.humanResolution, task_id: taskId, reviewer_id: reviewerId, decision }),
    );
  }

  /** Records agent_final_response; returns the answer for delivery only after the COMMIT is confirmed. */
  async finalResponse(taskId: string, response: unknown): Promise<JsonValue> {
    const json = snapshotJson(response, 'final response');
    await this.writer.append(
      payload({ event_type: 'agent_final_response', operation: OPERATION.finalResponse, task_id: taskId, response_digest: responseDigest(json) }),
    );
    return json;
  }
}
