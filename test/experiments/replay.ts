// SPDX-License-Identifier: AGPL-3.0-or-later
// Replay adapter for experiment B: plays experiments/dataset/traces.jsonl
// through the real interceptor. A tool_call line becomes tool_call then
// tool_result (with the recorded result or error); call_id values are unique
// across the whole chain. Nothing here is part of TEAR itself.

import * as fs from 'node:fs';
import type { Interceptor } from '../../src/interceptor/interceptor.js';
import { DATASET_PATH } from '../../scripts/generate-dataset.js';

export type ArgClass = 'small' | 'medium' | 'large';

export interface DatasetStep {
  readonly task_id: string;
  readonly step: number;
  readonly kind: 'tool_call' | 'epistemic_pause' | 'human_resolution' | 'final_answer';
  readonly tool_name?: string;
  readonly args?: unknown;
  readonly result?: unknown;
  readonly error?: { error_type: string; message: string } | null;
  readonly reason?: string;
  readonly missing_sources?: string[];
  readonly reviewer_id?: string;
  readonly decision?: string;
  readonly response?: string;
}

export function readDataset(): DatasetStep[] {
  return fs.readFileSync(DATASET_PATH, 'utf8').trimEnd().split('\n').map((l) => JSON.parse(l) as DatasetStep);
}

/** Argument size class of a tool call, from the byte length of its JSON arguments. */
export function argClassOf(args: unknown): ArgClass {
  const n = Buffer.byteLength(JSON.stringify(args), 'utf8');
  return n < 500 ? 'small' : n < 5000 ? 'medium' : 'large';
}

/** Application events a step records: a tool call records two. */
export const eventsOfStep = (s: DatasetStep): number => (s.kind === 'tool_call' ? 2 : 1);

export interface ReplayRecord {
  readonly seq: number;
  readonly kind: 'tool_call' | 'tool_result' | 'epistemic_pause' | 'human_resolution' | 'agent_final_response';
  readonly argClass?: ArgClass;
  readonly ms: number;
}

/** Replays the steps whose events fit within `maxEvents`; returns one record per application event recorded. */
export async function replay(icp: Interceptor, steps: readonly DatasetStep[], maxEvents = Number.POSITIVE_INFINITY): Promise<ReplayRecord[]> {
  const out: ReplayRecord[] = [];
  let events = 0;
  let call = 0;
  const now = (): number => performance.now();
  for (const s of steps) {
    if (events + eventsOfStep(s) > maxEvents) break;
    events += eventsOfStep(s);
    const t0 = now();
    switch (s.kind) {
      case 'tool_call': {
        call++;
        const h = await icp.beginCall(s.task_id, s.tool_name!, `call-${String(call)}`, s.args);
        const t1 = now();
        const cls = argClassOf(s.args);
        out.push({ seq: h.call.seq, kind: 'tool_call', argClass: cls, ms: t1 - t0 });
        const r = await icp.completeCall(
          h,
          s.error ? { ok: false, errorType: s.error.error_type, message: s.error.message } : { ok: true, value: s.result as never },
        );
        out.push({ seq: r.seq, kind: 'tool_result', argClass: cls, ms: now() - t1 });
        break;
      }
      case 'epistemic_pause': {
        const r = await icp.epistemicPause(s.task_id, s.reason!, s.missing_sources ?? []);
        out.push({ seq: r.seq, kind: 'epistemic_pause', ms: now() - t0 });
        break;
      }
      case 'human_resolution': {
        const r = await icp.humanResolution(s.task_id, s.reviewer_id!, s.decision!);
        out.push({ seq: r.seq, kind: 'human_resolution', ms: now() - t0 });
        break;
      }
      case 'final_answer': {
        await icp.finalResponse(s.task_id, s.response!);
        out.push({ seq: -1, kind: 'agent_final_response', ms: now() - t0 });
        break;
      }
    }
  }
  return out;
}
