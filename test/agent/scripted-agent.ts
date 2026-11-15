// SPDX-License-Identifier: AGPL-3.0-or-later
// Scripted reference agent (a test instrument, not a real agent and not
// evidence of any model's behavior): TypeScript, no framework, no LLM. It walks
// a fixed script over three deterministic local tools; `lookup_record` always
// fails, to exercise a failed tool call.

import { createHash } from 'node:crypto';
import { Interceptor, ToolError } from '../../src/interceptor/interceptor.js';
import type { JsonValue } from '../../src/json/strict-json.js';

export const TOOLS = {
  word_count: (args: JsonValue): JsonValue => {
    const text = (args as { text: string }).text;
    return { words: text.split(/\s+/).filter((w) => w !== '').length };
  },
  text_digest: (args: JsonValue): JsonValue => ({
    sha256: createHash('sha256').update((args as { text: string }).text, 'utf8').digest('hex'),
  }),
  lookup_record: (args: JsonValue): JsonValue => {
    throw new ToolError('not_found', `no record with id ${String((args as { id: string }).id)}`);
  },
} as const;

export type ToolName = keyof typeof TOOLS;

export type Step =
  | { kind: 'tool'; tool: ToolName; args: JsonValue }
  | { kind: 'pause'; reason: string; missing: string[] }
  | { kind: 'resolution'; reviewer: string; decision: string }
  | { kind: 'final'; response: JsonValue };

/** One task of the script: 9 events (3 tool calls with results, a pause, a resolution, a final answer). */
export function taskScript(i: number): Step[] {
  const text = `scripted input number ${String(i)} for the reference agent`;
  return [
    { kind: 'tool', tool: 'word_count', args: { text } },
    { kind: 'tool', tool: 'text_digest', args: { text } },
    { kind: 'tool', tool: 'lookup_record', args: { id: `rec-${String(i)}` } },
    { kind: 'pause', reason: 'record not found; waiting for a reviewer', missing: [`rec-${String(i)}`] },
    { kind: 'resolution', reviewer: 'reviewer-1', decision: 'continue without the record' },
    { kind: 'final', response: `task ${String(i)} done` },
  ];
}

/** Events a step records: a tool step records two (tool_call and tool_result). */
export function eventsOf(step: Step): number {
  return step.kind === 'tool' ? 2 : 1;
}

/** A script of exactly `events` application events: whole tasks, then pauses to fill the remainder. */
export function scriptOf(events: number): { taskId: string; step: Step }[] {
  const out: { taskId: string; step: Step }[] = [];
  let n = 0;
  let task = 0;
  while (n + 9 <= events) {
    task++;
    for (const step of taskScript(task)) out.push({ taskId: `task-${String(task)}`, step });
    n += 9;
  }
  while (n < events) {
    out.push({ taskId: `task-fill-${String(n)}`, step: { kind: 'pause', reason: 'filler pause', missing: [] } });
    n++;
  }
  return out;
}

export interface StepTiming {
  readonly kind: Step['kind'];
  /**
   * Milliseconds per event of this step. A tool step has two: the call half (recording tool_call) and the
   * result half (running the tool, then recording tool_result). Without the interceptor the same halves
   * hold no recording.
   */
  readonly eventsMs: number[];
  /** Application seqs this step recorded, when recorded. */
  readonly seqs: number[];
  /** True when one of its records triggered an anchor. */
  readonly anchored: boolean[];
}

export interface Recorder {
  run(taskId: string, step: Step, callId: string): Promise<StepTiming>;
}

const now = (): number => performance.now();

/** Runs each step through the interceptor; each time covers the work done for that event, write included. */
export function interceptedRecorder(icp: Interceptor): Recorder {
  for (const [name, fn] of Object.entries(TOOLS)) icp.register(name, fn);
  return {
    async run(taskId, step, callId) {
      switch (step.kind) {
        case 'tool': {
          const t0 = now();
          const h = await icp.beginCall(taskId, step.tool, callId, step.args);
          const t1 = now();
          let outcome: Parameters<Interceptor['completeCall']>[1];
          try {
            outcome = { ok: true, value: TOOLS[step.tool](step.args) };
          } catch (err) {
            if (!(err instanceof ToolError)) throw err;
            outcome = { ok: false, errorType: err.errorType, message: err.message };
          }
          const r = await icp.completeCall(h, outcome);
          const t3 = now();
          return { kind: step.kind, eventsMs: [t1 - t0, t3 - t1], seqs: [h.call.seq, r.seq], anchored: [h.call.anchor !== undefined, r.anchor !== undefined] };
        }
        case 'pause': {
          const t0 = now();
          const r = await icp.epistemicPause(taskId, step.reason, step.missing);
          return { kind: step.kind, eventsMs: [now() - t0], seqs: [r.seq], anchored: [r.anchor !== undefined] };
        }
        case 'resolution': {
          const t0 = now();
          const r = await icp.humanResolution(taskId, step.reviewer, step.decision);
          return { kind: step.kind, eventsMs: [now() - t0], seqs: [r.seq], anchored: [r.anchor !== undefined] };
        }
        case 'final': {
          const t0 = now();
          await icp.finalResponse(taskId, step.response);
          return { kind: step.kind, eventsMs: [now() - t0], seqs: [], anchored: [false] };
        }
      }
    },
  };
}

/** The same workload with no interceptor: tools run and answers are produced, nothing is recorded. */
export const directRecorder: Recorder = {
  async run(_taskId, step) {
    switch (step.kind) {
      case 'tool': {
        const t0 = now();
        const t1 = now();
        try {
          TOOLS[step.tool](step.args);
        } catch (err) {
          if (!(err instanceof ToolError)) throw err;
        }
        const t2 = now();
        return { kind: step.kind, eventsMs: [t1 - t0, t2 - t1], seqs: [], anchored: [false, false] };
      }
      default: {
        const t0 = now();
        return { kind: step.kind, eventsMs: [now() - t0], seqs: [], anchored: [false] };
      }
    }
  },
};

/** Runs the scripted agent: one step after another, each awaited before the next. */
export async function runAgent(recorder: Recorder, events: number, callPrefix = 'call'): Promise<StepTiming[]> {
  const out: StepTiming[] = [];
  let n = 0;
  for (const { taskId, step } of scriptOf(events)) {
    n++;
    out.push(await recorder.run(taskId, step, `${callPrefix}-${String(n)}`));
  }
  return out;
}
