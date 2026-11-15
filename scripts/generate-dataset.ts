// SPDX-License-Identifier: AGPL-3.0-or-later
// Deterministic synthetic trace generator for experiment B
// (experiments/dataset/traces.jsonl). It uses mulberry32, a small seeded PRNG
// (not cryptographic), and closed lists of neutral words: no person names,
// e-mail addresses, phone numbers, URLs or real organizations. The output is
// synthetic, produced by a script, and does not represent the behavior of any
// agent or model.
//
// Run: npm run dataset:generate   (writes experiments/dataset/traces.jsonl)

import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';

/** Fixed, declared parameters. */
export const PARAMS = {
  seed: 20261115,
  steps: 1000,
  /** Per non-final step of a task; with the follow-up resolutions this keeps pauses within 10–20 % of all steps. */
  pauseProbability: 0.15,
  /** Probability that a pause is followed by a human resolution. */
  resolutionAfterPause: 0.5,
  /** Share of tool calls that fail. */
  errorRate: 0.1,
  /** Task length range (steps, final answer included). */
  taskLength: [4, 12] as const,
  /** Argument size classes: target bytes of the JSON arguments, with their shares. */
  argClasses: [
    { name: 'small', bytes: 100, share: 0.7 },
    { name: 'medium', bytes: 2048, share: 0.25 },
    { name: 'large', bytes: 20480, share: 0.05 },
  ] as const,
} as const;

/** mulberry32: a 32-bit seeded PRNG returning floats in [0, 1). */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const WORDS = [
  'amber', 'basin', 'cedar', 'delta', 'ember', 'fable', 'grove', 'harbor', 'island', 'juniper', 'kernel', 'lantern',
  'meadow', 'nectar', 'orbit', 'pebble', 'quartz', 'river', 'summit', 'timber', 'umbra', 'valley', 'willow', 'zenith',
  'atlas', 'beacon', 'canyon', 'dune', 'estuary', 'fjord', 'glacier', 'horizon', 'inlet', 'lagoon', 'mesa', 'prairie',
];
const TOOLS = ['search_docs', 'summarize_text', 'fetch_record', 'compare_values'] as const;
const ERRORS = ['timeout', 'not_found', 'invalid_input'] as const;
const REVIEWERS = ['reviewer-a', 'reviewer-b', 'reviewer-c'] as const;
const DECISIONS = ['proceed with caveat', 'proceed', 'stop the task', 'request another source'] as const;
const PAUSE_REASONS = [
  'no primary source for the claim',
  'conflicting values in two records',
  'the requested record is outside the available set',
  'the answer needs a reviewer decision',
] as const;

export function generateDataset(): string {
  const rnd = mulberry32(PARAMS.seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rnd() * xs.length)]!;
  const int = (lo: number, hi: number): number => lo + Math.floor(rnd() * (hi - lo + 1));
  const words = (n: number): string => Array.from({ length: n }, () => pick(WORDS)).join(' ');
  const textOfBytes = (bytes: number): string => {
    let s = '';
    while (s.length < bytes) s += (s === '' ? '' : ' ') + pick(WORDS);
    return s.slice(0, bytes);
  };
  const argClass = (): (typeof PARAMS.argClasses)[number] => {
    let r = rnd();
    for (const c of PARAMS.argClasses) {
      if (r < c.share) return c;
      r -= c.share;
    }
    return PARAMS.argClasses[0];
  };

  const lines: string[] = [];
  let task = 0;
  while (lines.length < PARAMS.steps) {
    task++;
    const taskId = `t-${String(task).padStart(3, '0')}`;
    const length = Math.min(int(PARAMS.taskLength[0], PARAMS.taskLength[1]), PARAMS.steps - lines.length);
    let step = 0;
    const emit = (o: Record<string, unknown>): void => {
      lines.push(JSON.stringify({ task_id: taskId, step: ++step, ...o }));
    };
    while (step < length - 1) {
      if (rnd() < PARAMS.pauseProbability) {
        emit({ kind: 'epistemic_pause', reason: pick(PAUSE_REASONS), missing_sources: [`source-${String(int(1, 40))}`] });
        if (step < length - 1 && rnd() < PARAMS.resolutionAfterPause) {
          emit({ kind: 'human_resolution', reviewer_id: pick(REVIEWERS), decision: pick(DECISIONS) });
        }
        continue;
      }
      const tool = pick(TOOLS);
      const cls = argClass();
      // The JSON of {"query": "..."} carries 12 bytes of structure around the text.
      const args = { query: textOfBytes(Math.max(1, cls.bytes - 12)) };
      const failed = rnd() < PARAMS.errorRate;
      emit({
        kind: 'tool_call',
        tool_name: tool,
        args,
        result: failed ? null : { hits: int(0, 9), note: words(3) },
        error: failed ? { error_type: pick(ERRORS), message: `${tool} could not complete: ${words(2)}` } : null,
      });
    }
    if (lines.length < PARAMS.steps) emit({ kind: 'final_answer', response: `task ${taskId} result: ${words(6)}` });
  }
  return lines.slice(0, PARAMS.steps).map((l) => `${l}\n`).join('');
}

export const DATASET_PATH = path.resolve('experiments/dataset/traces.jsonl');

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  fs.mkdirSync(path.dirname(DATASET_PATH), { recursive: true });
  fs.writeFileSync(DATASET_PATH, generateDataset());
  process.stdout.write(`wrote ${DATASET_PATH}\n`);
}
