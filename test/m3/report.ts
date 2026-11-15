// SPDX-License-Identifier: AGPL-3.0-or-later
// M3 statistics and the generated results table (Blueprint §7, M3). Targets
// are reported as met or not met with the measured number; the workload is
// never adjusted to meet them.

export const TARGET_ORDINARY_MEDIAN_MS = 15;
export const TARGET_RECORD_BYTES = 2048;

/** Median of a non-empty sample (mean of the two middle values for an even count). */
export function median(xs: readonly number[]): number {
  if (xs.length === 0) throw new RangeError('empty sample');
  const s = [...xs].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 === 1 ? s[m]! : (s[m - 1]! + s[m]!) / 2;
}

/** Nearest-rank percentile (p in 0..100) of a non-empty sample. */
export function percentile(xs: readonly number[], p: number): number {
  if (xs.length === 0) throw new RangeError('empty sample');
  const s = [...xs].sort((a, b) => a - b);
  const rank = Math.max(1, Math.ceil((p / 100) * s.length));
  return s[rank - 1]!;
}

export interface RunSample {
  /** Per-event latency (ms) of ordinary records, anchors excluded. */
  readonly ordinaryMs: number[];
  /** Per-event latency (ms) of records that triggered an anchor. */
  readonly anchorMs: number[];
  /** Bytes of each exported row (the JSONL line, final LF included); empty without the interceptor. */
  readonly recordBytes: number[];
}

export interface M3Input {
  readonly withInterceptor: readonly RunSample[];
  readonly withoutInterceptor: readonly RunSample[];
  readonly environment: Readonly<Record<string, string>>;
  readonly stamps: Readonly<Record<string, number>>;
  readonly eventsPerRun: number;
}

export interface M3Summary {
  readonly ordinaryMedianMs: number;
  readonly ordinaryMedianMsWithout: number;
  readonly perRunMediansMs: number[];
  readonly perRunMediansMsWithout: number[];
  readonly anchorP50Ms: number | null;
  readonly anchorP95Ms: number | null;
  readonly anchorSamples: number;
  readonly meanRecordBytes: number;
  readonly ordinaryMet: boolean;
  readonly recordMet: boolean;
}

export function summarize(i: M3Input): M3Summary {
  const ordinary = i.withInterceptor.flatMap((r) => r.ordinaryMs);
  const without = i.withoutInterceptor.flatMap((r) => [...r.ordinaryMs, ...r.anchorMs]);
  const anchors = i.withInterceptor.flatMap((r) => r.anchorMs);
  const bytes = i.withInterceptor.flatMap((r) => r.recordBytes);
  const ordinaryMedianMs = median(ordinary);
  const meanRecordBytes = bytes.reduce((a, b) => a + b, 0) / bytes.length;
  return {
    ordinaryMedianMs,
    ordinaryMedianMsWithout: median(without),
    perRunMediansMs: i.withInterceptor.map((r) => median(r.ordinaryMs)),
    perRunMediansMsWithout: i.withoutInterceptor.map((r) => median([...r.ordinaryMs, ...r.anchorMs])),
    anchorP50Ms: anchors.length === 0 ? null : percentile(anchors, 50),
    anchorP95Ms: anchors.length === 0 ? null : percentile(anchors, 95),
    anchorSamples: anchors.length,
    meanRecordBytes,
    ordinaryMet: ordinaryMedianMs < TARGET_ORDINARY_MEDIAN_MS,
    recordMet: meanRecordBytes < TARGET_RECORD_BYTES,
  };
}

/** Milliseconds with three decimals, or six below one microsecond's worth of resolution at three. */
const f3 = (x: number): string => (x !== 0 && Math.abs(x) < 0.01 ? x.toFixed(6) : x.toFixed(3));
const spread = (xs: readonly number[]): string => (xs.length === 0 ? 'n/a' : `${f3(Math.min(...xs))}–${f3(Math.max(...xs))} ms`);

export function renderM3(i: M3Input, s: M3Summary = summarize(i)): string {
  const env = Object.entries(i.environment).map(([k, v]) => `| ${k} | ${v} |`);
  const stamps = Object.entries(i.stamps).map(([k, v]) => `${k}: ${String(v)}`).join(', ');
  return [
    '# M3 results (Blueprint §7)',
    '',
    `Workload: ${String(i.eventsPerRun)} application events per run; ${String(i.withInterceptor.length)} runs with the interceptor and ${String(i.withoutInterceptor.length)} without, on the same scripted workload.`,
    '',
    '| Measure | Target | Measured | Result |',
    '| --- | --- | --- | --- |',
    `| Ordinary records, median per event (with interceptor) | under ${String(TARGET_ORDINARY_MEDIAN_MS)} ms | ${f3(s.ordinaryMedianMs)} ms | ${s.ordinaryMet ? 'met' : 'not met'} |`,
    `| Same events without interceptor, median | — | ${f3(s.ordinaryMedianMsWithout)} ms | — |`,
    `| Interceptor cost per ordinary event (median with − median without), absolute | — | ${f3(s.ordinaryMedianMs - s.ordinaryMedianMsWithout)} ms | — |`,
    `| Anchor points, p50 (${String(s.anchorSamples)} samples) | reported | ${s.anchorP50Ms === null ? 'unmeasured' : `${f3(s.anchorP50Ms)} ms`} | — |`,
    `| Anchor points, p95 (${String(s.anchorSamples)} samples) | reported | ${s.anchorP95Ms === null ? 'unmeasured' : `${f3(s.anchorP95Ms)} ms`} | — |`,
    `| Average record size (exported row) | under ${String(TARGET_RECORD_BYTES)} bytes | ${s.meanRecordBytes.toFixed(1)} bytes | ${s.recordMet ? 'met' : 'not met'} |`,
    '',
    'The cost is reported as an absolute time per event, not as a ratio: the scripted tools are trivial, so the',
    'baseline without the interceptor is close to zero by construction.',
    '',
    `Spread of per-run medians: with interceptor ${spread(s.perRunMediansMs)}; without ${spread(s.perRunMediansMsWithout)}.`,
    `Per-run medians with interceptor (ms): ${s.perRunMediansMs.map(f3).join(', ')}.`,
    `Per-run medians without interceptor (ms): ${s.perRunMediansMsWithout.map(f3).join(', ')}.`,
    '',
    `Time-stamp requests during the measurement: ${stamps === '' ? 'none' : stamps}.`,
    '',
    '| Environment | Value |',
    '| --- | --- |',
    ...env,
    '',
  ].join('\n');
}
