// SPDX-License-Identifier: AGPL-3.0-or-later
// Renders docs/REPORT.md, the final report Blueprint §9 requires (spec 007). Every number comes from a
// generated file: docs/results/ (final run, tamper battery, layer ladder, pause exposure, M3), the frozen
// fixture manifest and the pinned bundle. Lists are copied from their sources: "not tested" and "known
// limits" from spec 007, implementation choices from every spec, known debt from Blueprint §10. Fixed prose
// lives in this template. A test re-renders the report and requires identical bytes.
//
// Run: npm run report:render

import * as fs from 'node:fs';
import * as path from 'node:path';
import { pathToFileURL } from 'node:url';
import { bundleSha256 } from '../src/crypto/digests.js';
import { loadBundle } from '../src/pki/bundle.js';
import { crossCheckedReceipts } from '../test/helpers/real-receipts.js';

const R = (p: string): string => fs.readFileSync(path.resolve(p), 'utf8');

/** "<suite> passed/tests" plus the skipped count when there is one. */
function suiteCounts(s: { suite: string; tests: number; pass: number; skipped: number }): string {
  return `${s.suite} ${String(s.pass)}/${String(s.tests)} passed${s.skipped > 0 ? ` (${String(s.skipped)} skipped)` : ''}`;
}

interface FinalRun {
  commit: string;
  worktree_clean: boolean;
  finished_at: string;
  suites: { suite: string; exitCode: number | null; tests: number; pass: number; fail: number; skipped: number }[];
  environment: { cpu: string; memory_gib: number; kernel: string; node: string; openssl: string; checkpoint_fs_statfs_type: string; postgresql: Record<string, string> };
}

interface M3 {
  commit?: string;
  worktreeClean?: boolean;
  finishedAt?: string;
  eventsPerRun: number;
  withInterceptor: unknown[];
  withoutInterceptor: unknown[];
  stamps: Record<string, number>;
  environment: Record<string, string>;
  summary: {
    ordinaryMedianMs: number;
    ordinaryMedianMsWithout: number;
    perRunMediansMs: number[];
    anchorP50Ms: number | null;
    anchorP95Ms: number | null;
    anchorSamples: number;
    meanRecordBytes: number;
    ordinaryMet: boolean;
    recordMet: boolean;
  };
}

/** The lines of the first Markdown table that follows a line starting with `startsWith`. */
function tableAfter(text: string, startsWith: string): string[] {
  const lines = text.split('\n');
  let i = lines.findIndex((l) => l.startsWith(startsWith));
  if (i < 0) throw new Error(`table "${startsWith}" not found`);
  const out: string[] = [];
  while (i < lines.length && lines[i]!.startsWith('|')) out.push(lines[i++]!);
  return out;
}

function sectionBetween(text: string, start: string, end: string): string {
  const i = text.indexOf(start);
  const j = text.indexOf(end, i + start.length);
  if (i < 0 || j < 0) throw new Error(`section "${start}" not found`);
  return text.slice(i, j).trimEnd();
}

/** Rows of spec 007 by AC id: the "The report states" cell, verbatim. */
function spec007(): Map<string, string> {
  const rows = new Map<string, string>();
  for (const line of R('specs/007-final-report/spec.md').split('\n')) {
    const m = /^\| (AC-\d+) \| (.*) \| [^|]* \| `[^`]*` \|$/.exec(line);
    if (m !== null) rows.set(m[1]!, m[2]!);
  }
  return rows;
}

/** The "Implementation choices (not normative)" section of every spec, verbatim. */
function implementationChoices(): string[] {
  const out: string[] = [];
  for (const dir of fs.readdirSync(path.resolve('specs')).sort()) {
    const file = path.resolve('specs', dir, 'spec.md');
    if (!fs.existsSync(file)) continue;
    const text = R(`specs/${dir}/spec.md`);
    const title = text.split('\n')[0]!.replace(/^# /, '');
    const sections = /^## 2\. Blueprint sections\n\n(.*)$/m.exec(text)?.[1] ?? '';
    const i = text.indexOf('## Implementation choices (not normative)');
    if (i < 0) continue;
    const rest = text.slice(i).split('\n').slice(1);
    const end = rest.findIndex((l) => l.startsWith('## '));
    const body = (end < 0 ? rest : rest.slice(0, end)).filter((l) => !l.startsWith('Recorded here') && !l.startsWith('The Blueprint leaves') && !l.startsWith('the work package'));
    out.push(`### ${title} (Blueprint ${sections.replace(/\.$/, '')})`, '', ...body.join('\n').trim().split('\n'), '');
  }
  return out;
}

/** Pause counts and exposure in events of one run and moment ("Before close" or "After closeChain"). */
export function exposureLine(exposure: string, run: 'B1' | 'B2', moment: 'Before close' | 'After closeChain'): { pauses: string; covered: string; events: string } {
  const section = run === 'B1' ? sectionBetween(exposure, '## B1', '## B2') : sectionBetween(exposure, '## B2', '## Predeclared expectations');
  const lines = section.split('\n');
  const i = lines.findIndex((l) => l.startsWith(`- ${moment}:`));
  if (i < 0) throw new Error(`${run} ${moment} not found`);
  const m = /^- [^:]+: (\d+) pauses; .*; (\d+) covered, (\d+) uncovered\.$/.exec(lines[i]!);
  const e = /Exposure in events \(covered pauses\): (.*)\.$/.exec(lines[i + 1] ?? '');
  if (m === null || e === null) throw new Error(`${run} ${moment} line not parsed`);
  return { pauses: m[1]!, covered: m[2]!, events: e[1]! };
}

/** Measured B2 exposure in time (seconds), as the generated file states it. */
export function b2TimeRange(exposure: string): { min: string; max: string } {
  const m = /Exposure in time \(covered pauses\): min (\S+) · median \S+ · max (\S+) s\./.exec(sectionBetween(exposure, '## B2', '## Predeclared expectations'));
  if (m === null) throw new Error('B2 exposure in time not found');
  return { min: m[1]!, max: m[2]! };
}

/**
 * Experiment B for the report. B1 and B2 stay apart. The measured exposure in time of B2 is shown, with the reason
 * it is not interpreted (review finding 1); the reported result is the exposure in events.
 */
function exposureSection(exposure: string): string[] {
  const keep = (section: string): string[] =>
    section
      .split('\n')
      .filter((l) => !l.startsWith('Exposure in time can be negative'))
      .map((l) => l.replace(/^## /, '### ').replace(/Close: (\w+) \(B(\d)\)/, 'Close: $1 (closeChain branch B$2)'));
  const t = b2TimeRange(exposure);
  return [
    ...keep(sectionBetween(exposure, '## B1', '## B2')),
    '',
    ...keep(sectionBetween(exposure, '## B2', '## Predeclared expectations')),
    '',
    `Exposure in time (B2), as measured: from ${t.min} s to ${t.max} s. In some pauses the second signed by the TSA`,
    'precedes the second of the pause. These values are consistent with two causes acting together: FreeTSA signs',
    '`genTime` in whole seconds, and the host clock and the TSA clock differ by an amount these artifacts cannot',
    'separate from the truncation. For that reason the exposure in time is not reported as a result; the reported',
    'result is the exposure in events. The protocol tolerates such a difference: the time predicate accepts a signed',
    '`genTime` down to 5 s before the anchored row (Blueprint §5.7).',
    '',
    'B1 and B2 replay the dataset with `beginCall` and `completeCall`, taking each result from the dataset: they',
    'exercise the recording of tool calls, not the invocation of a registered tool through `callTool`.',
    '',
    `The truncation of the unanchored tail (B1) removed ${exposureFacts(exposure).removedPauses} pauses in this dataset; it is reported as measured.`,
    'The undetected deletion of pauses is shown on the frozen fixture by T3b (section 1), whose deleted rows 45..50',
    'are epistemic pauses.',
    '',
    'Predeclared checks (`test/experiments/expected.ts`):',
    '',
    ...tableAfter(exposure, '| Check |'),
  ];
}

/** Pauses removed by the B1 truncation demonstration, and the B2 time-stamp requests, from the generated file. */
export function exposureFacts(exposure: string): { removedPauses: string; b2Stamps: string } {
  const t = / (\d+) rows and (\d+) pauses disappeared/.exec(exposure);
  const st = /Time-stamp requests: ([^;.]+)[;.]/.exec(sectionBetween(exposure, '## B2', '## Predeclared expectations'));
  if (t === null || st === null) throw new Error('exposure facts not found');
  return { removedPauses: t[2]!, b2Stamps: st[1]!.trim() };
}

/** Section "Independent review": the response to each finding, from docs/review/response.json. */
function independentReview(): string[] {
  const r = JSON.parse(R('docs/review/response.json')) as { findings: { n: number; said: string; reproduced: string; action: string; commits: string }[] };
  return [
    '## Independent review',
    '',
    'A read-only review of the tag `sprint-submission` (commit `c96c980`) was made by an AI model different from the',
    'one that wrote the code, following [`docs/review/BRIEF.md`](review/BRIEF.md). It did not run the test suites. Its',
    'findings are [`docs/review/FINDINGS.md`](review/FINDINGS.md), unedited. Each finding was first reproduced with a',
    'test committed on its own, then corrected in a separate commit; a finding about the tests themselves was',
    'confirmed by reading.',
    '',
    '| # | What the review said | Reproduced | What was done | Commits |',
    '| --- | --- | --- | --- | --- |',
    ...r.findings.map((f) => `| ${String(f.n)} | ${f.said} | ${f.reproduced} | ${f.action} | ${f.commits} |`),
    '',
  ];
}

/** Blueprint §10 bullets, verbatim. */
function knownDebt(): string[] {
  const text = R('docs/BLUEPRINT.md');
  return sectionBetween(text, '## 10. Known debt', '## 11.').split('\n').filter((l) => l.startsWith('- '));
}

export function renderReport(): string {
  const run = JSON.parse(R('docs/results/final-run.json')) as FinalRun;
  const tamper = R('docs/results/tamper-results.md');
  const ladder = R('docs/results/layer-ladder.md');
  const exposure = R('docs/results/pause-exposure.md');
  const m3 = JSON.parse(R('docs/results/m3-results.json')) as M3;
  const fixture = JSON.parse(R('test/fixtures/frozen-m1/manifest.json')) as {
    chain_id: string;
    receipts: { k: number; tsa: string; gen_time: string; accuracy: unknown; serial_hex: string; tsr_sha256: string }[];
  };
  const bundleBytes = fs.readFileSync(path.resolve('certs/tsa_roots.pem'));
  const fingerprint = bundleSha256(bundleBytes);
  const roles = loadBundle(bundleBytes).certificates.map((c) => c.role);
  const s7 = spec007();
  const row = (id: string): string => {
    const t = s7.get(id);
    if (t === undefined) throw new Error(`spec 007 ${id} not found`);
    return t;
  };
  const allPassed = run.suites.every((s) => s.exitCode === 0 && s.fail === 0);
  const primaryLine = tamper.split('\n').find((l) => l.startsWith('Primary M1 results matched'))!;
  const pg = run.environment.postgresql;
  const f3 = (x: number | null): string => (x === null ? 'unmeasured' : `${x.toFixed(3)} ms`);
  const m3s = m3.summary;
  if (m3.commit === undefined) throw new Error('docs/results/m3-results.json has no commit: run npm run m3 on the code under test');

  return [
    '# TEAR — Final report',
    '',
    'This report states what was built, what was measured and what was not tested, as Blueprint §9 requires. It is',
    'generated by `scripts/render-report.ts`; every number in it comes from a generated file listed under "Sources".',
    'The normative design is `docs/BLUEPRINT.md` (readable copy: `docs/BLUEPRINT.rendered.md`).',
    '',
    `- Results were measured on the measurement commit \`${run.commit}\` (clean working tree: ${run.worktree_clean ? 'yes' : 'no'}; final run finished at ${run.finished_at}). The published commit adds the generated files (this report, \`docs/results/\` and the README results block) and can also carry manual documentation edits made after the run, but no code change; \`npm test\` and \`npm run test:tamper\` were repeated on it.`,
    '- Active cut profile: **Base** (no cut profile of §8 was activated).',
    '',
    '## 1. Tamper-detection matrix (M1), X1 and X2, as measured',
    '',
    'Each mutation of Blueprint §7 was applied to a copy of the frozen fixture and the offline verifier was run on it.',
    'The "Specified" column is copied from §7. A row whose specified result is "not detected" or a degraded coverage',
    'matches when the verifier accepts the copy as specified: that is conformity with a declared limit, not a',
    'detection.',
    '',
    ...tableAfter(tamper, '| Case |'),
    '',
    primaryLine,
    '',
    'Additional §7 vectors run on the frozen fixture:',
    '',
    ...tableAfter(tamper, '| Vector |'),
    '',
    '## 2. What VERIFIED_ANCHORED means',
    '',
    '`VERIFIED_ANCHORED 0..k` means that the prefix 0..k is backed by a verified RFC 3161 token whose signed',
    '`TSTInfo.genTime` is the TSA’s asserted time for that token (Blueprint §3.3 item 3). It does not mean that each',
    'event existed at its own `ts`; coverage is cumulative. The real receipts of the frozen fixture carry no',
    '`accuracy`, so the receipt-derived bound is reported as **accuracy unspecified**; no policy value is imported.',
    '',
    '| Anchor k | TSA | Signed genTime | Accuracy |',
    '| --- | --- | --- | --- |',
    ...fixture.receipts.map((r) => `| ${String(r.k)} | ${r.tsa} | \`${r.gen_time}\` | ${r.accuracy === 'absent' ? 'unspecified' : JSON.stringify(r.accuracy)} |`),
    '',
    '## 3. Deleted packages versus corrupt evidence',
    '',
    'Deleting anchor packages reduces coverage to `VALID_UNANCHORED` for the rows they covered; when the log still',
    'carries the matching `checkpoint_anchored`, the verifier prints `ANCHOR_EVIDENCE_MISSING <k>` and exits 0 (row X1',
    'above). Corrupt, mismatched or invalid evidence is a hard failure with a non-zero exit, never a silent',
    'degradation (rows T1–T6a above, and the Step 2 vectors of spec 003).',
    '',
    '## 4. Custody',
    '',
    'The receipt directory simulates an external custodian. T6b and T7 depend on that custody: with receipts held only',
    'by the operator, a coherent rewrite re-stamped inside the time window (T6b) is not detected, and replacing the',
    'last anchors with recorded failures (T7) only degrades coverage. Offline X.509 verification uses only the pinned',
    'bundle of §6a: no system or environment certificate source, no network, and no revocation check in this profile.',
    '',
    'Layer ladder (experiment A): the same 17 cases seen through four layers of evidence. L3 is a simulation of the',
    'external custodian: the retained manifest is built by the test from the original fixture.',
    '',
    ...tableAfter(ladder, '| Case |'),
    '',
    '## 5. One host: what was built and what was run',
    '',
    `All tests ran on one host: ${run.environment.cpu}, ${String(run.environment.memory_gib)} GiB, ${run.environment.kernel} (WSL2 on a virtual disk), Node.js ${run.environment.node}, ${run.environment.openssl}, checkpoint filesystem statfs type ${run.environment.checkpoint_fs_statfs_type}.`,
    '',
    `Effective PostgreSQL settings read by the final run: version ${pg['server_version']!}, server_encoding ${pg['server_encoding']!}, synchronous_commit ${pg['synchronous_commit']!}, fsync ${pg['fsync']!}, full_page_writes ${pg['full_page_writes']!}, wal_level ${pg['wal_level']!}.`,
    '',
    'These are the §5.4 deployment invariants (synchronous_commit on for every mutating transaction, fsync on,',
    'full_page_writes on, wal_level replica or logical, UTF8 encoding); the writer reads them before it writes and',
    'refuses to proceed without them. Durability is conditional on the storage stack honoring flush and ordering',
    'requests; on WSL2 that stack is a virtual disk, and no test here measures device behavior under',
    'power loss. Crashes were simulated in three ways, named per case in the test files and in spec 007: an',
    '`fs` double that fails one call (then the writer drains and exits), a real SIGKILL of a child process at an',
    'exact point (E1 barrier, E7, mid-anchor end to end, a tool that ran before its result), and direct SQL edits of',
    'the state row for the defensive states E4 and E5, which a conforming writer never produces.',
    '',
    'Final run of every suite:',
    '',
    '| Suite | Tests | Passed | Failed | Skipped | Exit |',
    '| --- | --- | --- | --- | --- | --- |',
    ...run.suites.map((s) => `| \`npm run ${s.suite}\` | ${String(s.tests)} | ${String(s.pass)} | ${String(s.fail)} | ${String(s.skipped)} | ${String(s.exitCode)} |`),
    '',
    'Skipped tests are the checks of this report itself (`test/unit/report.test.ts`, spec 007): they need',
    '`docs/REPORT.md`, which is rendered after this run, and they run in CI on the commit that adds it.',
    '',
    '## 6. Bundle custody',
    '',
    `- Fingerprint of \`certs/tsa_roots.pem\` (SHA-256 of the raw file, the same value as \`tsa_ca_bundle_sha256\`): \`${fingerprint}\`.`,
    '- Channel and time of publication: an e-mail to the sprint organizers on 2026-11-14 at 15:13 UTC, before the first',
    '  anchor. A repository the operator controls does not qualify as that channel (§3.3 item 9).',
    `- Contents, with roles derived from the certificate bytes by the loader: ${roles.join(', ')} (FreeTSA root and signer;`,
    '  DigiCert root, intermediate and signer).',
    '- Root and signer checks: when the bundle was assembled, each root fingerprint was checked against the root',
    '  published by its TSA, and each pinned signer subject was checked to name its TSA.',
    '',
    'Without a bundle that matches the published fingerprint there is no result against an operator who controls both',
    'the log and the bundle: X2 above is accepted by the verifier, and only the auditor comparison of L3 rejects it.',
    '',
    '## 7. Cut profiles',
    '',
    'Active profile: **Base**. No cut profile of §8 was activated; the cut profiles are implemented and tested, but',
    'none of them applies to these results.',
    '',
    '## 8. Overhead (M3), as measured',
    '',
    `M3 was measured by \`npm run m3\` (spec 005) on commit \`${m3.commit}\` (clean working tree: ${m3.worktreeClean === true ? 'yes' : 'no'}; finished at ${m3.finishedAt ?? ''}), on the host above: ${String(m3.eventsPerRun)} application events per run, ${String(m3.withInterceptor.length)} runs with the interceptor and ${String(m3.withoutInterceptor.length)} without, on a scripted reference agent (a test instrument with no LLM). Time-stamp requests: ${Object.entries(m3.stamps).map(([k, v]) => `${k} ${String(v)}`).join(', ')}. The samples are \`docs/results/m3-results.json\`.`,
    '',
    '| Measure | Target | Measured | Result |',
    '| --- | --- | --- | --- |',
    `| Interceptor cost per ordinary event (absolute: median with − median without) | — | ${f3(m3s.ordinaryMedianMs - m3s.ordinaryMedianMsWithout)} | — |`,
    `| Ordinary records, median per event with the interceptor | under 15 ms | ${f3(m3s.ordinaryMedianMs)} | ${m3s.ordinaryMet ? 'met' : 'not met'} |`,
    `| Anchor points, p50 (${String(m3s.anchorSamples)} samples) | reported | ${f3(m3s.anchorP50Ms)} | — |`,
    `| Anchor points, p95 (${String(m3s.anchorSamples)} samples) | reported | ${f3(m3s.anchorP95Ms)} | — |`,
    `| Average record size (exported row) | under 2048 bytes | ${m3s.meanRecordBytes.toFixed(1)} bytes | ${m3s.recordMet ? 'met' : 'not met'} |`,
    '',
    `Caveats: ${row('AC-21')}`,
    '',
    '## 9. Not tested, known limits, known debt, failed',
    '',
    '### Not tested',
    '',
    'Being absent from this list means a test was run, not that a property holds in general. Each item names the part',
    'that was tested.',
    '',
    ...['AC-10', 'AC-12', 'AC-13', 'AC-15', 'AC-17', 'AC-22'].map((id) => `- ${row(id)}`),
    '',
    '### Known limits',
    '',
    ...['AC-14', 'AC-18', 'AC-19', 'AC-20', 'AC-23'].map((id) => `- ${row(id)}`),
    '',
    '### Known debt (Blueprint §10)',
    '',
    ...knownDebt(),
    '',
    '### Failed',
    '',
    allPassed
      ? `None: no test of the final run failed (${run.suites.map(suiteCounts).join(', ')}).`
      : `Failed in the final run: ${run.suites.filter((s) => s.exitCode !== 0 || s.fail !== 0).map((s) => `${s.suite} (${String(s.fail)} failed)`).join(', ')}.`,
    '',
    '## 10. Implementation choices (not normative)',
    '',
    'Points the Blueprint leaves to the implementation (§10) and readings recorded while building, copied from each',
    'spec.',
    '',
    ...implementationChoices(),
    '## 11. Trust surfaces of this implementation',
    '',
    `- ${row('AC-16')} The cross-check covers ${String(crossCheckedReceipts().length)} real receipts: ${String(crossCheckedReceipts().filter((r) => r.label.startsWith('frozen')).length)} of the frozen fixture, ${String(crossCheckedReceipts().filter((r) => r.label.startsWith('T6')).length)} replacement receipts of T6a and T6b, and ${String(crossCheckedReceipts().filter((r) => r.label.startsWith('B2')).length)} distinct receipts of B2.`,
    '- The `ANCHOR_TIME` lines expected by the tamper battery are derived with the same receipt parser the verifier',
    '  uses; a shared decoding error would give the same expected and observed line. That parser is checked against',
    '  OpenSSL on the receipts listed above.',
    '- The only e-mail addresses in the repository are contact fields inside the public TSA certificates (in',
    '  `certs/tsa_roots.pem` and in the certificates embedded in the receipts); commits use GitHub noreply addresses.',
    '- The writer lock uses `fs-ext@2.1.1`, a native addon compiled at install time, because Node.js does not expose',
    '  `flock(2)` (§5.3). Its install script is the only one approved in `package.json`; the offline verifier does not',
    '  load it.',
    '',
    '## Experiment B: exposure window of an epistemic pause',
    '',
    'The dataset is synthetic (`experiments/dataset/`). The exposure window is a property of the design, measured on',
    'this workload; it is not a finding about agents or models. Anchors are requested "whenever an application event',
    'is committed at a positive physical sequence number seq divisible by 10 (seq % 10 == 0)" (Blueprint §2). The',
    'sequence also holds the control row of each anchor (at k+1), so nine application events fall between two',
    'consecutive automatic anchors (ten before the first one). A pause is therefore covered after at most 9 further',
    'application events in the first segment and at most 8 after it, as predeclared.',
    '',
    ...exposureSection(exposure),
    '',
    ...independentReview(),
    '## Sources',
    '',
    '- `docs/results/final-run.json`: commit, environment and suite counts (`npm run report:final-run` on a clean clone).',
    '- `docs/results/tamper-results.md`, `docs/results/layer-ladder.md`, `docs/results/pause-exposure.md`: tables written by that run.',
    '- `docs/results/m3-results.json`: the M3 samples of spec 005.',
    `- \`test/fixtures/frozen-m1/manifest.json\`: frozen fixture (chain \`${fixture.chain_id}\`).`,
    '- `certs/tsa_roots.pem`, `specs/`, `docs/BLUEPRINT.md`.',
    '',
  ].join('\n');
}

/** The short results table of README.md, between its results markers. */
export function renderReadmeResults(): string {
  const run = JSON.parse(R('docs/results/final-run.json')) as FinalRun;
  const tamper = R('docs/results/tamper-results.md');
  const ladder = R('docs/results/layer-ladder.md');
  const m3 = (JSON.parse(R('docs/results/m3-results.json')) as M3).summary;
  const primary = /Primary M1 results matched: (\d+)\/(\d+) \(A2a (\d+\/\d+), A2b (\d+\/\d+)\)\. X1: (\w+)\. X2: (\w+)\./.exec(tamper);
  if (primary === null) throw new Error('M1 summary line not found');
  const totals = tableAfter(ladder, '| Case |').find((l) => l.startsWith('| **Totals**'))!.split('|').slice(2, 6).map((c) => c.trim());
  const passed = run.suites.every((s) => s.exitCode === 0 && s.fail === 0);
  const exposure = R('docs/results/pause-exposure.md');
  const b1 = exposureLine(exposure, 'B1', 'Before close');
  const b1c = exposureLine(exposure, 'B1', 'After closeChain');
  const b2 = exposureLine(exposure, 'B2', 'Before close');
  const b2c = exposureLine(exposure, 'B2', 'After closeChain');
  const facts = exposureFacts(exposure);
  const b2t = b2TimeRange(exposure);
  return [
    README_START,
    '| What | Result |',
    '| --- | --- |',
    `| Tamper matrix of Blueprint §7 (M1, 15 primary results) | ${primary[1]!}/${primary[2]!} match the specified result (A2a ${primary[3]!}, A2b ${primary[4]!}), including the specified "not detected" and degraded-coverage rows |`,
    `| X1 (deleted packages), X2 (operator-made bundle) | X1 ${primary[5]!}, X2 ${primary[6]!} |`,
    `| Layer ladder (17 cases; detected · accepted · reduced) | plain log: ${totals[0]!}; local chain: ${totals[1]!}; with anchors: ${totals[2]!}; with retained references: ${totals[3]!} |`,
    `| Pause exposure, B1 (1000 synthetic steps, offline test TSA) | exposure in events before close: ${b1.events}; after closeChain ${b1c.covered} of ${b1c.pauses} pauses covered; truncating the unanchored tail removed ${facts.removedPauses} pauses |`,
    `| Pause exposure, B2 (first 150 application events, real time stamps: ${facts.b2Stamps}) | exposure in events before close: ${b2.events}; after closeChain ${b2c.covered} of ${b2c.pauses} pauses covered; exposure in time is not reported: signed times differ from the pause times by ${b2t.min} s to ${b2t.max} s, and these artifacts cannot separate the TSA's whole-second resolution from the host/TSA clock difference |`,
    `| M3: median per ordinary event with the interceptor (target under 15 ms) | ${m3.ordinaryMedianMs.toFixed(3)} ms (${m3.ordinaryMet ? 'met' : 'not met'}) |`,
    `| M3: average record size (target under 2 KB) | ${m3.meanRecordBytes.toFixed(1)} bytes (${m3.recordMet ? 'met' : 'not met'}) |`,
    `| Final run of every suite | ${passed ? 'no failures' : 'failures'}: ${run.suites.map((s) => s.suite === 'test' && s.skipped > 0 ? suiteCounts(s).replace(/ skipped\)$/, ' skipped: the report\'s own checks, which run once docs/REPORT.md exists)') : suiteCounts(s)).join(', ')} |`,
    README_END,
  ].join('\n');
}

export const README_START = '<!-- results:start (generated by scripts/render-report.ts) -->';
export const README_END = '<!-- results:end -->';
export const REPORT_PATH = path.resolve('docs/REPORT.md');
export const README_PATH = path.resolve('README.md');

/** README.md with its results block replaced by the rendered one. */
export function readmeWithResults(): string {
  const readme = R('README.md');
  const i = readme.indexOf(README_START);
  const j = readme.indexOf(README_END);
  if (i < 0 || j < 0) throw new Error('README results markers not found');
  return readme.slice(0, i) + renderReadmeResults() + readme.slice(j + README_END.length);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  fs.writeFileSync(REPORT_PATH, renderReport());
  fs.writeFileSync(README_PATH, readmeWithResults());
  process.stdout.write(`wrote ${REPORT_PATH} and the results block of ${README_PATH}\n`);
}
