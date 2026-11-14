// SPDX-License-Identifier: AGPL-3.0-or-later
// Timestamp grammars of Blueprint §4.2 (O_i.ts) and §5.7 (TSTInfo.genTime).
// Date.parse is never used: it normalizes and accepts offsets. Calendar math is
// proleptic Gregorian on whole days, years 0001..9999, seconds 00..59.

const TS_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z$/;
const GEN_TIME_RE = /^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]{1,9}))?Z$/;

const MS_PER_DAY = 86_400_000;
const NS_PER_MS = 1_000_000n;

function isLeapYear(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

function daysInMonth(y: number, m: number): number {
  const days = [31, isLeapYear(y) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return days[m - 1] ?? 0;
}

// Days since 1970-01-01 for a proleptic Gregorian date (H. Hinnant's algorithm).
function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const mp = (m + 9) % 12;
  const doy = Math.floor((153 * mp + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function civilFromDays(z: number): { y: number; m: number; d: number } {
  const zz = z + 719468;
  const era = Math.floor(zz / 146097);
  const doe = zz - era * 146097;
  const yoe = Math.floor((doe - Math.floor(doe / 1460) + Math.floor(doe / 36524) - Math.floor(doe / 146096)) / 365);
  const doy = doe - (365 * yoe + Math.floor(yoe / 4) - Math.floor(yoe / 100));
  const mp = Math.floor((5 * doy + 2) / 153);
  const d = doy - Math.floor((153 * mp + 2) / 5) + 1;
  const m = mp < 10 ? mp + 3 : mp - 9;
  const y = yoe + era * 400 + (m <= 2 ? 1 : 0);
  return { y, m, d };
}

interface CalendarFields {
  y: number;
  mo: number;
  d: number;
  h: number;
  mi: number;
  s: number;
}

function validCalendar(f: CalendarFields): boolean {
  return (
    f.y >= 1 &&
    f.y <= 9999 &&
    f.mo >= 1 &&
    f.mo <= 12 &&
    f.d >= 1 &&
    f.d <= daysInMonth(f.y, f.mo) &&
    f.h <= 23 &&
    f.mi <= 59 &&
    f.s <= 59
  );
}

function epochMsOf(f: CalendarFields): number {
  return daysFromCivil(f.y, f.mo, f.d) * MS_PER_DAY + ((f.h * 60 + f.mi) * 60 + f.s) * 1000;
}

/** Parses O_i.ts (§4.2). Returns epoch milliseconds, or null if the format or date is invalid. */
export function parseTimestampMs(ts: string): number | null {
  const m = TS_RE.exec(ts);
  if (m === null) return null;
  const f: CalendarFields = { y: +m[1]!, mo: +m[2]!, d: +m[3]!, h: +m[4]!, mi: +m[5]!, s: +m[6]! };
  if (!validCalendar(f)) return null;
  return epochMsOf(f) + Number(m[7]);
}

/** O_i.ts as Unix epoch nanoseconds: BigInt(epoch_ms) * 1_000_000n (§4.2). */
export function parseTimestampNs(ts: string): bigint | null {
  const ms = parseTimestampMs(ts);
  return ms === null ? null : BigInt(ms) * NS_PER_MS;
}

/** Formats epoch milliseconds as YYYY-MM-DDTHH:mm:ss.SSSZ. Throws outside years 0001..9999. */
export function formatTimestamp(epochMs: number): string {
  if (!Number.isSafeInteger(epochMs)) throw new RangeError('epoch milliseconds must be a safe integer');
  const days = Math.floor(epochMs / MS_PER_DAY);
  const rem = epochMs - days * MS_PER_DAY;
  const { y, m, d } = civilFromDays(days);
  if (y < 1 || y > 9999) throw new RangeError('timestamp outside years 0001..9999');
  const h = Math.floor(rem / 3_600_000);
  const mi = Math.floor((rem % 3_600_000) / 60_000);
  const s = Math.floor((rem % 60_000) / 1000);
  const ms = rem % 1000;
  const p = (n: number, w: number): string => String(n).padStart(w, '0');
  return `${p(y, 4)}-${p(m, 2)}-${p(d, 2)}T${p(h, 2)}:${p(mi, 2)}:${p(s, 2)}.${p(ms, 3)}Z`;
}

/**
 * Writer timestamp rule (§4.2): ts = max(now_ms, ts[physical_head_seq]), with
 * now_ms the wall clock truncated to whole milliseconds. A clock step back
 * therefore yields a tie, never a regression.
 */
export function writerTimestamp(nowMs: number, headTs: string): string {
  const headMs = parseTimestampMs(headTs);
  if (headMs === null) throw new RangeError('head timestamp is not a valid O_i.ts');
  return formatTimestamp(Math.max(Math.trunc(nowMs), headMs));
}

/**
 * Parses an ASN.1 GeneralizedTime lexical value under the §5.7 grammar.
 * Returns epoch nanoseconds; a present fraction is right-padded to nine digits.
 */
export function parseGeneralizedTimeNs(value: string): bigint | null {
  const m = GEN_TIME_RE.exec(value);
  if (m === null) return null;
  const f: CalendarFields = { y: +m[1]!, mo: +m[2]!, d: +m[3]!, h: +m[4]!, mi: +m[5]!, s: +m[6]! };
  if (!validCalendar(f)) return null;
  const fraction = m[7] === undefined ? 0n : BigInt(m[7].padEnd(9, '0'));
  return BigInt(epochMsOf(f)) * NS_PER_MS + fraction;
}
