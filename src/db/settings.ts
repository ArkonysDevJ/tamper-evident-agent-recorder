// SPDX-License-Identifier: AGPL-3.0-or-later
// Database preconditions (Blueprint §5.3 encoding, §5.4 durability).

import { TearError } from '../errors.js';

export interface DatabaseSettings {
  readonly serverEncoding: string | null;
  readonly fsync: string | null;
  readonly fullPageWrites: string | null;
  readonly walLevel: string | null;
  readonly synchronousCommit: string | null;
}

/**
 * Checks the encoding first, then the durability tuple, so a server failing
 * both reports DATABASE_ENCODING_UNSUPPORTED (§5.4). Missing or unreadable
 * values fail closed.
 */
export function assertDatabaseSettings(s: DatabaseSettings): void {
  if (s.serverEncoding !== 'UTF8') {
    throw new TearError('DATABASE_ENCODING_UNSUPPORTED', `server_encoding=${String(s.serverEncoding)}`);
  }
  const problems: string[] = [];
  if (s.fsync !== 'on') problems.push(`fsync=${String(s.fsync)}`);
  if (s.fullPageWrites !== 'on') problems.push(`full_page_writes=${String(s.fullPageWrites)}`);
  if (s.walLevel !== 'replica' && s.walLevel !== 'logical') problems.push(`wal_level=${String(s.walLevel)}`);
  if (s.synchronousCommit !== 'on') problems.push(`synchronous_commit=${String(s.synchronousCommit)}`);
  if (problems.length > 0) throw new TearError('DATABASE_DURABILITY_UNSUPPORTED', problems.join(', '));
}

export const SETTINGS_QUERY = `SELECT
  current_setting('server_encoding', true) AS server_encoding,
  current_setting('fsync', true) AS fsync,
  current_setting('full_page_writes', true) AS full_page_writes,
  current_setting('wal_level', true) AS wal_level,
  current_setting('synchronous_commit', true) AS synchronous_commit`;

export function settingsFromRow(row: Record<string, unknown> | undefined): DatabaseSettings {
  const text = (v: unknown): string | null => (typeof v === 'string' ? v : null);
  return {
    serverEncoding: text(row?.['server_encoding']),
    fsync: text(row?.['fsync']),
    fullPageWrites: text(row?.['full_page_writes']),
    walLevel: text(row?.['wal_level']),
    synchronousCommit: text(row?.['synchronous_commit']),
  };
}
