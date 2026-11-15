// SPDX-License-Identifier: AGPL-3.0-or-later
// The HMAC pepper for args_hmac (Blueprint §4.4). Implementation choice (not
// normative): it comes only from the environment variable TEAR_HMAC_PEPPER, as
// lowercase hex of at least 64 characters (32 bytes) and an even length. Any
// other form is refused before anything is written. The value is never put in
// an error message, a log, the database, the export or the namespace; only the
// public pepper_id is recorded in the genesis row.

import { TearError } from '../errors.js';

export const PEPPER_ENV = 'TEAR_HMAC_PEPPER';
const PEPPER_RE = /^(?:[0-9a-f]{2}){32,}$/;

/** Reads and decodes the pepper; throws PEPPER_MISSING or PEPPER_INVALID without echoing the value. */
export function readPepper(env: NodeJS.ProcessEnv = process.env): Uint8Array {
  const value = env[PEPPER_ENV];
  if (value === undefined || value === '') throw new TearError('PEPPER_MISSING', `${PEPPER_ENV} is not set`);
  if (!PEPPER_RE.test(value)) {
    throw new TearError('PEPPER_INVALID', `${PEPPER_ENV} must be lowercase hex of at least 64 characters and even length`);
  }
  return new Uint8Array(Buffer.from(value, 'hex'));
}
