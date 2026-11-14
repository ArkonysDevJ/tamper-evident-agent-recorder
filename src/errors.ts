// SPDX-License-Identifier: AGPL-3.0-or-later
// Error type carrying a protocol or operational code.

export class TearError extends Error {
  readonly code: string;
  constructor(code: string, message?: string, options?: { cause?: unknown }) {
    super(message === undefined ? code : `${code}: ${message}`, options);
    this.name = 'TearError';
    this.code = code;
  }
}
