// SPDX-License-Identifier: AGPL-3.0-or-later
// pg.Client sets processID from the server's BackendKeyData message; the
// published typings omit it. It is the backend pid of the session.

import 'pg';

declare module 'pg' {
  interface Client {
    readonly processID: number | null;
  }
}
