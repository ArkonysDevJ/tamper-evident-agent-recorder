// SPDX-License-Identifier: AGPL-3.0-or-later
// SQL schema of Blueprint §5.3. Schema provisioning is a separate step from
// per-chain operations and runs on its own connection.

import pg from 'pg';
import type { ClientConfig } from 'pg';

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS tear_events (
  chain_id    uuid    NOT NULL,
  seq         bigint  NOT NULL,
  ts          text    NOT NULL,
  prev_hash   text    NOT NULL,
  payload     jsonb   NOT NULL,
  block_json  text    NOT NULL,
  entry_hash  text    NOT NULL,
  PRIMARY KEY (chain_id, seq),
  UNIQUE (chain_id, prev_hash)
);
CREATE TABLE IF NOT EXISTS tear_chain_state (
  chain_id            uuid        PRIMARY KEY,
  chain_closed        boolean     NOT NULL DEFAULT false,
  pending_anchor_seq  bigint      NULL,
  pending_entry_hash  text        NULL,
  pending_ts          text        NULL,
  pending_mode        text        NULL
);
`;

export async function provisionSchema(config: ClientConfig): Promise<void> {
  const client = new pg.Client(config);
  await client.connect();
  try {
    await client.query(SCHEMA_SQL);
  } finally {
    await client.end();
  }
}
