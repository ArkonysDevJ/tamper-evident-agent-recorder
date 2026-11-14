// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkPayload } from '../../src/chain/schema.js';
import type { JsonObject, JsonValue } from '../../src/json/strict-json.js';
import { obj } from '../helpers/chain-builder.js';

const H = 'b'.repeat(64);

const VALID: Record<string, JsonObject> = {
  chain_genesis: obj({ event_type: 'chain_genesis', operation: 'tear.genesis', chain_version: '1.0.4', pepper_id: 'p', tsa_ca_bundle_sha256: H }),
  tool_call: obj({ event_type: 'tool_call', operation: 'execute_tool', tool_name: 't', call_id: 'c', task_id: 'k', args_hmac: H }),
  tool_result: obj({ event_type: 'tool_result', operation: 'execute_tool', call_id: 'c', task_id: 'k', error_type: null, result_digest: H, summary: 's' }),
  epistemic_pause: obj({ event_type: 'epistemic_pause', operation: 'tear.epistemic_pause', task_id: 'k', reason: 'r', missing_sources: [] }),
  human_resolution: obj({ event_type: 'human_resolution', operation: 'tear.human_resolution', task_id: 'k', reviewer_id: 'r', decision: 'd' }),
  agent_final_response: obj({ event_type: 'agent_final_response', operation: 'invoke_agent', task_id: 'k', response_digest: H }),
  checkpoint_anchored: obj({ event_type: 'checkpoint_anchored', operation: 'tear.checkpoint', anchored_seq: 10, tsr_sha256: H, tsa_gen_time: '20261113120000.5Z' }),
  checkpoint_failed: obj({ event_type: 'checkpoint_failed', operation: 'tear.checkpoint', target_seq: 10, error_type: 'tsa_timeout' }),
};

function seqFor(type: string): number {
  return type === 'chain_genesis' ? 0 : 11;
}

function variant(base: JsonObject, change: Record<string, JsonValue | undefined>): JsonObject {
  const o = obj({});
  for (const [k, v] of Object.entries(base)) o[k] = v;
  for (const [k, v] of Object.entries(change)) {
    if (v === undefined) delete o[k];
    else o[k] = v;
  }
  return o;
}

test('001 AC-2 payload-schemas', async (t) => {
  for (const [type, payload] of Object.entries(VALID)) {
    await t.test(`${type}: exact key set accepted`, () => {
      assert.equal(checkPayload(payload, seqFor(type)), null);
    });
    await t.test(`${type}: extra key rejected`, () => {
      assert.notEqual(checkPayload(variant(payload, { extra: 'x' }), seqFor(type)), null);
    });
    for (const key of Object.keys(payload)) {
      await t.test(`${type}: missing ${key} rejected`, () => {
        assert.notEqual(checkPayload(variant(payload, { [key]: undefined }), seqFor(type)), null);
      });
      if (key === 'event_type') continue;
      await t.test(`${type}: wrong type for ${key} rejected`, () => {
        assert.notEqual(checkPayload(variant(payload, { [key]: true }), seqFor(type)), null);
      });
      const nullable = type === 'tool_result' && key === 'error_type';
      await t.test(`${type}: null ${key} ${nullable ? 'accepted' : 'rejected'}`, () => {
        const r = checkPayload(variant(payload, { [key]: null }), seqFor(type));
        if (nullable) assert.equal(r, null);
        else assert.notEqual(r, null);
      });
    }
  }
  await t.test('empty strings are rejected', () => {
    assert.notEqual(checkPayload(variant(VALID['epistemic_pause']!, { task_id: '' }), 1), null);
    assert.notEqual(checkPayload(variant(VALID['epistemic_pause']!, { missing_sources: [''] }), 1), null);
    assert.notEqual(checkPayload(variant(VALID['tool_result']!, { error_type: '' }), 1), null);
  });
  await t.test('chain_version is the literal 1.0.4', () => {
    assert.notEqual(checkPayload(variant(VALID['chain_genesis']!, { chain_version: '1.0.5' }), 0), null);
  });
  await t.test('event categories by seq', () => {
    assert.notEqual(checkPayload(VALID['chain_genesis']!, 1), null);
    assert.notEqual(checkPayload(VALID['epistemic_pause']!, 0), null);
    assert.notEqual(checkPayload(VALID['checkpoint_failed']!, 0), null);
  });
  await t.test('control fields: anchored_seq >= 1 and genTime grammar', () => {
    assert.notEqual(checkPayload(variant(VALID['checkpoint_anchored']!, { anchored_seq: 0 }), 1), null);
    assert.notEqual(checkPayload(variant(VALID['checkpoint_anchored']!, { tsa_gen_time: '20260230120000Z' }), 11), null);
    assert.notEqual(checkPayload(variant(VALID['checkpoint_anchored']!, { tsa_gen_time: '20261113120000.Z' }), 11), null);
  });
});
