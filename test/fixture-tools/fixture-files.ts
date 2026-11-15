// SPDX-License-Identifier: AGPL-3.0-or-later
// Location of the frozen M1 fixture and the receipt facts its manifest records.

import * as path from 'node:path';
import { sha256Hex } from '../../src/crypto/digests.js';
import type { ParsedReceipt } from '../../src/tsa/receipt.js';

export const FIXTURE_DIR = path.resolve('test/fixtures/frozen-m1');

const ATTR_NAMES: Record<string, string> = {
  '1.2.840.113549.1.9.3': 'content-type',
  '1.2.840.113549.1.9.4': 'message-digest',
  '1.2.840.113549.1.9.5': 'signing-time',
  '1.2.840.113549.1.9.16.2.12': 'signing-certificate',
  '1.2.840.113549.1.9.16.2.47': 'signing-certificate-v2',
};

/** Exact bytes digest, serial, genTime, accuracy and the optional SignedData fields a receipt carries. */
export function describeReceipt(tsr: Uint8Array, r: ParsedReceipt): Record<string, unknown> {
  const t = r.tstInfo;
  const acc = t.accuracy;
  return {
    tsr_sha256: sha256Hex(tsr),
    tsr_bytes: tsr.length,
    serial_hex: t.serial.toString(16),
    gen_time: t.genTime,
    accuracy:
      acc === null
        ? 'absent'
        : { seconds: acc.seconds?.toString() ?? null, millis: acc.millis?.toString() ?? null, micros: acc.micros?.toString() ?? null },
    policy: t.policy,
    ordering: t.ordering,
    nonce_hex: t.nonce?.toString(16) ?? null,
    tsa_field: t.tsa === null ? 'absent' : 'present',
    tst_extensions: t.extensionOids,
    cms_digest: r.digest,
    signed_attributes: r.signer.signedAttrs?.attrs.map((a) => ATTR_NAMES[a.oid] ?? a.oid) ?? [],
    optional_signed_data_fields: {
      embedded_certificates: r.certificates.length,
      other_certificate_choices: r.otherCertificateChoices,
      crls: r.crlsPresent,
      unsigned_attributes: r.signer.unsignedAttrsPresent,
      sid: r.signer.sid.kind,
    },
  };
}
