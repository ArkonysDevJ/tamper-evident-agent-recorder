// SPDX-License-Identifier: AGPL-3.0-or-later
// TSA transport (Blueprint §5.7 step 2; transport details are left to the
// implementation by §10). Implementation choice (not normative): HTTP POST of
// the DER request with Content-Type application/timestamp-query, a 5000 ms
// timeout per TSA, and a cap on the response size. The response Content-Type
// plays no part in acceptance.

export const TSA_TIMEOUT_MS = 5000;
export const MAX_RESPONSE_BYTES = 256 * 1024;

export type TransportResult =
  | { readonly kind: 'response'; readonly body: Uint8Array }
  | { readonly kind: 'failure'; readonly reason: 'timeout' | 'network' | 'http_status' | 'too_large'; readonly detail: string };

/** One retained TSA, as the writer sees it. */
export interface TsaEndpoint {
  readonly name: string;
  request(tsq: Uint8Array): Promise<TransportResult>;
}

export const RETAINED_TSA_URLS = {
  freetsa: 'https://freetsa.org/tsr',
  digicert: 'http://timestamp.digicert.com',
} as const;

export function httpTsa(name: string, url: string, timeoutMs: number = TSA_TIMEOUT_MS): TsaEndpoint {
  return {
    name,
    async request(tsq) {
      let res: Response;
      try {
        res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/timestamp-query' },
          body: Buffer.from(tsq),
          signal: AbortSignal.timeout(timeoutMs),
          redirect: 'error',
        });
      } catch (err) {
        const timeout = err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
        return { kind: 'failure', reason: timeout ? 'timeout' : 'network', detail: String(err) };
      }
      try {
        if (res.status !== 200) return { kind: 'failure', reason: 'http_status', detail: String(res.status) };
        const body = new Uint8Array(await res.arrayBuffer());
        if (body.length > MAX_RESPONSE_BYTES) return { kind: 'failure', reason: 'too_large', detail: String(body.length) };
        return { kind: 'response', body };
      } catch (err) {
        const timeout = err instanceof Error && (err.name === 'TimeoutError' || err.name === 'AbortError');
        return { kind: 'failure', reason: timeout ? 'timeout' : 'network', detail: String(err) };
      }
    },
  };
}

/** The retained TSAs in the §5.7 order: FreeTSA first, DigiCert second. */
export function retainedTsas(): TsaEndpoint[] {
  return [httpTsa('freetsa', RETAINED_TSA_URLS.freetsa), httpTsa('digicert', RETAINED_TSA_URLS.digicert)];
}
