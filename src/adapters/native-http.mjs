import { Readable } from 'node:stream';
import {
  createBrotliDecompress,
  createGunzip,
  createInflate,
} from 'node:zlib';

import { ATTEMPT_CODE, ATTEMPT_KIND } from '../contracts.mjs';

const TRANSIENT_HTTP = new Set([408, 425, 500, 502, 503, 504]);
const POLICY_STOP = new Set([
  'invalid_intent',
  'invalid_url',
  'ambiguous_url',
  'scheme_denied',
  'userinfo_denied',
  'special_hostname',
  'non_public_ip',
  'dns_non_public',
  'peer_mismatch',
  'invalid_redirect',
  'redirect_downgrade',
  'redirect_loop',
]);

class BodyLimitError extends Error {}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    normalized[name.toLowerCase()] = Array.isArray(value) ? value.join(', ') : String(value);
  }
  return normalized;
}

function safeConditionalHeaders(headers) {
  const safe = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    const lower = name.toLowerCase();
    if (!['if-none-match', 'if-modified-since'].includes(lower)) {
      throw new TypeError('unsafe conditional header');
    }
    if (typeof value !== 'string' || value.length === 0 || value.length > 1024
        || /[\r\n\0]/u.test(value)) {
      throw new TypeError('invalid conditional header');
    }
    safe[lower === 'if-none-match' ? 'If-None-Match' : 'If-Modified-Since'] = value;
  }
  return safe;
}

function requestHeaders(conditionalHeaders) {
  return {
    'User-Agent': 'Lynceuz/0.1',
    Accept: 'text/html,application/xhtml+xml,application/json,application/xml,text/xml,text/plain;q=0.9,*/*;q=0.1',
    'Accept-Encoding': 'gzip, deflate, br',
    ...safeConditionalHeaders(conditionalHeaders),
  };
}

async function discard(body) {
  try {
    body?.destroy?.();
  } catch {
    // Outcome remains fail-closed even when cleanup itself fails.
  }
}

async function collectBounded(body, maximum, signal) {
  if (!Number.isSafeInteger(maximum) || maximum <= 0) throw new TypeError('body limit is invalid');
  const chunks = [];
  let size = 0;
  try {
    for await (const value of body) {
      if (signal?.aborted) throw signal.reason ?? new Error('aborted');
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      size += chunk.length;
      if (size > maximum) throw new BodyLimitError('body limit exceeded');
      chunks.push(chunk);
    }
  } catch (error) {
    body?.destroy?.();
    throw error;
  }
  return Buffer.concat(chunks, size);
}

function decoderFor(encoding) {
  switch (encoding) {
    case 'gzip':
    case 'x-gzip': return createGunzip();
    case 'deflate': return createInflate();
    case 'br': return createBrotliDecompress();
    default: return null;
  }
}

async function decodeBounded(wire, encoding, maximum, signal) {
  if (encoding === '' || encoding === 'identity') {
    if (wire.length > maximum) throw new BodyLimitError('decoded body limit exceeded');
    return wire;
  }
  if (encoding.includes(',')) throw new TypeError('stacked content encoding is unsupported');
  const decoder = decoderFor(encoding);
  if (!decoder) throw new TypeError('content encoding is unsupported');
  Readable.from([wire]).pipe(decoder);
  return collectBounded(decoder, maximum, signal);
}

function retryAfterMs(value) {
  if (typeof value !== 'string') return 0;
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds) && seconds >= 0) return Math.round(seconds * 1000);
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : 0;
}

function statusOutcome(statusCode, headers) {
  if ((statusCode >= 200 && statusCode < 300) || statusCode === 304) return null;
  if (statusCode === 403) return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.ACCESS_DENIED };
  if (statusCode === 401) return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.AUTH_REQUIRED };
  if (statusCode === 402) return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.PAID_REQUIRED };
  if (statusCode === 404) return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.NOT_FOUND };
  if (statusCode === 410) return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.GONE };
  if (statusCode === 429) {
    return {
      kind: ATTEMPT_KIND.RETRYABLE,
      code: ATTEMPT_CODE.RATE_LIMITED,
      retryAfterMs: retryAfterMs(headers['retry-after']),
    };
  }
  if (TRANSIENT_HTTP.has(statusCode)) {
    return { kind: ATTEMPT_KIND.RETRYABLE, code: ATTEMPT_CODE.HTTP_5XX };
  }
  return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.ACCESS_DENIED };
}

function errorOutcome(error, signal) {
  if (signal?.aborted) return { kind: ATTEMPT_KIND.RETRYABLE, code: ATTEMPT_CODE.TIMEOUT };
  if (error instanceof BodyLimitError) {
    return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.HARD_LIMIT };
  }
  if (POLICY_STOP.has(error?.code) || error?.code === 'redirect_limit') {
    return {
      kind: ATTEMPT_KIND.TERMINAL,
      code: error?.code === 'redirect_limit' ? ATTEMPT_CODE.HARD_LIMIT : ATTEMPT_CODE.POLICY_DENIED,
    };
  }
  if (['request_failed', 'dns_resolution_failed', 'connect_failed'].includes(error?.code)) {
    return { kind: ATTEMPT_KIND.RETRYABLE, code: ATTEMPT_CODE.NETWORK };
  }
  return { kind: ATTEMPT_KIND.BROKEN, code: ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR };
}

export function createNativeHttpAdapter({ gateway }) {
  if (!gateway || typeof gateway.execute !== 'function') {
    throw new TypeError('native adapter requires an egress gateway');
  }
  return Object.freeze({
    id: 'native',
    version: '1',
    async run(input) {
      const maxWireBytes = input?.limits?.maxWireBytes;
      const maxDecodedBytes = input?.limits?.maxDecodedBytes;
      try {
        const response = await gateway.execute({
          runId: input.runId,
          purpose: 'page',
          url: input.url,
          method: input.method ?? 'GET',
          headers: requestHeaders(input.conditionalHeaders),
          remaining: input.remaining,
        }, { signal: input.signal });
        const headers = normalizeHeaders(response.headers);
        const classified = statusOutcome(response.statusCode, headers);
        if (classified) {
          await discard(response.body);
          return {
            ...classified,
            evidence: {
              statusCode: response.statusCode,
              headers,
              finalUrl: response.finalUrl,
              redirectChain: response.redirectChain,
              permit: response.permit,
            },
          };
        }
        const wire = await collectBounded(response.body, maxWireBytes, input.signal);
        const body = await decodeBounded(
          wire,
          (headers['content-encoding'] ?? 'identity').trim().toLowerCase(),
          maxDecodedBytes,
          input.signal,
        );
        return {
          kind: ATTEMPT_KIND.SUCCESS,
          code: ATTEMPT_CODE.OK,
          response: {
            statusCode: response.statusCode,
            headers,
            body,
            wireBytes: wire.length,
            decodedBytes: body.length,
            finalUrl: response.finalUrl,
            redirectChain: response.redirectChain,
            permit: response.permit,
          },
        };
      } catch (error) {
        return errorOutcome(error, input?.signal);
      }
    },
  });
}
