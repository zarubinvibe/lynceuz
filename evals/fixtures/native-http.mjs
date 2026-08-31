import { Readable } from 'node:stream';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';

import { createEgressGateway } from '../../src/network.mjs';

export const FIXTURE_ADDRESS = '93.184.216.34';
export const FIXTURE_URL = 'https://public.example.com/source';

const bytes = (value) => (Buffer.isBuffer(value) ? value : Buffer.from(value));

export const RESPONSE_FIXTURES = Object.freeze({
  html: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({
      'content-type': 'text/html; charset=utf-8',
      etag: '"html-v1"',
      'last-modified': 'Wed, 26 Aug 2026 12:00:00 GMT',
    }),
    body: Buffer.from('<!doctype html><html><head><title>Eyes</title></head><body><h1>Lynceuz</h1><p>Sees public facts.</p><a href="/next">Next</a></body></html>'),
  }),
  json: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({ 'content-type': 'application/json' }),
    body: Buffer.from('{"name":"Lynceuz","free":true}'),
  }),
  malformedJson: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({ 'content-type': 'application/json' }),
    body: Buffer.from('{"broken":'),
  }),
  xml: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({ 'content-type': 'application/xml' }),
    body: Buffer.from('<?xml version="1.0"?><records><record id="1"/></records>'),
  }),
  rss: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({ 'content-type': 'application/rss+xml' }),
    body: Buffer.from('<?xml version="1.0"?><rss version="2.0"><channel><title>News</title></channel></rss>'),
  }),
  atom: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({ 'content-type': 'application/atom+xml' }),
    body: Buffer.from('<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>News</title></feed>'),
  }),
  sitemap: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({ 'content-type': 'application/xml' }),
    body: Buffer.from('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://public.example.com/a</loc></url></urlset>'),
  }),
  binary: Object.freeze({
    statusCode: 200,
    headers: Object.freeze({ 'content-type': 'application/octet-stream' }),
    body: Buffer.from([0, 1, 2, 3, 255, 0, 17]),
  }),
  redirect: Object.freeze({
    statusCode: 302,
    headers: Object.freeze({ location: '/final' }),
    body: Buffer.alloc(0),
  }),
  forbidden: Object.freeze({ statusCode: 403, headers: Object.freeze({}), body: Buffer.from('no') }),
  notFound: Object.freeze({ statusCode: 404, headers: Object.freeze({}), body: Buffer.from('missing') }),
  retryAfter: Object.freeze({
    statusCode: 429,
    headers: Object.freeze({ 'retry-after': '120' }),
    body: Buffer.from('slow down'),
  }),
  unavailable: Object.freeze({ statusCode: 503, headers: Object.freeze({}), body: Buffer.from('later') }),
  notModified: Object.freeze({
    statusCode: 304,
    headers: Object.freeze({ etag: '"html-v1"' }),
    body: Buffer.alloc(0),
  }),
});

export function encodedResponse(encoding, value, overrides = {}) {
  const source = bytes(value);
  const encoders = { gzip: gzipSync, deflate: deflateSync, br: brotliCompressSync };
  if (!encoders[encoding]) throw new TypeError('unsupported fixture encoding');
  return {
    statusCode: 200,
    headers: { 'content-type': 'text/plain', 'content-encoding': encoding },
    body: encoders[encoding](source),
    ...overrides,
  };
}

export function createFakeClock(startMs = Date.parse('2026-08-26T12:00:00.000Z')) {
  let currentMs = startMs;
  const sleeps = [];
  return Object.freeze({
    now: () => currentMs,
    date: () => new Date(currentMs),
    advance: (milliseconds) => { currentMs += milliseconds; },
    sleep: async (milliseconds) => {
      sleeps.push(milliseconds);
      currentMs += milliseconds;
    },
    sleeps,
  });
}

function cloneResponse(response, peerAddress) {
  return {
    statusCode: response.statusCode,
    headers: { ...(response.headers ?? {}) },
    body: Readable.from([bytes(response.body ?? Buffer.alloc(0))]),
    peerAddress: response.peerAddress ?? peerAddress,
  };
}

export function createNativeFixture({
  responses = [RESPONSE_FIXTURES.html],
  address = FIXTURE_ADDRESS,
  clock: suppliedClock,
  startMs,
} = {}) {
  const clock = suppliedClock ?? createFakeClock(startMs);
  const queue = [...responses];
  const calls = { lookupAll: [], requestPinned: [], connectPinned: [], sleeps: clock.sleeps };

  const lookupAll = async (hostname, options = {}) => {
    calls.lookupAll.push({ hostname, signal: options.signal ?? null });
    return [{ address, family: address.includes(':') ? 6 : 4 }];
  };
  const requestPinned = async (request) => {
    calls.requestPinned.push({ ...request, headers: { ...(request.headers ?? {}) } });
    if (request.signal?.aborted) throw request.signal.reason ?? new Error('aborted');
    if (queue.length === 0) throw new Error('fixture response queue exhausted');
    const scripted = queue.shift();
    if (scripted instanceof Error) throw scripted;
    const response = typeof scripted === 'function' ? await scripted(request, calls) : scripted;
    if (response instanceof Error) throw response;
    return cloneResponse(response, address);
  };
  const connectPinned = async (request) => {
    calls.connectPinned.push(request);
    throw new Error('fixture tunnel is not available');
  };
  const gateway = createEgressGateway({ lookupAll, requestPinned, connectPinned, now: clock.now });
  return Object.freeze({
    gateway,
    lookupAll,
    requestPinned,
    connectPinned,
    calls,
    clock: clock.now,
    sleep: clock.sleep,
    advance: clock.advance,
    fakeClock: clock,
    queue,
  });
}

export function baseUrlJob(overrides = {}) {
  return {
    schemaVersion: 1,
    kind: 'url',
    target: { url: FIXTURE_URL },
    goal: 'markdown',
    limits: {
      wallMs: 10_000,
      perAttemptMs: 2_000,
      maxBytesPerPage: 64 * 1024,
      maxTotalBytes: 256 * 1024,
      maxPages: 1,
      maxDepth: 1,
      concurrency: 1,
      maxRedirects: 3,
      retriesPerAdapter: 2,
      maxRetryAfterMs: 1_500,
      maxWireBytes: 64 * 1024,
      maxDecodedBytes: 128 * 1024,
      maxArtifactBytes: 128 * 1024,
    },
    policy: {
      network: 'public-only',
      auth: 'none',
      moneyBudget: 0,
      allowFreeCloud: false,
      allowRendered: false,
      respectRobots: true,
    },
    output: {
      json: true,
      format: 'markdown',
      path: null,
      dataRoot: null,
    },
    cache: { mode: 'use', ttlMs: 60_000 },
    routing: { explain: false, forcedEngine: null },
    ...overrides,
  };
}
