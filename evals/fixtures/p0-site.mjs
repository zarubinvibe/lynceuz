import { Readable } from 'node:stream';

import { createEgressGateway } from '../../src/network.mjs';

export const P0_ORIGIN = 'https://public.example.com';
export const P0_ADDRESS = '93.184.216.34';

const html = (body, head = '') => Buffer.from(`<!doctype html><html><head>${head}</head><body>${body}</body></html>`);

const DEFAULT_ROBOTS = `User-agent: *
Disallow: /private
Allow: /private/public
Crawl-delay: 0.1
Sitemap: ${P0_ORIGIN}/sitemap.xml
`;

const DEFAULT_GRAPH = Object.freeze({
  '/': {
    statusCode: 200,
    headers: { 'content-type': 'text/html; charset=utf-8' },
    body: html(
      '<main><h1>Root</h1><p>Public facts.</p><a href="/a">A</a><a href="/private/blocked">Private</a><a href="/query?a=1#one">Query</a><a href="https://off-origin.example.net/out">Off</a></main>',
      '<title>Root</title><link rel="alternate" type="application/rss+xml" href="/feed.xml">',
    ),
  },
  '/a': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<main><h1>A</h1><a href="/b">B</a><a href="/">Cycle</a></main>', '<link rel="canonical" href="/a#alias">'),
  },
  '/b': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<main><h1>B</h1><p>Last page.</p></main>'),
  },
  '/query?a=1': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<main><h1>Query one</h1></main>'),
  },
  '/query?a=2': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<main><h1>Query two</h1></main>'),
  },
  '/private/blocked': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<main>Must never be fetched</main>'),
  },
  '/private/public': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<main>Allowed exception</main>'),
  },
  '/empty': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html(''),
  },
  '/shell': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<div id="app"></div><script src="/app.js"></script>'),
  },
  '/extract': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html(
      '<main><h1>Product</h1><span class="price">19.5</span></main>',
      '<title>Product</title><script type="application/ld+json">{"@type":"Product","sku":"sku-1","name":"Lens"}</script>',
    ),
  },
  '/extract-missing': {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    body: html('<main><h1>No SKU</h1></main>'),
  },
  '/sitemap.xml': {
    statusCode: 200,
    headers: { 'content-type': 'application/xml' },
    body: Buffer.from(`<?xml version="1.0"?><urlset><url><loc>${P0_ORIGIN}/a</loc></url><url><loc>${P0_ORIGIN}/private/blocked</loc></url></urlset>`),
  },
  '/feed.xml': {
    statusCode: 200,
    headers: { 'content-type': 'application/rss+xml' },
    body: Buffer.from(`<?xml version="1.0"?><rss><channel><link>${P0_ORIGIN}/a</link></channel></rss>`),
  },
  '/api.json': {
    statusCode: 200,
    headers: { 'content-type': 'application/json' },
    body: Buffer.from(`{"next":"${P0_ORIGIN}/b"}`),
  },
  '/redirect-private': {
    statusCode: 302,
    headers: { location: 'http://127.0.0.1/private' },
    body: Buffer.alloc(0),
  },
});

function keyFor(value) {
  const url = new URL(value);
  return `${url.pathname}${url.search}`;
}

function cloneResponse(response) {
  return {
    statusCode: response.statusCode,
    headers: { ...(response.headers ?? {}) },
    body: Readable.from([Buffer.from(response.body ?? '')]),
    peerAddress: P0_ADDRESS,
  };
}

export function createP0SiteFixture({
  robots = { statusCode: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from(DEFAULT_ROBOTS) },
  graph = DEFAULT_GRAPH,
  startMs = Date.parse('2026-08-26T12:00:00.000Z'),
} = {}) {
  let nowMs = startMs;
  const calls = { lookupAll: [], requestPinned: [], sleeps: [] };
  const lookupAll = async (hostname, options = {}) => {
    calls.lookupAll.push({ hostname, signal: options.signal ?? null });
    return [{ address: P0_ADDRESS, family: 4 }];
  };
  const requestPinned = async (request) => {
    calls.requestPinned.push({
      url: request.permit.canonicalUrl,
      purpose: request.permit.purpose,
      headers: { ...(request.headers ?? {}) },
    });
    const key = keyFor(request.permit.canonicalUrl);
    const selected = key === '/robots.txt' ? robots : graph[key];
    if (selected instanceof Error) throw selected;
    return cloneResponse(selected ?? {
      statusCode: 404,
      headers: { 'content-type': 'text/plain' },
      body: Buffer.from('missing'),
    });
  };
  const gateway = createEgressGateway({
    lookupAll,
    requestPinned,
    connectPinned: async () => { throw new Error('fixture tunnel disabled'); },
    now: () => nowMs,
  });
  return Object.freeze({
    gateway,
    calls,
    clock: () => nowMs,
    sleep: async (milliseconds) => {
      calls.sleeps.push(milliseconds);
      nowMs += milliseconds;
    },
    advance: (milliseconds) => { nowMs += milliseconds; },
  });
}

export { DEFAULT_GRAPH, DEFAULT_ROBOTS };
