import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';

import { createNativeHttpAdapter } from '../src/adapters/native-http.mjs';
import { runNativeAttempts } from '../src/core.mjs';
import { deriveRepresentation, detectRepresentation } from '../src/formats.mjs';
import { createNodeRequestPinned } from '../src/network.mjs';
import {
  FIXTURE_ADDRESS,
  FIXTURE_URL,
  RESPONSE_FIXTURES,
  baseUrlJob,
  createFakeClock,
  createNativeFixture,
  encodedResponse,
} from './fixtures/native-http.mjs';

test('production request port pins selected address while preserving Host and TLS SNI', async () => {
  const calls = [];
  const fakeRequest = (options, onResponse) => {
    calls.push(options);
    const request = new EventEmitter();
    request.setTimeout = () => request;
    request.destroy = (error) => { if (error) request.emit('error', error); };
    request.end = () => queueMicrotask(() => {
      const response = Readable.from([Buffer.from('redirect')]);
      response.statusCode = 302;
      response.headers = { location: 'https://public.example.com/final' };
      response.socket = { remoteAddress: FIXTURE_ADDRESS };
      onResponse(response);
    });
    return request;
  };
  const requestPinned = createNodeRequestPinned({ httpRequest: fakeRequest, httpsRequest: fakeRequest });
  const permit = {
    canonicalUrl: `${FIXTURE_URL}?x=1`,
    protocol: 'https:',
    hostname: 'public.example.com',
    port: 443,
    selectedAddress: FIXTURE_ADDRESS,
    expiresAtMs: Date.now() + 5_000,
  };
  const response = await requestPinned({
    permit,
    method: 'GET',
    headers: { Accept: 'text/html' },
    signal: new AbortController().signal,
  });

  assert.equal(calls.length, 1, 'request port must not follow redirects');
  assert.equal(calls[0].hostname, permit.hostname);
  assert.equal(calls[0].servername, permit.hostname);
  assert.equal(calls[0].headers.Host, permit.hostname);
  assert.equal(calls[0].agent, false);
  await new Promise((resolve, reject) => {
    calls[0].lookup(permit.hostname, { all: false }, (error, address, family) => {
      if (error) return reject(error);
      assert.equal(address, permit.selectedAddress);
      assert.equal(family, 4);
      resolve();
    });
  });
  assert.equal(response.peerAddress, permit.selectedAddress);
  assert.equal(response.statusCode, 302);
});

test('native adapter composes only through gateway and keeps selected peer evidence', async () => {
  const fixture = createNativeFixture({ responses: [RESPONSE_FIXTURES.html] });
  const adapter = createNativeHttpAdapter({ gateway: fixture.gateway });
  const outcome = await adapter.run({
    runId: 'run-native-1',
    url: FIXTURE_URL,
    method: 'GET',
    remaining: { wallMs: 5_000, bytes: 64 * 1024, redirects: 2 },
    limits: { maxWireBytes: 64 * 1024, maxDecodedBytes: 64 * 1024 },
  });

  assert.equal(outcome.kind, 'success');
  assert.equal(outcome.code, 'ok');
  assert.equal(outcome.response.permit.selectedAddress, FIXTURE_ADDRESS);
  assert.equal(fixture.calls.lookupAll.length, 1);
  assert.equal(fixture.calls.requestPinned.length, 1);
  assert.equal(outcome.response.body.includes(Buffer.from('Lynceuz')), true);
});

test('declared and sniffed representations cover native public formats', () => {
  const cases = [
    [RESPONSE_FIXTURES.html, 'html'],
    [RESPONSE_FIXTURES.json, 'json'],
    [RESPONSE_FIXTURES.xml, 'xml'],
    [RESPONSE_FIXTURES.rss, 'rss'],
    [RESPONSE_FIXTURES.atom, 'atom'],
    [RESPONSE_FIXTURES.sitemap, 'sitemap'],
    [RESPONSE_FIXTURES.binary, 'binary'],
  ];
  for (const [fixture, expected] of cases) {
    const detected = detectRepresentation({ headers: fixture.headers, prefixBytes: fixture.body });
    assert.equal(detected.kind, expected);
    assert.equal(typeof detected.mediaType, 'string');
  }

  const sniffed = detectRepresentation({
    headers: { 'content-type': 'text/plain' },
    prefixBytes: RESPONSE_FIXTURES.rss.body,
  });
  assert.equal(sniffed.kind, 'rss');
  assert.equal(sniffed.sniffedType, 'rss');

  const binary = detectRepresentation({ headers: {}, prefixBytes: RESPONSE_FIXTURES.binary.body });
  assert.equal(binary.kind, 'binary');
  assert.ok(binary.warnings.includes('unknown_mime_raw_preserved'));
});

test('native projections are deterministic, source preserving and reject malformed JSON', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'lynceuz-format-'));
  try {
    const htmlPath = join(directory, 'source.html');
    const jsonPath = join(directory, 'source.json');
    const invalidPath = join(directory, 'invalid.json');
    await writeFile(htmlPath, RESPONSE_FIXTURES.html.body);
    await writeFile(jsonPath, RESPONSE_FIXTURES.json.body);
    await writeFile(invalidPath, RESPONSE_FIXTURES.malformedJson.body);

    const markdown = await deriveRepresentation({
      format: 'markdown', sourcePath: htmlPath, mediaType: 'text/html', finalUrl: FIXTURE_URL,
      maxArtifactBytes: 64 * 1024,
    });
    assert.equal(markdown.format, 'markdown');
    assert.match(markdown.bytes.toString(), /# Lynceuz/);
    assert.match(markdown.bytes.toString(), /\[Next\]\(https:\/\/public\.example\.com\/next\)/);

    const raw = await deriveRepresentation({
      format: 'raw', sourcePath: htmlPath, mediaType: 'text/html', finalUrl: FIXTURE_URL,
      maxArtifactBytes: 64 * 1024,
    });
    assert.deepEqual(raw.bytes, RESPONSE_FIXTURES.html.body);

    const metadata = await deriveRepresentation({
      format: 'metadata', sourcePath: htmlPath, mediaType: 'text/html', finalUrl: FIXTURE_URL,
      maxArtifactBytes: 64 * 1024,
    });
    assert.deepEqual(JSON.parse(metadata.bytes), {
      bytes: RESPONSE_FIXTURES.html.body.length,
      final_url: FIXTURE_URL,
      media_type: 'text/html',
    });

    const links = await deriveRepresentation({
      format: 'links', sourcePath: htmlPath, mediaType: 'text/html', finalUrl: FIXTURE_URL,
      maxArtifactBytes: 64 * 1024,
    });
    assert.deepEqual(JSON.parse(links.bytes), ['https://public.example.com/next']);

    const json = await deriveRepresentation({
      format: 'json', sourcePath: jsonPath, mediaType: 'application/json', finalUrl: FIXTURE_URL,
      maxArtifactBytes: 64 * 1024,
    });
    assert.deepEqual(JSON.parse(json.bytes), { free: true, name: 'Lynceuz' });

    await assert.rejects(
      deriveRepresentation({
        format: 'json', sourcePath: invalidPath, mediaType: 'application/json', finalUrl: FIXTURE_URL,
        maxArtifactBytes: 64 * 1024,
      }),
      (error) => error?.code === 'output_failure',
    );
    await assert.rejects(
      deriveRepresentation({
        format: 'pdf', sourcePath: htmlPath, mediaType: 'text/html', finalUrl: FIXTURE_URL,
        maxArtifactBytes: 64 * 1024,
      }),
      (error) => error?.code === 'unsupported_format',
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('wire and decoded limits reject compressed overflow without partial success', async () => {
  for (const encoding of ['gzip', 'deflate', 'br']) {
    const fixture = createNativeFixture({ responses: [encodedResponse(encoding, 'x'.repeat(32 * 1024))] });
    const adapter = createNativeHttpAdapter({ gateway: fixture.gateway });
    const outcome = await adapter.run({
      runId: `run-${encoding}`,
      url: FIXTURE_URL,
      method: 'GET',
      remaining: { wallMs: 5_000, bytes: 64 * 1024, redirects: 1 },
      limits: { maxWireBytes: 64 * 1024, maxDecodedBytes: 1024 },
    });
    assert.deepEqual({ kind: outcome.kind, code: outcome.code }, { kind: 'terminal', code: 'hard_limit' });
    assert.equal('response' in outcome, false);
  }

  const malformed = createNativeFixture({
    responses: [{
      statusCode: 200,
      headers: { 'content-type': 'text/plain', 'content-encoding': 'gzip' },
      body: Buffer.from('not gzip'),
    }],
  });
  const outcome = await createNativeHttpAdapter({ gateway: malformed.gateway }).run({
    runId: 'run-malformed', url: FIXTURE_URL, method: 'GET',
    remaining: { wallMs: 5_000, bytes: 64 * 1024, redirects: 1 },
    limits: { maxWireBytes: 64 * 1024, maxDecodedBytes: 64 * 1024 },
  });
  assert.deepEqual(
    { kind: outcome.kind, code: outcome.code },
    { kind: 'broken', code: 'adapter_protocol_error' },
  );
});

test('retry owner bounds attempts, wall deadline and Retry-After while preserving timeline', async () => {
  const clock = createFakeClock();
  const scripted = [
    { kind: 'retryable', code: 'network' },
    { kind: 'retryable', code: 'rate_limited', retryAfterMs: 120_000 },
    { kind: 'success', code: 'ok', response: { body: Buffer.from('ok') } },
  ];
  const adapter = { run: async () => scripted.shift() };
  const result = await runNativeAttempts(baseUrlJob(), {
    adapter,
    clock: clock.now,
    sleep: clock.sleep,
  });
  assert.equal(result.outcome.kind, 'success');
  assert.equal(result.timeline.length, 3);
  assert.deepEqual(clock.sleeps, [0, 1_500]);
  assert.equal(result.timeline[1].delay_ms, 1_500);
  assert.equal(result.timeline[1].retry_after_capped, true);

  const deadlineClock = createFakeClock();
  const deadlineJob = baseUrlJob({
    limits: { ...baseUrlJob().limits, wallMs: 1_000, maxRetryAfterMs: 1_500 },
  });
  const deadline = await runNativeAttempts(deadlineJob, {
    adapter: { run: async () => ({ kind: 'retryable', code: 'rate_limited', retryAfterMs: 3_000 }) },
    clock: deadlineClock.now,
    sleep: deadlineClock.sleep,
  });
  assert.deepEqual(
    { kind: deadline.outcome.kind, code: deadline.outcome.code },
    { kind: 'terminal', code: 'hard_limit' },
  );
  assert.equal(deadline.timeline.length, 1);
});

test('403 and 404 are terminal and never retried', async () => {
  for (const [response, expected] of [
    [RESPONSE_FIXTURES.forbidden, ['terminal', 'access_denied']],
    [RESPONSE_FIXTURES.notFound, ['terminal', 'not_found']],
  ]) {
    const fixture = createNativeFixture({ responses: [response, RESPONSE_FIXTURES.html] });
    const adapter = createNativeHttpAdapter({ gateway: fixture.gateway });
    const result = await runNativeAttempts(baseUrlJob(), {
      adapter, clock: fixture.clock, sleep: fixture.sleep,
    });
    assert.deepEqual([result.outcome.kind, result.outcome.code], expected);
    assert.equal(fixture.calls.requestPinned.length, 1);
    assert.equal(result.timeline.length, 1);
  }
});
