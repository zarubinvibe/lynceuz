import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { createPythonTransformAdapter } from '../src/adapters/python-helper.mjs';
import { compileJobSpec, parseArgv } from '../src/cli.mjs';
import { ATTEMPT_CODE, ATTEMPT_KIND } from '../src/contracts.mjs';
import { runCrawlJob, runExtractJob, runUrlPipeline } from '../src/core.mjs';
import {
  canonicalFrontierKey,
  createFrontier,
  runBoundedCrawl,
} from '../src/frontier.mjs';
import { PYTHON_HELPER_PATH } from '../src/process.mjs';
import { createRobotsGate, parseRobots } from '../src/robots.mjs';
import { acceptRepresentation, decideTransition } from '../src/router.mjs';
import { createStorage } from '../src/storage.mjs';
import {
  DEFAULT_GRAPH,
  DEFAULT_ROBOTS,
  P0_ORIGIN,
  createP0SiteFixture,
} from './fixtures/p0-site.mjs';

const TARGET = `${P0_ORIGIN}/`;
const PYTHON_PROBE = spawnSync('python3', ['-c', 'import sys; print(sys.executable)'], {
  encoding: 'utf8',
});
const PYTHON = PYTHON_PROBE.status === 0 ? PYTHON_PROBE.stdout.trim() : '/usr/bin/python3';
const PARSER_AVAILABLE = PYTHON_PROBE.status === 0
  && spawnSync(PYTHON, ['-I', PYTHON_HELPER_PATH, '--self-check'], { encoding: 'utf8' }).status === 0;
const OPTIONAL_PARSER_SKIP = PARSER_AVAILABLE ? false : 'optional Python parser is unavailable';

async function temporaryStorage(t, prefix) {
  const workspace = await mkdtemp(join(tmpdir(), prefix));
  t.after(async () => rm(workspace, { recursive: true, force: true }));
  const dataRoot = join(workspace, '.lynceuz');
  return { dataRoot, storage: createStorage({ dataRoot }) };
}

async function readStoredJson(storage, relativePath) {
  return JSON.parse(await readFile(await storage.resolve(relativePath), 'utf8'));
}

function urlJob(url) {
  return compileJobSpec(parseArgv(['url', url, '--cache', 'off']));
}

test('crawl CLI compiles explicit scope, discovery and positive finite limits', () => {
  const spec = compileJobSpec(parseArgv([
    'crawl', TARGET,
    '--include', '/docs/**',
    '--include', '/news/*',
    '--exclude', '/docs/private/**',
    '--discover', 'sitemap,rss,api',
    '--prefer-discovered-source',
    '--max-pages', '7',
    '--max-depth', '2',
    '--max-time', '12.5',
    '--max-bytes', '65536',
    '--max-frontier', '20',
    '--concurrency', '2',
    '--delay', '0.1',
    '--max-redirects', '3',
    '--retries', '1',
    '--data-root', '/tmp/lynceuz-p0/.lynceuz',
  ]));
  assert.deepEqual(spec.scope.include, ['/docs/**', '/news/*']);
  assert.deepEqual(spec.scope.exclude, ['/docs/private/**']);
  assert.deepEqual(spec.discovery.sources, ['api', 'rss', 'sitemap']);
  assert.equal(spec.discovery.preferDiscoveredSource, true);
  assert.equal(spec.limits.maxPages, 7);
  assert.equal(spec.limits.maxDepth, 2);
  assert.equal(spec.limits.wallMs, 12_500);
  assert.equal(spec.limits.maxTotalBytes, 65_536);
  assert.equal(spec.limits.maxFrontier, 20);
  assert.equal(spec.limits.concurrency, 2);
  assert.equal(spec.limits.delayMs, 100);
  assert.equal(spec.output.dataRoot, '/tmp/lynceuz-p0/.lynceuz');

  for (const argv of [
    ['crawl', TARGET, '--max-pages', '0'],
    ['crawl', TARGET, '--concurrency', 'Infinity'],
    ['crawl', TARGET, '--include', '../escape/**'],
    ['crawl', TARGET, '--include', '/foo/[abc]'],
    ['url', TARGET, '--discover', 'sitemap'],
  ]) {
    assert.throws(() => compileJobSpec(parseArgv(argv)), /invalid input/u);
  }
});

test('goal acceptance rejects empty, JS-shell and wrong representations precisely', () => {
  assert.deepEqual(
    acceptRepresentation({ goal: 'markdown', representation: { kind: 'html', text: '', scriptCount: 0 } }),
    { kind: ATTEMPT_KIND.INADEQUATE, code: ATTEMPT_CODE.EMPTY, details: { reason: 'empty_main_content' } },
  );
  assert.deepEqual(
    acceptRepresentation({ goal: 'markdown', representation: { kind: 'html', text: '', scriptCount: 2 } }),
    { kind: ATTEMPT_KIND.INADEQUATE, code: ATTEMPT_CODE.JS_SHELL, details: { reason: 'proven_js_shell' } },
  );
  assert.deepEqual(
    acceptRepresentation({ goal: 'json', representation: { kind: 'binary', text: 'bytes' } }),
    { kind: ATTEMPT_KIND.INADEQUATE, code: ATTEMPT_CODE.WRONG_MIME, details: { reason: 'wrong_representation' } },
  );
  assert.equal(
    acceptRepresentation({ goal: 'markdown', representation: { kind: 'html', text: 'Public facts' } }).kind,
    ATTEMPT_KIND.SUCCESS,
  );
  assert.equal(
    decideTransition(
      { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.ROBOTS_DENIED },
      { hasNext: true },
    ).action,
    'stop',
  );
});

test('robots parser uses selected user-agent, longest match and Allow tie-break', () => {
  const wildcard = parseRobots(DEFAULT_ROBOTS, { userAgent: 'OtherBot/1.0' });
  assert.equal(wildcard.allows(`${P0_ORIGIN}/private/blocked`), false);
  assert.equal(wildcard.allows(`${P0_ORIGIN}/private/public`), true);
  assert.equal(wildcard.crawlDelayMs, 100);
  assert.deepEqual(wildcard.sitemaps, [`${P0_ORIGIN}/sitemap.xml`]);

  const parsed = parseRobots(`
User-agent: Lynceuz
Disallow: /same
Allow: /same
Disallow: /encoded/%2Fsecret$
`, { userAgent: 'Lynceuz/1.0' });
  assert.equal(parsed.allows(`${P0_ORIGIN}/same`), true);
  assert.equal(parsed.allows(`${P0_ORIGIN}/encoded/%2Fsecret`), false);
  assert.equal(parsed.allows(`${P0_ORIGIN}/encoded/%2Fsecret/child`), true);
});

test('robots gate uses EgressGateway, caches at most 24h and fails closed', async () => {
  const fixture = createP0SiteFixture();
  const gate = createRobotsGate({
    gateway: fixture.gateway,
    clock: fixture.clock,
    ttlMs: 48 * 60 * 60 * 1000,
    maxBodyBytes: 32 * 1024,
    maxRedirects: 2,
  });
  const allowed = await gate.check(`${P0_ORIGIN}/a`, { runId: 'robots-allow' });
  const denied = await gate.check(`${P0_ORIGIN}/private/blocked`, { runId: 'robots-deny' });
  assert.equal(allowed.kind, ATTEMPT_KIND.SUCCESS);
  assert.equal(denied.kind, ATTEMPT_KIND.TERMINAL);
  assert.equal(denied.code, ATTEMPT_CODE.ROBOTS_DENIED);
  assert.equal(fixture.calls.requestPinned.length, 1, 'second decision must use bounded robots cache');
  assert.equal(fixture.calls.requestPinned[0].purpose, 'robots');
  assert.ok(gate.ttlMs <= 24 * 60 * 60 * 1000);

  for (const robots of [
    { statusCode: 403, headers: {}, body: Buffer.from('denied') },
    { statusCode: 429, headers: { 'retry-after': '1' }, body: Buffer.from('slow') },
    { statusCode: 503, headers: {}, body: Buffer.from('down') },
    new Error('unreachable'),
  ]) {
    const blockedFixture = createP0SiteFixture({ robots });
    const blockedGate = createRobotsGate({ gateway: blockedFixture.gateway });
    const result = await blockedGate.check(`${P0_ORIGIN}/a`, { runId: 'robots-fail' });
    assert.equal(result.kind, ATTEMPT_KIND.TERMINAL);
    assert.equal(result.code, ATTEMPT_CODE.ROBOTS_DENIED);
  }

  const missingFixture = createP0SiteFixture({
    robots: { statusCode: 404, headers: {}, body: Buffer.from('missing') },
  });
  assert.equal(
    (await createRobotsGate({ gateway: missingFixture.gateway })
      .check(`${P0_ORIGIN}/a`, { runId: 'robots-404' })).kind,
    ATTEMPT_KIND.SUCCESS,
  );
});

test('frontier preserves queries, strips fragments and never broadens exact origin', () => {
  assert.equal(
    canonicalFrontierKey(`${P0_ORIGIN}/a#one`, P0_ORIGIN),
    `${P0_ORIGIN}/a`,
  );
  assert.notEqual(
    canonicalFrontierKey(`${P0_ORIGIN}/query?a=1`, P0_ORIGIN),
    canonicalFrontierKey(`${P0_ORIGIN}/query?a=2`, P0_ORIGIN),
  );
  assert.throws(
    () => canonicalFrontierKey('https://off-origin.example.net/a', P0_ORIGIN),
    /exact origin/u,
  );

  const frontier = createFrontier({
    seedUrl: TARGET,
    include: ['/**'],
    exclude: ['/private/**'],
    limits: { maxFrontier: 3, maxDepth: 2 },
  });
  assert.equal(frontier.enqueue(`${P0_ORIGIN}/a#x`, { depth: 1, source: TARGET }).accepted, true);
  assert.equal(frontier.enqueue(`${P0_ORIGIN}/a#y`, { depth: 1, source: TARGET }).reason, 'duplicate');
  assert.equal(frontier.enqueue(`${P0_ORIGIN}/private/x`, { depth: 1, source: TARGET }).reason, 'excluded');
  assert.equal(frontier.enqueue('https://off-origin.example.net/x', { depth: 1, source: TARGET }).reason, 'off_origin');
});

test('bounded crawl checks robots before every page and reports partial ledger', async () => {
  const visited = [];
  const checked = [];
  const links = new Map([
    [TARGET, [`${P0_ORIGIN}/a`, `${P0_ORIGIN}/private/blocked`, 'https://off-origin.example.net/out']],
    [`${P0_ORIGIN}/a`, [`${P0_ORIGIN}/b`, TARGET]],
    [`${P0_ORIGIN}/b`, []],
  ]);
  const result = await runBoundedCrawl({
    job: { kind: 'crawl', target: { url: TARGET }, goal: 'markdown' },
    context: {},
    adapters: {},
    robotsGate: {
      async check(url) {
        checked.push(url);
        return url.includes('/private/')
          ? { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.ROBOTS_DENIED }
          : { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK, crawlDelayMs: 0 };
      },
    },
    runUrlPipeline: async ({ job }) => {
      visited.push(job.target.url);
      return {
        outcome: { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK },
        representation: { links: links.get(job.target.url) ?? [] },
        usage: { wireBytes: 10, decodedBytes: 10, artifactBytes: 10 },
      };
    },
    limits: {
      maxPages: 2,
      maxDepth: 3,
      wallMs: 10_000,
      maxTotalBytes: 1_000,
      maxFrontier: 10,
      concurrency: 1,
      delayMs: 1,
    },
    include: ['/**'],
    exclude: [],
    clock: (() => { let value = 0; return () => value++; })(),
    sleep: async () => {},
  });
  assert.equal(result.status, 'partial');
  assert.deepEqual(visited, [TARGET, `${P0_ORIGIN}/a`]);
  assert.equal(checked.includes(`${P0_ORIGIN}/private/blocked`), true);
  assert.equal(checked.some((url) => url.includes('off-origin')), false);
  assert.equal(result.accepted.length, 2);
  assert.equal(result.unvisited.some((entry) => entry.url === `${P0_ORIGIN}/b`), true);
  assert.equal(result.skipped.some((entry) => entry.reason === 'off_origin'), true);
  assert.equal(result.blocked.some((entry) => entry.reason === ATTEMPT_CODE.ROBOTS_DENIED), true);
  assert.equal(result.limit, 'max_pages');
});

test('URL pipeline stops on terminal native outcome without Python fallback', async (t) => {
  const { storage } = await temporaryStorage(t, 'lynceuz-pipeline-terminal-');
  const fixture = createP0SiteFixture({
    graph: {
      ...DEFAULT_GRAPH,
      '/denied': {
        statusCode: 403,
        headers: { 'content-type': 'text/html' },
        body: Buffer.from('<main>denied</main>'),
      },
    },
  });
  const run = await storage.beginRun({ command: 'url', requested_url: `${P0_ORIGIN}/denied` });
  let pythonCalls = 0;
  const result = await runUrlPipeline({
    job: urlJob(`${P0_ORIGIN}/denied`),
    context: { storage, run, gateway: fixture.gateway, clock: fixture.clock, sleep: fixture.sleep },
    adapters: {
      python: {
        async parseHtml() {
          pythonCalls += 1;
          throw new Error('terminal outcomes must not fall through');
        },
      },
    },
  });

  assert.equal(result.outcome.kind, ATTEMPT_KIND.TERMINAL);
  assert.equal(result.outcome.code, ATTEMPT_CODE.ACCESS_DENIED);
  assert.equal(pythonCalls, 0);
  assert.deepEqual(
    fixture.calls.requestPinned.map(({ url }) => url),
    [`${P0_ORIGIN}/denied`],
  );
});

test('URL pipeline permits one local Python transform only after inadequate HTML', async (t) => {
  const { storage } = await temporaryStorage(t, 'lynceuz-pipeline-inadequate-');
  const fixture = createP0SiteFixture();
  const run = await storage.beginRun({ command: 'url', requested_url: `${P0_ORIGIN}/empty` });
  const pythonCalls = [];
  const result = await runUrlPipeline({
    job: urlJob(`${P0_ORIGIN}/empty`),
    context: { storage, run, gateway: fixture.gateway, clock: fixture.clock, sleep: fixture.sleep },
    adapters: {
      python: {
        id: 'python-parser',
        networkModel: 'none',
        async parseHtml(input) {
          pythonCalls.push(input);
          const markdown = '# Recovered locally\n';
          const markdownRef = await storage.putObject(run, Buffer.from(markdown), {
            role: 'derived',
            media_type: 'text/markdown; charset=utf-8',
            derived_from: input.sourceRef.hash,
          });
          return {
            kind: ATTEMPT_KIND.SUCCESS,
            code: ATTEMPT_CODE.OK,
            value: {
              title: 'Recovered locally',
              canonicalCandidate: null,
              text: 'Recovered locally',
              markdown,
              links: [],
              metadata: {},
              alternateCandidates: [],
              jsonld: [],
              artifacts: { markdown: markdownRef },
            },
          };
        },
      },
    },
  });

  assert.equal(result.outcome.kind, ATTEMPT_KIND.SUCCESS);
  assert.equal(result.representation.text, 'Recovered locally');
  assert.equal(pythonCalls.length, 1);
  assert.equal(pythonCalls[0].run.id, run.id);
  assert.match(pythonCalls[0].sourceRef.hash, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(pythonCalls[0].baseUrl, `${P0_ORIGIN}/empty`);
  assert.deepEqual(
    fixture.calls.requestPinned.map(({ url }) => url),
    [`${P0_ORIGIN}/empty`],
  );
});

test('extract job commits valid JSON and records required-field miss', {
  skip: OPTIONAL_PARSER_SKIP,
}, async (t) => {
  const { storage } = await temporaryStorage(t, 'lynceuz-extract-integration-');
  const fixture = createP0SiteFixture();
  const adapter = createPythonTransformAdapter({ pythonPath: PYTHON, storage });
  const successSchema = {
    schema_version: 1,
    fields: {
      price: { source: 'css', selector: '.price', take: 'text', required: true, type: 'number' },
      sku: { source: 'jsonld', path: ['sku'], required: true, type: 'string' },
    },
  };
  const successJob = {
    ...compileJobSpec(parseArgv(['extract', `${P0_ORIGIN}/extract`, '--schema', 'fixture.json'])),
    schema: successSchema,
  };
  const success = await runExtractJob(successJob, {
    gateway: fixture.gateway,
    storage,
    pythonAdapter: adapter,
    clock: fixture.clock,
    sleep: fixture.sleep,
  });
  const successManifest = await readStoredJson(storage, success.manifest_path);
  const successArtifact = await readStoredJson(storage, success.artifact_path);

  assert.equal(success.status, 'ok');
  assert.deepEqual(successArtifact, { price: 19.5, sku: 'sku-1' });
  assert.equal(successManifest.status, 'ok');
  assert.equal(successManifest.engine.id, 'python-parser');
  assert.equal(successManifest.requested_url, `${P0_ORIGIN}/extract`);
  assert.match(successManifest.source_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.match(successManifest.artifact_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(successManifest.cost_money, 0);

  let helperOutcome;
  const trackedAdapter = {
    ...adapter,
    async extractSchema(input) {
      helperOutcome = await adapter.extractSchema(input);
      return helperOutcome;
    },
  };
  const missingSchema = {
    schema_version: 1,
    fields: {
      sku: { source: 'css', selector: '.sku', take: 'text', required: true },
    },
  };
  const missingJob = {
    ...compileJobSpec(parseArgv([
      'extract', `${P0_ORIGIN}/extract-missing`, '--schema', 'fixture-missing.json',
    ])),
    schema: missingSchema,
  };
  const missing = await runExtractJob(missingJob, {
    gateway: fixture.gateway,
    storage,
    pythonAdapter: trackedAdapter,
    clock: fixture.clock,
    sleep: fixture.sleep,
  });
  const missingManifest = await readStoredJson(storage, missing.manifest_path);

  assert.equal(helperOutcome.kind, ATTEMPT_KIND.INADEQUATE);
  assert.equal(helperOutcome.code, ATTEMPT_CODE.PARSE_FAILED);
  assert.equal(helperOutcome.details.reason, 'required_fields_missing');
  assert.deepEqual(helperOutcome.details.missing, ['sku']);
  assert.equal(missing.status, 'exhausted');
  assert.equal(missingManifest.status, 'exhausted');
  assert.equal(missingManifest.artifact_hash, null);
  assert.match(missingManifest.source_hash, /^sha256:[0-9a-f]{64}$/u);
});

test('crawl job writes a truthful manifest and robots runs before page fetches', async (t) => {
  const { storage } = await temporaryStorage(t, 'lynceuz-crawl-integration-');
  const fixture = createP0SiteFixture();
  const job = compileJobSpec(parseArgv([
    'crawl', TARGET,
    '--max-pages', '3',
    '--max-depth', '2',
    '--max-time', '10',
    '--max-bytes', '65536',
    '--max-frontier', '20',
    '--concurrency', '1',
    '--delay', '0.001',
  ]));
  const result = await runCrawlJob(job, {
    gateway: fixture.gateway,
    storage,
    clock: fixture.clock,
    sleep: fixture.sleep,
  });
  const manifest = await readStoredJson(storage, result.manifest_path);
  const artifact = await readStoredJson(storage, result.artifact_path);
  const requests = fixture.calls.requestPinned;

  assert.equal(result.status, 'partial');
  assert.equal(result.code, 'partial');
  assert.equal(requests[0].url, `${P0_ORIGIN}/robots.txt`);
  assert.equal(requests[0].purpose, 'robots');
  assert.equal(requests[1].url, TARGET);
  assert.equal(requests.some(({ url }) => url === `${P0_ORIGIN}/private/blocked`), false);
  assert.equal(requests.filter(({ purpose }) => purpose === 'robots').length, 1);

  assert.equal(manifest.status, 'partial');
  assert.equal(manifest.requested_url, TARGET);
  assert.equal(manifest.source_hash, result.source_hash);
  assert.equal(manifest.artifact_hash, result.source_hash);
  assert.equal(manifest.cost_money, 0);
  assert.equal(manifest.credits_used, 0);
  assert.deepEqual(artifact, manifest.crawl);
  assert.deepEqual(manifest.attempts, manifest.crawl.ledger);
  assert.equal(manifest.crawl.limit, 'max_pages');
  assert.equal(manifest.crawl.accepted.length, 3);
  assert.equal(manifest.crawl.blocked.some(({ reason }) => reason === ATTEMPT_CODE.ROBOTS_DENIED), true);
  assert.equal(manifest.crawl.skipped.some(({ reason }) => reason === 'off_origin'), true);
  assert.equal(manifest.crawl.unvisited.length > 0, true);
  for (const page of manifest.crawl.accepted) {
    assert.match(page.source_hash, /^sha256:[0-9a-f]{64}$/u);
    assert.equal(manifest.artifacts.some(({ hash }) => hash === page.source_hash), true);
    assert.equal(manifest.evidence.some(({ url, hash }) => url === page.url && hash === page.source_hash), true);
  }
});
