import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, sep } from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';

import { createPythonTransformAdapter } from '../src/adapters/python-helper.mjs';
import { compileJobSpec, parseArgv, runCli } from '../src/cli.mjs';
import { ATTEMPT_CODE, ATTEMPT_KIND } from '../src/contracts.mjs';
import {
  createProductionExecutor,
  runCrawlJob,
  runExtractJob,
  runUrlJob,
  runUrlPipeline,
} from '../src/core.mjs';
import { runBoundedCrawl } from '../src/frontier.mjs';
import { createEgressGateway } from '../src/network.mjs';
import { PYTHON_HELPER_PATH } from '../src/process.mjs';
import { acceptRepresentation, createDefaultRegistry } from '../src/router.mjs';
import { createStorage } from '../src/storage.mjs';
import { RESPONSE_FIXTURES } from './fixtures/native-http.mjs';
import {
  DEFAULT_GRAPH,
  P0_ADDRESS,
  P0_ORIGIN,
  createP0SiteFixture,
} from './fixtures/p0-site.mjs';

const PYTHON_PROBE = spawnSync('python3', ['-c', 'import sys; print(sys.executable)'], {
  encoding: 'utf8',
});
const PYTHON = PYTHON_PROBE.status === 0 ? PYTHON_PROBE.stdout.trim() : '/usr/bin/python3';
const PARSER_AVAILABLE = PYTHON_PROBE.status === 0
  && spawnSync(PYTHON, ['-I', PYTHON_HELPER_PATH, '--self-check'], { encoding: 'utf8' }).status === 0;
const OPTIONAL_PARSER_SKIP = PARSER_AVAILABLE ? false : 'optional Python parser is unavailable';
const HASH = /^sha256:[0-9a-f]{64}$/u;

const REGISTRY = createDefaultRegistry(process.version).map((capability) => (
  capability.id === 'native'
    ? { ...capability, state: 'ready', version: '1', reason: 'offline_fixture_ready' }
    : capability
));

async function withStorage(t, prefix = 'lynceuz-p0-') {
  const workspace = await mkdtemp(join(tmpdir(), prefix));
  t.after(async () => rm(workspace, { recursive: true, force: true }));
  const dataRoot = join(workspace, '.lynceuz');
  return { workspace, dataRoot, storage: createStorage({ dataRoot }) };
}

async function storedJson(storage, path) {
  return JSON.parse(await readFile(await storage.resolve(path), 'utf8'));
}

function urlJob(url, ...flags) {
  return compileJobSpec(parseArgv(['url', url, '--cache', 'off', ...flags]));
}

function crawlJob(url, ...flags) {
  return compileJobSpec(parseArgv(['crawl', url, '--cache', 'off', ...flags]));
}

function extractJob(url, schemaPath, schema) {
  return {
    ...compileJobSpec(parseArgv(['extract', url, '--schema', schemaPath, '--cache', 'off'])),
    schema,
  };
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function memoryIo() {
  let stdout = '';
  let stderr = '';
  return {
    io: {
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
    },
    read: () => ({ stdout, stderr }),
  };
}

async function walk(root) {
  const paths = [];
  async function visit(path) {
    const info = await lstat(path);
    paths.push(path);
    if (!info.isDirectory()) return;
    for (const name of await readdir(path)) await visit(join(path, name));
  }
  await visit(root);
  return paths;
}

async function assertManifestHashes(storage, manifest, rawBytes) {
  assert.match(manifest.source_hash, HASH);
  assert.match(manifest.artifact_hash, HASH);
  const source = manifest.artifacts.find(({ hash }) => hash === manifest.source_hash);
  const artifact = manifest.artifacts.find(({ hash }) => hash === manifest.artifact_hash);
  assert.ok(source);
  assert.ok(artifact);
  const storedSource = await readFile(await storage.resolve(source.path));
  const storedArtifact = await readFile(await storage.resolve(artifact.path));
  assert.equal(manifest.source_hash, sha256(rawBytes));
  assert.equal(manifest.source_hash, sha256(storedSource));
  assert.equal(manifest.artifact_hash, sha256(storedArtifact));
  if (artifact.hash !== source.hash) assert.equal(artifact.derived_from, source.hash);
}

test('P0 preserves requested target and records discovered alternatives with immutable evidence', async (t) => {
  const { storage } = await withStorage(t, 'lynceuz-p0-alternatives-');
  const fixture = createP0SiteFixture();
  let forbiddenFallbackCalls = 0;
  const result = await runUrlJob(urlJob(`${P0_ORIGIN}/`), {
    gateway: fixture.gateway,
    storage,
    clock: fixture.clock,
    sleep: fixture.sleep,
    pythonAdapter: {
      async parseHtml() {
        forbiddenFallbackCalls += 1;
        throw new Error('accepted native HTML must not fall through');
      },
    },
  });
  const manifest = await storedJson(storage, result.manifest_path);

  assert.equal(result.status, 'ok');
  assert.equal(forbiddenFallbackCalls, 0);
  assert.equal(manifest.requested_url, `${P0_ORIGIN}/`);
  assert.equal(manifest.effective_url, `${P0_ORIGIN}/`);
  assert.deepEqual(manifest.alternatives, [{
    type: 'application/rss+xml',
    url: `${P0_ORIGIN}/feed.xml`,
  }]);
  assert.match(manifest.source_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.match(manifest.artifact_hash, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(manifest.artifacts.some(({ hash }) => hash === manifest.source_hash), true);
  assert.equal(manifest.artifacts.some(({ hash }) => hash === manifest.artifact_hash), true);
  assert.equal(manifest.evidence.some(({ hash }) => hash === manifest.source_hash), true);
  assert.equal(manifest.cost_money, 0);
  assert.equal(manifest.credits_used, 0);
});

test('P0 native format matrix keeps dual hashes and CLI state inside an explicit data root', async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-p0-formats-'));
  const caller = join(workspace, 'unrelated-cwd');
  const dataRoot = join(workspace, 'selected', '.lynceuz');
  await mkdir(caller, { recursive: true });
  const sentinel = join(caller, 'sentinel.txt');
  await writeFile(sentinel, 'unchanged\n');
  t.after(async () => rm(workspace, { recursive: true, force: true }));

  const cases = [
    ['html', RESPONSE_FIXTURES.html, 'markdown'],
    ['html-raw', RESPONSE_FIXTURES.html, 'raw'],
    ['json', RESPONSE_FIXTURES.json, 'json'],
    ['xml', RESPONSE_FIXTURES.xml, 'markdown'],
    ['rss', RESPONSE_FIXTURES.rss, 'markdown'],
    ['atom', RESPONSE_FIXTURES.atom, 'markdown'],
    ['sitemap', RESPONSE_FIXTURES.sitemap, 'markdown'],
    ['unknown', RESPONSE_FIXTURES.binary, 'raw'],
  ];
  const graph = { ...DEFAULT_GRAPH };
  for (const [name, response] of cases) graph[`/formats/${name}`] = response;
  const fixture = createP0SiteFixture({ graph });
  const storage = createStorage({ dataRoot, clock: fixture.clock });
  const previousCwd = process.cwd();

  try {
    process.chdir(caller);
    for (const [name, response, format] of cases) {
      const target = `${P0_ORIGIN}/formats/${name}`;
      const result = await runUrlJob(urlJob(target, '--format', format), {
        gateway: fixture.gateway,
        storage,
        clock: fixture.clock,
        sleep: fixture.sleep,
      });
      const manifest = await storedJson(storage, result.manifest_path);
      assert.equal(result.status, 'ok', name);
      assert.equal(manifest.requested_url, target);
      assert.equal(manifest.effective_url, target);
      assert.equal(manifest.cost_money, 0);
      assert.equal(manifest.credits_used, 0);
      await assertManifestHashes(storage, manifest, response.body);
    }

    const executeJob = createProductionExecutor({
      gateway: fixture.gateway,
      storage,
      clock: fixture.clock,
      sleep: fixture.sleep,
    });
    const output = memoryIo();
    const exitCode = await runCli([
      'url', `${P0_ORIGIN}/formats/unknown`,
      '--format', 'raw',
      '--cache', 'off',
      '--data-root', dataRoot,
      '--json',
    ], {
      io: output.io,
      registry: REGISTRY,
      executeJob,
      now: () => new Date(fixture.clock()),
    });
    const streams = output.read();
    assert.equal(exitCode, 0);
    assert.equal(streams.stdout.split('\n').filter(Boolean).length, 1);
    assert.equal(JSON.parse(streams.stdout).status, 'ok');
    assert.equal(streams.stderr, 'warning: unknown_mime_raw_preserved\n');
  } finally {
    process.chdir(previousCwd);
  }

  assert.equal(await readFile(sentinel, 'utf8'), 'unchanged\n');
  const paths = await walk(workspace);
  const files = [];
  for (const path of paths) if ((await lstat(path)).isFile()) files.push(path);
  assert.deepEqual(files.filter((path) => path.endsWith(`${sep}.gitignore`)), [join(dataRoot, '.gitignore')]);
  assert.equal(await readFile(join(dataRoot, '.gitignore'), 'utf8'), '*\n!.gitignore\n');
  for (const path of files) {
    assert.equal(
      path === sentinel || relative(dataRoot, path).split(sep)[0] !== '..',
      true,
      `unexpected write outside selected data root: ${path}`,
    );
  }
});

test('P0 raw acceptance requires captured bytes', () => {
  assert.deepEqual(
    acceptRepresentation({ goal: 'raw', representation: { kind: 'html' } }),
    {
      kind: ATTEMPT_KIND.INADEQUATE,
      code: ATTEMPT_CODE.EMPTY,
      details: { reason: 'empty_main_content' },
    },
  );
});

test('P0 terminal outcomes, redirect SSRF and mixed DNS make zero fallback calls', async () => {
  const terminalCodes = [
    ATTEMPT_CODE.POLICY_DENIED,
    ATTEMPT_CODE.ROBOTS_DENIED,
    ATTEMPT_CODE.ACCESS_DENIED,
    ATTEMPT_CODE.AUTH_REQUIRED,
    ATTEMPT_CODE.CAPTCHA,
    ATTEMPT_CODE.PAYWALL,
    ATTEMPT_CODE.PAID_REQUIRED,
    ATTEMPT_CODE.NOT_FOUND,
    ATTEMPT_CODE.RATE_LIMITED,
    ATTEMPT_CODE.HARD_LIMIT,
  ];
  for (const code of terminalCodes) {
    const calls = { native: 0, python: 0, browser: 0, cloud: 0 };
    const result = await runUrlPipeline({
      job: urlJob(`${P0_ORIGIN}/terminal-${code}`),
      adapters: {
        native: {
          async run() {
            calls.native += 1;
            return { kind: ATTEMPT_KIND.TERMINAL, code };
          },
        },
        python: { async parseHtml() { calls.python += 1; } },
        browser: { async run() { calls.browser += 1; } },
        cloud: { async run() { calls.cloud += 1; } },
      },
    });
    assert.equal(result.outcome.kind, ATTEMPT_KIND.TERMINAL, code);
    assert.equal(result.outcome.code, code);
    assert.deepEqual(calls, { native: 1, python: 0, browser: 0, cloud: 0 });
  }

  let poisonCalls = 0;
  const redirectFixture = createP0SiteFixture();
  const redirect = await runUrlPipeline({
    job: urlJob(`${P0_ORIGIN}/redirect-private`),
    context: { gateway: redirectFixture.gateway, clock: redirectFixture.clock, sleep: redirectFixture.sleep },
    adapters: {
      python: { async parseHtml() { poisonCalls += 1; } },
      browser: { async run() { poisonCalls += 1; } },
      cloud: { async run() { poisonCalls += 1; } },
    },
  });
  assert.deepEqual(
    { kind: redirect.outcome.kind, code: redirect.outcome.code },
    { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.POLICY_DENIED },
  );
  assert.equal(poisonCalls, 0);
  assert.deepEqual(
    redirectFixture.calls.requestPinned.map(({ url }) => url),
    [`${P0_ORIGIN}/redirect-private`],
  );

  let pinnedCalls = 0;
  const mixedGateway = createEgressGateway({
    lookupAll: async () => [
      { address: P0_ADDRESS, family: 4 },
      { address: '127.0.0.1', family: 4 },
    ],
    requestPinned: async () => {
      pinnedCalls += 1;
      throw new Error('mixed-address target must be denied before transport');
    },
    connectPinned: async () => { throw new Error('tunnel disabled'); },
  });
  const mixed = await runUrlPipeline({
    job: urlJob(`${P0_ORIGIN}/mixed-address`),
    context: { gateway: mixedGateway },
    adapters: { python: { async parseHtml() { poisonCalls += 1; } } },
  });
  assert.deepEqual(
    { kind: mixed.outcome.kind, code: mixed.outcome.code },
    { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.POLICY_DENIED },
  );
  assert.equal(pinnedCalls, 0);
  assert.equal(poisonCalls, 0);
});

test('P0 unreachable robots fails crawl closed before any page or fallback', async (t) => {
  const { storage } = await withStorage(t, 'lynceuz-p0-robots-');
  const fixture = createP0SiteFixture({ robots: new Error('offline robots failure') });
  let parserCalls = 0;
  const result = await runCrawlJob(crawlJob(`${P0_ORIGIN}/`,
    '--max-pages', '3', '--max-depth', '2', '--max-time', '5', '--max-bytes', '65536',
    '--max-frontier', '10', '--concurrency', '1', '--delay', '0.001'), {
    gateway: fixture.gateway,
    storage,
    clock: fixture.clock,
    sleep: fixture.sleep,
    pythonAdapter: { async parseHtml() { parserCalls += 1; } },
  });
  const manifest = await storedJson(storage, result.manifest_path);

  assert.equal(result.status, 'blocked');
  assert.equal(result.code, ATTEMPT_CODE.ROBOTS_DENIED);
  assert.equal(parserCalls, 0);
  assert.deepEqual(
    fixture.calls.requestPinned.map(({ url }) => url),
    [`${P0_ORIGIN}/robots.txt`],
  );
  assert.equal(manifest.crawl.accepted.length, 0);
  assert.equal(manifest.crawl.blocked[0].reason, ATTEMPT_CODE.ROBOTS_DENIED);
  assert.equal(manifest.cost_money, 0);
  assert.equal(manifest.credits_used, 0);
});

test('P0 inadequate HTML may reach only the missing local helper and then stops honestly', async (t) => {
  const { workspace, storage } = await withStorage(t, 'lynceuz-p0-missing-helper-');
  const fixture = createP0SiteFixture();
  const run = await storage.beginRun({
    schema_version: 1,
    command: 'url',
    requested_url: `${P0_ORIGIN}/empty`,
  });
  const python = createPythonTransformAdapter({
    pythonPath: join(workspace, 'missing', 'python3'),
    storage,
  });
  let poisonCalls = 0;
  const result = await runUrlPipeline({
    job: urlJob(`${P0_ORIGIN}/empty`),
    context: {
      storage,
      run,
      gateway: fixture.gateway,
      clock: fixture.clock,
      sleep: fixture.sleep,
    },
    adapters: {
      python,
      browser: { async run() { poisonCalls += 1; } },
      cloud: { async run() { poisonCalls += 1; } },
    },
  });

  assert.deepEqual(
    { kind: result.outcome.kind, code: result.outcome.code },
    { kind: ATTEMPT_KIND.SKIP, code: ATTEMPT_CODE.UNAVAILABLE },
  );
  assert.equal(result.sourceRef.hash.match(HASH) !== null, true);
  assert.deepEqual(
    result.timeline.filter(({ type }) => type === 'transform').map(({ adapter, outcome, code }) => ({
      adapter, outcome, code,
    })),
    [
      { adapter: 'builtin', outcome: ATTEMPT_KIND.INADEQUATE, code: ATTEMPT_CODE.EMPTY },
      { adapter: 'python-parser', outcome: ATTEMPT_KIND.SKIP, code: ATTEMPT_CODE.UNAVAILABLE },
    ],
  );
  assert.equal(poisonCalls, 0);
  assert.deepEqual(
    fixture.calls.requestPinned.map(({ url }) => url),
    [`${P0_ORIGIN}/empty`],
  );
});

test('P0 rejects an invalid extract schema before storage, DNS, transport or helper startup', async (t) => {
  const { workspace } = await withStorage(t, 'lynceuz-p0-schema-first-');
  const schemaPath = join(workspace, 'hostile-schema.json');
  await writeFile(schemaPath, JSON.stringify({
    schema_version: 1,
    fields: {
      title: {
        source: 'css',
        selector: 'h1',
        take: 'text',
        required: true,
        expression: 'process.exit()',
      },
    },
  }));
  const fixture = createP0SiteFixture();
  let storageCalls = 0;
  let helperCalls = 0;
  const executeJob = createProductionExecutor({
    gateway: fixture.gateway,
    storage: async () => {
      storageCalls += 1;
      throw new Error('invalid schema must stop before storage initialization');
    },
    pythonAdapter: async () => {
      helperCalls += 1;
      throw new Error('invalid schema must stop before helper startup');
    },
    clock: fixture.clock,
    sleep: fixture.sleep,
  });
  const job = compileJobSpec(parseArgv([
    'extract', `${P0_ORIGIN}/extract`, '--schema', schemaPath, '--cache', 'off',
  ]));
  const result = await executeJob(job, { registry: REGISTRY });

  assert.equal(result.status, 'invalid_input');
  assert.equal(result.code, 'invalid_input');
  assert.equal(storageCalls, 0);
  assert.equal(helperCalls, 0);
  assert.equal(fixture.calls.lookupAll.length, 0);
  assert.equal(fixture.calls.requestPinned.length, 0);
});

test('P0 extract publishes only schema-valid JSON and required-field failure keeps raw evidence only', {
  skip: OPTIONAL_PARSER_SKIP,
}, async (t) => {
  const { storage } = await withStorage(t, 'lynceuz-p0-extract-');
  const fixture = createP0SiteFixture({
    graph: {
      ...DEFAULT_GRAPH,
      '/extract-alt': {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        body: Buffer.from(`<!doctype html><html><head>
          <link rel="canonical" href="/products/sku-1">
          <link rel="alternate" type="application/rss+xml" href="/feed.xml">
          <script type="application/ld+json">{"sku":"sku-1"}</script>
        </head><body><main><span class="price">19.5</span></main></body></html>`),
      },
    },
  });
  const parser = createPythonTransformAdapter({ pythonPath: PYTHON, storage });
  const schema = {
    schema_version: 1,
    fields: {
      price: { source: 'css', selector: '.price', take: 'text', required: true, type: 'number' },
      sku: { source: 'jsonld', path: ['sku'], required: true, type: 'string' },
    },
  };
  const success = await runExtractJob(
    extractJob(`${P0_ORIGIN}/extract-alt`, 'success.json', schema),
    { gateway: fixture.gateway, storage, pythonAdapter: parser, clock: fixture.clock, sleep: fixture.sleep },
  );
  const successManifest = await storedJson(storage, success.manifest_path);
  const successArtifact = await storedJson(storage, success.artifact_path);
  const selected = successManifest.artifacts.find(({ hash }) => hash === successManifest.artifact_hash);

  assert.equal(success.status, 'ok');
  assert.deepEqual(successArtifact, { price: 19.5, sku: 'sku-1' });
  assert.equal(successManifest.requested_url, `${P0_ORIGIN}/extract-alt`);
  assert.equal(successManifest.effective_url, `${P0_ORIGIN}/extract-alt`);
  assert.deepEqual(successManifest.alternatives, [
    { type: 'canonical', url: `${P0_ORIGIN}/products/sku-1` },
    { type: 'application/rss+xml', url: `${P0_ORIGIN}/feed.xml` },
  ]);
  assert.match(successManifest.source_hash, HASH);
  assert.match(successManifest.artifact_hash, HASH);
  assert.equal(selected.derived_from, successManifest.source_hash);
  assert.equal(successManifest.evidence[0].hash, successManifest.source_hash);
  assert.equal(successManifest.cost_money, 0);
  assert.equal(successManifest.credits_used, 0);

  const missingSchema = {
    schema_version: 1,
    fields: {
      sku: { source: 'css', selector: '.sku', take: 'text', required: true },
    },
  };
  const missing = await runExtractJob(
    extractJob(`${P0_ORIGIN}/extract-missing`, 'missing.json', missingSchema),
    { gateway: fixture.gateway, storage, pythonAdapter: parser, clock: fixture.clock, sleep: fixture.sleep },
  );
  const missingManifest = await storedJson(storage, missing.manifest_path);

  assert.equal(missing.status, 'exhausted');
  assert.equal(missingManifest.requested_url, `${P0_ORIGIN}/extract-missing`);
  assert.equal(missingManifest.effective_url, `${P0_ORIGIN}/extract-missing`);
  assert.match(missingManifest.source_hash, HASH);
  assert.equal(missingManifest.artifact_hash, null);
  assert.equal(missingManifest.artifact_path, null);
  assert.equal(missingManifest.artifacts.length, 1);
  assert.equal(missingManifest.artifacts[0].role, 'raw');
  assert.equal(missingManifest.evidence[0].hash, missingManifest.source_hash);
});

test('P0 crawl enforces exact origin and scope, records discovery provenance and returns a complete partial ledger', async (t) => {
  const { storage } = await withStorage(t, 'lynceuz-p0-crawl-');
  const fixture = createP0SiteFixture();
  const job = crawlJob(`${P0_ORIGIN}/`,
    '--include', '/',
    '--include', '/a',
    '--include', '/query*',
    '--include', '/sitemap.xml',
    '--include', '/feed.xml',
    '--exclude', '/private/**',
    '--discover', 'sitemap,rss',
    '--max-pages', '4',
    '--max-depth', '3',
    '--max-time', '10',
    '--max-bytes', '65536',
    '--max-frontier', '20',
    '--concurrency', '2',
    '--delay', '0.001');
  const result = await runCrawlJob(job, {
    gateway: fixture.gateway,
    storage,
    clock: fixture.clock,
    sleep: fixture.sleep,
  });
  const manifest = await storedJson(storage, result.manifest_path);
  const crawl = await storedJson(storage, result.artifact_path);
  const requestedPages = fixture.calls.requestPinned
    .filter(({ purpose }) => purpose === 'page')
    .map(({ url }) => url);

  assert.equal(result.status, 'partial');
  assert.equal(manifest.status, 'partial');
  assert.equal(crawl.limit, 'max_pages');
  assert.equal(manifest.requested_url, `${P0_ORIGIN}/`);
  assert.deepEqual(manifest.crawl, crawl);
  assert.deepEqual(manifest.attempts, crawl.ledger);
  assert.equal(new Set(crawl.accepted.map(({ url }) => url)).size, crawl.accepted.length);
  assert.equal(crawl.accepted.some(({ provenance }) => provenance === 'robots_sitemap'), true);
  assert.equal(crawl.unvisited.some(({ provenance }) => provenance === 'rss'), true);
  assert.equal(crawl.skipped.some(({ reason }) => reason === 'excluded'), true);
  assert.equal(crawl.skipped.some(({ reason }) => reason === 'not_included'), true);
  assert.equal(crawl.skipped.some(({ reason }) => reason === 'off_origin'), true);
  assert.equal(crawl.skipped.some(({ reason }) => reason === 'duplicate'), true);
  assert.equal(crawl.accepted.some(({ url }) => url === `${P0_ORIGIN}/query?a=1`), true);
  assert.equal(requestedPages.some((url) => url.includes('/private/')), false);
  assert.equal(requestedPages.some((url) => url.startsWith('https://off-origin.example.net/')), false);
  assert.equal(requestedPages.some((url) => url.endsWith('/b')), false);
  assert.equal(fixture.calls.sleeps.some((milliseconds) => milliseconds >= 100), true);
  for (const entry of crawl.ledger) {
    assert.equal(typeof entry.state, 'string');
    assert.equal(typeof entry.url, 'string');
    assert.equal(Number.isSafeInteger(entry.depth), true);
    assert.equal(typeof entry.reason, 'string');
  }
  for (const page of crawl.accepted) {
    assert.match(page.source_hash, HASH);
    assert.equal(manifest.artifacts.some(({ hash }) => hash === page.source_hash), true);
    assert.equal(manifest.evidence.some(({ url, hash }) => url === page.url && hash === page.source_hash), true);
  }
  assert.equal(manifest.cost_money, 0);
  assert.equal(manifest.credits_used, 0);
});

test('P0 crawl reports depth, frontier, byte and wall exhaustion as partial', async () => {
  const baseLimits = {
    maxPages: 10,
    maxDepth: 3,
    wallMs: 1_000,
    maxTotalBytes: 1_000,
    maxFrontier: 10,
    concurrency: 1,
    delayMs: 1,
    retriesPerAdapter: 1,
    maxRedirects: 1,
  };
  async function scenario({ links, usage = {}, limits = {}, advanceOnPage = 0 }) {
    let now = 0;
    return runBoundedCrawl({
      job: { kind: 'crawl', target: { url: `${P0_ORIGIN}/` }, goal: 'markdown' },
      context: {},
      adapters: {},
      robotsGate: {
        async check() {
          return { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK, crawlDelayMs: 0 };
        },
      },
      runUrlPipeline: async ({ job }) => {
        now += advanceOnPage;
        return {
          outcome: { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK },
          representation: { links: links[job.target.url] ?? [] },
          usage: usage[job.target.url] ?? { totalBytes: 1 },
        };
      },
      limits: { ...baseLimits, ...limits },
      include: ['/**'],
      exclude: [],
      clock: () => now,
      sleep: async (milliseconds) => { now += milliseconds; },
    });
  }

  const depth = await scenario({
    links: {
      [`${P0_ORIGIN}/`]: [`${P0_ORIGIN}/a`],
      [`${P0_ORIGIN}/a`]: [`${P0_ORIGIN}/b`],
    },
    limits: { maxDepth: 1 },
  });
  assert.equal(depth.status, 'partial');
  assert.equal(depth.limit, 'max_depth');
  assert.equal(depth.unvisited.some(({ reason }) => reason === 'max_depth'), true);

  const frontier = await scenario({
    links: { [`${P0_ORIGIN}/`]: [`${P0_ORIGIN}/a`, `${P0_ORIGIN}/b`] },
    limits: { maxFrontier: 1 },
  });
  assert.equal(frontier.status, 'partial');
  assert.equal(frontier.limit, 'max_frontier');
  assert.equal(frontier.unvisited.some(({ reason }) => reason === 'max_frontier'), true);

  const bytes = await scenario({
    links: { [`${P0_ORIGIN}/`]: [`${P0_ORIGIN}/a`] },
    usage: {
      [`${P0_ORIGIN}/`]: { totalBytes: 10 },
      [`${P0_ORIGIN}/a`]: { totalBytes: 100 },
    },
    limits: { maxTotalBytes: 50 },
  });
  assert.equal(bytes.status, 'partial');
  assert.equal(bytes.limit, 'max_total_bytes');
  assert.equal(bytes.blocked.some(({ reason }) => reason === ATTEMPT_CODE.HARD_LIMIT), true);

  const wall = await scenario({
    links: { [`${P0_ORIGIN}/`]: [`${P0_ORIGIN}/a`] },
    limits: { wallMs: 10 },
    advanceOnPage: 11,
  });
  assert.equal(wall.status, 'partial');
  assert.equal(wall.limit, 'max_time');
  assert.equal(wall.unvisited.some(({ reason }) => reason === 'max_time'), true);
});

test('P0 crawl never exceeds its run-level concurrency cap', async () => {
  let active = 0;
  let maximumActive = 0;
  const links = {
    [`${P0_ORIGIN}/`]: [`${P0_ORIGIN}/a`, `${P0_ORIGIN}/b`, `${P0_ORIGIN}/c`],
  };
  const result = await runBoundedCrawl({
    job: { kind: 'crawl', target: { url: `${P0_ORIGIN}/` }, goal: 'markdown' },
    context: {},
    adapters: {},
    robotsGate: {
      async check() {
        return { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK, crawlDelayMs: 0 };
      },
    },
    runUrlPipeline: async ({ job }) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await Promise.resolve();
      active -= 1;
      return {
        outcome: { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK },
        representation: { links: links[job.target.url] ?? [] },
        usage: { totalBytes: 1 },
      };
    },
    limits: {
      maxPages: 4,
      maxDepth: 2,
      wallMs: 1_000,
      maxTotalBytes: 1_000,
      maxFrontier: 10,
      concurrency: 2,
      delayMs: 1,
      retriesPerAdapter: 1,
      maxRedirects: 1,
    },
    include: ['/**'],
    exclude: [],
    clock: () => 0,
    sleep: async () => {},
  });

  assert.equal(result.accepted.length, 4);
  assert.equal(maximumActive >= 1, true);
  assert.equal(maximumActive <= 2, true);
});

test('P0 crawl spends retry budget once across the whole frontier', async (t) => {
  const { storage } = await withStorage(t, 'lynceuz-p0-shared-retries-');
  const calls = new Map();
  let now = 0;
  const response = (statusCode, body, headers = {}) => ({
    statusCode,
    headers,
    body: Readable.from([Buffer.from(body)]),
    peerAddress: P0_ADDRESS,
  });
  const gateway = createEgressGateway({
    lookupAll: async () => [{ address: P0_ADDRESS, family: 4 }],
    requestPinned: async ({ permit }) => {
      const path = new URL(permit.canonicalUrl).pathname;
      calls.set(path, (calls.get(path) ?? 0) + 1);
      if (path === '/robots.txt') return response(200, 'User-agent: *\nAllow: /\n');
      if (path === '/') {
        return response(200, '<html><body><main>Root<a href="/a">A</a><a href="/b">B</a></main></body></html>', {
          'content-type': 'text/html',
        });
      }
      if (['/a', '/b'].includes(path) && calls.get(path) === 1) return response(503, 'retry');
      return response(200, `<html><body><main>${path}</main></body></html>`, {
        'content-type': 'text/html',
      });
    },
    connectPinned: async () => { throw new Error('tunnel disabled'); },
    now: () => now,
  });
  const job = crawlJob(`${P0_ORIGIN}/`,
    '--max-pages', '3', '--max-depth', '2', '--max-time', '10', '--max-bytes', '65536',
    '--max-frontier', '10', '--concurrency', '1', '--delay', '0.001', '--retries', '1');
  const result = await runCrawlJob(job, {
    gateway,
    storage,
    clock: () => now,
    sleep: async (milliseconds) => { now += milliseconds; },
  });
  const manifest = await storedJson(storage, result.manifest_path);

  assert.equal(result.status, 'partial');
  assert.equal(calls.get('/a'), 2);
  assert.equal(calls.get('/b'), 1);
  assert.equal(manifest.crawl.accepted.some(({ url }) => url.endsWith('/a')), true);
  assert.equal(manifest.crawl.failed.some(({ url }) => url.endsWith('/b')), true);
  assert.equal(manifest.crawl.usage.retriesUsed, 1);
});

test('P0 crawl spends redirect budget once across the whole frontier', async (t) => {
  const { storage } = await withStorage(t, 'lynceuz-p0-shared-redirects-');
  const calls = new Map();
  let now = 0;
  const response = (statusCode, body, headers = {}) => ({
    statusCode,
    headers,
    body: Readable.from([Buffer.from(body)]),
    peerAddress: P0_ADDRESS,
  });
  const gateway = createEgressGateway({
    lookupAll: async () => [{ address: P0_ADDRESS, family: 4 }],
    requestPinned: async ({ permit }) => {
      const path = new URL(permit.canonicalUrl).pathname;
      calls.set(path, (calls.get(path) ?? 0) + 1);
      if (path === '/robots.txt') return response(200, 'User-agent: *\nAllow: /\n');
      if (path === '/') {
        return response(200, '<html><body><main>Root<a href="/a">A</a><a href="/b">B</a></main></body></html>', {
          'content-type': 'text/html',
        });
      }
      if (path === '/a') return response(302, '', { location: '/final-a' });
      if (path === '/b') return response(302, '', { location: '/final-b' });
      return response(200, `<html><body><main>${path}</main></body></html>`, {
        'content-type': 'text/html',
      });
    },
    connectPinned: async () => { throw new Error('tunnel disabled'); },
    now: () => now,
  });
  const job = crawlJob(`${P0_ORIGIN}/`,
    '--max-pages', '3', '--max-depth', '2', '--max-time', '10', '--max-bytes', '65536',
    '--max-frontier', '10', '--concurrency', '1', '--delay', '0.001', '--max-redirects', '1');
  const result = await runCrawlJob(job, {
    gateway,
    storage,
    clock: () => now,
    sleep: async (milliseconds) => { now += milliseconds; },
  });
  const manifest = await storedJson(storage, result.manifest_path);

  assert.equal(result.status, 'partial');
  assert.equal(calls.get('/final-a'), 1);
  assert.equal(calls.has('/final-b'), false);
  assert.equal(manifest.crawl.accepted.some(({ url }) => url.endsWith('/a')), true);
  assert.equal(manifest.crawl.blocked.some(({ url }) => url.endsWith('/b')), true);
  assert.equal(manifest.crawl.usage.redirectsUsed, 1);
});

test('P0 manifest failure exposes neither selected output nor cache index', async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-p0-manifest-failure-'));
  t.after(async () => rm(workspace, { recursive: true, force: true }));
  const dataRoot = join(workspace, '.lynceuz');
  const fixture = createP0SiteFixture();
  const storage = createStorage({
    dataRoot,
    clock: fixture.clock,
    faultInjector(label) {
      if (label === 'manifest_rename') throw new Error('injected manifest failure');
    },
  });
  const job = compileJobSpec(parseArgv([
    'url', `${P0_ORIGIN}/a`,
    '--output', 'exports/page.md',
    '--cache', 'use',
  ]));

  await assert.rejects(
    runUrlJob(job, {
      gateway: fixture.gateway,
      storage,
      clock: fixture.clock,
      sleep: fixture.sleep,
    }),
    /injected manifest failure/u,
  );
  const files = await walk(dataRoot);
  assert.equal(files.some((path) => path.endsWith(`${sep}manifest.json`)), false);
  assert.equal(files.some((path) => path.includes(`${sep}cache${sep}requests${sep}`)), false);
  await assert.rejects(
    readFile(join(dataRoot, 'exports', 'page.md')),
    (error) => error?.code === 'ENOENT',
  );
});
