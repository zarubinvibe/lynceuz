import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve, sep } from 'node:path';
import test from 'node:test';

import { compileJobSpec, parseArgv, runCli } from '../src/cli.mjs';
import { createProductionExecutor } from '../src/core.mjs';
import { createDefaultRegistry } from '../src/router.mjs';
import { createStorage } from '../src/storage.mjs';
import { createNativeFixture } from './fixtures/native-http.mjs';

const TARGET = 'https://public.example.org/page';
const START_MS = Date.parse('2026-08-26T08:00:00.000Z');
const REGISTRY = createDefaultRegistry(process.version).map((capability) => (
  capability.id === 'native'
    ? {
      ...capability,
      version: '1',
      state: 'ready',
      reason: 'native_http_ready',
    }
    : capability
));

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

async function temporaryDataRoot(t) {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-cli-native-'));
  t.after(async () => rm(workspace, { recursive: true, force: true }));
  return {
    workspace,
    dataRoot: join(workspace, '.lynceuz'),
  };
}

async function productionHarness(t, responses) {
  const { workspace, dataRoot } = await temporaryDataRoot(t);
  const fixture = createNativeFixture({ responses, startMs: START_MS });
  const storage = await createStorage({ dataRoot, clock: fixture.clock });
  const executeJob = createProductionExecutor({
    gateway: fixture.gateway,
    storage,
    clock: fixture.clock,
    sleep: fixture.sleep,
  });
  assert.equal(typeof executeJob, 'function');
  return { workspace, dataRoot, fixture, storage, executeJob };
}

async function invoke(executeJob, argv) {
  const output = memoryIo();
  const exitCode = await runCli(argv, {
    io: output.io,
    registry: REGISTRY,
    executeJob,
    now: () => new Date(START_MS),
  });
  return { exitCode, ...output.read() };
}

function parseSingleJson(stdout) {
  assert.equal(stdout.endsWith('\n'), true);
  assert.equal(stdout.split('\n').filter(Boolean).length, 1);
  return JSON.parse(stdout);
}

function assertRelativeInside(dataRoot, relativePath) {
  assert.equal(typeof relativePath, 'string');
  assert.equal(isAbsolute(relativePath), false);
  const root = resolve(dataRoot);
  const target = resolve(root, relativePath);
  assert.equal(target.startsWith(`${root}${sep}`), true);
  return target;
}

function headerValue(headers, wantedName) {
  const entry = Object.entries(headers ?? {})
    .find(([name]) => name.toLowerCase() === wantedName.toLowerCase());
  return entry?.[1];
}

async function readManifest(dataRoot, result) {
  const path = assertRelativeInside(dataRoot, result.manifest_path);
  return JSON.parse(await readFile(path, 'utf8'));
}

test('URL flags compile to bounded Phase 2 defaults and explicit options', () => {
  const defaults = compileJobSpec(parseArgv(['url', TARGET]));
  assert.equal(defaults.goal, 'markdown');
  assert.deepEqual(defaults.output, {
    json: false,
    format: 'markdown',
    path: null,
    dataRoot: null,
  });
  assert.deepEqual(defaults.cache, { mode: 'use', ttlMs: 3_600_000 });

  for (const format of ['raw', 'markdown', 'metadata', 'links', 'json']) {
    const spec = compileJobSpec(parseArgv([
      TARGET,
      '--format', format,
      '--output', `exports/page.${format}`,
      '--data-root', 'state/.lynceuz',
      '--cache', 'refresh',
      '--ttl', '17',
      '--json',
    ]));
    assert.equal(spec.goal, format);
    assert.deepEqual(spec.output, {
      json: true,
      format,
      path: `exports/page.${format}`,
      dataRoot: 'state/.lynceuz',
    });
    assert.deepEqual(spec.cache, { mode: 'refresh', ttlMs: 17_000 });
    assert.ok(Object.isFrozen(spec.output));
    assert.ok(Object.isFrozen(spec.cache));
  }
});

test('format, cache, TTL, output and data-root inputs fail closed', () => {
  const invalid = [
    [TARGET, '--format', 'html'],
    [TARGET, '--cache', 'stale-ok'],
    [TARGET, '--ttl', '0'],
    [TARGET, '--ttl', '-1'],
    [TARGET, '--ttl', 'Infinity'],
    [TARGET, '--ttl', '9007199254740'],
    [TARGET, '--ttl', 'not-a-number'],
    [TARGET, '--output', '../escape.md'],
    [TARGET, '--output', '/tmp/escape.md'],
    [TARGET, '--output', '.'],
    [TARGET, '--data-root', 'state'],
    [TARGET, '--data-root', '.lynceuz/child'],
  ];
  for (const argv of invalid) {
    assert.throws(() => compileJobSpec(parseArgv(argv)), /invalid input/);
  }

  const absoluteRoot = compileJobSpec(parseArgv([
    TARGET,
    '--data-root', '/tmp/acceptance/.lynceuz',
    '--cache', 'off',
  ]));
  assert.equal(absoluteRoot.output.dataRoot, '/tmp/acceptance/.lynceuz');
  assert.equal(absoluteRoot.cache.mode, 'off');
});

test('one URL command emits one JSON result, keeps warnings on stderr and writes only below data root', async (t) => {
  const body = Buffer.from([0x00, 0x01, 0x02, 0xff]);
  const harness = await productionHarness(t, [{
    statusCode: 200,
    headers: { 'content-type': 'application/octet-stream' },
    body,
  }]);

  const outputPath = 'exports/evidence.bin';
  const run = await invoke(harness.executeJob, [
    TARGET,
    '--format', 'raw',
    '--output', outputPath,
    '--data-root', harness.dataRoot,
    '--cache', 'off',
    '--json',
  ]);
  const result = parseSingleJson(run.stdout);

  assert.equal(run.exitCode, 0);
  assert.equal(result.schema_version, 1);
  assert.equal(result.command, 'url');
  assert.equal(result.status, 'ok');
  assert.equal(result.code, 'ok');
  assert.equal(result.cache_status, 'off');
  assert.match(result.source_hash, /^sha256:[a-f0-9]{64}$/u);
  assert.match(run.stderr, /^warning: unknown_mime_raw_preserved\n$/u);
  assert.deepEqual(result.warnings, ['unknown_mime_raw_preserved']);

  const manifestPath = assertRelativeInside(harness.dataRoot, result.manifest_path);
  const artifactPath = assertRelativeInside(harness.dataRoot, result.artifact_path);
  assert.equal(result.artifact_path, outputPath);
  assert.deepEqual(await readFile(artifactPath), body);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  assert.equal(manifest.schema_version, 1);
  assert.equal(manifest.source_hash, result.source_hash);
  await assert.rejects(
    readFile(join(harness.workspace, '.gitignore')),
    (error) => error?.code === 'ENOENT',
  );
});

test('fresh TTL cache hit performs zero DNS and transport calls', async (t) => {
  const harness = await productionHarness(t, [{
    statusCode: 200,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      etag: '"v1"',
      'last-modified': 'Wed, 26 Aug 2026 07:00:00 GMT',
    },
    body: Buffer.from('<h1>Cached</h1>'),
  }]);
  const argv = [TARGET, '--data-root', harness.dataRoot, '--ttl', '60', '--json'];

  const first = parseSingleJson((await invoke(harness.executeJob, argv)).stdout);
  const callsAfterMiss = {
    lookupAll: harness.fixture.calls.lookupAll.length,
    requestPinned: harness.fixture.calls.requestPinned.length,
  };
  harness.fixture.advance(1_000);
  const secondRun = await invoke(harness.executeJob, argv);
  const second = parseSingleJson(secondRun.stdout);

  assert.equal(secondRun.exitCode, 0);
  assert.equal(first.cache_status, 'miss');
  assert.equal(second.cache_status, 'hit');
  assert.equal(second.source_hash, first.source_hash);
  assert.deepEqual({
    lookupAll: harness.fixture.calls.lookupAll.length,
    requestPinned: harness.fixture.calls.requestPinned.length,
  }, callsAfterMiss);

  const firstManifest = await readManifest(harness.dataRoot, first);
  const secondManifest = await readManifest(harness.dataRoot, second);
  assert.equal(secondManifest.fetched_at, firstManifest.fetched_at);
  assert.notEqual(secondManifest.served_at, null);
});

test('stale cache sends ETag and Last-Modified once; 304 preserves provenance timestamps', async (t) => {
  const etag = '"fixture-v1"';
  const lastModified = 'Wed, 26 Aug 2026 07:00:00 GMT';
  const harness = await productionHarness(t, [
    {
      statusCode: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        etag,
        'last-modified': lastModified,
      },
      body: Buffer.from('<h1>Stable source</h1>'),
    },
    {
      statusCode: 304,
      headers: { etag, 'last-modified': lastModified },
      body: Buffer.alloc(0),
    },
  ]);
  const argv = [TARGET, '--data-root', harness.dataRoot, '--ttl', '1', '--json'];

  const first = parseSingleJson((await invoke(harness.executeJob, argv)).stdout);
  const firstManifest = await readManifest(harness.dataRoot, first);
  harness.fixture.advance(2_000);
  const secondRun = await invoke(harness.executeJob, argv);
  const second = parseSingleJson(secondRun.stdout);
  const secondManifest = await readManifest(harness.dataRoot, second);

  assert.equal(secondRun.exitCode, 0);
  assert.equal(first.cache_status, 'miss');
  assert.equal(second.cache_status, 'revalidated');
  assert.equal(harness.fixture.calls.requestPinned.length, 2);
  const conditional = harness.fixture.calls.requestPinned[1];
  assert.equal(headerValue(conditional.headers, 'if-none-match'), etag);
  assert.equal(headerValue(conditional.headers, 'if-modified-since'), lastModified);
  assert.equal(second.source_hash, first.source_hash);
  assert.equal(secondManifest.source_hash, firstManifest.source_hash);
  assert.equal(secondManifest.fetched_at, firstManifest.fetched_at);
  assert.notEqual(secondManifest.served_at, null);
  assert.notEqual(secondManifest.revalidated_at, null);
  assert.notEqual(secondManifest.served_at, firstManifest.served_at);
});
