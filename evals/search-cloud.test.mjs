import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { compileJobSpec, parseArgv } from '../src/cli.mjs';
import { RUN_STATUS, createResultEnvelope } from '../src/contracts.mjs';
import { createSearchRegistry, runSearchJob } from '../src/search.mjs';
import { createStorage } from '../src/storage.mjs';

const NOW = '2026-08-26T17:00:00.000Z';

function searchJob(argv = ['search', 'public records']) {
  return compileJobSpec(parseArgv(argv));
}

function provider(overrides = {}) {
  return {
    id: 'fixture-search',
    version: '1',
    state: 'ready',
    reason: 'fixture_ready',
    automatic: true,
    commands: ['search'],
    cost: 'local-zero',
    price: 0,
    networkModel: 'core-http',
    async search() {
      return {
        requestUrl: 'https://search.example.test/v1?q=public%20records',
        evidenceUrl: 'https://search.example.test/evidence/fixture',
        accessedAt: NOW,
        results: [
          { url: 'https://example.com/a#one', title: 'A', snippet: 'first' },
          { url: 'http://127.0.0.1/private', title: 'private', snippet: 'reject' },
          { url: 'https://example.com/a#two', title: 'duplicate', snippet: 'reject' },
          { url: 'javascript:alert(1)', title: 'invalid', snippet: 'reject' },
          { url: 'https://example.org/b', title: 'B', snippet: 'second' },
        ],
      };
    },
    ...overrides,
  };
}

async function sandbox(t) {
  const root = await mkdtemp(join(tmpdir(), 'lynceuz-search-'));
  t.after(async () => rm(root, { recursive: true, force: true }));
  const dataRoot = join(root, '.lynceuz');
  return {
    dataRoot,
    storage: createStorage({ dataRoot, clock: () => new Date(NOW) }),
  };
}

async function manifestFor(dataRoot, result) {
  return JSON.parse(await readFile(join(dataRoot, result.manifest_path), 'utf8'));
}

test('search and scrape-results flags compile into one immutable bounded JobSpec', () => {
  const job = searchJob([
    'search', 'public records', '--limit', '7', '--scrape-results', '2', '--json',
  ]);
  assert.deepEqual(job.target, { query: 'public records' });
  assert.deepEqual(job.search, { limit: 7, scrapeResults: 2 });
  assert.equal(job.policy.moneyBudget, 0);
  assert.equal(job.policy.allowFreeCloud, false);
  assert.ok(Object.isFrozen(job.search));

  for (const argv of [
    ['search', 'q', '--limit', '0'],
    ['search', 'q', '--limit', '1.5'],
    ['search', 'q', '--scrape-results', '0'],
    ['search', 'q', '--scrape-results', '101'],
    ['https://example.com', '--scrape-results', '1'],
    ['crawl', 'https://example.com', '--limit', '1'],
  ]) {
    assert.throws(() => searchJob(argv), /invalid input/);
  }
});

test('default search has no provider or SERP fallback and exits with exact honest reason', () => {
  const cwd = fileURLToPath(new URL('../', import.meta.url));
  const executable = fileURLToPath(new URL('../src/lynceuz.mjs', import.meta.url));
  const tripwire = fileURLToPath(new URL('./fixtures/no-network.mjs', import.meta.url));
  const child = spawnSync(process.execPath, [
    '--import', tripwire, executable, 'search', 'public records', '--json',
  ], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, LYNCEUZ_FORBID_NETWORK: '1' },
    timeout: 10_000,
  });
  assert.equal(child.status, 4, child.stderr);
  assert.equal(child.signal, null);
  const result = JSON.parse(child.stdout);
  assert.equal(result.status, RUN_STATUS.EXHAUSTED);
  assert.equal(result.code, 'unavailable_no_free_search_provider');
  assert.equal(result.manifest_path, undefined);
});

test('search normalizes strict provider evidence and scrapes only permitted unique candidates', async (t) => {
  const { dataRoot, storage } = await sandbox(t);
  const registry = createSearchRegistry([provider()]);
  const calls = [];
  const sharedContexts = [];
  const runUrlJob = async (childJob, sharedRunContext) => {
    calls.push(childJob);
    sharedContexts.push(sharedRunContext);
    return createResultEnvelope({
      command: 'url',
      status: calls.length === 1 ? RUN_STATUS.OK : RUN_STATUS.EXHAUSTED,
      code: calls.length === 1 ? 'ok' : 'exhausted',
      message: 'fixture result',
      route: [],
      capabilities: [],
      warnings: [],
      ...(calls.length === 1
        ? { source_hash: `sha256:${'a'.repeat(64)}`, cache_status: 'off' }
        : {}),
    });
  };
  const result = await runSearchJob(searchJob([
    'search', 'public records', '--limit', '5', '--scrape-results', '2', '--json',
  ]), {
    registry,
    storage,
    clock: () => new Date(NOW),
    runUrlJob,
    sharedRunContext: {
      gateway: { execute: async () => { throw new Error('not used by fixture'); } },
      signal: new AbortController().signal,
      budget: { pagesUsed: 0, bytesUsed: 0, attemptsUsed: 0 },
    },
  });

  assert.equal(result.status, RUN_STATUS.PARTIAL);
  assert.equal(result.code, 'partial');
  assert.equal(calls.length, 2);
  assert.deepEqual(calls.map((job) => job.target.url), [
    'https://example.com/a',
    'https://example.org/b',
  ]);
  assert.equal(sharedContexts[0], sharedContexts[1]);
  assert.equal(sharedContexts[0].run.id, sharedContexts[0].runId);
  assert.equal(calls.every((job) => job.runId === sharedContexts[0].runId), true);
  assert.equal(calls.every((job) => job.limits === result.search_limits), false);
  assert.deepEqual(result.warnings, [
    'search_candidate_private_or_invalid:2',
    'search_candidate_duplicate:1',
  ]);

  const manifest = await manifestFor(dataRoot, result);
  assert.equal(manifest.provider.id, 'fixture-search');
  assert.equal(manifest.provider.version, '1');
  assert.equal(manifest.provider.request_url, 'https://search.example.test/v1?q=public%20records');
  assert.equal(manifest.provider.evidence_url, 'https://search.example.test/evidence/fixture');
  assert.equal(manifest.provider.accessed_at, NOW);
  assert.equal(manifest.cost_money, 0);
  assert.equal(manifest.search.results.length, 2);
  assert.equal(manifest.search.results.every((entry) => (
    entry.snippet_kind === 'discovery_metadata'
  )), true);
  assert.equal(manifest.evidence.some((entry) => entry.status === 'destination_source_captured'
    && entry.url === 'https://example.com/a'), true);
  assert.equal(manifest.evidence.some((entry) => entry.snippet), false);
  assert.deepEqual(manifest.search.scraped.map(({ status }) => status), ['ok', 'exhausted']);
});

test('search provider response schema is strict and bounded before normalization', async (t) => {
  const { storage } = await sandbox(t);
  const invalidProviders = [
    provider({ search: async () => ({ results: [] }) }),
    provider({ search: async () => ({
      requestUrl: 'https://search.example.test/',
      evidenceUrl: 'https://search.example.test/evidence',
      accessedAt: NOW,
      results: [{ url: 'https://example.com', title: 'x', snippet: 'x', extra: true }],
    }) }),
    provider({ search: async () => ({
      requestUrl: 'https://search.example.test/',
      evidenceUrl: 'https://search.example.test/evidence',
      accessedAt: NOW,
      results: Array.from({ length: 101 }, (_, index) => ({
        url: `https://example.com/${index}`, title: 'x', snippet: 'x',
      })),
    }) }),
  ];
  for (const invalidProvider of invalidProviders) {
    const result = await runSearchJob(searchJob(), {
      registry: createSearchRegistry([invalidProvider]),
      storage,
      clock: () => new Date(NOW),
    });
    assert.equal(result.status, RUN_STATUS.INTERNAL_ERROR);
    assert.equal(result.code, 'adapter_protocol_error');
  }
});
