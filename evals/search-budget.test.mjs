// RED contract for the shared search budget (CAP-05 CLI authority, CAP-06 shared budget).
//
// Part 1 — CAP-05 tests use only the already-shipped CLI + contract surface
// (compileJobSpec/parseArgv/createResultEnvelope). They pin the default search
// as a zero-network, no-provider job that can only end in honest exhaustion.
//
// Part 2 — CAP-06 tests dynamic-import the future src/search.mjs *inside* each
// test body. Until that model exists they fail with ERR_MODULE_NOT_FOUND, which
// is the intended red state; they green once search.mjs threads one shared
// budget + AbortSignal through every scraped child.

import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { compileJobSpec, parseArgv } from '../src/cli.mjs';
import { EXIT_CODE, RUN_STATUS, createResultEnvelope, exitCodeForStatus } from '../src/contracts.mjs';
import { createStorage } from '../src/storage.mjs';

const NOW = '2026-08-26T17:00:00.000Z';
const NOW_MS = Date.parse(NOW);
const SEARCH_MODEL = '../src/search.mjs';

function searchJob(argv) {
  return compileJobSpec(parseArgv(argv));
}

async function sandbox(t) {
  const root = await mkdtemp(join(tmpdir(), 'lynceuz-budget-'));
  t.after(async () => rm(root, { recursive: true, force: true }));
  return { storage: createStorage({ dataRoot: join(root, '.lynceuz'), clock: () => new Date(NOW) }) };
}

// A shared run budget the runtime carries across an entire search: counters that
// accumulate (never reset per scrape) plus a wall-clock deadline. Optional caps
// are absent by default (unbounded), matching the frozen search-cloud fixtures.
function freshBudget(overrides = {}) {
  return {
    pagesUsed: 0,
    bytesUsed: 0,
    attemptsUsed: 0,
    creditsUsed: 0,
    deadline: NOW_MS + 3_600_000,
    ...overrides,
  };
}

function makeContext({ signal, budget, gateway } = {}) {
  return {
    gateway: gateway ?? { execute: async () => { throw new Error('gateway must not run in the budget model'); } },
    signal: signal ?? new AbortController().signal,
    budget: budget ?? freshBudget(),
  };
}

function validResults(count) {
  return Array.from({ length: count }, (_, index) => ({
    url: `https://example.com/r${index}`,
    title: `Result ${index}`,
    snippet: `Snippet ${index}`,
  }));
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
        requestUrl: 'https://search.example.test/v1?q=q',
        evidenceUrl: 'https://search.example.test/evidence',
        accessedAt: NOW,
        results: validResults(2),
      };
    },
    ...overrides,
  };
}

function providerWithResults(results, overrides = {}) {
  return provider({
    async search() {
      return {
        requestUrl: 'https://search.example.test/v1?q=q',
        evidenceUrl: 'https://search.example.test/evidence',
        accessedAt: NOW,
        results,
      };
    },
    ...overrides,
  });
}

// Records every runUrlJob invocation: the child job, the run context handed to
// it, and a snapshot of the shared budget as observed at call time.
function scrapeSpy({ onCall } = {}) {
  const calls = [];
  const contexts = [];
  const observed = [];
  const runUrlJob = async (childJob, context) => {
    calls.push(childJob);
    contexts.push(context);
    observed.push({
      budget: context.budget,
      signal: context.signal,
      pagesUsed: context.budget.pagesUsed,
      bytesUsed: context.budget.bytesUsed,
      attemptsUsed: context.budget.attemptsUsed,
      creditsUsed: context.budget.creditsUsed,
    });
    if (onCall) await onCall(childJob, context, calls.length);
    return createResultEnvelope({
      command: 'url',
      status: RUN_STATUS.OK,
      code: 'ok',
      message: 'scraped',
      route: [],
      capabilities: [],
      warnings: [],
      source_hash: `sha256:${'a'.repeat(64)}`,
      cache_status: 'off',
    });
  };
  return { runUrlJob, calls, contexts, observed };
}

// --- CAP-05: CLI authority (proved by the shipped CLI + contract surface) ---

test('CAP-05 CLI authority compiles a default search that authorizes no paid or cloud backend', () => {
  const job = searchJob(['search', 'public records']);
  assert.deepEqual(job.target, { query: 'public records' });
  assert.equal(job.goal, 'search-results');
  assert.equal(job.policy.moneyBudget, 0);
  assert.equal(job.policy.allowFreeCloud, false);
  assert.equal(job.policy.network, 'public-only');
  assert.equal(job.policy.auth, 'none');
  assert.ok(Object.isFrozen(job));
});

test('CAP-05 CLI authority freezes bounded search and scrape-results flags', () => {
  const job = searchJob(['search', 'public records', '--limit', '7', '--scrape-results', '2', '--json']);
  assert.deepEqual(job.search, { limit: 7, scrapeResults: 2 });
  assert.ok(Object.isFrozen(job.search));

  for (const argv of [
    ['search', 'q', '--limit', '0'],
    ['search', 'q', '--limit', '1.5'],
    ['search', 'q', '--scrape-results', '0'],
    ['search', 'q', '--scrape-results', '1.5'],
    ['search', 'q', '--scrape-results', '101'],
    ['search', ''],
    ['search', '   '],
    ['https://example.com', '--scrape-results', '1'],
    ['crawl', 'https://example.com', '--limit', '1'],
  ]) {
    assert.throws(() => searchJob(argv), /invalid input/, `expected invalid input for ${JSON.stringify(argv)}`);
  }
});

test('CAP-05 CLI authority bounds the search query itself', () => {
  assert.throws(() => searchJob(['search', 'x'.repeat(100_001)]), /invalid input/);
});

test('CAP-05 CLI authority pins the honest no-provider exhaustion to a zero-network exit', () => {
  const envelope = createResultEnvelope({
    command: 'search',
    status: RUN_STATUS.EXHAUSTED,
    code: 'unavailable_no_free_search_provider',
    message: 'no free search provider is configured',
    route: [],
    capabilities: [],
    warnings: [],
  });
  assert.equal(envelope.status, RUN_STATUS.EXHAUSTED);
  assert.equal(envelope.code, 'unavailable_no_free_search_provider');
  assert.equal(envelope.manifest_path, undefined);
  assert.equal(exitCodeForStatus(envelope.status), EXIT_CODE.EXHAUSTED);
  assert.equal(EXIT_CODE.EXHAUSTED, 4);
});

// --- CAP-06: shared budget (proved by the future src/search.mjs model) ---

test('CAP-06 shared budget threads one context, budget and AbortSignal into every scrape without reset', async (t) => {
  const { createSearchRegistry, runSearchJob } = await import(SEARCH_MODEL);
  const { storage } = await sandbox(t);
  const controller = new AbortController();
  const budget = freshBudget();
  const context = makeContext({ signal: controller.signal, budget });
  const spy = scrapeSpy({
    onCall: (job, ctx) => {
      ctx.budget.pagesUsed += 1;
      ctx.budget.bytesUsed += 512;
      ctx.budget.attemptsUsed += 1;
    },
  });

  const result = await runSearchJob(
    searchJob(['search', 'public records', '--limit', '10', '--scrape-results', '3', '--json']),
    {
      registry: createSearchRegistry([providerWithResults(validResults(3))]),
      storage,
      clock: () => new Date(NOW),
      runUrlJob: spy.runUrlJob,
      sharedRunContext: context,
    },
  );

  assert.equal(spy.calls.length, 3);
  // One and the same context object is handed to every child.
  assert.equal(spy.contexts[0], spy.contexts[1]);
  assert.equal(spy.contexts[1], spy.contexts[2]);
  // The shared budget and signal are passed by identity, not copied per child.
  assert.equal(spy.observed.every((o) => o.budget === budget), true);
  assert.equal(spy.observed.every((o) => o.signal === controller.signal), true);
  assert.ok(spy.contexts[0].signal instanceof AbortSignal);
  // Counters accumulate across scrapes — never reset to zero per attempt.
  assert.deepEqual(spy.observed.map((o) => o.pagesUsed), [0, 1, 2]);
  assert.deepEqual(spy.observed.map((o) => o.bytesUsed), [0, 512, 1024]);
  assert.deepEqual(spy.observed.map((o) => o.attemptsUsed), [0, 1, 2]);
  assert.deepEqual(spy.observed.map((o) => o.creditsUsed), [0, 0, 0]);
  assert.equal(budget.pagesUsed, 3);
  assert.equal(budget.deadline, freshBudget().deadline);
  // Children run under the shared run id but carry their own per-attempt limits.
  assert.equal(spy.contexts[0].run.id, spy.contexts[0].runId);
  assert.equal(spy.calls.every((job) => job.runId === spy.contexts[0].runId), true);
  assert.equal(spy.calls.every((job) => job.limits === result.search_limits), false);
});

test('CAP-06 shared budget stops before starting the next child once the deadline is spent', async (t) => {
  const { createSearchRegistry, runSearchJob } = await import(SEARCH_MODEL);
  const { storage } = await sandbox(t);
  let nowMs = NOW_MS;
  const budget = freshBudget({ deadline: NOW_MS + 1_000 });
  const context = makeContext({ budget });
  // The first scrape consumes the entire deadline; the second must never start.
  const spy = scrapeSpy({ onCall: () => { nowMs += 60_000; } });

  await runSearchJob(
    searchJob(['search', 'q', '--limit', '10', '--scrape-results', '3']),
    {
      registry: createSearchRegistry([providerWithResults(validResults(3))]),
      storage,
      clock: () => new Date(nowMs),
      runUrlJob: spy.runUrlJob,
      sharedRunContext: context,
    },
  );

  assert.equal(spy.calls.length, 1);
});

test('CAP-06 shared budget halts planning the moment the shared AbortSignal fires', async (t) => {
  const { createSearchRegistry, runSearchJob } = await import(SEARCH_MODEL);
  const { storage } = await sandbox(t);
  const controller = new AbortController();
  const context = makeContext({ signal: controller.signal });
  const spy = scrapeSpy({ onCall: () => controller.abort() });

  await runSearchJob(
    searchJob(['search', 'q', '--limit', '10', '--scrape-results', '3']),
    {
      registry: createSearchRegistry([providerWithResults(validResults(3))]),
      storage,
      clock: () => new Date(NOW),
      runUrlJob: spy.runUrlJob,
      sharedRunContext: context,
    },
  );

  assert.equal(spy.calls.length, 1);
  assert.ok(controller.signal.aborted);
});

test('CAP-06 shared budget starts no child and no provider call when the signal is already aborted', async (t) => {
  const { createSearchRegistry, runSearchJob } = await import(SEARCH_MODEL);
  const { storage } = await sandbox(t);
  const controller = new AbortController();
  controller.abort();
  let searched = 0;
  const eager = provider({
    async search() {
      searched += 1;
      return {
        requestUrl: 'https://search.example.test/v1?q=q',
        evidenceUrl: 'https://search.example.test/evidence',
        accessedAt: NOW,
        results: validResults(3),
      };
    },
  });
  const spy = scrapeSpy();

  await runSearchJob(
    searchJob(['search', 'q', '--limit', '10', '--scrape-results', '3']),
    {
      registry: createSearchRegistry([eager]),
      storage,
      clock: () => new Date(NOW),
      runUrlJob: spy.runUrlJob,
      sharedRunContext: makeContext({ signal: controller.signal }),
    },
  );

  assert.equal(spy.calls.length, 0);
  assert.equal(searched, 0);
});

test('CAP-06 shared budget refuses paid and ineligible providers despite present credentials or binaries', async (t) => {
  const { createSearchRegistry, runSearchJob } = await import(SEARCH_MODEL);
  const { storage } = await sandbox(t);
  let searched = 0;
  const counting = () => async () => {
    searched += 1;
    return {
      requestUrl: 'https://search.example.test/v1?q=q',
      evidenceUrl: 'https://search.example.test/evidence',
      accessedAt: NOW,
      results: validResults(3),
    };
  };
  const paid = provider({ id: 'paid-serp', cost: 'cloud-paid', price: 5, credentials: 'present', search: counting() });
  const disabled = provider({ id: 'disabled-cli', state: 'disabled', reason: 'disabled_by_policy', binary: '/opt/bin/foo', search: counting() });
  const spy = scrapeSpy();

  const result = await runSearchJob(
    searchJob(['search', 'q', '--limit', '10', '--scrape-results', '3']),
    {
      registry: createSearchRegistry([paid, disabled]),
      storage,
      clock: () => new Date(NOW),
      runUrlJob: spy.runUrlJob,
      sharedRunContext: makeContext(),
    },
  );

  assert.equal(spy.calls.length, 0);
  assert.equal(searched, 0);
  assert.equal(result.status, RUN_STATUS.EXHAUSTED);
  assert.equal(result.code, 'unavailable_no_free_search_provider');
});

test('CAP-06 shared budget rejects an out-of-bounds provider response before touching a child', async (t) => {
  const { createSearchRegistry, runSearchJob } = await import(SEARCH_MODEL);
  const { storage } = await sandbox(t);
  const base = {
    requestUrl: 'https://search.example.test/v1?q=q',
    evidenceUrl: 'https://search.example.test/evidence',
    accessedAt: NOW,
  };
  const invalidResponses = [
    { ...base, results: [] }, // empty
    { ...base, results: validResults(101) }, // more than 100
    { ...base, results: [{ url: 'https://example.com', title: 'x', snippet: 'x', extra: true }] }, // unexpected field
    { ...base, results: [{ url: 'https://example.com', title: 'x'.repeat(100_001), snippet: 'x' }] }, // unbounded title
    { ...base, results: [{ url: 'https://example.com', title: 'x', snippet: 'x'.repeat(100_001) }] }, // unbounded snippet
  ];

  for (const response of invalidResponses) {
    const spy = scrapeSpy();
    const result = await runSearchJob(
      searchJob(['search', 'q', '--limit', '10', '--scrape-results', '3']),
      {
        registry: createSearchRegistry([provider({ search: async () => response })]),
        storage,
        clock: () => new Date(NOW),
        runUrlJob: spy.runUrlJob,
        sharedRunContext: makeContext(),
      },
    );
    assert.equal(result.status, RUN_STATUS.INTERNAL_ERROR);
    assert.equal(result.code, 'adapter_protocol_error');
    assert.equal(spy.calls.length, 0);
  }
});
