import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { compileJobSpec, parseArgv } from '../src/cli.mjs';
import {
  buildRoutePlan,
  createCapabilitySnapshot,
  decideTransition,
  healthReport,
  runModelRoute,
} from '../src/router.mjs';
import { capability, scriptedAdapter } from './fixtures/fake-adapters.mjs';

const job = (argv = ['https://example.com']) => compileJobSpec(parseArgv(argv));

test('capability snapshot and route plan are immutable and deterministic', () => {
  const registry = [
    capability({ id: 'native' }),
    capability({
      id: 'playwright',
      state: 'unavailable_security_gate',
      reason: 'hostile_egress_proof_missing',
      networkModel: 'guard-proxy',
    }),
    capability({
      id: 'browser-use',
      state: 'disabled',
      reason: 'automatic_path_forbidden',
      automatic: false,
      networkModel: 'guard-proxy',
    }),
    capability({
      id: 'firecrawl',
      state: 'disabled',
      reason: 'free_cloud_not_allowed',
      cost: 'free-credit',
      networkModel: 'provider-managed',
    }),
  ];
  const snapshot = createCapabilitySnapshot(registry);
  const first = buildRoutePlan(job(), snapshot);
  const second = buildRoutePlan(job(), snapshot);
  assert.equal(JSON.stringify(first), JSON.stringify(second));
  assert.ok(Object.isFrozen(snapshot));
  assert.ok(Object.isFrozen(snapshot[0]));
  assert.ok(Object.isFrozen(first));
  assert.deepEqual(first.candidates.map(({ id }) => id), ['native', 'playwright', 'firecrawl']);
  assert.equal(first.candidates.find(({ id }) => id === 'playwright').eligible, false);
  assert.equal(first.candidates.find(({ id }) => id === 'firecrawl').costState, 'unknown_and_blocked');

  const forced = buildRoutePlan(job(['https://example.com', '--engine', 'browser-use']), snapshot);
  assert.equal(forced.candidates.length, 1);
  assert.equal(forced.candidates[0].id, 'browser-use');
  assert.equal(forced.candidates[0].automatic, false);
  assert.equal(forced.candidates[0].state, 'disabled');
  assert.equal(forced.candidates[0].eligible, false);

  const unknown = buildRoutePlan(job(['https://example.com', '--engine', 'unknown']), snapshot);
  assert.deepEqual(unknown.candidates, []);
});

test('health report preserves every known state, version and reason', () => {
  const snapshot = createCapabilitySnapshot([
    capability({ id: 'core', version: 'v24.0.0', state: 'ready' }),
    capability({ id: 'parser', version: null, state: 'missing' }),
    capability({ id: 'cloud', version: null, state: 'disabled' }),
    capability({ id: 'broken', version: null, state: 'misconfigured' }),
    capability({ id: 'browser', version: null, state: 'unavailable_security_gate' }),
  ]);
  assert.deepEqual(healthReport(snapshot).map(({ id, state, version, reason }) => ({
    id, state, version, reason,
  })), snapshot.map(({ id, state, version, reason }) => ({ id, state, version, reason })));
});

test('transition table blocks terminal outcomes and never selects next adapter', () => {
  for (const code of [
    'policy_denied', 'robots_denied', 'access_denied', 'auth_required', 'captcha',
    'paywall', 'paid_required', 'hard_limit',
  ]) {
    const decision = decideTransition(
      { kind: 'terminal', code },
      { hasNext: true, retriesUsed: 0, retriesLimit: 2, maxRetryAfterMs: 15_000 },
    );
    assert.equal(decision.action, 'stop');
    assert.equal(decision.status, 'blocked');
    assert.equal(decision.code, code);
  }
  for (const code of ['not_found', 'gone']) {
    const decision = decideTransition({ kind: 'terminal', code }, { hasNext: true });
    assert.equal(decision.action, 'stop');
    assert.equal(decision.status, 'exhausted');
  }
});

test('rate limit retries only the same adapter with capped delay, then blocks', () => {
  assert.deepEqual(
    decideTransition(
      { kind: 'retryable', code: 'rate_limited', retryAfterMs: 60_000 },
      { hasNext: true, retriesUsed: 0, retriesLimit: 1, maxRetryAfterMs: 15_000 },
    ),
    { action: 'retry_same', delayMs: 15_000, status: null, code: 'rate_limited' },
  );
  assert.deepEqual(
    decideTransition(
      { kind: 'retryable', code: 'rate_limited', retryAfterMs: 1 },
      { hasNext: true, retriesUsed: 1, retriesLimit: 1, maxRetryAfterMs: 15_000 },
    ),
    { action: 'stop', delayMs: 0, status: 'blocked', code: 'rate_limited' },
  );
});

test('unknown or kind-mismatched outcomes stop as internal errors', () => {
  for (const outcome of [
    { kind: 'skip', code: 'invented' },
    { kind: 'success', code: 'unavailable' },
    null,
  ]) {
    const decision = decideTransition(outcome, { hasNext: true });
    assert.equal(decision.action, 'stop');
    assert.equal(decision.status, 'internal_error');
    assert.equal(decision.code, 'unknown_attempt_code');
  }
});

test('model route skips only typed unavailable adapter and can reach success', async () => {
  const snapshot = createCapabilitySnapshot([
    capability({ id: 'first' }),
    capability({ id: 'second' }),
  ]);
  const first = scriptedAdapter([{ kind: 'skip', code: 'unavailable' }]);
  const second = scriptedAdapter([{ kind: 'success', code: 'ok' }]);
  const result = await runModelRoute(job(), snapshot, {
    adapters: new Map([['first', first], ['second', second]]),
  });
  assert.equal(result.status, 'ok');
  assert.equal(first.calls.length, 1);
  assert.equal(second.calls.length, 1);
});

test('model route never calls fallback after terminal outcome', async () => {
  for (const terminal of [
    { kind: 'terminal', code: 'access_denied' },
    { kind: 'terminal', code: 'not_found' },
    { kind: 'retryable', code: 'rate_limited', retryAfterMs: 0 },
  ]) {
    const snapshot = createCapabilitySnapshot([
      capability({ id: 'first' }),
      capability({ id: 'second' }),
    ]);
    const first = scriptedAdapter([terminal, terminal, terminal]);
    const second = scriptedAdapter([{ kind: 'success', code: 'ok' }]);
    const result = await runModelRoute(job(), snapshot, {
      adapters: new Map([['first', first], ['second', second]]),
      sleep: async () => {},
    });
    assert.notEqual(result.status, 'ok');
    assert.equal(second.calls.length, 0, terminal.code);
  }
});

async function runBlackBox(args) {
  const cwd = await mkdtemp(join(tmpdir(), 'lynceuz-empty-'));
  try {
    const executable = fileURLToPath(new URL('../src/lynceuz.mjs', import.meta.url));
    const tripwire = fileURLToPath(new URL('./fixtures/no-network.mjs', import.meta.url));
    return spawnSync(process.execPath, [
      '--import', tripwire,
      executable,
      ...args,
    ], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, LYNCEUZ_FORBID_NETWORK: '1' },
      timeout: 10_000,
    });
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
}

test('health and explain are zero-call black-box commands under tripwire', async () => {
  const health = await runBlackBox(['health', '--json']);
  assert.equal(health.status, 0, health.stderr);
  assert.equal(health.signal, null);
  assert.equal(health.stdout.match(/\n/g)?.length, 1);
  const healthResult = JSON.parse(health.stdout);
  assert.equal(healthResult.status, 'ok');
  const byId = Object.fromEntries(healthResult.capabilities.map((entry) => [entry.id, entry]));
  assert.equal(byId.core.state, 'ready');
  assert.equal(byId.playwright.state, 'unavailable_security_gate');
  assert.equal(byId.crawl4ai.state, 'unavailable_security_gate');
  assert.equal(byId['browser-use'].automatic, false);
  assert.equal(byId.firecrawl.state, 'disabled');
  assert.equal(byId.scrapegraphai.state, 'disabled');

  const explain = await runBlackBox(['https://example.com', '--explain', '--json']);
  assert.equal(explain.status, 0, explain.stderr);
  const explainResult = JSON.parse(explain.stdout);
  assert.equal(explainResult.status, 'ok');
  assert.equal(explainResult.code, 'route_explained');
  assert.equal(explainResult.route.some(({ id }) => id === 'browser-use'), false);

  const humanHealth = await runBlackBox(['health']);
  assert.equal(humanHealth.status, 0, humanHealth.stderr);
  assert.match(humanHealth.stdout, /playwright\tunavailable_security_gate/);
  assert.match(humanHealth.stdout, /browser-use\tdisabled/);

  const humanExplain = await runBlackBox(['https://example.com', '--explain']);
  assert.equal(humanExplain.status, 0, humanExplain.stderr);
  assert.match(humanExplain.stdout, /native\teligible\teligible/);
  assert.match(humanExplain.stdout, /playwright\tblocked\thostile_egress_proof_missing/);
  assert.match(humanExplain.stdout, /firecrawl\tblocked\tfree_cloud_not_allowed/);

  const unknownEngine = await runBlackBox([
    'https://example.com', '--engine', 'unknown', '--explain', '--json',
  ]);
  assert.equal(unknownEngine.status, 2, unknownEngine.stderr);
  assert.equal(JSON.parse(unknownEngine.stdout).status, 'invalid_input');

  const forcedDisabled = await runBlackBox([
    'https://example.com', '--engine', 'browser-use', '--explain', '--json',
  ]);
  assert.equal(forcedDisabled.status, 0, forcedDisabled.stderr);
  const forcedRoute = JSON.parse(forcedDisabled.stdout).route;
  assert.equal(forcedRoute.length, 1);
  assert.equal(forcedRoute[0].id, 'browser-use');
  assert.equal(forcedRoute[0].state, 'disabled');
  assert.equal(forcedRoute[0].eligible, false);

  const forcedRun = await runBlackBox([
    'https://example.com', '--engine', 'browser-use', '--json',
  ]);
  assert.equal(forcedRun.status, 4, forcedRun.stderr);
  assert.equal(JSON.parse(forcedRun.stdout).status, 'exhausted');
});

test('black-box commands report exhausted, blocked and invalid input honestly', async () => {
  for (const args of [
    ['https://example.com', '--json'],
    ['search', 'public records', '--json'],
  ]) {
    const child = await runBlackBox(args);
    assert.equal(child.status, 4, `${args[0]}: ${child.stderr}`);
    assert.equal(child.stdout.match(/\n/g)?.length, 1);
    assert.equal(JSON.parse(child.stdout).status, 'exhausted');
  }

  const crawl = await runBlackBox(['crawl', 'https://example.com', '--json']);
  assert.equal(crawl.status, 5, crawl.stderr);
  assert.equal(crawl.stdout.match(/\n/g)?.length, 1);
  const crawlResult = JSON.parse(crawl.stdout);
  assert.equal(crawlResult.status, 'blocked');
  assert.equal(crawlResult.code, 'robots_denied');

  const extract = await runBlackBox([
    'extract', 'https://example.com', '--schema', 'schema.json', '--json',
  ]);
  assert.equal(extract.status, 2, extract.stderr);
  assert.equal(extract.stdout.match(/\n/g)?.length, 1);
  const extractResult = JSON.parse(extract.stdout);
  assert.equal(extractResult.status, 'invalid_input');
  assert.equal(extractResult.code, 'invalid_input');
});
