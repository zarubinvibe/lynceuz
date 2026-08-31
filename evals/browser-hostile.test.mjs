import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { compileJobSpec, parseArgv } from '../src/cli.mjs';
import {
  browserCapabilityState,
  computeBrowserFingerprint,
  createBrowserProofIntegrity,
  createChildEgressSandbox,
  createGuardProxy,
  verifyBrowserSecurityProof,
} from '../src/browser-security.mjs';
import { createPlaywrightAdapter } from '../src/adapters/playwright.mjs';
import { runUrlJob } from '../src/core.mjs';
import { createNodeConnectPinned } from '../src/network.mjs';
import {
  buildRoutePlan,
  createCapabilitySnapshot,
  renderedFallbackSkip,
  runModelRoute,
} from '../src/router.mjs';
import { createStorage } from '../src/storage.mjs';
import {
  REQUIRED_BROWSER_CHANNELS,
  connectViaGuardProxy,
  createBrowserHostileHarness,
  requestViaGuardProxy,
} from './fixtures/browser-hostile.mjs';
import { baseUrlJob, createNativeFixture } from './fixtures/native-http.mjs';

const helperPath = fileURLToPath(new URL('../src/lynceuz-browser.py', import.meta.url));
const directProbePath = fileURLToPath(new URL('./fixtures/direct-egress-probe.py', import.meta.url));
const gatePath = fileURLToPath(new URL('../scripts/p1-browser-gate.mjs', import.meta.url));
const executablePath = fileURLToPath(new URL('../src/lynceuz.mjs', import.meta.url));
const noNetworkPath = fileURLToPath(new URL('./fixtures/no-network.mjs', import.meta.url));

function descriptor(id, state, reason, networkModel = 'guard-proxy') {
  return {
    id,
    version: 'test',
    state,
    reason,
    automatic: true,
    commands: ['url'],
    cost: 'local-zero',
    price: 0,
    networkModel,
  };
}

function routeJob(argv = ['https://public.example.com/', '--allow-rendered']) {
  return compileJobSpec(parseArgv(argv));
}

test('browser hostile contract is bounded and fail-closed', { timeout: 55_000 }, async (suite) => {
  await suite.test('corpus names every TEST-02 channel', () => {
    assert.deepEqual(REQUIRED_BROWSER_CHANNELS, [
      'navigation', 'redirect', 'iframe', 'popup', 'worker', 'service_worker',
      'websocket', 'webrtc_udp', 'webtransport', 'quic',
    ]);
  });

  await suite.test('installed package, missing proof and forced engine make zero browser calls', async () => {
    const missing = browserCapabilityState({
      id: 'playwright', installed: false, version: null, allowRendered: true,
      proof: { valid: false, reason: 'proof_missing' },
    });
    assert.equal(missing.state, 'missing');
    const gated = browserCapabilityState({
      id: 'playwright', installed: true, version: '1.60.0', allowRendered: true,
      proof: { valid: false, reason: 'proof_missing' },
    });
    assert.equal(gated.state, 'unavailable_security_gate');

    const job = routeJob(['https://public.example.com/', '--allow-rendered', '--engine', 'playwright']);
    const snapshot = createCapabilitySnapshot([
      descriptor('playwright', gated.state, gated.reason),
    ]);
    assert.equal(buildRoutePlan(job, snapshot).candidates[0].eligible, false);
    let processCalls = 0;
    const adapter = createPlaywrightAdapter({
      capability: gated,
      supervisor: { run: async () => { processCalls += 1; } },
    });
    const outcome = await adapter.run({ job });
    assert.deepEqual(outcome, {
      kind: 'skip', code: 'policy_unenforceable',
      details: { reason: 'proof_missing' },
    });
    assert.equal(processCalls, 0);

    const cwd = await mkdtemp(join(tmpdir(), 'lynceuz-forced-browser-'));
    try {
      const child = spawnSync(process.execPath, [
        '--import', noNetworkPath,
        executablePath,
        'https://public.example.com/', '--allow-rendered', '--engine', 'playwright', '--json',
      ], {
        cwd,
        encoding: 'utf8',
        timeout: 5_000,
        env: { ...process.env, LYNCEUZ_FORBID_NETWORK: '1' },
      });
      assert.equal(child.status, 4, child.stderr);
      const result = JSON.parse(child.stdout);
      assert.equal(result.status, 'exhausted');
      assert.equal(result.route[0].id, 'playwright');
      assert.equal(result.route[0].eligible, false);
      assert.match(result.route[0].reason, /sandbox_(?:loopback_scope_unproven|platform_unsupported)/u);
    } finally {
      await rm(cwd, { recursive: true, force: true });
    }
  });

  await suite.test('allow-rendered is immutable per-run authority and cannot make invalid proof ready', () => {
    const enabled = routeJob();
    const defaultJob = routeJob(['https://public.example.com/']);
    assert.equal(enabled.policy.allowRendered, true);
    assert.equal(defaultJob.policy.allowRendered, false);
    assert.equal(enabled.policy.moneyBudget, 0);
    assert.equal(enabled.policy.auth, 'none');
    assert.ok(Object.isFrozen(enabled));
    const state = browserCapabilityState({
      id: 'playwright', installed: true, version: '1.60.0', allowRendered: true,
      proof: { valid: false, reason: 'fingerprint_mismatch' },
    });
    assert.equal(state.state, 'unavailable_security_gate');
    const validProof = { valid: true, reason: 'proof_valid', fingerprint: 'sha256:proof' };
    assert.equal(browserCapabilityState({
      id: 'playwright', installed: true, version: '1.60.0', allowRendered: false,
      proof: validProof,
    }).state, 'disabled');
    assert.equal(browserCapabilityState({
      id: 'playwright', installed: true, version: '1.60.0', allowRendered: true,
      proof: validProof,
    }).state, 'ready');
  });

  await suite.test('only typed inadequate content can produce a rendered gate skip', () => {
    const job = routeJob();
    const route = [{
      id: 'playwright', eligible: false, reason: 'sandbox_loopback_scope_unproven',
      proofFingerprint: null,
    }];
    assert.deepEqual(renderedFallbackSkip(job, route, {
      kind: 'inadequate', code: 'js_shell',
    }), {
      kind: 'skip', code: 'policy_unenforceable',
      details: { reason: 'sandbox_loopback_scope_unproven' },
    });
    for (const outcome of [
      { kind: 'terminal', code: 'access_denied' },
      { kind: 'terminal', code: 'captcha' },
      { kind: 'retryable', code: 'rate_limited' },
      { kind: 'inadequate', code: 'wrong_mime' },
    ]) {
      assert.equal(renderedFallbackSkip(job, route, outcome), null, outcome.code);
    }
  });

  await suite.test('native JS shell records a typed browser skip in the normal manifest', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'lynceuz-render-skip-'));
    const dataRoot = join(parent, '.lynceuz');
    const fixture = createNativeFixture({ responses: [{
      statusCode: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      body: Buffer.from('<!doctype html><html><body><script>document.body.textContent="ready"</script></body></html>'),
    }] });
    try {
      const job = baseUrlJob({
        policy: { ...baseUrlJob().policy, allowRendered: true },
        cache: { mode: 'off', ttlMs: 60_000 },
      });
      const route = [{
        id: 'playwright', eligible: false, reason: 'sandbox_loopback_scope_unproven',
        proofFingerprint: null,
      }];
      const result = await runUrlJob(job, {
        gateway: fixture.gateway,
        storage: createStorage({ dataRoot, clock: fixture.clock }),
        clock: fixture.clock,
        sleep: fixture.sleep,
        route,
        capabilities: [],
      });
      assert.equal(result.status, 'exhausted');
      const manifest = JSON.parse(await readFile(join(dataRoot, result.manifest_path), 'utf8'));
      assert.deepEqual(manifest.attempts.at(-1), {
        attempt: manifest.attempts.length,
        type: 'transform',
        adapter: 'playwright',
        version: '1',
        outcome: 'skip',
        code: 'policy_unenforceable',
        details: { reason: 'sandbox_loopback_scope_unproven' },
      });
      assert.equal(manifest.requested_url, job.target.url);
      assert.equal(manifest.cost_money, 0);
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  await suite.test('terminal outcomes never transition to rendered adapter', async () => {
    const terminalCases = [
      ['policy_denied', 'terminal'], ['robots_denied', 'terminal'],
      ['access_denied', 'terminal'], ['auth_required', 'terminal'],
      ['captcha', 'terminal'], ['paywall', 'terminal'], ['paid_required', 'terminal'],
      ['not_found', 'terminal'], ['gone', 'terminal'], ['hard_limit', 'terminal'],
      ['rate_limited', 'retryable'],
    ];
    for (const [code, kind] of terminalCases) {
      let browserCalls = 0;
      const job = routeJob();
      const snapshot = createCapabilitySnapshot([
        descriptor('native', 'ready', 'ready', 'core-http'),
        descriptor('playwright', 'ready', 'proof_valid'),
      ]);
      const result = await runModelRoute(job, snapshot, {
        adapters: {
          native: { run: async () => ({ kind, code, retryAfterMs: 0 }) },
          playwright: { run: async () => { browserCalls += 1; return { kind: 'success', code: 'ok' }; } },
        },
      });
      assert.notEqual(result.status, 'ok', code);
      assert.equal(browserCalls, 0, code);
    }
  });

  await suite.test('GuardProxy authenticates and is the sole public fixture path', async () => {
    const harness = await createBrowserHostileHarness();
    const proxy = await createGuardProxy({ gateway: harness.gateway });
    try {
      assert.equal(proxy.host, '127.0.0.1');
      const denied = await requestViaGuardProxy(proxy, harness.publicUrl, 'wrong-token');
      assert.match(denied, /^HTTP\/1\.1 407 /u);
      const allowed = await requestViaGuardProxy(proxy, harness.publicUrl, proxy.token);
      assert.match(allowed, /^HTTP\/1\.1 200 /u);
      assert.match(allowed, /rendered through GuardProxy/u);
      const methodDenied = await requestViaGuardProxy(proxy, harness.publicUrl, proxy.token, 'POST');
      assert.match(methodDenied, /^HTTP\/1\.1 405 /u);
      const tunnel = await connectViaGuardProxy(proxy, proxy.token);
      assert.match(tunnel, /^HTTP\/1\.1 200 Connection Established/u);
      assert.match(tunnel, /rendered through GuardProxy/u);
      assert.equal(harness.counters.privateTcp, 0);
      assert.equal(harness.counters.privateUdp, 0);
      assert.equal(proxy.stats.authorizedRequests, 2);
    } finally {
      await proxy.close();
      await harness.close();
    }
  });

  await suite.test('production pinned connector rejects an expired permit before dialing', async () => {
    let dialCalls = 0;
    const connectPinned = createNodeConnectPinned({
      now: () => 101,
      connect: () => { dialCalls += 1; throw new Error('must not dial'); },
    });
    await assert.rejects(connectPinned({
      permit: {
        protocol: 'https:', port: 443, selectedAddress: '93.184.216.34', expiresAtMs: 100,
      },
    }), /expired/u);
    assert.equal(dialCalls, 0);
  });

  await suite.test('current child containment fails closed before any browser launch', async () => {
    const harness = await createBrowserHostileHarness();
    const proxy = await createGuardProxy({ gateway: harness.gateway });
    try {
      const sandbox = await createChildEgressSandbox({
        proxyPort: proxy.port,
        probeScript: directProbePath,
      });
      assert.equal(sandbox.state, 'unavailable_security_gate');
      assert.equal(sandbox.proofEligible, false);
      assert.match(sandbox.reason, /(?:unsupported|unenforceable|unproven|port_filter)/u);
      assert.equal(harness.counters.privateTcp, 0);
      assert.equal(harness.counters.privateUdp, 0);
    } finally {
      await proxy.close();
      await harness.close();
    }
  });

  await suite.test('proof is exact, complete, local-only and drift-sensitive', async () => {
    const parent = await mkdtemp(join(tmpdir(), 'lynceuz-proof-'));
    const dataRoot = join(parent, '.lynceuz');
    await mkdir(join(dataRoot, 'security'), { recursive: true, mode: 0o700 });
    const component = join(parent, 'component.mjs');
    await writeFile(component, 'export const value = 1;\n');
    try {
      const fingerprint = await computeBrowserFingerprint({
        sourcePaths: { component },
        runtime: {
          platform: 'test-platform', arch: 'test-arch', node: 'test-node',
          python: 'test-python', playwright: 'test-playwright', chromium: 'test-chromium',
          containment: 'test-containment', profile: 'test-profile',
        },
      });
      const channels = Object.fromEntries(REQUIRED_BROWSER_CHANNELS.map((name) => [name, true]));
      const minimalForgery = {
        kind: 'browser_security_proof', schema_version: 1, status: 'passed',
        fingerprint: fingerprint.digest, channels, generated_at: new Date().toISOString(),
      };
      await writeFile(join(dataRoot, 'security/browser-proof-v1.json'), JSON.stringify(minimalForgery));
      assert.equal((await verifyBrowserSecurityProof({ dataRoot, fingerprint })).valid, false);
      const suites = [
        'evals/browser-hostile.test.mjs',
        'evals/router.test.mjs',
        'evals/p0-acceptance.test.mjs',
      ].map((suite) => ({
        suite, passed: true, skipped: false, exit_code: 0, signal: null,
        duration_ms: 1, stdout_hash: `sha256:${'1'.repeat(64)}`,
        stderr_hash: `sha256:${'2'.repeat(64)}`,
      }));
      const passedDraft = {
        kind: 'browser_security_proof', schema_version: 1, status: 'passed',
        reason: 'proof_valid', fingerprint: fingerprint.digest,
        generated_at: new Date().toISOString(),
        platform: fingerprint.runtime.platform, arch: fingerprint.runtime.arch,
        runtime: fingerprint.runtime, source_hashes: fingerprint.sources, channels, suites,
      };
      const passed = {
        ...passedDraft,
        marker_hash: createBrowserProofIntegrity(passedDraft),
      };
      await writeFile(join(dataRoot, 'security/browser-proof-v1.json'), JSON.stringify(passed));
      assert.equal((await verifyBrowserSecurityProof({ dataRoot, fingerprint })).valid, true);
      await writeFile(component, 'export const value = 2;\n');
      const drifted = await computeBrowserFingerprint({
        sourcePaths: { component }, fingerprintRuntime: fingerprint.runtime,
      });
      const verification = await verifyBrowserSecurityProof({ dataRoot, fingerprint: drifted });
      assert.equal(verification.valid, false);
      assert.equal(verification.reason, 'fingerprint_mismatch');
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });

  await suite.test('browser helper rejects interactive operations without launching Playwright', () => {
    const result = spawnSync('python3', ['-I', helperPath], {
      input: `${JSON.stringify({ version: 1, id: 'forbidden', operation: 'click' })}\n`,
      encoding: 'utf8', timeout: 3_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const response = JSON.parse(result.stdout);
    assert.equal(response.ok, false);
    assert.equal(response.code, 'unsupported_operation');
    assert.equal(result.stdout.trim().split(/\r?\n/u).length, 1);
  });
});

if (process.env.LYNCEUZ_GATE_SUITE !== '1') {
  test('release gate atomically records an honest containment failure', { timeout: 55_000 }, async () => {
    const parent = await mkdtemp(join(tmpdir(), 'lynceuz-gate-'));
    const dataRoot = join(parent, '.lynceuz');
    try {
      const result = spawnSync(process.execPath, [gatePath, '--json', '--data-root', dataRoot], {
        cwd: fileURLToPath(new URL('..', import.meta.url)),
        encoding: 'utf8',
        timeout: 45_000,
        env: { ...process.env, LYNCEUZ_GATE_TEST: '1' },
      });
      assert.equal(result.status, 1, result.stderr);
      assert.equal(result.signal, null);
      assert.equal(result.stdout.trim().split(/\r?\n/u).length, 1);
      const output = JSON.parse(result.stdout);
      assert.equal(output.kind, 'browser_security_proof');
      assert.equal(output.status, 'failed');
      assert.equal(output.reason, 'sandbox_loopback_scope_unproven');
      const marker = JSON.parse(await readFile(
        join(dataRoot, 'security/browser-proof-v1.json'), 'utf8',
      ));
      assert.equal(marker.status, 'failed');
      assert.equal(marker.fingerprint, output.fingerprint);
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  });
}
