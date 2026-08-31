import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { evaluateReleaseGate, expectedBrowserFingerprint, runReleaseGate } from '../scripts/p1-release-gate.mjs';
import {
  REQUIRED_BROWSER_PROOF_CHANNELS,
  REQUIRED_CONTAINMENT_PROOF_CHANNELS,
  createBrowserProofIntegrity,
} from '../src/browser-security.mjs';
import { compileJobSpec, parseArgv } from '../src/cli.mjs';
import { runUrlJob } from '../src/core.mjs';
import { createStorage } from '../src/storage.mjs';
import { P0_ORIGIN, createP0SiteFixture } from './fixtures/p0-site.mjs';

const PROJECT_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MARKER_RELATIVE = 'release/p1-release-proof-v1.json';
const NOW_MS = Date.parse('2026-08-30T12:00:00.000Z');
const SEALED_REASON = 'sandbox_loopback_scope_unproven';
const HASH = /^sha256:[0-9a-f]{64}$/u;
const P1_FILES = Object.freeze([
  ['evals/cloud.test.mjs', 'cloud-contract', true],
  ['evals/fixtures/interruption-worker.mjs', 'recovery-fixture', true],
  ['evals/p1-release.test.mjs', 'gate-contract', false],
  ['evals/recovery.test.mjs', 'recovery-contract', true],
  ['evals/search-budget.test.mjs', 'search-budget-contract', true],
  ['evals/search-cloud.test.mjs', 'search-contract', true],
]);
const TEST_FINGERPRINT = Object.freeze({
  digest: `sha256:${'a'.repeat(64)}`,
  runtime: Object.freeze({
    platform: 'fixture-platform',
    arch: 'fixture-arch',
    node: 'fixture-node',
    python: 'fixture-python',
    playwright: 'fixture-playwright',
    chromium: `sha256:${'b'.repeat(64)}`,
    containment: `sha256:${'c'.repeat(64)}`,
    profile: `sha256:${'d'.repeat(64)}`,
  }),
  sources: Object.freeze({ gate_contract: `sha256:${'e'.repeat(64)}` }),
});

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value);
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

async function fileHash(relativePath) {
  return sha256(await readFile(join(PROJECT_ROOT, relativePath)));
}

async function suiteManifest() {
  return {
    kind: 'lynceuz_p1_suite_manifest',
    schema_version: 1,
    baseline_manifest: {
      path: 'evals/fixtures/p0-suite-hashes.json',
      sha256: await fileHash('evals/fixtures/p0-suite-hashes.json'),
    },
    files: await Promise.all(P1_FILES.map(async ([path, role, runByReleaseGate]) => ({
      path,
      sha256: await fileHash(path),
      role,
      run_by_release_gate: runByReleaseGate,
    }))),
  };
}

function browserProof(generatedAt = new Date(NOW_MS).toISOString()) {
  const suites = [
    'evals/browser-hostile.test.mjs',
    'evals/router.test.mjs',
    'evals/p0-acceptance.test.mjs',
  ].map((suite) => ({
    suite,
    passed: true,
    skipped: false,
    exit_code: 0,
    signal: null,
    duration_ms: 1,
    stdout_hash: `sha256:${'1'.repeat(64)}`,
    stderr_hash: `sha256:${'2'.repeat(64)}`,
  }));
  const draft = {
    kind: 'browser_security_proof',
    schema_version: 1,
    status: 'passed',
    reason: 'proof_valid',
    fingerprint: TEST_FINGERPRINT.digest,
    generated_at: generatedAt,
    platform: TEST_FINGERPRINT.runtime.platform,
    arch: TEST_FINGERPRINT.runtime.arch,
    runtime: TEST_FINGERPRINT.runtime,
    source_hashes: TEST_FINGERPRINT.sources,
    channels: Object.fromEntries(REQUIRED_BROWSER_PROOF_CHANNELS.map((name) => [name, true])),
    suites,
  };
  return { ...draft, marker_hash: createBrowserProofIntegrity(draft) };
}

async function temporaryDataRoot(t, prefix) {
  const workspace = await mkdtemp(join(tmpdir(), prefix));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  return join(workspace, '.lynceuz');
}

async function writeProof(dataRoot, value) {
  const path = join(dataRoot, 'security/browser-proof-v1.json');
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  await writeFile(path, typeof value === 'string' ? value : JSON.stringify(value), { mode: 0o600 });
}

function child(status, output) {
  return Object.freeze({
    status,
    signal: null,
    stdout: `${JSON.stringify(output)}\n`,
    stderr: '',
  });
}

function injectedRunner({ dataRoot, proof = 'valid', failSuite = false, browserReason = null }) {
  const calls = [];
  const runner = async (executable, argv, options) => {
    assert.equal(executable, process.execPath);
    assert.equal(options.shell, false);
    assert.ok(Number.isSafeInteger(options.timeout) && options.timeout > 0);
    assert.ok(Number.isSafeInteger(options.maxBuffer) && options.maxBuffer <= 2 * 1024 * 1024);
    calls.push({ executable, argv: [...argv], options: { ...options } });

    const isBrowserGate = argv.some((value) => value.endsWith('scripts/p1-browser-gate.mjs'));
    if (isBrowserGate) {
      if (browserReason) {
        return child(1, { kind: 'browser_security_proof', status: 'failed', reason: browserReason });
      }
      if (proof === 'valid') await writeProof(dataRoot, browserProof());
      if (proof === 'stale') await writeProof(dataRoot, browserProof('2020-01-01T00:00:00.000Z'));
      if (proof === 'tampered') await writeProof(dataRoot, '{"tampered":');
      return child(0, browserProof());
    }

    assert.equal(argv[0], '--test');
    assert.equal(argv.some((value) => value.endsWith('evals/p1-release.test.mjs')), false, 'recursion');
    if (failSuite) return child(1, { status: 'failed', reason: 'suite_failed' });
    return child(0, { status: 'passed', reason: 'suite_passed' });
  };
  return { runner, calls };
}

async function evaluate(t, runnerOptions = {}) {
  const dataRoot = await temporaryDataRoot(t, 'lynceuz-p1-release-');
  const manifest = await suiteManifest();
  const injected = injectedRunner({ dataRoot, ...runnerOptions });
  const result = await evaluateReleaseGate({
    dataRoot,
    projectRoot: PROJECT_ROOT,
    suiteManifest: manifest,
    fingerprint: TEST_FINGERPRINT,
    now: () => NOW_MS,
    runner: injected.runner,
  });
  return { dataRoot, manifest, result, calls: injected.calls };
}

async function assertNoMarker(dataRoot) {
  await assert.rejects(
    readFile(join(dataRoot, MARKER_RELATIVE)),
    (error) => error?.code === 'ENOENT',
  );
}

test('valid proof and green non-recursive suites atomically seal the P1 release marker', async (t) => {
  const { dataRoot, manifest, result, calls } = await evaluate(t);
  const markerPath = join(dataRoot, MARKER_RELATIVE);
  const markerBytes = await readFile(markerPath);
  const marker = JSON.parse(markerBytes);

  assert.equal(result.accepted, true);
  assert.equal(result.exit_code, 0);
  assert.equal(result.status, 'passed');
  assert.equal(result.p1_release_state, 'released');
  assert.equal(result.kind, 'lynceuz_p1_release_proof');
  assert.equal(result.marker_path, MARKER_RELATIVE);
  assert.equal(marker.kind, 'lynceuz_p1_release_proof');
  assert.equal(marker.cost_money, 0);
  assert.deepEqual(marker.suite_hashes, {
    p0: manifest.baseline_manifest.sha256,
    p1: sha256(stableJson(manifest)),
  });
  assert.equal(marker.browser_proof_hash, sha256(await readFile(
    join(dataRoot, 'security/browser-proof-v1.json'),
  )));
  assert.match(marker.marker_hash, HASH);
  const { marker_hash: markerHash, ...markerPayload } = marker;
  assert.equal(markerHash, sha256(stableJson(markerPayload)));
  assert.equal((await stat(markerPath)).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(dirname(markerPath)), ['p1-release-proof-v1.json']);

  const invoked = calls.flatMap(({ argv }) => argv);
  assert.equal(invoked.some((value) => value.endsWith('evals/p1-release.test.mjs')), false);
  for (const entry of manifest.files.filter((item) => item.run_by_release_gate)) {
    assert.equal(invoked.some((value) => value.endsWith(entry.path)), true, entry.path);
  }
});

test('missing, stale and tampered proof are exact accepted browser blocks without marker', async (t) => {
  for (const [proof, reason] of [
    ['missing', 'proof_missing'],
    ['stale', 'proof_stale'],
    ['tampered', 'proof_corrupt'],
  ]) {
    await t.test(proof, async (subtest) => {
      const { dataRoot, result } = await evaluate(subtest, { proof });
      assert.equal(result.accepted, true);
      assert.notEqual(result.exit_code, 0);
      assert.equal(result.status, 'blocked');
      assert.equal(result.p1_release_state, 'blocked_browser');
      assert.equal(result.reason, reason);
      await assertNoMarker(dataRoot);
    });
  }
});

test('sealed browser reason remains exact and does not create a marker', async (t) => {
  const { dataRoot, result } = await evaluate(t, { browserReason: SEALED_REASON });
  assert.equal(result.accepted, true);
  assert.notEqual(result.exit_code, 0);
  assert.equal(result.p1_release_state, 'blocked_browser');
  assert.equal(result.reason, SEALED_REASON);
  await assertNoMarker(dataRoot);
});

test('suite failure, gate error and arbitrary browser reason are rejected, not browser blocks', async (t) => {
  await t.test('suite_failed', async (subtest) => {
    const { dataRoot, result, calls } = await evaluate(subtest, { failSuite: true });
    assert.equal(result.accepted, false);
    assert.notEqual(result.exit_code, 0);
    assert.equal(result.p1_release_state, 'rejected');
    assert.equal(result.reason, 'suite_failed');
    assert.equal(calls.some(({ argv }) => argv.some((value) => (
      value.endsWith('scripts/p1-browser-gate.mjs')
    ))), false);
    await assertNoMarker(dataRoot);
  });

  await t.test('gate_internal_error', async (subtest) => {
    const dataRoot = await temporaryDataRoot(subtest, 'lynceuz-p1-error-');
    const result = await evaluateReleaseGate({
      dataRoot,
      projectRoot: PROJECT_ROOT,
      suiteManifest: await suiteManifest(),
      fingerprint: TEST_FINGERPRINT,
      now: () => NOW_MS,
      runner: async () => { throw new Error('fixture runner failure'); },
    });
    assert.equal(result.accepted, false);
    assert.notEqual(result.exit_code, 0);
    assert.equal(result.p1_release_state, 'rejected');
    assert.equal(result.reason, 'gate_internal_error');
    await assertNoMarker(dataRoot);
  });

  await t.test('arbitrary_reason', async (subtest) => {
    const { dataRoot, result } = await evaluate(subtest, { browserReason: 'invented_bypass' });
    assert.equal(result.accepted, false);
    assert.notEqual(result.exit_code, 0);
    assert.equal(result.p1_release_state, 'rejected');
    assert.equal(result.reason, 'invented_bypass');
    await assertNoMarker(dataRoot);
  });
});

test('native P0 evidence remains successful when P1 is browser-blocked', async (t) => {
  const dataRoot = await temporaryDataRoot(t, 'lynceuz-p0-independent-');
  const fixture = createP0SiteFixture();
  const storage = createStorage({ dataRoot, clock: fixture.clock });
  const job = compileJobSpec(parseArgv([
    'url', `${P0_ORIGIN}/`, '--cache', 'off', '--data-root', dataRoot,
  ]));
  const p0 = await runUrlJob(job, {
    gateway: fixture.gateway,
    storage,
    clock: fixture.clock,
    sleep: fixture.sleep,
  });
  const p0Bytes = await readFile(join(dataRoot, p0.manifest_path));

  const injected = injectedRunner({ dataRoot, browserReason: SEALED_REASON });
  const p1 = await evaluateReleaseGate({
    dataRoot,
    projectRoot: PROJECT_ROOT,
    suiteManifest: await suiteManifest(),
    fingerprint: TEST_FINGERPRINT,
    now: () => NOW_MS,
    runner: injected.runner,
  });

  assert.equal(p0.status, 'ok');
  assert.match(p0.source_hash, HASH);
  assert.equal(JSON.parse(p0Bytes).cost_money, 0);
  assert.equal(p1.p1_release_state, 'blocked_browser');
  assert.equal(p1.reason, SEALED_REASON);
  assert.deepEqual(await readFile(join(dataRoot, p0.manifest_path)), p0Bytes);
  await assertNoMarker(dataRoot);
});

const READY_SUITES = Object.freeze([
  'evals/browser-hostile.test.mjs',
  'evals/router.test.mjs',
  'evals/p0-acceptance.test.mjs',
  'evals/browser-containment.test.mjs',
]);

// A valid macOS containment receipt shape — the independent, root-generated facts the release gate
// fingerprints (never the proof itself). Fields mirror what containmentEvidence maps.
function readyContainmentReceipt() {
  return {
    backend: 'pf_uid_anchor_guardproxy',
    uid: { name: '_lynceuz', uid: 401, gid: 401 },
    guard_proxy: { host: '127.0.0.1', port: 48191 },
    pf: {
      anchor_name: 'com.lynceuz/browser',
      anchor_path: '/etc/pf.anchors/com.lynceuz.browser',
      anchor_sha256: `sha256:${'a'.repeat(64)}`,
      rules_sha256: `sha256:${'b'.repeat(64)}`,
    },
    boot_session: 'boot-fixture-0001',
    reboot_verified: true,
    reboot_verified_at: '2026-08-30T11:00:00.000Z',
    source_hashes: { macos_containment: `sha256:${'c'.repeat(64)}`, canary: `sha256:${'d'.repeat(64)}` },
    suite_hashes: { wave2: `sha256:${'e'.repeat(64)}` },
  };
}

// The schema_version-2 (containment-bound) proof a ready browser gate seals, carrying exactly the
// supplied fingerprint. verifyBrowserSecurityProof accepts it only against a matching fingerprint.
function readyBrowserProof(fingerprint, generatedAt = new Date(NOW_MS).toISOString()) {
  const suites = READY_SUITES.map((suite) => ({
    suite,
    passed: true,
    skipped: false,
    exit_code: 0,
    signal: null,
    duration_ms: 1,
    stdout_hash: `sha256:${'1'.repeat(64)}`,
    stderr_hash: `sha256:${'2'.repeat(64)}`,
  }));
  const draft = {
    kind: 'browser_security_proof',
    schema_version: 1,
    status: 'passed',
    reason: 'proof_valid',
    fingerprint: fingerprint.digest,
    generated_at: generatedAt,
    platform: fingerprint.runtime.platform,
    arch: fingerprint.runtime.arch,
    runtime: fingerprint.runtime,
    source_hashes: fingerprint.sources,
    channels: Object.fromEntries(REQUIRED_CONTAINMENT_PROOF_CHANNELS.map((name) => [name, true])),
    containment_state: 'ready',
    containment: fingerprint.containment,
    suites,
  };
  return { ...draft, marker_hash: createBrowserProofIntegrity(draft) };
}

function readyRunner({ dataRoot, proof }) {
  return async (executable, argv) => {
    if (argv.some((value) => value.endsWith('scripts/p1-browser-gate.mjs'))) {
      await writeProof(dataRoot, proof);
      return child(0, proof);
    }
    return child(0, { status: 'passed', reason: 'suite_passed' });
  };
}

test('release gate expects the same fingerprint the ready proof carries', async (t) => {
  const detectedRuntime = Object.freeze({
    platform: 'darwin',
    arch: 'arm64',
    node: 'v-fixture',
    python: '/opt/homebrew/bin/python3@3.13.1',
    playwright: '1.55.0',
    chromium: `sha256:${'b'.repeat(64)}`,
    containment: `sha256:${'c'.repeat(64)}`,
  });
  const receipt = readyContainmentReceipt();
  const receiptHash = sha256(JSON.stringify(receipt));
  const detect = async () => ({ runtime: detectedRuntime });
  const loadReceipt = async () => ({ receipt, receiptHash });

  // MATCH: runReleaseGate rebuilds the expected fingerprint from the SAME machine + receipt the proof
  // was sealed against, so its own internal expectation equals the proof's digest → sealed release.
  // The proof is derived from expectedBrowserFingerprint only to learn what digest a ready gate emits;
  // the gate under test recomputes it — the WIRING, not a hand-fed fingerprint, is what's exercised.
  const matchRoot = await temporaryDataRoot(t, 'lynceuz-fp-match-');
  const fingerprint = await expectedBrowserFingerprint({ dataRoot: matchRoot, detect, loadReceipt });
  const proof = readyBrowserProof(fingerprint);
  const released = await runReleaseGate({
    dataRoot: matchRoot,
    projectRoot: PROJECT_ROOT,
    suiteManifest: await suiteManifest(),
    now: () => NOW_MS,
    runner: readyRunner({ dataRoot: matchRoot, proof }),
    detect,
    loadReceipt,
  });
  assert.equal(released.p1_release_state, 'released', released.reason);
  assert.equal(released.reason, 'released');
  assert.match(released.marker_hash, HASH);

  // DRIFT: the proof on disk still carries the original digest, but the gate is driven with a tampered
  // receipt, so runReleaseGate's own internal fingerprint diverges → fingerprint_mismatch, no marker.
  // The proof cannot certify itself.
  const driftRoot = await temporaryDataRoot(t, 'lynceuz-fp-drift-');
  const tampered = { ...receipt, boot_session: `${receipt.boot_session}-tampered` };
  const tamperedLoad = async () => ({ receipt: tampered, receiptHash: sha256(JSON.stringify(tampered)) });
  const driftFingerprint = await expectedBrowserFingerprint({
    dataRoot: driftRoot, detect, loadReceipt: tamperedLoad,
  });
  assert.notEqual(driftFingerprint.digest, fingerprint.digest);
  const blocked = await runReleaseGate({
    dataRoot: driftRoot,
    projectRoot: PROJECT_ROOT,
    suiteManifest: await suiteManifest(),
    now: () => NOW_MS,
    runner: readyRunner({ dataRoot: driftRoot, proof }),
    detect,
    loadReceipt: tamperedLoad,
  });
  assert.equal(blocked.p1_release_state, 'blocked_browser');
  assert.equal(blocked.reason, 'fingerprint_mismatch');
  await assertNoMarker(driftRoot);
});
