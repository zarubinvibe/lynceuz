import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import { EventEmitter } from 'node:events';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { EXIT_CODE, RUN_STATUS } from '../src/contracts.mjs';
import * as core from '../src/core.mjs';
import { createRequestFingerprint, createStorage } from '../src/storage.mjs';

// Requirement: DATA-05 — interruption + crash recovery contract.

const FIXED_TIME = '2026-08-26T12:15:40.123Z';
const REQUESTED_URL = 'https://example.com/interrupted';
const clock = () => new Date(FIXED_TIME);
const WORKER = fileURLToPath(new URL('./fixtures/interruption-worker.mjs', import.meta.url));

function fingerprint() {
  return createRequestFingerprint({
    canonicalUrl: REQUESTED_URL,
    method: 'GET',
    headers: { accept: 'text/html', 'accept-encoding': 'gzip' },
    adapter: { id: 'native', version: '1' },
    policyVersion: '1',
    format: 'markdown',
    goal: 'markdown',
    decode: { encodings: ['gzip'], maxBytes: 1_048_576 },
  });
}

async function withSandbox(fn) {
  const sandbox = await mkdtemp(join(tmpdir(), 'lynceuz-recovery-'));
  const dataRoot = join(sandbox, '.lynceuz');
  try {
    await fn({ sandbox, dataRoot });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
}

async function walk(root) {
  const found = [];
  async function visit(path) {
    const info = await lstat(path);
    found.push({ path, info });
    if (info.isDirectory()) {
      for (const name of await readdir(path)) await visit(join(path, name));
    }
  }
  await visit(root);
  return found;
}

// Reach the deterministic milestone in a real child, then hand the caller the
// live handle. Resolves on the IPC milestone OR an early exit so a missing guard
// (the RED target) surfaces as a wrong exit code, never a hang.
async function startWorker(config) {
  const child = fork(WORKER, [JSON.stringify(config)], {
    stdio: ['ignore', 'ignore', 'inherit', 'ipc'],
  });
  const exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }));
  });
  const readied = new Promise((resolve) => child.once('message', resolve));
  const first = await Promise.race([
    readied.then((message) => ({ type: 'ready', message })),
    exited.then((exit) => ({ type: 'exit', exit })),
  ]);
  return { child, exited, ready: first.type === 'ready' ? first.message : null };
}

// Build an incomplete run on disk (no manifest) using only shipped storage APIs.
async function seedIncompleteRun(storage, label) {
  const run = await storage.beginRun({
    schema_version: 1,
    command: 'url',
    requested_url: REQUESTED_URL,
    method: 'GET',
    format: 'markdown',
    cache: 'use',
  });
  const source = await storage.putObject(run, Buffer.from(`evidence ${label}`), {
    role: 'raw', media_type: 'text/plain', derived_from: null,
  });
  await storage.appendAttempt(run, {
    type: 'attempt_finished', at: FIXED_TIME, outcome: 'ok', source_hash: source.hash,
  });
  return { run, source };
}

// ---------------------------------------------------------------------------
// Edge 1 — graceful interruption: signal/timeout -> one interrupted commit.
// ---------------------------------------------------------------------------

test('SIGINT interrupts a live run: exit 130, interrupted manifest, signal recorded, no cache hit', async () => {
  await withSandbox(async ({ dataRoot }) => {
    const worker = await startWorker({ mode: 'signal', dataRoot });
    if (worker.ready) worker.child.kill('SIGINT');
    const { code } = await worker.exited;

    assert.equal(code, EXIT_CODE.SIGINT, 'SIGINT must finalize as interrupted and exit 130');
    assert.ok(worker.ready?.runId, 'worker must confirm its milestone before the signal');

    const manifest = JSON.parse(
      await readFile(join(dataRoot, 'runs', worker.ready.runId, 'manifest.json'), 'utf8'),
    );
    assert.equal(manifest.status, RUN_STATUS.INTERRUPTED);
    assert.deepEqual(manifest.termination, { signal: 'SIGINT' });
    assert.equal(manifest.source_hash, worker.ready.sourceHash);

    const reopened = createStorage({ dataRoot, clock });
    const cached = await reopened.readCache(fingerprint());
    assert.equal(cached.hit, false, 'an interrupted run must never publish a cache hit');
  });
});

test('SIGTERM interrupts a live run: exit 143 with SIGTERM termination', async () => {
  await withSandbox(async ({ dataRoot }) => {
    const worker = await startWorker({ mode: 'signal', dataRoot });
    if (worker.ready) worker.child.kill('SIGTERM');
    const { code } = await worker.exited;

    assert.equal(code, EXIT_CODE.SIGTERM, 'SIGTERM must finalize as interrupted and exit 143');
    const manifest = JSON.parse(
      await readFile(join(dataRoot, 'runs', worker.ready.runId, 'manifest.json'), 'utf8'),
    );
    assert.equal(manifest.status, RUN_STATUS.INTERRUPTED);
    assert.deepEqual(manifest.termination, { signal: 'SIGTERM' });
  });
});

test('wall-clock timeout interrupts a live run: exit 124 with reason=timeout', async () => {
  await withSandbox(async ({ dataRoot }) => {
    const worker = await startWorker({ mode: 'timeout', dataRoot, wallMs: 40 });
    const { code } = await worker.exited;

    assert.equal(code, EXIT_CODE.TIMEOUT, 'a wall-clock timeout must exit 124');
    const manifest = JSON.parse(
      await readFile(join(dataRoot, 'runs', worker.ready.runId, 'manifest.json'), 'utf8'),
    );
    assert.equal(manifest.status, RUN_STATUS.INTERRUPTED);
    assert.deepEqual(manifest.termination, { reason: 'timeout' });
  });
});

test('a double SIGINT commits exactly one interrupted manifest and detaches its listeners', async () => {
  assert.equal(
    typeof core.createInterruptionGuard,
    'function',
    'core must expose createInterruptionGuard',
  );
  await withSandbox(async ({ dataRoot }) => {
    const storage = createStorage({ dataRoot, clock });
    const { run, source } = await seedIncompleteRun(storage, 'double');
    const emitter = new EventEmitter();
    const exits = [];
    const guard = core.createInterruptionGuard({
      storage,
      run,
      emitter,
      exit: (code) => exits.push(code),
      buildInterruptedManifest: (termination) => ({
        schema_version: 1,
        run_id: run.id,
        status: 'interrupted',
        requested_url: REQUESTED_URL,
        effective_url: REQUESTED_URL,
        requested_format: 'markdown',
        format: 'markdown',
        alternatives: [],
        fetched_at: null,
        served_at: FIXED_TIME,
        revalidated_at: null,
        engine: { id: 'native', version: '1' },
        policy: { version: '1', network: 'public-only', auth: 'none', money_budget: 0 },
        attempts: [],
        source_hash: source.hash,
        artifact_hash: null,
        artifact_path: null,
        artifacts: [source],
        evidence: [{ url: REQUESTED_URL, hash: source.hash, status: 'source_captured' }],
        warnings: [],
        cost_money: 0,
        credits_used: 0,
        termination,
      }),
    });
    guard.install();
    emitter.emit('SIGINT');
    emitter.emit('SIGINT');
    await guard.done;

    assert.equal(guard.commitCount, 1, 'redundant signals must not double-commit');
    assert.deepEqual(exits, [EXIT_CODE.SIGINT], 'the process must exit exactly once');
    assert.equal(emitter.listenerCount('SIGINT'), 0, 'SIGINT listener must be detached');
    assert.equal(emitter.listenerCount('SIGTERM'), 0, 'SIGTERM listener must be detached');

    const manifest = JSON.parse(
      await readFile(join(dataRoot, 'runs', run.id, 'manifest.json'), 'utf8'),
    );
    assert.equal(manifest.status, RUN_STATUS.INTERRUPTED);
    assert.deepEqual(manifest.termination, { signal: 'SIGINT' });
  });
});

test('a signal arriving during timeout finalization still yields one interrupted commit', async () => {
  assert.equal(
    typeof core.createInterruptionGuard,
    'function',
    'core must expose createInterruptionGuard',
  );
  await withSandbox(async ({ dataRoot }) => {
    const storage = createStorage({ dataRoot, clock });
    const { run, source } = await seedIncompleteRun(storage, 'race');
    const emitter = new EventEmitter();
    const exits = [];
    let fireTimeout;
    const guard = core.createInterruptionGuard({
      storage,
      run,
      emitter,
      wallMs: 25,
      exit: (code) => exits.push(code),
      scheduler: {
        setTimeout: (fn) => { fireTimeout = fn; return { fake: true }; },
        clearTimeout: () => { fireTimeout = null; },
      },
      buildInterruptedManifest: (termination) => ({
        schema_version: 1,
        run_id: run.id,
        status: 'interrupted',
        requested_url: REQUESTED_URL,
        effective_url: REQUESTED_URL,
        requested_format: 'markdown',
        format: 'markdown',
        alternatives: [],
        fetched_at: null,
        served_at: FIXED_TIME,
        revalidated_at: null,
        engine: { id: 'native', version: '1' },
        policy: { version: '1', network: 'public-only', auth: 'none', money_budget: 0 },
        attempts: [],
        source_hash: source.hash,
        artifact_hash: null,
        artifact_path: null,
        artifacts: [source],
        evidence: [{ url: REQUESTED_URL, hash: source.hash, status: 'source_captured' }],
        warnings: [],
        cost_money: 0,
        credits_used: 0,
        termination,
      }),
    });
    guard.install();
    assert.equal(typeof fireTimeout, 'function', 'wallMs must arm a timeout through the scheduler');
    fireTimeout();          // deadline fires -> finalize(reason=timeout) starts
    emitter.emit('SIGINT'); // signal races in mid-finalization
    await guard.done;

    assert.equal(guard.commitCount, 1, 'a racing signal must not add a second commit');
    assert.deepEqual(exits, [EXIT_CODE.TIMEOUT], 'the timeout outcome must win the race');

    const manifest = JSON.parse(
      await readFile(join(dataRoot, 'runs', run.id, 'manifest.json'), 'utf8'),
    );
    assert.deepEqual(manifest.termination, { reason: 'timeout' });
  });
});

// ---------------------------------------------------------------------------
// Edge 2 — crash recovery: a real SIGKILL before commit stays recoverable.
// ---------------------------------------------------------------------------

test('a real SIGKILL before commit leaves a recoverable incomplete run', async () => {
  await withSandbox(async ({ dataRoot }) => {
    const worker = await startWorker({ mode: 'crash', dataRoot });
    assert.ok(worker.ready?.runId, 'worker must reach the milestone before the kill');
    worker.child.kill('SIGKILL');
    const { signal } = await worker.exited;
    assert.equal(signal, 'SIGKILL', 'the child must die on the uncatchable kill');

    // Killed strictly before commitManifest: no manifest on disk.
    await assert.rejects(
      lstat(join(dataRoot, 'runs', worker.ready.runId, 'manifest.json')),
      { code: 'ENOENT' },
    );

    const storage = createStorage({ dataRoot, clock });
    assert.equal(
      typeof storage.recoverIncompleteRuns,
      'function',
      'storage must expose recoverIncompleteRuns',
    );
    const report = await storage.recoverIncompleteRuns();

    assert.ok(Array.isArray(report.incomplete));
    const entry = report.incomplete.find((item) => item.run_id === worker.ready.runId);
    assert.ok(entry, 'the killed run must be reported as incomplete');
    assert.equal(entry.manifest_committed, false);
    assert.ok(
      entry.source_hashes.includes(worker.ready.sourceHash),
      'recovery must preserve the captured evidence hashes',
    );

    // A mode-0600 incomplete.json is persisted under the data root.
    const reportPath = join(dataRoot, 'incomplete.json');
    const reportInfo = await lstat(reportPath);
    assert.equal(reportInfo.mode & 0o777, 0o600, 'incomplete.json must be private');
    const persisted = JSON.parse(await readFile(reportPath, 'utf8'));
    assert.ok(persisted.incomplete.some((item) => item.run_id === worker.ready.runId));

    // Recovery never fabricates a cache hit for an uncommitted run.
    const cached = await storage.readCache(fingerprint());
    assert.equal(cached.hit, false);
  });
});

test('corrupt and symlink-escaping run state surfaces typed corruption, never escapes the data root', async () => {
  await withSandbox(async ({ sandbox, dataRoot }) => {
    const storage = createStorage({ dataRoot, clock });
    const healthy = await seedIncompleteRun(storage, 'healthy');
    const corrupt = await seedIncompleteRun(storage, 'corrupt');
    const escaping = await seedIncompleteRun(storage, 'escape');

    // Corrupt the journal with non-JSON content.
    await writeFile(join(dataRoot, corrupt.run.path, 'attempts.ndjson'), '{ not json\n', {
      mode: 0o600,
    });

    // Point the journal at a symlink escaping the data root.
    const outside = join(sandbox, 'outside');
    await mkdir(outside, { recursive: true, mode: 0o700 });
    const stolen = join(outside, 'stolen.ndjson');
    const journalPath = join(dataRoot, escaping.run.path, 'attempts.ndjson');
    await unlink(journalPath);
    await symlink(stolen, journalPath);

    assert.equal(
      typeof storage.recoverIncompleteRuns,
      'function',
      'storage must expose recoverIncompleteRuns',
    );
    const report = await storage.recoverIncompleteRuns();

    // Healthy run still recovers; broken runs are quarantined as typed corruption.
    assert.ok(report.incomplete.some((item) => item.run_id === healthy.run.id));
    assert.ok(Array.isArray(report.corrupt));
    for (const runId of [corrupt.run.id, escaping.run.id]) {
      const flagged = report.corrupt.find((item) => item.run_id === runId);
      assert.ok(flagged, `run ${runId} must be reported as corrupt`);
      assert.equal(typeof flagged.corruption?.code, 'string');
      assert.ok(flagged.corruption.code.length > 0, 'corruption must carry a typed code');
    }
    assert.ok(
      !report.incomplete.some((item) => item.run_id === corrupt.run.id
        || item.run_id === escaping.run.id),
      'corrupt runs must not masquerade as clean incomplete runs',
    );

    // The symlink was never followed and nothing landed outside the data root.
    assert.deepEqual(await readdir(outside), [], 'the escaping symlink must not be written through');
    for (const { path } of await walk(sandbox)) {
      assert.ok(
        path.startsWith(dataRoot) || path === sandbox || path === outside,
        `recovery must not create state outside the data root: ${path}`,
      );
    }

    const cached = await storage.readCache(fingerprint());
    assert.equal(cached.hit, false);
  });
});
