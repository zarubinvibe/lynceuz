// Deterministic interruption worker for evals/recovery.test.mjs.
//
// Reaches a fixed milestone (beginRun -> putObject -> appendAttempt), confirms
// it via IPC, then keeps the event loop alive and waits for the parent to send
// a real signal:
//   mode=crash   -> waits for a real SIGKILL strictly BEFORE commitManifest, so
//                   the on-disk run stays incomplete (uses only shipped storage APIs).
//   mode=signal  -> installs the future core interruption guard; a real
//                   SIGINT/SIGTERM must commit ONE interrupted manifest and exit
//                   with the mapped code.
//   mode=timeout -> the guard's own wall deadline fires and commits an
//                   interrupted (reason=timeout) manifest, exit 124.
//
// No live network, no sleep-based readiness: the parent waits on the IPC
// milestone (or an early exit), never on a timer.

import { createStorage } from '../../src/storage.mjs';
import * as core from '../../src/core.mjs';

const FIXED_TIME = '2026-08-26T12:15:40.123Z';
const REQUESTED_URL = 'https://example.com/interrupted';
const EVIDENCE = Buffer.from('interrupted public evidence');

function buildInterruptedManifest(run, source, termination) {
  return {
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
    attempts: [{
      type: 'attempt_finished', at: FIXED_TIME, outcome: 'ok', source_hash: source.hash,
    }],
    source_hash: source.hash,
    artifact_hash: null,
    artifact_path: null,
    artifacts: [source],
    evidence: [{ url: REQUESTED_URL, hash: source.hash, status: 'source_captured' }],
    warnings: [],
    cost_money: 0,
    credits_used: 0,
    termination,
  };
}

function keepAlive() {
  // Ref'd timer keeps the process alive until a signal or the guard exits it.
  // Not a readiness sleep: it never fires meaningfully.
  setInterval(() => {}, 1 << 30);
}

async function main() {
  const config = JSON.parse(process.argv[2] ?? '{}');
  const clock = () => new Date(FIXED_TIME);
  const storage = createStorage({ dataRoot: config.dataRoot, clock });

  const run = await storage.beginRun({
    schema_version: 1,
    command: 'url',
    requested_url: REQUESTED_URL,
    method: 'GET',
    format: 'markdown',
    cache: 'use',
  });
  const source = await storage.putObject(run, EVIDENCE, {
    role: 'raw', media_type: 'text/plain', derived_from: null,
  });
  await storage.appendAttempt(run, {
    type: 'attempt_finished', at: FIXED_TIME, outcome: 'ok', source_hash: source.hash,
  });

  const milestone = { ready: true, runId: run.id, sourceHash: source.hash, dataRoot: storage.dataRoot };

  if (config.mode === 'crash') {
    process.send?.(milestone);
    keepAlive();
    return;
  }

  // signal / timeout modes exercise the future core interruption guard.
  const guard = core.createInterruptionGuard({
    storage,
    run,
    wallMs: config.mode === 'timeout' ? (config.wallMs ?? 50) : null,
    buildInterruptedManifest: (termination) => buildInterruptedManifest(run, source, termination),
  });
  guard.install();
  process.send?.(milestone);
  keepAlive();
}

main().catch((error) => {
  process.stderr.write(`${error?.stack ?? error}\n`);
  process.exit(1);
});
