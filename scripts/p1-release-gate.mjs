#!/usr/bin/env node

// Honest, non-recursive P1 release gate. Confirms the P0/P1 suite set has not drifted,
// runs ONLY the manifest-designated release suites via a fixed `node --test` argv, then
// requires a CURRENT valid browser-security proof before sealing an atomic release marker.
// It never re-runs itself (no recursion) and never deletes P0 evidence.

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { arch, platform } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  computeBrowserFingerprint,
  verifyBrowserSecurityProof,
  browserCapabilityState,
} from '../src/browser-security.mjs';
import {
  containmentEvidence,
  detectRuntime,
  readReceipt,
  readyRuntime,
} from './p1-browser-gate.mjs';
import { createStorage } from '../src/storage.mjs';

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MARKER_RELATIVE = 'release/p1-release-proof-v1.json';
const BROWSER_GATE = 'scripts/p1-browser-gate.mjs';
const BROWSER_PROOF_RELATIVE = 'security/browser-proof-v1.json';
const SUITE_MANIFEST_RELATIVE = 'evals/fixtures/p1-suite-manifest.json';
const MAX_BUFFER = 2 * 1024 * 1024;
const SUITE_TIMEOUT_MS = 120_000;
const BROWSER_GATE_TIMEOUT_MS = 240_000;
const EXIT_RELEASED = 0;
const EXIT_REJECTED = 10;
const EXIT_BLOCKED_BROWSER = 20;
const EXIT_INVALID_INPUT = 2;

// Fail-closed fingerprint used only when the independent facts cannot be read (no/invalid
// receipt): a digest that can never match a real proof, so verify blocks, never releases.
const UNPROVABLE_FINGERPRINT = Object.freeze({ digest: `sha256:${'0'.repeat(64)}` });

// Closed list of browser reasons that are an HONEST block (accepted, no marker) rather than
// a rejected verdict. Either the browser gate reports a proven containment/availability limit,
// or verifyBrowserSecurityProof reports there is no current valid proof. Anything else — a
// suite failure, an internal error, an unknown/forged reason — is rejected, never accepted.
const ACCEPTED_BROWSER_REASONS = Object.freeze(new Set([
  'sandbox_loopback_scope_unproven',
  'sandbox_platform_unsupported',
  'sandbox_executable_missing',
  'playwright_missing',
  'proof_missing',
  'proof_stale',
  'proof_corrupt',
  'fingerprint_mismatch',
  'proof_failed_or_incomplete',
]));

// Minimal allowlisted environment for spawned children: no inherited secrets, only what
// node/python need to locate a runtime, plus a deterministic locale.
function suiteEnv() {
  return {
    PATH: process.env.PATH ?? '',
    HOME: process.env.HOME ?? '',
    TMPDIR: process.env.TMPDIR ?? '',
    LANG: 'C.UTF-8',
    LC_ALL: 'C.UTF-8',
    LYNCEUZ_GATE_SUITE: '1',
  };
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${stableJson(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function hashFile(path) {
  try { return sha256(await readFile(path)); } catch { return null; }
}

function firstJsonLine(stdout) {
  if (typeof stdout !== 'string') return null;
  const line = stdout.split('\n', 1)[0];
  try { return JSON.parse(line); } catch { return null; }
}

function verdict(fields) {
  return Object.freeze({ kind: 'lynceuz_p1_release_proof', cost_money: 0, marker_path: MARKER_RELATIVE, ...fields });
}

function rejected(reason, exitCode = EXIT_REJECTED) {
  return verdict({ accepted: false, exit_code: exitCode, status: 'rejected', p1_release_state: 'rejected', reason });
}

function blockedBrowser(reason) {
  return verdict({ accepted: true, exit_code: EXIT_BLOCKED_BROWSER, status: 'blocked', p1_release_state: 'blocked_browser', reason });
}

function validManifest(manifest) {
  return manifest && typeof manifest === 'object' && !Array.isArray(manifest)
    && manifest.baseline_manifest && typeof manifest.baseline_manifest.sha256 === 'string'
    && typeof manifest.baseline_manifest.path === 'string'
    && Array.isArray(manifest.files)
    && manifest.files.every((file) => file && typeof file.path === 'string' && typeof file.sha256 === 'string');
}

// Detects whether the release-suite set on disk still matches the pinned manifest. A drift is a
// rejected verdict, never an accepted block: the gate cannot certify a suite set it did not run.
async function detectDrift(projectRoot, manifest) {
  const targets = [
    { path: manifest.baseline_manifest.path, sha256: manifest.baseline_manifest.sha256 },
    ...manifest.files.map((file) => ({ path: file.path, sha256: file.sha256 })),
  ];
  for (const target of targets) {
    const actual = await hashFile(join(projectRoot, target.path));
    if (actual !== target.sha256) return target.path;
  }
  return null;
}

async function sealMarker({ dataRoot, now, p0Hash, p1Hash, verification }) {
  const browserProofHash = await hashFile(join(dataRoot, BROWSER_PROOF_RELATIVE));
  if (browserProofHash === null) return rejected('gate_internal_error');
  const capability = browserCapabilityState({
    id: 'playwright',
    installed: true,
    version: verification.proof?.runtime?.playwright ?? null,
    allowRendered: true,
    proof: verification,
  });
  const payload = {
    kind: 'lynceuz_p1_release_proof',
    schema_version: 1,
    cost_money: 0,
    generated_at: new Date(Number(now())).toISOString(),
    node: process.version,
    platform: process.platform,
    arch: process.arch,
    suite_hashes: { p0: p0Hash, p1: p1Hash },
    browser_proof_hash: browserProofHash,
    browser_proof_fingerprint: verification.fingerprint,
    capability_state: capability.state,
  };
  const marker = { ...payload, marker_hash: sha256(stableJson(payload)) };
  const storage = createStorage({ dataRoot, clock: now });
  await storage.publishPrivateJson(MARKER_RELATIVE, marker);
  return verdict({
    accepted: true,
    exit_code: EXIT_RELEASED,
    status: 'passed',
    p1_release_state: 'released',
    reason: 'released',
    marker_hash: marker.marker_hash,
  });
}

// Pure, injectable gate evaluation. `runner(executable, argv, options)` returns a spawn-style
// result ({ status, signal, stdout, stderr }); tests inject a stub so no real process is spawned.
export async function evaluateReleaseGate({
  dataRoot,
  projectRoot = PROJECT_ROOT,
  suiteManifest,
  fingerprint,
  now = Date.now,
  runner,
} = {}) {
  try {
    if (typeof dataRoot !== 'string' || basename(resolve(dataRoot)) !== '.lynceuz'
        || typeof runner !== 'function' || !validManifest(suiteManifest)
        || !fingerprint || typeof fingerprint.digest !== 'string') {
      return rejected('invalid_input', EXIT_INVALID_INPUT);
    }

    const drifted = await detectDrift(projectRoot, suiteManifest);
    if (drifted) return rejected('hash_drift');

    const p0Hash = suiteManifest.baseline_manifest.sha256;
    const p1Hash = sha256(stableJson(suiteManifest));

    // Fixed `node --test` argv over ONLY the release-gate suites. p1-release.test.mjs carries
    // run_by_release_gate=false, so the gate never runs its own contract test: no recursion.
    const suitePaths = suiteManifest.files
      .filter((file) => file.run_by_release_gate === true)
      .map((file) => join(projectRoot, file.path));
    const suiteRun = await runner(process.execPath, ['--test', ...suitePaths], {
      cwd: projectRoot,
      env: suiteEnv(),
      shell: false,
      timeout: SUITE_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      encoding: 'utf8',
    });
    if (!(suiteRun && suiteRun.status === 0 && !suiteRun.signal)) {
      return rejected('suite_failed');
    }

    // Only now, with suites green, run the independent browser gate against the same data root.
    const gateRun = await runner(process.execPath, [
      join(projectRoot, BROWSER_GATE), '--json', '--data-root', dataRoot,
    ], {
      cwd: projectRoot,
      env: suiteEnv(),
      shell: false,
      timeout: BROWSER_GATE_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
      encoding: 'utf8',
    });

    let browserReason;
    if (gateRun && gateRun.status === 0 && !gateRun.signal) {
      // Do NOT reinvent fingerprint rules: verifyBrowserSecurityProof owns them.
      const verification = await verifyBrowserSecurityProof({ dataRoot, fingerprint, now });
      if (verification.valid) {
        return await sealMarker({ dataRoot, now, p0Hash, p1Hash, verification });
      }
      browserReason = verification.reason;
    } else {
      const parsed = firstJsonLine(gateRun?.stdout);
      if (!parsed || typeof parsed.reason !== 'string') return rejected('malformed_gate_output');
      browserReason = parsed.reason;
    }

    return ACCEPTED_BROWSER_REASONS.has(browserReason)
      ? blockedBrowser(browserReason)
      : rejected(browserReason);
  } catch {
    return rejected('gate_internal_error');
  }
}

// Build the fingerprint we EXPECT a ready proof to carry, from independent facts only — the
// machine's runtime detection plus the root-generated containment receipt — never from the proof
// under test. Reuses the browser gate's own detectRuntime/containmentEvidence/readyRuntime so both
// sides fingerprint identically; verifyBrowserSecurityProof still owns the comparison rules.
export async function expectedBrowserFingerprint({
  dataRoot,
  detect = detectRuntime,
  loadReceipt = readReceipt,
} = {}) {
  try {
    const loaded = await loadReceipt(dataRoot);
    if (!loaded?.receipt) return UNPROVABLE_FINGERPRINT;
    const detected = await detect();
    const evidence = containmentEvidence(loaded.receipt, loaded.receiptHash);
    return await computeBrowserFingerprint({ runtime: readyRuntime(detected.runtime, evidence), containment: evidence });
  } catch {
    return UNPROVABLE_FINGERPRINT;
  }
}

// The single wiring seam: rebuild the expected fingerprint from independent facts and hand it to the
// pure evaluator. main() and the contract test both drive THIS, so the wiring — not just the pieces —
// is exercised. Injection points are inputs only (roots, runner, runtime/receipt readers); a ready
// fingerprint is never accepted here, so a test can't skip past the code that computes it.
export async function runReleaseGate({
  dataRoot,
  projectRoot = PROJECT_ROOT,
  suiteManifest,
  now = Date.now,
  runner,
  detect = detectRuntime,
  loadReceipt = readReceipt,
} = {}) {
  const fingerprint = await expectedBrowserFingerprint({ dataRoot, detect, loadReceipt });
  return evaluateReleaseGate({ dataRoot, projectRoot, suiteManifest, fingerprint, now, runner });
}

function parseArgs(argv) {
  let dataRoot = resolve(PROJECT_ROOT, '.lynceuz');
  let json = false;
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (seen.has(flag)) throw new TypeError('duplicate option');
    seen.add(flag);
    if (flag === '--json') { json = true; continue; }
    if (flag === '--data-root') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--') || /[\0\r\n]/u.test(value)) throw new TypeError('invalid data root');
      dataRoot = resolve(PROJECT_ROOT, value);
      index += 1;
      continue;
    }
    throw new TypeError('unknown option');
  }
  if (basename(dataRoot) !== '.lynceuz') dataRoot = join(dataRoot, '.lynceuz');
  return { dataRoot, json };
}

function spawnRunner(executable, argv, options) {
  return spawnSync(executable, argv, options);
}

async function main(argv) {
  let options;
  try { options = parseArgs(argv); } catch {
    const result = rejected('invalid_input', EXIT_INVALID_INPUT);
    process.stdout.write(`${JSON.stringify(result)}\n`);
    return result.exit_code;
  }

  let suiteManifest;
  try {
    suiteManifest = JSON.parse(await readFile(join(PROJECT_ROOT, SUITE_MANIFEST_RELATIVE)));
  } catch {
    const result = rejected('gate_internal_error');
    if (options.json) process.stdout.write(`${JSON.stringify(result)}\n`);
    return result.exit_code;
  }

  // Containment is unsealed: runReleaseGate rebuilds the expected fingerprint from the same
  // independent facts the browser gate fingerprints (detected runtime + containment receipt), so a
  // proven-ready proof matches and releases, while any source/receipt drift still mismatches and
  // blocks. main() owns no fingerprint logic — the one computation lives inside runReleaseGate.
  const result = await runReleaseGate({
    dataRoot: options.dataRoot,
    projectRoot: PROJECT_ROOT,
    suiteManifest,
    now: Date.now,
    runner: spawnRunner,
  });
  if (options.json) process.stdout.write(`${JSON.stringify(result)}\n`);
  return result.exit_code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = await main(process.argv.slice(2));
}

export {
  MARKER_RELATIVE,
  ACCEPTED_BROWSER_REASONS,
  parseArgs,
  stableJson,
};
