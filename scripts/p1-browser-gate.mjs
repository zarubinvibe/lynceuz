#!/usr/bin/env node

import { execFile, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { access, chmod, lstat, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { arch, platform } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  REQUIRED_CONTAINMENT_PROOF_CHANNELS,
  computeBrowserFingerprint,
  createPfContainmentBackend,
  createChildEgressSandbox,
  createBrowserProofIntegrity,
} from '../src/browser-security.mjs';
import { createStorage } from '../src/storage.mjs';
import {
  createContainmentCanaryHarness,
  evaluateCanaryObservations,
} from '../evals/fixtures/pf-containment-canary.mjs';
import { renderCanaryClientSource } from './emit-macos-containment-receipt.mjs';

const execFileAsync = promisify(execFile);
const SELF = fileURLToPath(import.meta.url);
const PROJECT_ROOT = resolve(dirname(SELF), '..');
const PYTHON_CANDIDATES = Object.freeze([
  '/opt/homebrew/bin/python3',
  '/usr/local/bin/python3',
  '/Library/Frameworks/Python.framework/Versions/3.13/bin/python3',
  '/Library/Frameworks/Python.framework/Versions/3.12/bin/python3',
  '/Library/Frameworks/Python.framework/Versions/3.11/bin/python3',
  '/usr/bin/python3',
]);
const SUITES = Object.freeze([
  'evals/browser-hostile.test.mjs',
  'evals/router.test.mjs',
  'evals/p0-acceptance.test.mjs',
  'evals/browser-containment.test.mjs',
]);
const MAX_RECEIPT_BYTES = 64 * 1024;
const RECEIPT_RELATIVE = 'security/macos-containment-receipt-v1.json';
const BASE_EXPECTED = Object.freeze({
  backend: 'pf_uid_anchor_guardproxy',
  uid_name: '_lynceuz',
  uid: 401,
  gid: 401,
  guard_proxy_host: '127.0.0.1',
  guard_proxy_port: 48191,
  anchor_name: 'com.lynceuz/browser',
  anchor_path: '/etc/pf.anchors/com.lynceuz.browser',
});
const PYTHON_METADATA = [
  'import hashlib,importlib.metadata,json,pathlib,sys',
  'result={"python_version":sys.version.split()[0],"playwright_version":importlib.metadata.version("playwright"),"chromium_path":None}',
  'from playwright.sync_api import sync_playwright',
  'manager=sync_playwright().start()',
  'result["chromium_path"]=manager.chromium.executable_path',
  'manager.stop()',
  'path=pathlib.Path(result["chromium_path"])',
  'result["chromium_sha256"]="sha256:"+hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"',
  'print(json.dumps(result,separators=(",",":")))',
].join(';');

function parseArgs(argv) {
  let dataRoot = resolve(PROJECT_ROOT, '.lynceuz');
  let json = false;
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (seen.has(flag)) throw new TypeError('duplicate option');
    seen.add(flag);
    if (flag === '--json') {
      json = true;
      continue;
    }
    if (flag === '--data-root') {
      const value = argv[index + 1];
      if (!value || value.startsWith('--') || /[\0\r\n]/u.test(value)) throw new TypeError('invalid data root');
      dataRoot = resolve(PROJECT_ROOT, value);
      index += 1;
      continue;
    }
    throw new TypeError('unknown option');
  }
  if (basename(dataRoot) !== '.lynceuz') {
    dataRoot = join(dataRoot, '.lynceuz');
  }
  return Object.freeze({ dataRoot, json });
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function fileHash(path) {
  try { return sha256(await readFile(path)); } catch { return 'missing'; }
}

export async function readReceipt(dataRoot) {
  const receiptPath = join(resolve(dataRoot), RECEIPT_RELATIVE);
  try {
    const info = await lstat(receiptPath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_RECEIPT_BYTES) {
      return { error: 'containment_receipt_invalid' };
    }
    const [root, file] = await Promise.all([realpath(resolve(dataRoot)), realpath(receiptPath)]);
    if (!file.startsWith(`${root}/`)) return { error: 'containment_receipt_invalid' };
    const bytes = await readFile(file);
    return { receipt: JSON.parse(bytes), receiptHash: sha256(bytes) };
  } catch (error) {
    if (error?.code === 'ENOENT') return { missing: true };
    if (error?.code === 'EACCES' || error?.code === 'EPERM') {
      return { error: 'containment_receipt_permission_denied' };
    }
    return { error: 'containment_receipt_invalid' };
  }
}

async function expectedContainment(receipt) {
  const [macosContainment, canary, wave2] = await Promise.all([
    fileHash(resolve(PROJECT_ROOT, 'src/macos-containment.mjs')),
    fileHash(resolve(PROJECT_ROOT, 'evals/fixtures/pf-containment-canary.mjs')),
    fileHash(resolve(PROJECT_ROOT, 'evals/fixtures/wave2-suite-manifest.json')),
  ]);
  return {
    ...BASE_EXPECTED,
    anchor_sha256: receipt?.pf?.anchor_sha256 ?? `sha256:${'0'.repeat(64)}`,
    rules_sha256: receipt?.pf?.rules_sha256 ?? `sha256:${'0'.repeat(64)}`,
    source_hashes: { macos_containment: macosContainment, canary },
    suite_hashes: { wave2 },
  };
}

export async function positiveCanary({ uidName, proxyPort, runner = execFileAsync } = {}) {
  let harness;
  let temporaryDirectory;
  try {
    if (typeof uidName !== 'string' || uidName.length === 0 || !Number.isInteger(proxyPort)) {
      throw new TypeError('invalid containment canary facts');
    }
    harness = await createContainmentCanaryHarness({ proxyPort });
    temporaryDirectory = await mkdtemp('/private/tmp/lynceuz-gate-canary-');
    await chmod(temporaryDirectory, 0o755);
    const clientPath = resolve(temporaryDirectory, 'canary-client.mjs');
    await writeFile(clientPath, renderCanaryClientSource(), { mode: 0o644 });
    const { stdout } = await runner(
      '/usr/bin/sudo',
      ['-n', '-u', uidName, process.execPath, clientPath, JSON.stringify(harness.endpoints)],
      { shell: false, timeout: 20_000, maxBuffer: 256 * 1024, encoding: 'utf8' },
    );
    const observations = JSON.parse(stdout.trim().split('\n').filter(Boolean).at(-1) ?? '');
    return evaluateCanaryObservations(observations);
  } catch {
    throw Object.assign(new Error('containment_canary_failed'), {
      reason: 'containment_canary_failed',
      containment_state: 'unavailable_security_gate',
    });
  } finally {
    await harness?.close().catch(() => {});
    if (temporaryDirectory) await rm(temporaryDirectory, { recursive: true, force: true }).catch(() => {});
  }
}

export function containmentEvidence(receipt, receiptHash) {
  return Object.freeze({
    backend: receipt.backend,
    system_receipt_hash: receiptHash,
    uid: Object.freeze({ ...receipt.uid }),
    guard_proxy: Object.freeze({ ...receipt.guard_proxy }),
    anchor: Object.freeze({ ...receipt.pf }),
    boot_session: receipt.boot_session,
    reboot_verified: receipt.reboot_verified,
    reboot_verified_at: receipt.reboot_verified_at,
    source_hashes: Object.freeze({ ...receipt.source_hashes }),
    wave2_suite_hash: receipt.suite_hashes.wave2,
    negative_control_required: true,
  });
}

// The runtime the gate fingerprints once containment is proven ready: the detected machine
// runtime with the live sandbox executable hash replaced by the containment backend and the
// receipt hash pinned as the profile. Shared so the release gate rebuilds the same fingerprint.
export function readyRuntime(detectedRuntime, evidence) {
  return { ...detectedRuntime, containment: evidence.backend, profile: evidence.system_receipt_hash };
}

export async function detectRuntime() {
  let pythonPath = null;
  let metadata = null;
  for (const candidate of PYTHON_CANDIDATES) {
    try {
      await access(candidate);
    } catch {
      continue;
    }
    const child = spawnSync(candidate, ['-I', '-c', PYTHON_METADATA], {
      cwd: PROJECT_ROOT,
      encoding: 'utf8',
      env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PYTHONNOUSERSITE: '1' },
      shell: false,
      timeout: 10_000,
      maxBuffer: 128 * 1024,
    });
    if (child.status === 0 && child.signal === null) {
      try {
        metadata = JSON.parse(child.stdout);
        pythonPath = candidate;
        break;
      } catch {}
    }
  }
  const containmentPath = '/usr/bin/sandbox-exec';
  return Object.freeze({
    installed: Boolean(metadata?.playwright_version && metadata?.chromium_path),
    pythonPath,
    runtime: {
      platform: platform(),
      arch: arch(),
      node: process.version,
      python: pythonPath && metadata?.python_version
        ? `${pythonPath}@${metadata.python_version}`
        : 'missing',
      playwright: metadata?.playwright_version ?? 'missing',
      chromium: metadata?.chromium_sha256 ?? 'missing',
      containment: await fileHash(containmentPath),
    },
  });
}

function runSuite(relativePath) {
  const started = Date.now();
  const child = spawnSync(process.execPath, ['--test', relativePath], {
    cwd: PROJECT_ROOT,
    encoding: 'utf8',
    env: { ...process.env, LYNCEUZ_GATE_SUITE: '1' },
    shell: false,
    timeout: 55_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  return Object.freeze({
    suite: relativePath,
    passed: child.status === 0 && child.signal === null && !/ℹ skipped [1-9]/u.test(child.stdout),
    skipped: /ℹ skipped [1-9]/u.test(child.stdout),
    exit_code: child.status,
    signal: child.signal,
    duration_ms: Date.now() - started,
    stdout_hash: sha256(child.stdout ?? ''),
    stderr_hash: sha256(child.stderr ?? ''),
  });
}

function channels(value) {
  return Object.fromEntries(REQUIRED_CONTAINMENT_PROOF_CHANNELS.map((name) => [name, value]));
}

export async function main() {
  let options;
  try { options = parseArgs(process.argv.slice(2)); } catch {
    process.stdout.write(`${JSON.stringify({
      kind: 'browser_security_proof', status: 'failed', reason: 'invalid_input',
      containment_state: 'unavailable_security_gate',
    })}\n`);
    return 2;
  }
  const storage = createStorage({ dataRoot: options.dataRoot, clock: Date.now });
  try {
    const detected = await detectRuntime();
    const loaded = await readReceipt(options.dataRoot);
    let reason = loaded.error ?? null;
    let evidence;
    let canary;
    let backend;
    if (loaded.missing) {
      backend = await createChildEgressSandbox({ proxyPort: 1 });
      reason = backend.reason;
    } else if (!reason) {
      const expected = await expectedContainment(loaded.receipt);
      backend = await createPfContainmentBackend({
        receipt: loaded.receipt,
        expected,
        canary: null,
        pythonPath: detected.pythonPath,
      });
      if (backend.reason !== 'containment_canary_missing') reason = backend.reason;
      else try {
        canary = await positiveCanary({
          uidName: expected.uid_name,
          proxyPort: expected.guard_proxy_port,
        });
      } catch (error) {
        reason = error?.reason ?? 'containment_canary_failed';
      }
      if (!reason) {
        backend = await createPfContainmentBackend({
          receipt: loaded.receipt,
          expected,
          canary,
          pythonPath: detected.pythonPath,
        });
        if (backend.state !== 'ready') {
          reason = !detected.installed && backend.reason === 'containment_launch_unavailable'
            ? 'playwright_missing'
            : backend.reason;
        }
        else evidence = containmentEvidence(loaded.receipt, loaded.receiptHash);
      }
    }
    const runtime = evidence
      ? readyRuntime(detected.runtime, evidence)
      : { ...detected.runtime, profile: backend?.profileHash ?? 'sandbox_loopback_scope_unproven' };
    const fingerprint = await computeBrowserFingerprint({ runtime, ...(evidence ? { containment: evidence } : {}) });
    const generatedAt = new Date().toISOString();
    const base = {
      kind: 'browser_security_proof',
      schema_version: 1,
      fingerprint: fingerprint.digest,
      generated_at: generatedAt,
      platform: runtime.platform,
      arch: runtime.arch,
      runtime,
      source_hashes: fingerprint.sources,
      channels: channels(false),
      containment_state: 'unavailable_security_gate',
      ...(evidence ? { containment: evidence } : {}),
    };
    await storage.publishPrivateJson('security/browser-proof-v1.json', {
      ...base,
      status: 'in_progress',
      reason: 'gate_running',
      suites: [],
    });

    const suites = SUITES.map(runSuite);
    if (!reason && !suites.every((suite) => suite.passed)) reason = 'suite_failed';
    if (!reason && !detected.installed) reason = 'playwright_missing';
    if (!reason && backend?.state !== 'ready') reason = backend?.reason ?? 'sandbox_loopback_scope_unproven';
    const verifiedFingerprint = await computeBrowserFingerprint({
      runtime, ...(evidence ? { containment: evidence } : {}),
    });
    if (!reason && verifiedFingerprint.digest !== fingerprint.digest) {
      reason = 'fingerprint_drift_during_gate';
    }
    if (reason) {
      const failed = { ...base, status: 'failed', reason, suites };
      await storage.publishPrivateJson('security/browser-proof-v1.json', failed);
      process.stdout.write(`${JSON.stringify(failed)}\n`);
      return 1;
    }

    const passedDraft = {
      ...base,
      fingerprint: verifiedFingerprint.digest,
      source_hashes: verifiedFingerprint.sources,
      status: 'passed',
      reason: 'proof_valid',
      channels: channels(true),
      containment_state: 'ready',
      suites,
    };
    const passed = { ...passedDraft, marker_hash: createBrowserProofIntegrity(passedDraft) };
    await storage.publishPrivateJson('security/browser-proof-v1.json', passed);
    process.stdout.write(`${JSON.stringify(passed)}\n`);
    return 0;
  } catch {
    const failed = {
      kind: 'browser_security_proof',
      schema_version: 1,
      status: 'failed',
      reason: 'gate_internal_error',
      fingerprint: null,
      generated_at: new Date().toISOString(),
      channels: channels(false),
      containment_state: 'unavailable_security_gate',
      suites: [],
    };
    await storage.publishPrivateJson('security/browser-proof-v1.json', failed).catch(() => {});
    process.stdout.write(`${JSON.stringify(failed)}\n`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === SELF) {
  process.exitCode = await main().catch(async () => {
    process.stdout.write(`${JSON.stringify({
      kind: 'browser_security_proof', status: 'failed', reason: 'gate_internal_error',
      containment_state: 'unavailable_security_gate',
    })}\n`);
    return 1;
  });
}
