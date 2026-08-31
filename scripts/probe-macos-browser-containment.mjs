#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  inspectMacosContainment,
  verifyMacosContainmentReceipt,
} from '../src/macos-containment.mjs';
import {
  createContainmentCanaryHarness,
  probeContainmentCanary,
} from '../evals/fixtures/pf-containment-canary.mjs';

const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RECEIPT_PATH = resolve(PROJECT_ROOT, '.lynceuz/security/macos-containment-receipt-v1.json');
const MAX_RECEIPT_BYTES = 64 * 1024;
const BASE_EXPECTED = Object.freeze({
  backend: 'pf_uid_anchor_guardproxy',
  uid_name: '_lynceuz',
  uid: 401,
  gid: 401,
  guard_proxy_host: '127.0.0.1',
  guard_proxy_port: 48191,
  anchor_name: 'com.lynceuz/browser',
  anchor_path: '/etc/pf.anchors/com.lynceuz.browser',
  anchor_sha256: `sha256:${'0'.repeat(64)}`,
  rules_sha256: `sha256:${'0'.repeat(64)}`,
});

function output(mode, verdict, canary = undefined) {
  process.stdout.write(`${JSON.stringify({
    kind: 'lynceuz_macos_containment_probe',
    schema_version: 1,
    mode,
    ...verdict,
    ...(canary ? { canary } : {}),
  })}\n`);
}

function parseArgs(argv) {
  const allowed = new Set(['--json', '--negative-control']);
  if (argv.some((arg) => !allowed.has(arg)) || new Set(argv).size !== argv.length) {
    throw new TypeError('invalid_input');
  }
  return argv.includes('--negative-control') ? 'negative-control' : 'positive';
}

async function readReceipt() {
  try {
    const bytes = await readFile(RECEIPT_PATH);
    if (bytes.length > MAX_RECEIPT_BYTES) return { error: 'containment_receipt_invalid' };
    return { receipt: JSON.parse(bytes.toString('utf8')) };
  } catch (error) {
    if (error?.code === 'ENOENT') return { error: 'containment_receipt_missing' };
    if (error?.code === 'EACCES' || error?.code === 'EPERM') {
      return { error: 'containment_receipt_permission_denied' };
    }
    return { error: 'containment_receipt_invalid' };
  }
}

async function fileHash(relativePath) {
  const bytes = await readFile(resolve(PROJECT_ROOT, relativePath));
  if (bytes.length > 2 * 1024 * 1024) throw new Error('source_file_too_large');
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function expectedFacts() {
  const [macosContainment, canary, wave2] = await Promise.all([
    fileHash('src/macos-containment.mjs'),
    fileHash('evals/fixtures/pf-containment-canary.mjs'),
    fileHash('evals/fixtures/wave2-suite-manifest.json'),
  ]);
  return {
    ...BASE_EXPECTED,
    anchor_sha256: `sha256:${'0'.repeat(64)}`,
    rules_sha256: `sha256:${'0'.repeat(64)}`,
    source_hashes: { macos_containment: macosContainment, canary },
    suite_hashes: { wave2 },
  };
}

async function main() {
  let mode;
  try {
    mode = parseArgs(process.argv.slice(2));
  } catch {
    output('invalid', { state: 'unavailable_security_gate', reason: 'invalid_input' });
    return 2;
  }

  let harness;
  try {
    if (mode === 'negative-control') {
      harness = await createContainmentCanaryHarness();
      const canary = await probeContainmentCanary({
        endpoints: harness.endpoints,
        negativeControl: true,
        timeoutMs: 1_000,
      });
      output(mode, {
        state: 'unavailable_security_gate',
        reason: canary.reason,
      }, canary);
      return canary.exit_code || 1;
    }

    const loaded = await readReceipt();
    if (loaded.error) {
      output(mode, { state: 'unavailable_security_gate', reason: loaded.error });
      return 1;
    }

    const provisionalExpected = await expectedFacts();
    const system = await inspectMacosContainment({ expected: provisionalExpected });
    if (system.state === 'unavailable_security_gate') {
      output(mode, system);
      return 1;
    }
    const expected = {
      ...provisionalExpected,
      anchor_sha256: system.pf.anchor_sha256,
      rules_sha256: system.pf.rules_sha256,
    };
    harness = await createContainmentCanaryHarness();
    const canary = await probeContainmentCanary({
      endpoints: harness.endpoints,
      timeoutMs: 1_000,
    });
    const verdict = await verifyMacosContainmentReceipt({
      receipt: loaded.receipt,
      expected,
      system,
      canary,
    });
    output(mode, verdict, canary);
    return verdict.state === 'ready' ? 0 : 1;
  } catch {
    output(mode ?? 'invalid', {
      state: 'unavailable_security_gate',
      reason: 'containment_probe_unavailable',
    });
    return 1;
  } finally {
    await harness?.close().catch(() => {});
  }
}

process.exitCode = await main();
