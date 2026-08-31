#!/usr/bin/env node

// Owner-run generator for `.lynceuz/security/macos-containment-receipt-v1.json`.
//
// The probe (`probe-macos-browser-containment.mjs`) only READS that receipt; nothing wrote it.
// PF facts (`pfctl -s info/-sr`) need root and the canary client must run under the contained uid,
// so this must be launched by the owner with root. It never mutates the system: it only READS PF
// facts and drives a canary stand on local addresses.
//
// Default mode (root parent):
//   sudo node scripts/emit-macos-containment-receipt.mjs
// It stands up `createContainmentCanaryHarness` (proxy pinned to the guard port so a contained uid
// can reach it), stages a self-contained canary client under /private/tmp and runs it as `_lynceuz`
// to probe the four channels from inside containment,
// reads PF/uid/boot facts, then writes a `ready` receipt ONLY when the canary proves proxy TCP
// answers while direct TCP, UDP and QUIC stay silent. Any missing/unreadable fact -> non-zero exit
// with a typed reason and NOTHING is written (fail-closed).
//
// `reboot_verified: true` means the PF anchor is active AND `boot_session` (kern.boottime) is the
// live one — it confirms containment is active in the CURRENT boot, not that a reboot cycle was
// survived. The receipt goes stale with the boot session, which is the point.
//
// The canary client is emitted by `renderCanaryClientSource()` as a fully self-contained ESM module
// (only `node:` builtins, no repo imports, no home-dir paths). The parent stages it in a temp dir
// under /private/tmp — reachable by the contained uid, which cannot traverse the owner's home — runs
// it as `_lynceuz` with the endpoints as argv, then deletes the temp dir in any outcome.

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { chmod, chown, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import { inspectMacosContainment, verifyMacosContainmentReceipt } from '../src/macos-containment.mjs';
import {
  createContainmentCanaryHarness,
  evaluateCanaryObservations,
} from '../evals/fixtures/pf-containment-canary.mjs';

const execFileAsync = promisify(execFile);
const SELF = fileURLToPath(import.meta.url);
const PROJECT_ROOT = resolve(dirname(SELF), '..');
const SECURITY_DIR = resolve(PROJECT_ROOT, '.lynceuz/security');
const RECEIPT_PATH = resolve(SECURITY_DIR, 'macos-containment-receipt-v1.json');
const CHANNELS = Object.freeze(['proxy_tcp', 'direct_tcp', 'udp', 'quic']);
const CLIENT_TIMEOUT_MS = 20_000;
const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const ZERO_HASH = `sha256:${'0'.repeat(64)}`;
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

function emit(status, reason, extra = {}) {
  process.stdout.write(`${JSON.stringify({
    kind: 'lynceuz_macos_containment_receipt',
    schema_version: 1,
    status,
    reason,
    generated_at: new Date().toISOString(),
    ...extra,
  })}\n`);
}

function impossible(reason, extra = {}) {
  emit('impossible', reason, extra);
  return 1;
}

async function fileHash(relativePath) {
  const bytes = await readFile(resolve(PROJECT_ROOT, relativePath));
  if (bytes.length > MAX_SOURCE_BYTES) throw new Error('source_file_too_large');
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

async function buildProvisionalExpected() {
  const [macosContainment, canary, wave2] = await Promise.all([
    fileHash('src/macos-containment.mjs'),
    fileHash('evals/fixtures/pf-containment-canary.mjs'),
    fileHash('evals/fixtures/wave2-suite-manifest.json'),
  ]);
  return {
    ...BASE_EXPECTED,
    anchor_sha256: ZERO_HASH,
    rules_sha256: ZERO_HASH,
    source_hashes: { macos_containment: macosContainment, canary },
    suite_hashes: { wave2 },
  };
}

// A fully self-contained ESM canary client: only `node:` builtins, no repo imports, no home-dir
// paths. The parent stages this string in a temp dir the contained uid can reach (it cannot traverse
// the owner's home). The client reads endpoints from argv, runs the four exchanges, and prints
// observations as JSON. Confirmation is by RESPONSE, never by a successful send — PF `block drop`
// gives no RST, so only a confirmed reply proves a leak.
export function renderCanaryClientSource() {
  return `import { connect } from 'node:net';
import { createSocket } from 'node:dgram';

const MAX_MESSAGE_BYTES = 256;
const TIMEOUT_MS = 2000;
const CHANNELS = ['proxy_tcp', 'direct_tcp', 'udp', 'quic'];
const PROTOCOLS = {
  proxy_tcp: { request: 'LYNCEUZ_PROXY_TCP?', response: 'LYNCEUZ_PROXY_TCP_OK' },
  direct_tcp: { request: 'LYNCEUZ_DIRECT_TCP?', response: 'LYNCEUZ_DIRECT_TCP_LEAK' },
  udp: { request: 'LYNCEUZ_UDP?', response: 'LYNCEUZ_UDP_LEAK' },
  quic: { request: 'LYNCEUZ_QUIC_INITIAL?', response: 'LYNCEUZ_QUIC_RETRY_LEAK' },
};

function observation(channel, operationSucceeded, response) {
  return {
    channel,
    operation_succeeded: operationSucceeded,
    response,
    response_confirmed: response === PROTOCOLS[channel].response,
  };
}

function exchangeTcp(channel, endpoint) {
  const protocol = PROTOCOLS[channel];
  return new Promise((resolve) => {
    let operationSucceeded = false;
    let settled = false;
    const chunks = [];
    const socket = connect(endpoint);
    const finish = (response = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(observation(channel, operationSucceeded, response));
    };
    const timer = setTimeout(() => finish(), TIMEOUT_MS);
    socket.once('connect', () => {
      operationSucceeded = true;
      socket.write(protocol.request);
    });
    socket.on('data', (chunk) => {
      if (Buffer.concat(chunks).length + chunk.length > MAX_MESSAGE_BYTES) return finish();
      chunks.push(Buffer.from(chunk));
    });
    socket.once('end', () => finish(Buffer.concat(chunks).toString('utf8')));
    socket.once('error', () => finish());
  });
}

function exchangeUdp(channel, endpoint) {
  const protocol = PROTOCOLS[channel];
  return new Promise((resolve) => {
    const socket = createSocket('udp4');
    let operationSucceeded = false;
    let settled = false;
    const finish = (response = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      resolve(observation(channel, operationSucceeded, response));
    };
    const timer = setTimeout(() => finish(), TIMEOUT_MS);
    socket.once('error', () => finish());
    socket.on('message', (message, peer) => {
      if (peer.port === endpoint.port && message.length <= MAX_MESSAGE_BYTES) {
        finish(message.toString('utf8'));
      }
    });
    socket.send(protocol.request, endpoint.port, endpoint.host, (error) => {
      operationSucceeded = !error;
      if (error) finish();
    });
  });
}

function validEndpoint(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && typeof value.host === 'string' && value.host.length > 0
    && Number.isInteger(value.port) && value.port > 0 && value.port <= 65535;
}

async function main() {
  let endpoints;
  try {
    endpoints = JSON.parse(process.argv[2] ?? '');
  } catch {
    process.stdout.write(JSON.stringify({ error: 'invalid_input' }) + '\\n');
    return 2;
  }
  if (!endpoints || CHANNELS.some((channel) => !validEndpoint(endpoints[channel]))) {
    process.stdout.write(JSON.stringify({ error: 'invalid_input' }) + '\\n');
    return 2;
  }
  const [proxyTcp, directTcp, udp, quic] = await Promise.all([
    exchangeTcp('proxy_tcp', endpoints.proxy_tcp),
    exchangeTcp('direct_tcp', endpoints.direct_tcp),
    exchangeUdp('udp', endpoints.udp),
    exchangeUdp('quic', endpoints.quic),
  ]);
  process.stdout.write(JSON.stringify({
    proxy_tcp: proxyTcp, direct_tcp: directTcp, udp, quic,
  }) + '\\n');
  return 0;
}

process.exitCode = await main();
`;
}

// Trim a client's stderr for the failure receipt: keep printable bytes only, cap length. Endpoints
// are the only data the client ever sees and they are not secret, so this leaks nothing sensitive.
function excerptStderr(value) {
  if (typeof value !== 'string' || value.trim().length === 0) return null;
  const printable = Array.from(value, (ch) => {
    const code = ch.codePointAt(0);
    return code >= 0x20 && code !== 0x7f ? ch : ' ';
  }).join('');
  return printable.trim().slice(0, 400);
}

// Stage the self-contained client outside the owner's home (the contained uid cannot traverse it),
// run it as that uid, and collect its observations. Async spawn is required: a blocking spawn would
// freeze this event loop and starve the canary responders. The temp dir is removed in any outcome.
async function probeFromContainment(uidName, endpoints) {
  const dir = await mkdtemp('/private/tmp/lynceuz-canary-');
  try {
    await chmod(dir, 0o755);
    const clientPath = resolve(dir, 'canary-client.mjs');
    await writeFile(clientPath, renderCanaryClientSource(), { mode: 0o644 });
    await chmod(clientPath, 0o644);
    let stdout;
    try {
      ({ stdout } = await execFileAsync(
        '/usr/bin/sudo',
        ['-n', '-u', uidName, process.execPath, clientPath, JSON.stringify(endpoints)],
        { shell: false, timeout: CLIENT_TIMEOUT_MS, maxBuffer: 256 * 1024, encoding: 'utf8' },
      ));
    } catch (error) {
      throw Object.assign(new Error('containment_canary_client_failed'), {
        details: { stderr: excerptStderr(error?.stderr) },
      });
    }
    const line = stdout.trim().split('\n').filter(Boolean).at(-1);
    let observations;
    try {
      observations = JSON.parse(line ?? '');
    } catch {
      throw new Error('containment_canary_client_unreadable');
    }
    if (!observations || CHANNELS.some((channel) => typeof observations[channel] !== 'object')) {
      throw new Error('containment_canary_client_unreadable');
    }
    return observations;
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

async function writeReceipt(receipt) {
  await mkdir(SECURITY_DIR, { recursive: true });
  await writeFile(RECEIPT_PATH, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
  await chmod(RECEIPT_PATH, 0o600);
  // Root wrote it; hand ownership back so the owner's verify can read it (dir traversal + file read).
  const uid = Number(process.env.SUDO_UID);
  const gid = Number(process.env.SUDO_GID);
  if (Number.isInteger(uid) && Number.isInteger(gid)) {
    for (const target of [SECURITY_DIR, RECEIPT_PATH]) {
      await chown(target, uid, gid).catch(() => {});
    }
  }
}

async function runParentMode() {
  if (typeof process.geteuid !== 'function' || process.geteuid() !== 0) {
    return impossible('containment_requires_root');
  }

  const provisional = await buildProvisionalExpected();
  const system = await inspectMacosContainment({ expected: provisional });
  if (system.state === 'unavailable_security_gate') {
    return impossible(system.reason, system.details ? { details: system.details } : {});
  }
  const expected = {
    ...provisional,
    anchor_sha256: system.pf.anchor_sha256,
    rules_sha256: system.pf.rules_sha256,
  };

  let harness;
  let canary;
  try {
    harness = await createContainmentCanaryHarness({ proxyPort: expected.guard_proxy_port });
  } catch {
    return impossible('containment_canary_harness_unavailable');
  }
  try {
    canary = evaluateCanaryObservations(await probeFromContainment(expected.uid_name, harness.endpoints));
  } catch (error) {
    return impossible(error.message, error.details ? { details: error.details } : {});
  } finally {
    await harness.close().catch(() => {});
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const receipt = {
    kind: 'lynceuz_macos_containment_receipt',
    schema_version: 1,
    status: 'ready',
    backend: expected.backend,
    generated_at: nowIso,
    uid: { name: system.uid.name, uid: system.uid.uid, gid: system.uid.gid },
    guard_proxy: { host: expected.guard_proxy_host, port: expected.guard_proxy_port },
    pf: {
      anchor_name: system.pf.anchor_name,
      anchor_path: system.pf.anchor_path,
      anchor_sha256: system.pf.anchor_sha256,
      rules_sha256: system.pf.rules_sha256,
    },
    source_hashes: expected.source_hashes,
    suite_hashes: expected.suite_hashes,
    boot_session: system.boot_session,
    reboot_verified: system.pf.active === true,
    reboot_verified_at: nowIso,
    canary,
  };

  // Never emit a receipt we cannot honestly stand behind: run it through the real verifier first.
  const verdict = await verifyMacosContainmentReceipt({
    receipt, expected, system, canary, now: () => now.getTime(),
  });
  if (verdict.state !== 'ready') return impossible(verdict.reason, verdict.details ? { details: verdict.details } : {});

  try {
    await writeReceipt(receipt);
  } catch {
    return impossible('containment_receipt_write_failed');
  }
  emit('ready', 'containment_ready', { receipt_path: RECEIPT_PATH });
  return 0;
}

async function main() {
  if (process.argv.slice(2).length !== 0) return impossible('invalid_input');
  return runParentMode();
}

// Only auto-run when invoked directly; importing this module (e.g. from the eval suite) must be
// side-effect free so `renderCanaryClientSource` can be exercised without a root parent run.
function invokedDirectly() {
  try {
    return Boolean(process.argv[1]) && realpathSync(process.argv[1]) === realpathSync(SELF);
  } catch {
    return false;
  }
}

if (invokedDirectly()) {
  process.exitCode = await main();
}
