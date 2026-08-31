import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { access, lstat, readFile, realpath } from 'node:fs/promises';
import { arch, platform } from 'node:os';
import { basename, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CAPABILITY_STATE, deepFreeze } from './contracts.mjs';
import { verifyMacosContainmentReceipt } from './macos-containment.mjs';

const LOOPBACK = '127.0.0.1';
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_TUNNELS = 8;
const DEADLINE_MS = 15_000;
const MAX_PROOF_BYTES = 128 * 1024;
const MAX_PROOF_AGE_MS = 7 * 24 * 60 * 60 * 1_000;
const HOSTILE_CHANNELS = Object.freeze([
  'navigation', 'redirect', 'iframe', 'popup', 'worker', 'service_worker',
  'websocket', 'webrtc_udp', 'webtransport', 'quic',
]);
const CONTAINMENT_CHANNELS = Object.freeze(['TCP', 'UDP', 'QUIC']);
const REQUIRED_CHANNELS = Object.freeze([...HOSTILE_CHANNELS, ...CONTAINMENT_CHANNELS]);
const HOSTILE_SUITES = Object.freeze([
  'evals/browser-hostile.test.mjs',
  'evals/router.test.mjs',
  'evals/p0-acceptance.test.mjs',
]);
const REQUIRED_SUITES = Object.freeze([
  ...HOSTILE_SUITES,
  'evals/browser-containment.test.mjs',
]);
const SHA256 = /^sha256:[0-9a-f]{64}$/u;
const LEGACY_PASSED_PROOF_KEYS = Object.freeze([
  'arch', 'channels', 'fingerprint', 'generated_at', 'kind', 'marker_hash',
  'platform', 'reason', 'runtime', 'schema_version', 'source_hashes', 'status', 'suites',
]);
const PASSED_PROOF_KEYS = Object.freeze([
  ...LEGACY_PASSED_PROOF_KEYS, 'containment', 'containment_state',
]);
const CONTAINMENT_KEYS = Object.freeze([
  'anchor', 'backend', 'boot_session', 'guard_proxy', 'negative_control_required',
  'reboot_verified', 'reboot_verified_at', 'source_hashes', 'system_receipt_hash', 'uid',
  'wave2_suite_hash',
]);
const SAFE_RESPONSE_HEADERS = new Set([
  'cache-control', 'content-encoding', 'content-language', 'content-length',
  'content-type', 'etag', 'last-modified',
]);
const SAFE_REQUEST_HEADERS = new Set([
  'accept', 'accept-encoding', 'if-modified-since', 'if-none-match', 'user-agent',
]);
const SOURCE_PATHS = Object.freeze({
  guard_proxy: fileURLToPath(new URL('./browser-security.mjs', import.meta.url)),
  network: fileURLToPath(new URL('./network.mjs', import.meta.url)),
  adapter: fileURLToPath(new URL('./adapters/playwright.mjs', import.meta.url)),
  helper: fileURLToPath(new URL('./lynceuz-browser.py', import.meta.url)),
  cli: fileURLToPath(new URL('./cli.mjs', import.meta.url)),
  core: fileURLToPath(new URL('./core.mjs', import.meta.url)),
  router: fileURLToPath(new URL('./router.mjs', import.meta.url)),
  gate: fileURLToPath(new URL('../scripts/p1-browser-gate.mjs', import.meta.url)),
  hostile_suite: fileURLToPath(new URL('../evals/browser-hostile.test.mjs', import.meta.url)),
  router_suite: fileURLToPath(new URL('../evals/router.test.mjs', import.meta.url)),
  p0_suite: fileURLToPath(new URL('../evals/p0-acceptance.test.mjs', import.meta.url)),
  direct_probe: fileURLToPath(new URL('../evals/fixtures/direct-egress-probe.py', import.meta.url)),
  macos_containment: fileURLToPath(new URL('./macos-containment.mjs', import.meta.url)),
  containment_canary: fileURLToPath(new URL('../evals/fixtures/pf-containment-canary.mjs', import.meta.url)),
  wave2_manifest: fileURLToPath(new URL('../evals/fixtures/wave2-suite-manifest.json', import.meta.url)),
});

function frozen(value) {
  return deepFreeze(value);
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function proofIntegrityPayload(proof) {
  const payload = {
    kind: proof.kind,
    schema_version: proof.schema_version,
    status: proof.status,
    reason: proof.reason,
    fingerprint: proof.fingerprint,
    generated_at: proof.generated_at,
    platform: proof.platform,
    arch: proof.arch,
    runtime: proof.runtime,
    source_hashes: proof.source_hashes,
    channels: proof.channels,
    suites: proof.suites,
  };
  if (Object.hasOwn(proof, 'containment')) payload.containment = proof.containment;
  if (Object.hasOwn(proof, 'containment_state')) payload.containment_state = proof.containment_state;
  return payload;
}

export function createBrowserProofIntegrity(proof) {
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) {
    throw new TypeError('browser proof is invalid');
  }
  return sha256(stableJson(proofIntegrityPayload(proof)));
}

function equalToken(actual, expected) {
  if (typeof actual !== 'string') return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}

function plainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, keys) {
  return plainObject(value)
    && stableJson(Object.keys(value).sort()) === stableJson([...keys].sort());
}

function validContainmentEvidence(value) {
  return exactKeys(value, CONTAINMENT_KEYS)
    && value.backend === 'pf_uid_anchor_guardproxy'
    && SHA256.test(value.system_receipt_hash)
    && exactKeys(value.uid, ['gid', 'name', 'uid'])
    && typeof value.uid.name === 'string' && value.uid.name.length > 0
    && Number.isSafeInteger(value.uid.uid) && value.uid.uid > 0
    && Number.isSafeInteger(value.uid.gid) && value.uid.gid > 0
    && exactKeys(value.guard_proxy, ['host', 'port'])
    && value.guard_proxy.host === LOOPBACK
    && Number.isSafeInteger(value.guard_proxy.port)
    && value.guard_proxy.port > 0 && value.guard_proxy.port <= 65_535
    && exactKeys(value.anchor, ['anchor_name', 'anchor_path', 'anchor_sha256', 'rules_sha256'])
    && typeof value.anchor.anchor_name === 'string' && value.anchor.anchor_name.length > 0
    && typeof value.anchor.anchor_path === 'string' && isAbsolute(value.anchor.anchor_path)
    && SHA256.test(value.anchor.anchor_sha256) && SHA256.test(value.anchor.rules_sha256)
    && typeof value.boot_session === 'string' && value.boot_session.length > 0
    && value.reboot_verified === true
    && Number.isFinite(Date.parse(value.reboot_verified_at))
    && plainObject(value.source_hashes) && Object.keys(value.source_hashes).length > 0
    && Object.values(value.source_hashes).every((hash) => SHA256.test(hash))
    && SHA256.test(value.wave2_suite_hash)
    && value.negative_control_required === true;
}

function proxyToken(headers) {
  const value = headers['proxy-authorization'];
  if (typeof value !== 'string' || value.length > 512) return null;
  if (value.startsWith('Bearer ')) return value.slice(7);
  if (!value.startsWith('Basic ')) return null;
  let decoded;
  try { decoded = Buffer.from(value.slice(6), 'base64').toString('utf8'); } catch { return null; }
  const separator = decoded.indexOf(':');
  return separator === -1 ? null : decoded.slice(separator + 1);
}

function safeHeaders(headers) {
  const result = {};
  for (const [name, raw] of Object.entries(headers ?? {})) {
    const lower = name.toLowerCase();
    const value = Array.isArray(raw) ? raw[0] : raw;
    if (SAFE_REQUEST_HEADERS.has(lower) && typeof value === 'string'
        && Buffer.byteLength(value) <= 8 * 1024 && !/[\r\n\0]/u.test(value)) {
      result[lower] = value;
    }
  }
  return result;
}

function responseHeaders(headers) {
  const result = {};
  let total = 0;
  for (const [name, raw] of Object.entries(headers ?? {})) {
    const lower = name.toLowerCase();
    const value = Array.isArray(raw) ? raw.join(', ') : String(raw);
    const bytes = Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
    if (SAFE_RESPONSE_HEADERS.has(lower) && bytes <= 8 * 1024 && total + bytes <= MAX_HEADER_BYTES
        && !/[\r\n\0]/u.test(value)) {
      result[name] = value;
      total += bytes;
    }
  }
  return result;
}

function writeProxyError(socket, status, message) {
  if (!socket || socket.destroyed) return;
  const body = `${message}\n`;
  socket.end(
    `HTTP/1.1 ${status}\r\nContent-Type: text/plain; charset=utf-8\r\n`
    + `Content-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
  );
}

function parseConnectAuthority(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512
      || /[\s\0]/u.test(value)) return null;
  try {
    const url = new URL(`https://${value}/`);
    if (url.username || url.password || Number(url.port || 443) !== 443) return null;
    return url;
  } catch {
    return null;
  }
}

export async function createGuardProxy({
  gateway,
  token = randomBytes(32).toString('base64url'),
  limits = {},
} = {}) {
  if (!gateway || typeof gateway.execute !== 'function'
      || typeof gateway.openAuthorizedTunnel !== 'function') {
    throw new TypeError('GuardProxy requires the EgressGateway');
  }
  if (typeof token !== 'string' || token.length < 32 || token.length > 256) {
    throw new TypeError('GuardProxy token is invalid');
  }
  const maxBytes = Number.isSafeInteger(limits.maxBytes) && limits.maxBytes > 0
    ? Math.min(limits.maxBytes, MAX_RESPONSE_BYTES)
    : MAX_RESPONSE_BYTES;
  const deadlineMs = Number.isSafeInteger(limits.deadlineMs) && limits.deadlineMs > 0
    ? Math.min(limits.deadlineMs, DEADLINE_MS)
    : DEADLINE_MS;
  const sockets = new Set();
  const stats = { authorizedRequests: 0, deniedRequests: 0, openedTunnels: 0, bytes: 0 };
  let activeTunnels = 0;
  let closed = false;

  const server = createServer({ maxHeaderSize: MAX_HEADER_BYTES }, async (request, response) => {
    const supplied = proxyToken(request.headers);
    if (!equalToken(supplied, token)) {
      stats.deniedRequests += 1;
      response.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="Lynceuz"', Connection: 'close' });
      response.end();
      return;
    }
    if (!['GET', 'HEAD'].includes(request.method)
        || typeof request.url !== 'string' || !/^https?:\/\//u.test(request.url)
        || request.headers['content-length'] !== undefined || request.headers['transfer-encoding'] !== undefined) {
      response.writeHead(405, { Connection: 'close' });
      response.end();
      return;
    }
    let target;
    try {
      target = new URL(request.url);
      if (target.username || target.password) throw new Error('credentials');
    } catch {
      response.writeHead(400, { Connection: 'close' });
      response.end();
      return;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('GuardProxy deadline')), deadlineMs);
    timer.unref?.();
    try {
      const upstream = await gateway.execute({
        runId: 'browser-guard-proxy',
        purpose: 'subresource',
        url: target.href,
        method: request.method,
        headers: safeHeaders(request.headers),
        remaining: { wallMs: deadlineMs, bytes: maxBytes, redirects: 5 },
      }, { signal: controller.signal });
      stats.authorizedRequests += 1;
      response.writeHead(upstream.statusCode, responseHeaders(upstream.headers));
      let consumed = 0;
      const abortBody = () => {
        upstream.body.destroy?.(controller.signal.reason ?? new Error('GuardProxy aborted'));
        response.destroy();
      };
      controller.signal.addEventListener('abort', abortBody, { once: true });
      upstream.body.on('data', (chunk) => {
        consumed += Buffer.byteLength(chunk);
        stats.bytes += Buffer.byteLength(chunk);
        if (consumed > maxBytes) {
          controller.abort(new Error('GuardProxy byte limit'));
          upstream.body.destroy?.();
          response.destroy();
        }
      });
      upstream.body.once('error', () => response.destroy());
      upstream.body.pipe(response);
      await Promise.race([once(response, 'finish'), once(response, 'close')]);
      controller.signal.removeEventListener('abort', abortBody);
    } catch {
      if (!response.headersSent) response.writeHead(502, { Connection: 'close' });
      response.end();
    } finally {
      clearTimeout(timer);
    }
  });
  server.headersTimeout = deadlineMs;
  server.requestTimeout = deadlineMs;
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  server.on('connect', async (request, client, head) => {
    if (!equalToken(proxyToken(request.headers), token)) {
      stats.deniedRequests += 1;
      writeProxyError(client, '407 Proxy Authentication Required', 'proxy authentication required');
      return;
    }
    const target = parseConnectAuthority(request.url);
    if (!target || head.length > 0 || activeTunnels >= MAX_TUNNELS) {
      writeProxyError(client, '400 Bad Request', 'invalid tunnel request');
      return;
    }
    activeTunnels += 1;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('GuardProxy tunnel deadline')), deadlineMs);
    timer.unref?.();
    try {
      const opened = await gateway.openAuthorizedTunnel({
        runId: 'browser-guard-proxy',
        purpose: 'subresource',
        url: target.href,
        method: 'GET',
        headers: {},
        remaining: { wallMs: deadlineMs, bytes: maxBytes, redirects: 0 },
      }, { signal: controller.signal });
      stats.authorizedRequests += 1;
      stats.openedTunnels += 1;
      const abortTunnel = () => {
        client.destroy(controller.signal.reason);
        opened.socket.destroy(controller.signal.reason);
      };
      controller.signal.addEventListener('abort', abortTunnel, { once: true });
      let consumed = 0;
      const account = (chunk) => {
        consumed += Buffer.byteLength(chunk);
        stats.bytes += Buffer.byteLength(chunk);
        if (consumed > maxBytes) {
          client.destroy();
          opened.socket.destroy();
        }
      };
      client.on('data', account);
      opened.socket.on('data', account);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      opened.socket.once('error', () => client.destroy());
      client.once('error', () => opened.socket.destroy());
      client.pipe(opened.socket);
      opened.socket.pipe(client);
      await Promise.race([once(client, 'close'), once(opened.socket, 'close')]);
      controller.signal.removeEventListener('abort', abortTunnel);
      client.destroy();
      opened.socket.destroy();
    } catch {
      writeProxyError(client, '502 Bad Gateway', 'tunnel unavailable');
    } finally {
      clearTimeout(timer);
      activeTunnels -= 1;
    }
  });
  server.listen(0, LOOPBACK);
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string' || address.address !== LOOPBACK) {
    server.close();
    throw new Error('GuardProxy did not bind IPv4 loopback');
  }

  return Object.freeze({
    host: LOOPBACK,
    port: address.port,
    token,
    stats,
    async close() {
      if (closed) return;
      closed = true;
      for (const socket of sockets) socket.destroy();
      const closedEvent = server.listening ? once(server, 'close') : Promise.resolve();
      server.close();
      await closedEvent;
    },
  });
}

function sandboxProfile(proxyPort) {
  return `(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote tcp "localhost:${proxyPort}"))\n`;
}

export async function createChildEgressSandbox({
  proxyPort,
  platformName = platform(),
  sandboxPath = '/usr/bin/sandbox-exec',
  probeScript,
} = {}) {
  if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
    throw new TypeError('sandbox proxy port is invalid');
  }
  if (probeScript !== undefined && (typeof probeScript !== 'string' || !isAbsolute(probeScript))) {
    throw new TypeError('sandbox probe path is invalid');
  }
  const profile = sandboxProfile(proxyPort);
  const base = {
    state: CAPABILITY_STATE.UNAVAILABLE_SECURITY_GATE,
    proofEligible: false,
    profileHash: sha256(profile),
    executable: sandboxPath,
  };
  if (platformName !== 'darwin') {
    return frozen({ ...base, reason: 'sandbox_platform_unsupported' });
  }
  try {
    await access(sandboxPath);
  } catch {
    return frozen({ ...base, reason: 'sandbox_executable_missing' });
  }
  // sandbox-exec accepts only `localhost`, not a numeric loopback address. On current Darwin,
  // that selector also matches the host's non-loopback addresses, so lo0-only egress cannot
  // be proven even when the direct TCP/UDP canaries pass. Keep the launcher unavailable.
  return frozen({ ...base, reason: 'sandbox_loopback_scope_unproven' });
}

export async function createPfContainmentBackend({
  receipt,
  expected,
  system,
  runner,
  canary,
  now,
  pythonPath,
  helperPath = fileURLToPath(new URL('./lynceuz-browser.py', import.meta.url)),
} = {}) {
  const fallback = {
    state: CAPABILITY_STATE.UNAVAILABLE_SECURITY_GATE,
    proofEligible: false,
    reason: receipt == null ? 'sandbox_loopback_scope_unproven' : 'containment_receipt_invalid',
  };
  if (receipt == null) return frozen(fallback);

  const verification = await verifyMacosContainmentReceipt({
    receipt, expected, system, runner, canary, ...(now ? { now } : {}),
  });
  if (verification.state !== CAPABILITY_STATE.READY) {
    return frozen({ ...fallback, reason: verification.reason });
  }
  if (typeof pythonPath !== 'string' || !isAbsolute(pythonPath)
      || typeof helperPath !== 'string' || !isAbsolute(helperPath)) {
    return frozen({ ...fallback, reason: 'containment_launch_unavailable' });
  }
  try {
    await Promise.all([access(pythonPath), access(helperPath), access('/usr/bin/sudo')]);
  } catch {
    return frozen({ ...fallback, reason: 'containment_launch_unavailable' });
  }

  const launchPlan = frozen({
    kind: 'lynceuz_macos_containment_launch_plan',
    executable: '/usr/bin/sudo',
    argv: ['-n', '-u', `#${receipt.uid.uid}`, '--', pythonPath, '-I', helperPath],
    uid: receipt.uid.uid,
    gid: receipt.uid.gid,
    guard_proxy: { host: receipt.guard_proxy.host, port: receipt.guard_proxy.port },
    env: { LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PYTHONNOUSERSITE: '1' },
    shell: false,
  });
  return frozen({
    state: CAPABILITY_STATE.READY,
    proofEligible: true,
    reason: 'containment_ready',
    backend: 'pf_uid_anchor_guardproxy',
    launch: () => launchPlan,
  });
}

export async function computeBrowserFingerprint({
  sourcePaths = SOURCE_PATHS,
  runtime,
  fingerprintRuntime,
  containment,
} = {}) {
  if (!sourcePaths || typeof sourcePaths !== 'object' || Array.isArray(sourcePaths)) {
    throw new TypeError('fingerprint source paths are invalid');
  }
  const resolvedRuntime = runtime ?? fingerprintRuntime ?? {
    platform: platform(),
    arch: arch(),
    node: process.version,
    python: 'unprobed',
    playwright: 'unprobed',
    chromium: 'unprobed',
    containment: '/usr/bin/sandbox-exec',
    profile: 'sandbox_loopback_scope_unproven',
  };
  const sources = {};
  for (const name of Object.keys(sourcePaths).sort()) {
    const path = sourcePaths[name];
    if (typeof path !== 'string' || path.length === 0) throw new TypeError('fingerprint path is invalid');
    let bytes;
    try { bytes = await readFile(path); } catch { bytes = Buffer.from('missing'); }
    sources[name] = { path: basename(path), hash: sha256(bytes) };
  }
  if (containment !== undefined && !validContainmentEvidence(containment)) {
    throw new TypeError('fingerprint containment evidence is invalid');
  }
  const payload = {
    schema_version: containment === undefined && sourcePaths !== SOURCE_PATHS ? 1 : 2,
    runtime: resolvedRuntime,
    sources,
    ...(containment === undefined ? {} : { containment }),
  };
  return frozen({ ...payload, digest: sha256(stableJson(payload)) });
}

export async function verifyBrowserSecurityProof({
  dataRoot,
  fingerprint,
  now = Date.now,
  maxAgeMs = MAX_PROOF_AGE_MS,
} = {}) {
  if (typeof dataRoot !== 'string' || basename(resolve(dataRoot)) !== '.lynceuz'
      || !fingerprint || typeof fingerprint.digest !== 'string') {
    return frozen({ valid: false, reason: 'proof_input_invalid', fingerprint: null });
  }
  const proofPath = join(resolve(dataRoot), 'security/browser-proof-v1.json');
  let bytes;
  try {
    const info = await lstat(proofPath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_PROOF_BYTES) {
      return frozen({ valid: false, reason: 'proof_corrupt', fingerprint: null });
    }
    const root = await realpath(resolve(dataRoot));
    const file = await realpath(proofPath);
    if (!file.startsWith(`${root}/`)) return frozen({ valid: false, reason: 'proof_corrupt', fingerprint: null });
    bytes = await readFile(file);
  } catch {
    return frozen({ valid: false, reason: 'proof_missing', fingerprint: null });
  }
  let proof;
  try { proof = JSON.parse(bytes); } catch {
    return frozen({ valid: false, reason: 'proof_corrupt', fingerprint: null });
  }
  if (proof && typeof proof === 'object' && !Array.isArray(proof)
      && typeof proof.fingerprint === 'string'
      && proof.fingerprint !== fingerprint.digest) {
    return frozen({ valid: false, reason: 'fingerprint_mismatch', fingerprint: proof.fingerprint });
  }
  const proofKeys = proof && typeof proof === 'object' && !Array.isArray(proof)
    ? Object.keys(proof).sort()
    : [];
  const channelKeys = proof?.channels && typeof proof.channels === 'object'
    && !Array.isArray(proof.channels) ? Object.keys(proof.channels).sort() : [];
  const containmentBound = fingerprint.schema_version === 2;
  const expectedProofKeys = containmentBound ? PASSED_PROOF_KEYS : LEGACY_PASSED_PROOF_KEYS;
  const expectedChannels = containmentBound ? REQUIRED_CHANNELS : HOSTILE_CHANNELS;
  const expectedSuites = containmentBound ? REQUIRED_SUITES : HOSTILE_SUITES;
  const sourceMatch = stableJson(proof?.source_hashes) === stableJson(fingerprint.sources);
  const runtimeMatch = stableJson(proof?.runtime) === stableJson(fingerprint.runtime);
  const containmentMatch = !containmentBound
    || (validContainmentEvidence(fingerprint.containment)
      && proof?.containment_state === CAPABILITY_STATE.READY
      && validContainmentEvidence(proof?.containment)
      && stableJson(proof.containment) === stableJson(fingerprint.containment));
  const suites = Array.isArray(proof?.suites) ? proof.suites : [];
  const suiteNames = suites.map((suite) => suite?.suite);
  const validSuites = suites.length === expectedSuites.length
    && new Set(suiteNames).size === expectedSuites.length
    && expectedSuites.every((suite) => suiteNames.includes(suite))
    && suites.every((suite) => {
      const keys = suite && typeof suite === 'object' && !Array.isArray(suite)
        ? Object.keys(suite).sort()
        : [];
      return stableJson(keys) === stableJson([
        'duration_ms', 'exit_code', 'passed', 'signal', 'skipped', 'stderr_hash',
        'stdout_hash', 'suite',
      ])
        && suite.passed === true && suite.skipped === false
        && suite.exit_code === 0 && suite.signal === null
        && Number.isSafeInteger(suite.duration_ms) && suite.duration_ms >= 0
        && SHA256.test(suite.stdout_hash) && SHA256.test(suite.stderr_hash);
    });
  let markerMatches = false;
  try {
    markerMatches = SHA256.test(proof?.marker_hash)
      && proof.marker_hash === createBrowserProofIntegrity(proof);
  } catch {}
  if (!proof || stableJson(proofKeys) !== stableJson([...expectedProofKeys].sort())
      || proof.kind !== 'browser_security_proof' || proof.schema_version !== 1
      || proof.status !== 'passed' || proof.reason !== 'proof_valid'
      || proof.platform !== fingerprint.runtime?.platform || proof.arch !== fingerprint.runtime?.arch
      || !runtimeMatch || !sourceMatch || !containmentMatch || !validSuites || !markerMatches
      || stableJson(channelKeys) !== stableJson([...expectedChannels].sort())
      || expectedChannels.some((channel) => proof.channels[channel] !== true)) {
    return frozen({ valid: false, reason: 'proof_failed_or_incomplete', fingerprint: null });
  }
  const generated = typeof proof.generated_at === 'string' ? Date.parse(proof.generated_at) : Number.NaN;
  const current = Number(now());
  if (!Number.isFinite(generated) || !Number.isFinite(current)
      || generated > current + 5 * 60_000 || current - generated > maxAgeMs) {
    return frozen({ valid: false, reason: 'proof_stale', fingerprint: proof.fingerprint });
  }
  return frozen({ valid: true, reason: 'proof_valid', fingerprint: proof.fingerprint, proof });
}

export function browserCapabilityState({ id, installed, version, allowRendered, proof } = {}) {
  if (typeof id !== 'string' || !id) throw new TypeError('browser capability id is required');
  const common = { id, version: typeof version === 'string' ? version : null };
  if (!installed) return frozen({ ...common, state: CAPABILITY_STATE.MISSING, reason: 'engine_missing' });
  if (id !== 'playwright') {
    return frozen({ ...common, state: CAPABILITY_STATE.UNAVAILABLE_SECURITY_GATE, reason: 'independent_security_proof_missing' });
  }
  if (!proof?.valid) {
    return frozen({
      ...common,
      state: CAPABILITY_STATE.UNAVAILABLE_SECURITY_GATE,
      reason: proof?.reason ?? 'proof_missing',
      proofFingerprint: proof?.fingerprint ?? null,
    });
  }
  if (allowRendered !== true) {
    return frozen({
      ...common,
      state: CAPABILITY_STATE.DISABLED,
      reason: 'rendered_not_allowed',
      proofFingerprint: proof.fingerprint,
      enable_with: '--allow-rendered',
    });
  }
  return frozen({
    ...common,
    state: CAPABILITY_STATE.READY,
    reason: 'browser_security_proof_valid',
    proofFingerprint: proof.fingerprint,
  });
}

export {
  HOSTILE_CHANNELS as REQUIRED_BROWSER_PROOF_CHANNELS,
  REQUIRED_CHANNELS as REQUIRED_CONTAINMENT_PROOF_CHANNELS,
};
