import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const READY = 'ready';
const UNAVAILABLE = 'unavailable_security_gate';
const HASH = /^sha256:[a-f0-9]{64}$/u;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const CHANNELS = Object.freeze(['proxy_tcp', 'direct_tcp', 'udp', 'quic']);
const RECEIPT_KEYS = Object.freeze([
  'backend', 'boot_session', 'canary', 'generated_at', 'guard_proxy', 'kind', 'pf',
  'reboot_verified', 'reboot_verified_at', 'schema_version', 'source_hashes', 'status',
  'suite_hashes', 'uid',
]);
const RUN_OPTIONS = Object.freeze({
  encoding: 'utf8',
  env: Object.freeze({ LANG: 'C', LC_ALL: 'C' }),
  maxBuffer: 256 * 1024,
  shell: false,
  timeout: 5_000,
});

function unavailable(reason, details = undefined) {
  return Object.freeze({ state: UNAVAILABLE, reason, ...(details ? { details } : {}) });
}

function plainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, keys) {
  return plainObject(value)
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function validText(value, max = 512) {
  return typeof value === 'string' && value.length > 0 && value.length <= max
    && !/[\0\r\n]/u.test(value);
}

function validHashes(value, expected) {
  if (!plainObject(value) || !plainObject(expected)) return false;
  const keys = Object.keys(expected).sort();
  return keys.length > 0 && keys.length <= 32
    && exactKeys(value, keys)
    && keys.every((key) => validText(key, 128) && HASH.test(value[key]) && value[key] === expected[key]);
}

function validObservation(value, channel) {
  return exactKeys(value, ['channel', 'operation_succeeded', 'response', 'response_confirmed'])
    && value.channel === channel
    && typeof value.operation_succeeded === 'boolean'
    && (value.response === null || validText(value.response, 256))
    && typeof value.response_confirmed === 'boolean'
    && (!value.response_confirmed || value.response !== null);
}

function validCanaryShape(value) {
  if (!exactKeys(value, [
    'detected_channels', 'exit_code', 'observations', 'passed', 'reason', 'status',
  ])) return false;
  if (!Array.isArray(value.detected_channels) || value.detected_channels.length > CHANNELS.length
      || !value.detected_channels.every((channel) => CHANNELS.includes(channel))
      || !Number.isSafeInteger(value.exit_code) || value.exit_code < 0 || value.exit_code > 255
      || typeof value.passed !== 'boolean' || !validText(value.reason)
      || !validText(value.status, 64) || !exactKeys(value.observations, CHANNELS)) return false;
  return CHANNELS.every((channel) => validObservation(value.observations[channel], channel));
}

function canaryPassed(value) {
  return validCanaryShape(value)
    && value.passed === true
    && value.status === 'passed'
    && value.reason === 'containment_canary_passed'
    && value.exit_code === 0
    && value.detected_channels.length === 0
    && value.observations.proxy_tcp.response_confirmed === true
    && ['direct_tcp', 'udp', 'quic'].every(
      (channel) => value.observations[channel].response_confirmed === false,
    );
}

function validExpected(expected) {
  return plainObject(expected)
    && expected.backend === 'pf_uid_anchor_guardproxy'
    && validText(expected.uid_name, 64)
    && Number.isSafeInteger(expected.uid) && expected.uid > 0
    && Number.isSafeInteger(expected.gid) && expected.gid > 0
    && expected.guard_proxy_host === '127.0.0.1'
    && Number.isSafeInteger(expected.guard_proxy_port)
    && expected.guard_proxy_port > 0 && expected.guard_proxy_port <= 65_535
    && validText(expected.anchor_name, 128)
    && validText(expected.anchor_path, 512) && expected.anchor_path.startsWith('/')
    && HASH.test(expected.anchor_sha256)
    && HASH.test(expected.rules_sha256)
    && validHashes(expected.source_hashes, expected.source_hashes)
    && validHashes(expected.suite_hashes, expected.suite_hashes);
}

function validReceiptShape(receipt) {
  return exactKeys(receipt, RECEIPT_KEYS)
    && receipt.kind === 'lynceuz_macos_containment_receipt'
    && receipt.schema_version === 1
    && receipt.status === READY
    && validText(receipt.backend, 64)
    && ISO.test(receipt.generated_at)
    && exactKeys(receipt.uid, ['gid', 'name', 'uid'])
    && validText(receipt.uid.name, 64)
    && Number.isSafeInteger(receipt.uid.uid) && receipt.uid.uid > 0
    && Number.isSafeInteger(receipt.uid.gid) && receipt.uid.gid > 0
    && exactKeys(receipt.guard_proxy, ['host', 'port'])
    && receipt.guard_proxy.host === '127.0.0.1'
    && Number.isSafeInteger(receipt.guard_proxy.port)
    && receipt.guard_proxy.port > 0 && receipt.guard_proxy.port <= 65_535
    && exactKeys(receipt.pf, ['anchor_name', 'anchor_path', 'anchor_sha256', 'rules_sha256'])
    && validText(receipt.pf.anchor_name, 128)
    && validText(receipt.pf.anchor_path, 512) && receipt.pf.anchor_path.startsWith('/')
    && HASH.test(receipt.pf.anchor_sha256)
    && HASH.test(receipt.pf.rules_sha256)
    && validText(receipt.boot_session, 512)
    && typeof receipt.reboot_verified === 'boolean'
    && ISO.test(receipt.reboot_verified_at)
    && validCanaryShape(receipt.canary)
    && plainObject(receipt.source_hashes)
    && plainObject(receipt.suite_hashes);
}

function receiptMatchesExpected(receipt, expected) {
  return receipt.backend === expected.backend
    && receipt.uid.name === expected.uid_name
    && receipt.uid.uid === expected.uid
    && receipt.uid.gid === expected.gid
    && receipt.guard_proxy.host === expected.guard_proxy_host
    && receipt.guard_proxy.port === expected.guard_proxy_port
    && receipt.pf.anchor_name === expected.anchor_name
    && receipt.pf.anchor_path === expected.anchor_path
    && receipt.pf.anchor_sha256 === expected.anchor_sha256
    && receipt.pf.rules_sha256 === expected.rules_sha256
    && validHashes(receipt.source_hashes, expected.source_hashes)
    && validHashes(receipt.suite_hashes, expected.suite_hashes);
}

export function safeRules(text, expected) {
  if (typeof text !== 'string' || text.length === 0 || text.length > 256 * 1024
      || /^\s*set\s+skip\s+on\s+lo0\b/imu.test(text)) return false;
  const lines = text.split(/\r?\n/u)
    .map((line) => line.replace(/#.*$/u, '').trim())
    .filter(Boolean);
  const pass = lines.filter((line) => /^pass\b/iu.test(line));
  const uid = String(expected.uid).replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const port = String(expected.guard_proxy_port);
  // Real pfctl prints `port = <port>` / `user = <uid>`, places `user` at the end of the
  // line, and appends a `flags ... keep state` tail. The older middle-`user` form (and the
  // spelling without `=`) stays accepted; the destination is still pinned to 127.0.0.1:<port>.
  const dstOld = `from\\s+any\\s+user\\s*=?\\s*${uid}\\s+to\\s+127\\.0\\.0\\.1\\s+port\\s*=?\\s*${port}`;
  const dstNew = `from\\s+any\\s+to\\s+127\\.0\\.0\\.1\\s+port\\s*=?\\s*${port}\\s+user\\s*=?\\s*${uid}`;
  const tail = '(?:\\s+flags\\s+\\S+)?(?:\\s+(?:keep|modulate)\\s+state)?';
  const allowed = new RegExp(
    `^pass\\s+(?:(?:out|quick|on\\s+lo0)\\s+)*inet\\s+proto\\s+tcp\\s+(?:${dstOld}|${dstNew})${tail}$`,
    'iu',
  );
  if (pass.length !== 1 || !allowed.test(pass[0]) || !/\bquick\b/iu.test(pass[0])) return false;
  // Blocks: the real `inet all user = <uid>` shorthand alongside the old `inet from any user <uid> to any`.
  const blockFor = (family) => new RegExp(
    `^block\\s+drop\\s+(?:(?:out|quick)\\s+)*${family}\\s+(?:from\\s+any\\s+user\\s*=?\\s*${uid}\\s+to\\s+any|all\\s+user\\s*=?\\s*${uid})$`,
    'iu',
  );
  const block4 = blockFor('inet');
  const block6 = blockFor('inet6');
  return lines.some((line) => block4.test(line) && /\bquick\b/iu.test(line))
    && lines.some((line) => block6.test(line) && /\bquick\b/iu.test(line));
}

function sha256(value) {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function defaultRunner(executable, argv, options) {
  return spawnSync(executable, argv, options);
}

async function runReadOnly(runner, executable, argv) {
  let result;
  try {
    result = await runner(executable, Object.freeze([...argv]), RUN_OPTIONS);
  } catch (error) {
    throw Object.assign(new Error('read_only_command_unavailable'), { cause: error });
  }
  if (!plainObject(result) || result.status !== 0 || result.signal != null || result.error) {
    throw new Error('read_only_command_unavailable');
  }
  const stdout = typeof result.stdout === 'string'
    ? result.stdout
    : Buffer.isBuffer(result.stdout) ? result.stdout.toString('utf8') : '';
  const stderr = typeof result.stderr === 'string'
    ? result.stderr
    : Buffer.isBuffer(result.stderr) ? result.stderr.toString('utf8') : '';
  if (Buffer.byteLength(stdout) > RUN_OPTIONS.maxBuffer
      || Buffer.byteLength(stderr) > RUN_OPTIONS.maxBuffer) {
    throw new Error('read_only_command_output_limit');
  }
  return stdout.trim();
}

// Root reads PF facts directly. A non-root gate reads the SAME two calls through a
// password-less, no-exec sudo path (ops/macos/sudoers/lynceuz-browser). If `sudo -n` is
// denied, runReadOnly throws like any other failure and the caller stays fail-closed.
function pfctlReader(geteuid) {
  const asRoot = typeof geteuid === 'function' && geteuid() === 0;
  return (argv) => asRoot
    ? { executable: '/sbin/pfctl', argv }
    : { executable: '/usr/bin/sudo', argv: ['-n', '/sbin/pfctl', ...argv] };
}

export async function inspectMacosContainment({
  expected, runner = defaultRunner, geteuid = typeof process.geteuid === 'function' ? () => process.geteuid() : undefined,
} = {}) {
  if (!validExpected(expected) || typeof runner !== 'function') {
    return unavailable('containment_configuration_invalid');
  }
  const pfctl = pfctlReader(geteuid);
  const pfInfoCall = pfctl(['-s', 'info']);
  const rulesCall = pfctl(['-a', expected.anchor_name, '-sr']);
  try {
    const [uidText, gidText, pfInfo, rulesText, bootSession, anchorHashText] = await Promise.all([
      runReadOnly(runner, '/usr/bin/id', ['-u', expected.uid_name]),
      runReadOnly(runner, '/usr/bin/id', ['-g', expected.uid_name]),
      runReadOnly(runner, pfInfoCall.executable, pfInfoCall.argv),
      runReadOnly(runner, rulesCall.executable, rulesCall.argv),
      runReadOnly(runner, '/usr/sbin/sysctl', ['-n', 'kern.boottime']),
      runReadOnly(runner, '/usr/bin/shasum', ['-a', '256', expected.anchor_path]),
    ]);
    const uid = Number(uidText);
    const gid = Number(gidText);
    const anchorDigest = /^([a-f0-9]{64})(?:\s|$)/u.exec(anchorHashText)?.[1];
    if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0
        || !anchorDigest || !bootSession) throw new Error('read_only_command_parse_failed');
    return Object.freeze({
      uid: Object.freeze({ name: expected.uid_name, uid, gid, dedicated: true }),
      pf: Object.freeze({
        active: /(?:^|\n)Status:\s+Enabled(?:\s|$)|^Enabled$/imu.test(pfInfo),
        anchor_name: expected.anchor_name,
        anchor_path: expected.anchor_path,
        anchor_sha256: `sha256:${anchorDigest}`,
        rules_sha256: sha256(rulesText),
        rules_text: rulesText,
      }),
      boot_session: bootSession,
    });
  } catch (error) {
    return unavailable('containment_system_facts_unavailable', {
      failure: error?.message === 'read_only_command_output_limit' ? 'output_limit' : 'permission_or_read_failure',
    });
  }
}

export async function verifyMacosContainmentReceipt({
  receipt,
  expected,
  system,
  runner,
  canary = null,
  now = Date.now,
  maxAgeMs = 5 * 60_000,
} = {}) {
  if (receipt == null) return unavailable('containment_receipt_missing');
  if (!validExpected(expected) || typeof now !== 'function'
      || !Number.isSafeInteger(maxAgeMs) || maxAgeMs <= 0) {
    return unavailable('containment_configuration_invalid');
  }
  if (!validReceiptShape(receipt)) return unavailable('containment_receipt_invalid');
  if (!receiptMatchesExpected(receipt, expected)) return unavailable('containment_receipt_tampered');

  const nowMs = Number(now());
  const generatedMs = Date.parse(receipt.generated_at);
  const rebootVerifiedMs = Date.parse(receipt.reboot_verified_at);
  if (!Number.isFinite(nowMs) || !Number.isFinite(generatedMs) || generatedMs > nowMs
      || nowMs - generatedMs > maxAgeMs) return unavailable('containment_receipt_stale');
  if (receipt.reboot_verified !== true || !Number.isFinite(rebootVerifiedMs)
      || rebootVerifiedMs > nowMs || nowMs - rebootVerifiedMs > maxAgeMs) {
    return unavailable('containment_reboot_unverified');
  }

  const facts = system ?? await inspectMacosContainment({ expected, runner });
  if (facts?.state === UNAVAILABLE) return facts;
  if (!plainObject(facts) || !plainObject(facts.uid) || !plainObject(facts.pf)) {
    return unavailable('containment_system_facts_unavailable');
  }
  if (facts.boot_session !== receipt.boot_session) {
    return unavailable('containment_boot_session_mismatch');
  }
  if (facts.pf.active !== true) return unavailable('containment_anchor_inactive');
  if (facts.uid.dedicated !== true) return unavailable('containment_uid_not_dedicated');
  if (facts.uid.name !== receipt.uid.name || facts.uid.uid !== receipt.uid.uid
      || facts.uid.gid !== receipt.uid.gid) return unavailable('containment_uid_mismatch');
  if (facts.pf.anchor_name !== receipt.pf.anchor_name
      || facts.pf.anchor_path !== receipt.pf.anchor_path
      || facts.pf.anchor_sha256 !== receipt.pf.anchor_sha256
      || facts.pf.rules_sha256 !== receipt.pf.rules_sha256) {
    return unavailable('containment_anchor_mismatch');
  }
  if (!safeRules(facts.pf.rules_text, expected)) {
    return unavailable('containment_pf_rules_unsafe');
  }
  if (canary == null) return unavailable('containment_canary_missing');
  if (!canaryPassed(receipt.canary) || !canaryPassed(canary)) {
    return unavailable('containment_canary_failed');
  }
  return Object.freeze({ state: READY, reason: 'containment_ready' });
}
