import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createPlaywrightAdapter } from '../src/adapters/playwright.mjs';
import {
  REQUIRED_BROWSER_PROOF_CHANNELS,
  browserCapabilityState,
  createChildEgressSandbox,
  verifyBrowserSecurityProof,
} from '../src/browser-security.mjs';
import {
  CANARY_PROTOCOLS,
  createContainmentCanaryHarness,
  probeContainmentCanary,
} from './fixtures/pf-containment-canary.mjs';

const NOW_MS = Date.parse('2026-08-30T12:00:00.000Z');
const HASH_A = `sha256:${'a'.repeat(64)}`;
const HASH_B = `sha256:${'b'.repeat(64)}`;
const HASH_C = `sha256:${'c'.repeat(64)}`;
const SAFE_PF_RULES = [
  'pass quick on lo0 inet proto tcp from any user 401 to 127.0.0.1 port 48191',
  'block drop quick inet from any user 401 to any',
  'block drop quick inet6 from any user 401 to any',
].join('\n');

function result(channel, operationSucceeded, response) {
  return Object.freeze({
    channel,
    operation_succeeded: operationSucceeded,
    response,
    response_confirmed: response === CANARY_PROTOCOLS[channel].response,
  });
}

function passedCanary() {
  return Object.freeze({
    passed: true,
    status: 'passed',
    reason: 'containment_canary_passed',
    exit_code: 0,
    detected_channels: Object.freeze([]),
    observations: Object.freeze({
      proxy_tcp: result('proxy_tcp', true, CANARY_PROTOCOLS.proxy_tcp.response),
      direct_tcp: result('direct_tcp', false, null),
      udp: result('udp', true, null),
      quic: result('quic', true, null),
    }),
  });
}

function expectedContainment() {
  return Object.freeze({
    backend: 'pf_uid_anchor_guardproxy',
    uid_name: '_lynceuz',
    uid: 401,
    gid: 401,
    guard_proxy_host: '127.0.0.1',
    guard_proxy_port: 48191,
    anchor_name: 'com.lynceuz/browser',
    anchor_path: '/etc/pf.anchors/com.lynceuz.browser',
    anchor_sha256: HASH_A,
    rules_sha256: HASH_B,
    source_hashes: Object.freeze({ macos_containment: HASH_C, canary: HASH_A }),
    suite_hashes: Object.freeze({ wave2: HASH_B }),
  });
}

function systemFacts(overrides = {}) {
  const base = {
    uid: { name: '_lynceuz', uid: 401, gid: 401, dedicated: true },
    pf: {
      active: true,
      anchor_name: 'com.lynceuz/browser',
      anchor_path: '/etc/pf.anchors/com.lynceuz.browser',
      anchor_sha256: HASH_A,
      rules_sha256: HASH_B,
      rules_text: SAFE_PF_RULES,
    },
    boot_session: 'boot-session-2026-08-30',
  };
  return {
    ...base,
    ...overrides,
    uid: { ...base.uid, ...overrides.uid },
    pf: { ...base.pf, ...overrides.pf },
  };
}

function validReceipt(overrides = {}) {
  const expected = expectedContainment();
  const base = {
    kind: 'lynceuz_macos_containment_receipt',
    schema_version: 1,
    status: 'ready',
    backend: expected.backend,
    generated_at: new Date(NOW_MS - 60_000).toISOString(),
    uid: { name: expected.uid_name, uid: expected.uid, gid: expected.gid },
    guard_proxy: { host: expected.guard_proxy_host, port: expected.guard_proxy_port },
    pf: {
      anchor_name: expected.anchor_name,
      anchor_path: expected.anchor_path,
      anchor_sha256: expected.anchor_sha256,
      rules_sha256: expected.rules_sha256,
    },
    source_hashes: expected.source_hashes,
    suite_hashes: expected.suite_hashes,
    boot_session: 'boot-session-2026-08-30',
    reboot_verified: true,
    reboot_verified_at: new Date(NOW_MS - 120_000).toISOString(),
    canary: passedCanary(),
  };
  return {
    ...base,
    ...overrides,
    uid: { ...base.uid, ...overrides.uid },
    guard_proxy: { ...base.guard_proxy, ...overrides.guard_proxy },
    pf: { ...base.pf, ...overrides.pf },
  };
}

test('Darwin sandbox containment stays closed with the concrete scope reason', async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-sandbox-contract-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const sandboxPath = join(workspace, 'sandbox-exec');
  await writeFile(sandboxPath, 'fixture');
  const containment = await createChildEgressSandbox({
    proxyPort: 48191,
    platformName: 'darwin',
    sandboxPath,
  });
  assert.equal(containment.state, 'unavailable_security_gate');
  assert.equal(containment.proofEligible, false);
  assert.equal(containment.reason, 'sandbox_loopback_scope_unproven');
  assert.notEqual(containment.state, 'ready');
});

test('browserCapabilityState rejects missing browser proof and keeps all hostile channels', async (t) => {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-wave2-proof-'));
  t.after(() => rm(workspace, { recursive: true, force: true }));
  const dataRoot = join(workspace, '.lynceuz');
  await mkdir(dataRoot, { recursive: true });
  const proof = await verifyBrowserSecurityProof({
    dataRoot,
    fingerprint: { digest: HASH_A },
    now: () => NOW_MS,
  });
  assert.deepEqual(proof, { valid: false, reason: 'proof_missing', fingerprint: null });
  assert.equal(browserCapabilityState({
    id: 'playwright', installed: true, version: 'fixture', allowRendered: true, proof,
  }).state, 'unavailable_security_gate');
  assert.ok(REQUIRED_BROWSER_PROOF_CHANNELS.includes('webrtc_udp'), 'UDP proof channel');
  assert.ok(REQUIRED_BROWSER_PROOF_CHANNELS.includes('quic'), 'QUIC proof channel');
});

test('containment receipt rejects missing stale tampered and reboot-unverified evidence', async () => {
  const { verifyMacosContainmentReceipt } = await import('../src/macos-containment.mjs');
  const verify = (receipt, options = {}) => verifyMacosContainmentReceipt({
    receipt,
    expected: expectedContainment(),
    system: options.system ?? systemFacts(),
    canary: options.canary === undefined ? passedCanary() : options.canary,
    now: () => NOW_MS,
    maxAgeMs: 5 * 60_000,
  });
  const unavailable = async (receipt, reason, options) => {
    const verdict = await verify(receipt, options);
    assert.equal(verdict.state, 'unavailable_security_gate', reason);
    assert.equal(verdict.reason, reason);
    assert.notEqual(verdict.state, 'ready');
  };

  await unavailable(undefined, 'containment_receipt_missing');
  await unavailable(validReceipt({ generated_at: '2020-01-01T00:00:00.000Z' }), 'containment_receipt_stale');
  await unavailable(validReceipt({ pf: { rules_sha256: HASH_C } }), 'containment_receipt_tampered');
  await unavailable(validReceipt({ reboot_verified: false }), 'containment_reboot_unverified');
  await unavailable(validReceipt({ boot_session: 'previous-boot-session' }), 'containment_boot_session_mismatch');

  await unavailable(validReceipt(), 'containment_anchor_inactive', {
    system: systemFacts({ pf: { active: false } }),
  });
  await unavailable(validReceipt(), 'containment_uid_not_dedicated', {
    system: systemFacts({ uid: { dedicated: false } }),
  });
  await unavailable(validReceipt(), 'containment_pf_rules_unsafe', {
    system: systemFacts({ pf: { rules_text: `set skip on lo0\n${SAFE_PF_RULES}` } }),
  });
  await unavailable(validReceipt(), 'containment_pf_rules_unsafe', {
    system: systemFacts({ pf: { rules_text: `${SAFE_PF_RULES}\npass quick from any to any` } }),
  });

  await unavailable(validReceipt(), 'containment_canary_missing', { canary: null });
  await unavailable(validReceipt(), 'containment_canary_failed', {
    canary: { ...passedCanary(), passed: false, status: 'red', exit_code: 1 },
  });
  const ready = await verify(validReceipt());
  assert.equal(ready.state, 'ready');
  assert.equal(ready.reason, 'containment_ready');
  assert.equal(systemFacts().pf.active, true, 'active anchor required');
  assert.equal(systemFacts().uid.dedicated, true, 'dedicated UID required');
});

test('containment accepts real pfctl output', async () => {
  const { safeRules } = await import('../src/macos-containment.mjs');
  const expected = expectedContainment();
  const real = await readFile(new URL('./fixtures/pf-real-rules.txt', import.meta.url), 'utf8');

  assert.equal(safeRules(real, expected), true, 'real pfctl output is accepted');

  const withoutInet6 = real.split('\n').filter(Boolean)
    .filter((line) => !/\binet6\b/u.test(line)).join('\n');
  assert.equal(safeRules(withoutInet6, expected), false, 'a set without the inet6 block is rejected');

  assert.equal(safeRules(`set skip on lo0\n${real}`, expected), false, 'set skip on lo0 makes the set unsafe');

  const broadPass = real.replace('to 127.0.0.1', 'to any');
  assert.notEqual(broadPass, real, 'broad-pass mutation applied');
  assert.equal(safeRules(broadPass, expected), false, 'a pass to any address is rejected');
});

test('positive канарейка allows proxy TCP and confirms no direct TCP UDP or QUIC response', async () => {
  const tcpExchange = async (channel) => channel === 'proxy_tcp'
    ? result(channel, true, CANARY_PROTOCOLS[channel].response)
    : result(channel, true, null);
  const udpExchange = async (channel) => result(channel, true, null);
  const verdict = await probeContainmentCanary({
    endpoints: {
      proxy_tcp: {}, direct_tcp: {}, udp: {}, quic: {},
    },
    tcpExchange,
    udpExchange,
  });
  assert.equal(verdict.passed, true);
  assert.equal(verdict.exit_code, 0);
  assert.equal(verdict.observations.proxy_tcp.response_confirmed, true);
  assert.equal(verdict.observations.direct_tcp.response_confirmed, false);
  assert.equal(verdict.observations.udp.operation_succeeded, true, 'UDP send may succeed');
  assert.equal(verdict.observations.udp.response_confirmed, false, 'UDP requires a response');
  assert.equal(verdict.observations.quic.operation_succeeded, true, 'QUIC-like UDP send may succeed');
  assert.equal(verdict.observations.quic.response_confirmed, false, 'QUIC requires a response');
});

test('negative control without containment detects every local non-loopback channel and turns red', async (t) => {
  const harness = await createContainmentCanaryHarness();
  t.after(() => harness.close());
  assert.notEqual(harness.non_loopback_host, '127.0.0.1');
  assert.equal(harness.endpoints.proxy_tcp.host, '127.0.0.1');
  for (const channel of ['direct_tcp', 'udp', 'quic']) {
    assert.equal(harness.endpoints[channel].host, harness.non_loopback_host, channel);
  }
  const verdict = await probeContainmentCanary({
    endpoints: harness.endpoints,
    negativeControl: true,
    timeoutMs: 1_000,
  });
  assert.equal(verdict.passed, false);
  assert.equal(verdict.status, 'red');
  assert.equal(verdict.exit_code, 1);
  assert.equal(verdict.reason, 'containment_removed_channels_reachable');
  assert.deepEqual(verdict.detected_channels, ['direct_tcp', 'udp', 'quic']);
  for (const channel of verdict.detected_channels) {
    assert.equal(verdict.observations[channel].response_confirmed, true, channel);
  }
});

test('negative control does not confuse successful UDP sends with responses', async () => {
  const sendOnly = async (channel) => result(channel, true, null);
  const verdict = await probeContainmentCanary({
    endpoints: {
      proxy_tcp: {}, direct_tcp: {}, udp: {}, quic: {},
    },
    negativeControl: true,
    tcpExchange: sendOnly,
    udpExchange: sendOnly,
  });
  assert.equal(verdict.passed, false);
  assert.equal(verdict.status, 'invalid_negative_control');
  assert.equal(verdict.exit_code, 2);
  assert.deepEqual(verdict.detected_channels, []);
});

test('containment PF anchor template permits only UID-scoped proxy TCP and blocks all other egress', async () => {
  const anchor = await readFile(new URL('../ops/macos/pf/lynceuz-browser.anchor.conf.in', import.meta.url), 'utf8');
  assert.doesNotMatch(anchor, /^\s*set\s+skip\s+on\s+lo0\b/imu);

  const passLines = anchor.split('\n').filter((line) => /^\s*pass\b/u.test(line));
  assert.equal(passLines.length, 1, 'one pass rule only');
  const pass = /^\s*pass\s+out\s+quick\s+inet\s+proto\s+tcp\s+from\s+any\s+to\s+127\.0\.0\.1\s+port\s+48191\s+user\s+(\S+)\s*$/u.exec(passLines[0]);
  assert.ok(pass, 'dedicated UID may use only proxy TCP on 127.0.0.1:48191');
  assert.match(pass[1], /UID/u, 'template substitutes only the numeric UID');

  const uid = pass[1].replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  assert.match(anchor, new RegExp(`^\\s*block\\s+drop\\s+out\\s+quick\\s+inet\\s+from\\s+any\\s+to\\s+any\\s+user\\s+${uid}\\s*$`, 'mu'));
  assert.match(anchor, new RegExp(`^\\s*block\\s+drop\\s+out\\s+quick\\s+inet6\\s+from\\s+any\\s+to\\s+any\\s+user\\s+${uid}\\s*$`, 'mu'));
  assert.doesNotMatch(passLines[0], /\b(?:inet6|udp|quic)\b/iu, 'no IPv6, UDP or QUIC pass');

  const tempDirectory = await mkdtemp(join(tmpdir(), 'lynceuz-pf-anchor-'));
  try {
    const parsedAnchorPath = join(tempDirectory, 'anchor.conf');
    await writeFile(parsedAnchorPath, anchor.replaceAll(pass[1], '401'), { mode: 0o600 });
    const parsed = spawnSync('/sbin/pfctl', ['-n', '-f', parsedAnchorPath], {
      encoding: 'utf8',
      shell: false,
      timeout: 5_000,
    });
    assert.equal(parsed.status, 0);
  } finally {
    await rm(tempDirectory, { recursive: true, force: true });
  }
});

test('containment owner templates are syntactically valid and least-privilege', async () => {
  const paths = {
    installer: fileURLToPath(new URL('../ops/macos/install-containment.sh', import.meta.url)),
    launchd: fileURLToPath(new URL('../ops/macos/launchd/com.lynceuz.browser-containment.plist', import.meta.url)),
    sudoers: fileURLToPath(new URL('../ops/macos/sudoers/lynceuz-browser', import.meta.url)),
  };
  const [installer, launchd, sudoers] = await Promise.all(
    Object.values(paths).map((path) => readFile(path, 'utf8')),
  );
  for (const [command, args] of [
    ['/bin/sh', ['-n', paths.installer]],
    ['/usr/bin/plutil', ['-lint', paths.launchd]],
    ['/usr/sbin/visudo', ['-cf', paths.sudoers]],
  ]) {
    const checked = spawnSync(command, args, { encoding: 'utf8', shell: false, timeout: 5_000 });
    assert.equal(checked.status, 0, checked.stderr || checked.stdout);
  }

  for (const flag of ['--dry-run', '--apply', '--rollback']) assert.ok(installer.includes(flag), flag);
  for (const fixed of ['_lynceuz', 'com.lynceuz/browser', '/etc/pf.anchors/com.lynceuz.browser']) {
    assert.ok(`${installer}\n${launchd}\n${sudoers}`.includes(fixed), fixed);
  }
  assert.match(installer, /\bid\s+-u\b/u, 'apply and rollback require an existing root shell');
  assert.doesNotMatch(installer, /\b(?:sudo|doas)\b/u, 'template must not elevate itself');
  assert.match(launchd, /<key>RunAtLoad<\/key>\s*<true\/>/u);
  assert.doesNotMatch(launchd, /\/(?:ba|z|c)?sh\b/u, 'launchd uses fixed argv, not a shell');
  assert.match(sudoers, /\/sbin\/pfctl\b/u);
  assert.doesNotMatch(sudoers, /NOPASSWD:\s*ALL\b|\(\s*ALL(?::ALL)?\s*\)|\*|\/(?:ba|z|c)?sh\b/u);
});

test('containment launcher requires a proven fixed-argv plan before Playwright supervisor spawn', async () => {
  const adapterSource = await readFile(new URL('../src/adapters/playwright.mjs', import.meta.url), 'utf8');
  assert.match(adapterSource, /shell:\s*false/u, 'contained spawn must set shell:false');

  const capability = Object.freeze({
    state: 'ready', version: 'fixture', proofFingerprint: HASH_A,
  });
  const job = Object.freeze({
    policy: Object.freeze({ allowRendered: true }),
    target: Object.freeze({ url: 'https://public.example.com/' }),
  });
  const launchPlan = Object.freeze({
    kind: 'lynceuz_macos_containment_launch_plan',
    executable: '/usr/bin/sudo',
    argv: Object.freeze(['-n', '-u', '#401', '--', '/usr/bin/python3', '-I', '/opt/lynceuz/lynceuz-browser.py']),
    uid: 401,
    gid: 401,
    guard_proxy: Object.freeze({ host: '127.0.0.1', port: 48191 }),
    env: Object.freeze({ LANG: 'C.UTF-8', LC_ALL: 'C.UTF-8', PYTHONNOUSERSITE: '1' }),
    shell: false,
  });

  let supervisorCalls = 0;
  let received;
  const supervisor = {
    async run(profile, payload) {
      supervisorCalls += 1;
      received = { profile, payload };
      return {
        kind: 'success', code: 'ok',
        response: { version: 1, id: 'render', ok: true, payload: {} },
      };
    },
  };
  const run = (sandbox) => createPlaywrightAdapter({ capability, sandbox, supervisor }).run({ job });

  await run({ proofEligible: false, reason: 'containment_receipt_missing', launch: () => launchPlan });
  await run({ proofEligible: true, launch: () => ({ ...launchPlan, shell: true }) });
  assert.equal(supervisorCalls, 0, 'missing or invalid containment proof makes zero spawn calls');

  let launchCalls = 0;
  await run({
    proofEligible: true,
    launch() {
      launchCalls += 1;
      return launchPlan;
    },
  });
  assert.equal(launchCalls, 1, 'adapter must consume sandbox.launch');
  assert.equal(supervisorCalls, 1);
  assert.equal(received.profile, 'python-browser');
  assert.deepEqual(received.payload.launchPlan, launchPlan);
  assert.equal(received.payload.launchPlan.shell, false);
});

test('containment receipt emitter refuses without root and writes no receipt', () => {
  const script = fileURLToPath(new URL('../scripts/emit-macos-containment-receipt.mjs', import.meta.url));
  const receiptPath = fileURLToPath(new URL('../.lynceuz/security/macos-containment-receipt-v1.json', import.meta.url));
  const existedBefore = existsSync(receiptPath);
  const run = spawnSync(process.execPath, [script], { encoding: 'utf8', shell: false, timeout: 10_000 });
  assert.notEqual(run.status, 0, 'a non-root run must exit non-zero');
  const printed = JSON.parse(run.stdout.trim().split('\n').filter(Boolean).at(-1));
  assert.equal(printed.status, 'impossible');
  assert.equal(printed.reason, 'containment_requires_root');
  assert.equal(existsSync(receiptPath), existedBefore, 'the refused run must not create or delete the receipt');
});

test('containment canary client is self contained', async (t) => {
  const { renderCanaryClientSource } = await import('../scripts/emit-macos-containment-receipt.mjs');
  const source = renderCanaryClientSource();
  assert.equal(typeof source, 'string');
  assert.ok(source.length > 0, 'client source is non-empty');
  assert.ok(!source.includes('/Users'), 'no home-directory absolute paths');
  const imports = [...source.matchAll(/from\s+(['"])([^'"]+)\1/gu)].map((m) => m[2]);
  assert.ok(imports.length > 0, 'client imports at least one module');
  for (const specifier of imports) {
    assert.ok(specifier.startsWith('node:'), `import must be a node: builtin: ${specifier}`);
  }

  const dir = await mkdtemp(join(tmpdir(), 'lynceuz-canary-client-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const clientPath = join(dir, 'canary-client.mjs');
  await writeFile(clientPath, source);
  const checked = spawnSync(process.execPath, ['--check', clientPath], {
    encoding: 'utf8', shell: false, timeout: 10_000,
  });
  assert.equal(checked.status, 0, checked.stderr || checked.stdout);
});

test('gate canary runs inside containment and fails closed when sudo refuses', async () => {
  const { positiveCanary } = await import('../scripts/p1-browser-gate.mjs');
  const { renderCanaryClientSource } = await import('../scripts/emit-macos-containment-receipt.mjs');
  const expected = expectedContainment();
  const calls = [];
  let clientPath;
  const runner = async (executable, argv, options) => {
    calls.push({ executable, argv: [...argv], options });
    clientPath = argv[4];
    assert.equal(await readFile(clientPath, 'utf8'), renderCanaryClientSource());
    return { stdout: `${JSON.stringify(passedCanary().observations)}\n`, stderr: '' };
  };

  const passed = await positiveCanary({ uidName: expected.uid_name, proxyPort: 0, runner });
  assert.equal(passed.passed, true);
  assert.deepEqual(calls[0].argv.slice(0, 4), ['-n', '-u', expected.uid_name, process.execPath]);
  assert.equal(calls[0].executable, '/usr/bin/sudo');
  assert.equal(calls[0].options.shell, false);
  assert.match(clientPath, /^\/private\/tmp\/lynceuz-gate-canary-/u);
  assert.equal(existsSync(clientPath), false, 'successful probe removes staged client');

  let deniedPath;
  await assert.rejects(
    positiveCanary({
      uidName: expected.uid_name,
      proxyPort: 0,
      runner: async (executable, argv) => {
        assert.equal(executable, '/usr/bin/sudo');
        deniedPath = argv[4];
        throw new Error('sudo refused');
      },
    }),
    (error) => error?.reason === 'containment_canary_failed'
      && error?.containment_state === 'unavailable_security_gate',
  );
  assert.equal(existsSync(deniedPath), false, 'failed probe removes staged client');
});

test('containment reads facts without root through a narrow non-root sudo path', async () => {
  const { inspectMacosContainment } = await import('../src/macos-containment.mjs');
  const expected = expectedContainment();
  const ok = (stdout) => ({ status: 0, signal: null, stdout, stderr: '' });

  // euid != 0: the two PF reads must go through `/usr/bin/sudo -n /sbin/pfctl ...`, never direct.
  const seen = [];
  const grantingRunner = (executable, argv) => {
    seen.push({ executable, argv: [...argv] });
    if (executable === '/usr/bin/id') return ok('401');
    if (executable === '/usr/sbin/sysctl') return ok('{ sec = 1756000000 }');
    if (executable === '/usr/bin/shasum') return ok(`${'a'.repeat(64)}  ${expected.anchor_path}`);
    if (executable === '/usr/bin/sudo') return ok(argv.includes('-sr') ? SAFE_PF_RULES : 'Status: Enabled');
    throw new Error(`unexpected direct call: ${executable}`);
  };
  const facts = await inspectMacosContainment({ expected, runner: grantingRunner, geteuid: () => 1000 });
  assert.notEqual(facts.state, 'unavailable_security_gate', 'the sudo path yields facts');
  assert.equal(facts.pf.active, true);
  assert.ok(!seen.some((c) => c.executable === '/sbin/pfctl'), 'a non-root gate never calls pfctl directly');
  assert.deepEqual(
    seen.find((c) => c.executable === '/usr/bin/sudo' && c.argv.includes('info'))?.argv,
    ['-n', '/sbin/pfctl', '-s', 'info'],
  );
  assert.deepEqual(
    seen.find((c) => c.executable === '/usr/bin/sudo' && c.argv.includes('-sr'))?.argv,
    ['-n', '/sbin/pfctl', '-a', expected.anchor_name, '-sr'],
  );

  // `sudo -n` denied (no password-less grant): stay fail-closed with the same typed reason.
  const denyingRunner = (executable, argv) => {
    if (executable === '/usr/bin/sudo') {
      return { status: 1, signal: null, stdout: '', stderr: 'sudo: a password is required' };
    }
    if (executable === '/usr/bin/id') return ok('401');
    if (executable === '/usr/sbin/sysctl') return ok('{ sec = 1756000000 }');
    if (executable === '/usr/bin/shasum') return ok(`${'a'.repeat(64)}  ${expected.anchor_path}`);
    throw new Error(`unexpected direct call: ${executable}`);
  };
  const denied = await inspectMacosContainment({ expected, runner: denyingRunner, geteuid: () => 1000 });
  assert.equal(denied.state, 'unavailable_security_gate');
  assert.equal(denied.reason, 'containment_system_facts_unavailable');
});

test('containment binary paths in macos-containment.mjs exist on disk', async () => {
  const source = await readFile(new URL('../src/macos-containment.mjs', import.meta.url), 'utf8');
  // every string literal that is an absolute system binary path (/bin, /sbin, /usr/bin, /usr/sbin)
  const paths = [...source.matchAll(/(['"])((?:\/usr)?\/s?bin\/[^'"]*)\1/gu)].map((m) => m[2]);
  assert.ok(paths.length > 0, 'no binary paths extracted — selection broke');
  for (const path of paths) {
    assert.ok(existsSync(path), `binary path does not exist on disk: ${path}`);
  }
});
