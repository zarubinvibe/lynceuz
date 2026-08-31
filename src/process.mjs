import { spawn as nodeSpawn } from 'node:child_process';
import { realpath } from 'node:fs/promises';
import { basename, dirname, isAbsolute, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { ATTEMPT_CODE, ATTEMPT_KIND } from './contracts.mjs';

const PROFILE_ID = 'python-parser';
const BROWSER_PROFILE_ID = 'python-browser';
export const PYTHON_HELPER_PATH = fileURLToPath(new URL('./lynceuz-helper.py', import.meta.url));
const OPERATIONS = new Set(['self_check', 'parse_html', 'extract_schema']);
const ENV_KEYS = new Set([
  'LANG',
  'LC_ALL',
  'PYTHONHASHSEED',
  'PYTHONIOENCODING',
  'PYTHONNOUSERSITE',
]);
const REQUEST_KEYS = new Set([
  'version',
  'id',
  'operation',
  'input_path',
  'input_hash',
  'base_url',
  'output_path',
  'schema',
]);
const RESPONSE_KEYS = new Set(['version', 'id', 'ok', 'code', 'details', 'payload']);
const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const HASH = /^sha256:[0-9a-f]{64}$/u;
const BROWSER_ENV_KEYS = Object.freeze(['LANG', 'LC_ALL', 'PYTHONNOUSERSITE']);
const LAUNCH_PLAN_KEYS = Object.freeze([
  'argv', 'env', 'executable', 'gid', 'guard_proxy', 'kind', 'shell', 'uid',
]);
const BROWSER_LIMITS = Object.freeze({
  maxInputBytes: 64 * 1024,
  maxStdoutBytes: 64 * 1024,
  maxStderrBytes: 64 * 1024,
  timeoutMs: 30_000,
});

function plainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function nowMilliseconds(clock) {
  const value = clock();
  const milliseconds = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isFinite(milliseconds)) throw new TypeError('clock returned invalid time');
  return milliseconds;
}

function absolutePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || !isAbsolute(value)) {
    throw new TypeError(`${label} must be an absolute path`);
  }
  return value;
}

function exactKeys(value, keys) {
  return plainObject(value)
    && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}

function safeLaunchText(value, maximum = 4096) {
  return typeof value === 'string' && value.length > 0 && value.length <= maximum
    && !/[\0\r\n]/u.test(value);
}

function frozenData(value) {
  return Object.isFrozen(value)
    && Object.values(Object.getOwnPropertyDescriptors(value)).every((field) => 'value' in field);
}

export function validContainedBrowserLaunchPlan(plan) {
  if (!exactKeys(plan, LAUNCH_PLAN_KEYS) || !frozenData(plan)
      || plan.kind !== 'lynceuz_macos_containment_launch_plan'
      || plan.executable !== '/usr/bin/sudo' || plan.shell !== false
      || !Number.isSafeInteger(plan.uid) || plan.uid < 1
      || !Number.isSafeInteger(plan.gid) || plan.gid < 1
      || !Array.isArray(plan.argv) || !frozenData(plan.argv) || plan.argv.length !== 7
      || plan.argv[0] !== '-n' || plan.argv[1] !== '-u' || plan.argv[2] !== `#${plan.uid}`
      || plan.argv[3] !== '--' || plan.argv[5] !== '-I'
      || !isAbsolute(plan.argv[4]) || !/^python(?:\d+(?:\.\d+)*)?$/u.test(basename(plan.argv[4]))
      || !isAbsolute(plan.argv[6]) || basename(plan.argv[6]) !== 'lynceuz-browser.py'
      || !plan.argv.every((value) => safeLaunchText(value))) return false;
  if (!exactKeys(plan.guard_proxy, ['host', 'port']) || !frozenData(plan.guard_proxy)
      || plan.guard_proxy.host !== '127.0.0.1'
      || !Number.isInteger(plan.guard_proxy.port)
      || plan.guard_proxy.port < 1 || plan.guard_proxy.port > 65_535) return false;
  return exactKeys(plan.env, BROWSER_ENV_KEYS) && frozenData(plan.env)
    && BROWSER_ENV_KEYS.every((key) => safeLaunchText(plan.env[key], 128))
    && plan.env.PYTHONNOUSERSITE === '1';
}

function contained(root, candidate) {
  const fromRoot = relative(root, candidate);
  return fromRoot === '' || (fromRoot !== '..' && !fromRoot.startsWith('../') && !isAbsolute(fromRoot));
}

function assertProfile(id, profile) {
  if (id !== PROFILE_ID || !plainObject(profile)) {
    throw new TypeError('only the fixed python-parser profile is supported');
  }
  absolutePath(profile.command, 'python-parser command');
  absolutePath(profile.cwd, 'python-parser cwd');
  if (!/^python(?:\d+(?:\.\d+)*)?$/u.test(basename(profile.command))) {
    throw new TypeError('python-parser command must be Python');
  }
  if (!Array.isArray(profile.args) || profile.args.length !== 2 || profile.args[0] !== '-I'
      || profile.args[1] !== PYTHON_HELPER_PATH) {
    throw new TypeError('python-parser argv is not the fixed helper argv');
  }
  if (!plainObject(profile.env)) throw new TypeError('python-parser env is invalid');
  for (const [key, value] of Object.entries(profile.env)) {
    if (!ENV_KEYS.has(key) || typeof value !== 'string' || value.length > 128 || /[\r\n\0]/u.test(value)) {
      throw new TypeError(`python-parser env entry is not allowlisted: ${key}`);
    }
  }
  for (const field of ['maxInputBytes', 'maxStdoutBytes', 'maxStderrBytes', 'timeoutMs']) {
    if (!Number.isSafeInteger(profile[field]) || profile[field] < 1) {
      throw new TypeError(`python-parser ${field} is invalid`);
    }
  }
}

function fixedProfile(profile) {
  return Object.freeze({
    ...profile,
    args: Object.freeze([...profile.args]),
    env: Object.freeze({ ...profile.env }),
  });
}

function typed(kind, code, details = undefined) {
  return Object.freeze({ kind, code, ...(details === undefined ? {} : { details }) });
}

function protocol(reason) {
  return typed(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, { reason });
}

function collectStream(stream, maximum, overflow) {
  const chunks = [];
  let length = 0;
  let exceeded = false;
  stream.on('data', (chunk) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    if (exceeded) return;
    if (length + bytes.length > maximum) {
      exceeded = true;
      overflow();
      return;
    }
    length += bytes.length;
    chunks.push(Buffer.from(bytes));
  });
  return () => Buffer.concat(chunks, length);
}

async function defaultKillProcessTree(child, {
  platform,
  graceMs = 200,
  setTimer = setTimeout,
} = {}) {
  if (!child?.pid) return;
  const processGroup = platform !== 'win32';
  try {
    if (processGroup) process.kill(-child.pid, 'SIGTERM');
    else child.kill('SIGTERM');
  } catch {}
  await new Promise((resolveGrace) => {
    const timer = setTimer(resolveGrace, graceMs);
    timer.unref?.();
  });
  try {
    if (processGroup) process.kill(-child.pid, 'SIGKILL');
    else child.kill('SIGKILL');
  } catch {}
}

function validateRequest(request) {
  if (!plainObject(request) || Object.keys(request).some((key) => !REQUEST_KEYS.has(key))) {
    throw new TypeError('request has unknown fields');
  }
  if (request.version !== 1 || !SAFE_ID.test(request.id ?? '') || !OPERATIONS.has(request.operation)) {
    throw new TypeError('request envelope is invalid');
  }
  if (request.operation === 'self_check') {
    if (Object.keys(request).length !== 3) throw new TypeError('self_check has extra data');
    return;
  }
  absolutePath(request.input_path, 'input path');
  absolutePath(request.output_path, 'output path');
  if (!HASH.test(request.input_hash ?? '')) throw new TypeError('input hash is invalid');
  if (typeof request.base_url !== 'string' || Buffer.byteLength(request.base_url) > 8192) {
    throw new TypeError('base URL is invalid');
  }
  if (request.operation === 'extract_schema' && !plainObject(request.schema)) {
    throw new TypeError('extract_schema requires schema');
  }
  if (request.operation === 'parse_html' && request.schema !== undefined) {
    throw new TypeError('parse_html cannot receive schema');
  }
}

async function validatePaths(request, payload, profile) {
  if (request.operation === 'self_check') return profile.cwd;
  absolutePath(payload.inputRoot, 'input root');
  absolutePath(payload.scratchDir, 'scratch directory');
  const [inputRoot, scratchRoot, inputPath, outputParent] = await Promise.all([
    realpath(payload.inputRoot),
    realpath(payload.scratchDir),
    realpath(request.input_path),
    realpath(dirname(request.output_path)),
  ]);
  if (!contained(inputRoot, inputPath)) throw new TypeError('input escaped storage root');
  if (!contained(scratchRoot, outputParent)) throw new TypeError('output escaped scratch root');
  return scratchRoot;
}

function validResponse(response, id) {
  return plainObject(response)
    && Object.keys(response).every((key) => RESPONSE_KEYS.has(key))
    && response.version === 1
    && response.id === id
    && typeof response.ok === 'boolean'
    && (response.ok ? response.code === undefined : typeof response.code === 'string')
    && (response.code === undefined || typeof response.code === 'string')
    && (response.details === undefined || plainObject(response.details))
    && (response.payload === undefined || plainObject(response.payload));
}

export function createProcessSupervisor({
  profiles,
  spawnImpl = nodeSpawn,
  clock = Date.now,
  platform = process.platform,
  killProcessTree = defaultKillProcessTree,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (!(profiles instanceof Map) || profiles.size !== 1 || !profiles.has(PROFILE_ID)) {
    throw new TypeError('profile registry must contain only python-parser');
  }
  if (typeof spawnImpl !== 'function' || typeof clock !== 'function'
      || typeof killProcessTree !== 'function' || typeof setTimer !== 'function'
      || typeof clearTimer !== 'function') {
    throw new TypeError('process supervisor ports are invalid');
  }
  const configured = profiles.get(PROFILE_ID);
  assertProfile(PROFILE_ID, configured);
  const profile = fixedProfile(configured);

  async function run(profileId, payload = {}) {
    if (profileId !== PROFILE_ID && profileId !== BROWSER_PROFILE_ID) {
      return typed(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNSUPPORTED, { reason: 'unknown_profile' });
    }
    const request = payload.request ?? payload;
    let execution = profile;
    let cwd;
    let requestBytes;
    try {
      if (profileId === BROWSER_PROFILE_ID) {
        if (!validContainedBrowserLaunchPlan(payload.launchPlan)) throw new TypeError('invalid launch plan');
        if (!plainObject(request) || request.version !== 1 || !SAFE_ID.test(request.id ?? '')
            || request.operation !== 'render') throw new TypeError('invalid browser request');
        cwd = request.output_path === undefined
          ? profile.cwd
          : await realpath(dirname(absolutePath(request.output_path, 'output path')));
        execution = { ...BROWSER_LIMITS, ...payload.launchPlan };
      } else {
        validateRequest(request);
        cwd = await validatePaths(request, payload, profile);
      }
      requestBytes = Buffer.from(`${JSON.stringify(request)}\n`);
    } catch {
      return protocol(profileId === BROWSER_PROFILE_ID ? 'invalid_contained_launch' : 'invalid_request');
    }
    if (requestBytes.length > execution.maxInputBytes) return protocol('input_oversized');
    if (payload.signal?.aborted) {
      return typed(ATTEMPT_KIND.RETRYABLE, ATTEMPT_CODE.TIMEOUT, { reason: 'aborted' });
    }

    const startedAt = nowMilliseconds(clock);
    let child;
    try {
      child = spawnImpl(execution.command ?? execution.executable, execution.args ?? execution.argv, {
        cwd,
        env: { ...execution.env },
        shell: false,
        detached: platform !== 'win32',
        stdio: ['pipe', 'pipe', 'pipe'],
      });
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return typed(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNAVAILABLE, { reason: 'python_missing' });
      }
      return typed(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_CRASH, { reason: 'spawn_failed' });
    }

    let stopReason = null;
    let spawnError = null;
    let killPromise = null;
    const terminate = (reason) => {
      stopReason ??= reason;
      killPromise ??= Promise.resolve(killProcessTree(child, { platform, setTimer }));
    };
    const stdout = collectStream(child.stdout, execution.maxStdoutBytes, () => terminate('stdout_oversized'));
    const stderr = collectStream(child.stderr, execution.maxStderrBytes, () => terminate('stderr_oversized'));
    child.once('error', (error) => { spawnError = error; });
    child.stdin.on('error', () => {});
    const abort = () => terminate('aborted');
    payload.signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimer(() => terminate('timeout'), execution.timeoutMs);
    timer.unref?.();

    try {
      child.stdin.end(requestBytes);
      const [exitCode, signal] = await new Promise((resolveClose) => {
        child.once('close', (code, closeSignal) => resolveClose([code, closeSignal]));
      });
      if (killPromise) await killPromise;
      if (spawnError) {
        if (spawnError.code === 'ENOENT') {
          return typed(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNAVAILABLE, { reason: 'python_missing' });
        }
        return typed(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_CRASH, { reason: 'spawn_failed' });
      }
      if (stopReason === 'timeout' || stopReason === 'aborted') {
        return typed(ATTEMPT_KIND.RETRYABLE, ATTEMPT_CODE.TIMEOUT, {
          reason: stopReason,
          exitCode,
          signal,
          durationMs: Math.max(0, nowMilliseconds(clock) - startedAt),
        });
      }
      if (stopReason) return protocol(stopReason);
      if (exitCode !== 0) {
        return typed(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_CRASH, {
          reason: 'non_zero_exit', exitCode, signal,
        });
      }
      const output = stdout().toString('utf8');
      const diagnostics = stderr().toString('utf8');
      const lines = output.split(/\r?\n/u);
      if (lines.at(-1) === '') lines.pop();
      if (lines.length !== 1 || lines[0].length === 0) return protocol('invalid_framing');
      let response;
      try {
        response = JSON.parse(lines[0]);
      } catch {
        return protocol('invalid_json');
      }
      if (!validResponse(response, request.id)) return protocol('invalid_response');
      return Object.freeze({
        kind: ATTEMPT_KIND.SUCCESS,
        code: ATTEMPT_CODE.OK,
        response,
        details: {
          durationMs: Math.max(0, nowMilliseconds(clock) - startedAt),
          stderrBytes: Buffer.byteLength(diagnostics),
        },
      });
    } finally {
      clearTimer(timer);
      payload.signal?.removeEventListener('abort', abort);
    }
  }

  return Object.freeze({ run });
}
