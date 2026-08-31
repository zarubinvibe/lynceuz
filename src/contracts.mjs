export const RUN_STATUS = Object.freeze({
  OK: 'ok',
  INVALID_INPUT: 'invalid_input',
  PARTIAL: 'partial',
  EXHAUSTED: 'exhausted',
  BLOCKED: 'blocked',
  INTERNAL_ERROR: 'internal_error',
  OUTPUT_FAILURE: 'output_failure',
  INTERRUPTED: 'interrupted',
});

export const EXIT_CODE = Object.freeze({
  OK: 0,
  INVALID_INPUT: 2,
  PARTIAL: 3,
  EXHAUSTED: 4,
  BLOCKED: 5,
  INTERNAL_ERROR: 70,
  OUTPUT_FAILURE: 74,
  TIMEOUT: 124,
  SIGINT: 130,
  SIGTERM: 143,
});

export const ATTEMPT_KIND = Object.freeze({
  SUCCESS: 'success',
  SKIP: 'skip',
  RETRYABLE: 'retryable',
  INADEQUATE: 'inadequate',
  TERMINAL: 'terminal',
  BROKEN: 'broken',
});

export const ATTEMPT_CODE = Object.freeze({
  OK: 'ok',
  UNAVAILABLE: 'unavailable',
  UNSUPPORTED: 'unsupported',
  CLOUD_DISABLED: 'cloud_disabled',
  POLICY_UNENFORCEABLE: 'policy_unenforceable',
  TIMEOUT: 'timeout',
  NETWORK: 'network',
  HTTP_5XX: 'http_5xx',
  RATE_LIMITED: 'rate_limited',
  JS_SHELL: 'js_shell',
  EMPTY: 'empty',
  WRONG_MIME: 'wrong_mime',
  PARSE_FAILED: 'parse_failed',
  POLICY_DENIED: 'policy_denied',
  ROBOTS_DENIED: 'robots_denied',
  ACCESS_DENIED: 'access_denied',
  AUTH_REQUIRED: 'auth_required',
  CAPTCHA: 'captcha',
  PAYWALL: 'paywall',
  PAID_REQUIRED: 'paid_required',
  NOT_FOUND: 'not_found',
  GONE: 'gone',
  HARD_LIMIT: 'hard_limit',
  ADAPTER_CRASH: 'adapter_crash',
  ADAPTER_PROTOCOL_ERROR: 'adapter_protocol_error',
  HASH_MISMATCH: 'hash_mismatch',
});

export const CAPABILITY_STATE = Object.freeze({
  READY: 'ready',
  MISSING: 'missing',
  DISABLED: 'disabled',
  MISCONFIGURED: 'misconfigured',
  UNAVAILABLE_SECURITY_GATE: 'unavailable_security_gate',
});

const COMMANDS = new Set(['url', 'crawl', 'extract', 'search', 'health']);
const REQUIRED_FIELDS = [
  'schema_version',
  'command',
  'status',
  'code',
  'message',
  'route',
  'capabilities',
  'warnings',
];
const OPTIONAL_FIELDS = new Set([
  'termination',
  'manifest_path',
  'artifact_path',
  'source_hash',
  'cache_status',
]);
const CACHE_STATUS = new Set(['off', 'miss', 'hit', 'revalidated']);
const SHA256 = /^sha256:[a-f0-9]{64}$/u;
const ALLOWED_CODES = Object.freeze({
  [RUN_STATUS.OK]: new Set(['ok', 'health', 'route_explained']),
  [RUN_STATUS.INVALID_INPUT]: new Set(['invalid_input']),
  [RUN_STATUS.PARTIAL]: new Set(['partial']),
  [RUN_STATUS.EXHAUSTED]: new Set([
    'exhausted',
    'no_eligible_engine',
    'unavailable_no_free_search_provider',
    ATTEMPT_CODE.NOT_FOUND,
    ATTEMPT_CODE.GONE,
  ]),
  [RUN_STATUS.BLOCKED]: new Set([
    'blocked',
    ATTEMPT_CODE.POLICY_DENIED,
    ATTEMPT_CODE.ROBOTS_DENIED,
    ATTEMPT_CODE.ACCESS_DENIED,
    ATTEMPT_CODE.AUTH_REQUIRED,
    ATTEMPT_CODE.CAPTCHA,
    ATTEMPT_CODE.PAYWALL,
    ATTEMPT_CODE.PAID_REQUIRED,
    ATTEMPT_CODE.HARD_LIMIT,
    ATTEMPT_CODE.RATE_LIMITED,
  ]),
  [RUN_STATUS.INTERNAL_ERROR]: new Set([
    'internal_error',
    'unknown_attempt_code',
    ATTEMPT_CODE.ADAPTER_CRASH,
    ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR,
    ATTEMPT_CODE.HASH_MISMATCH,
  ]),
  [RUN_STATUS.OUTPUT_FAILURE]: new Set(['output_failure']),
  [RUN_STATUS.INTERRUPTED]: new Set(['interrupted', ATTEMPT_CODE.TIMEOUT]),
});

function assertPlainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object`);
  }
}

function copyJson(value, label, seen = new WeakSet()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError(`${label} contains a non-finite number`);
    return value;
  }
  if (typeof value !== 'object') throw new TypeError(`${label} contains a non-JSON value`);
  if (seen.has(value)) throw new TypeError(`${label} contains a cycle`);
  seen.add(value);
  if (Array.isArray(value)) {
    const copied = value.map((item, index) => copyJson(item, `${label}[${index}]`, seen));
    seen.delete(value);
    return copied;
  }
  assertPlainObject(value, label);
  const copied = {};
  for (const [key, item] of Object.entries(value)) {
    copied[key] = copyJson(item, `${label}.${key}`, seen);
  }
  seen.delete(value);
  return copied;
}

export function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function validateTermination(termination) {
  assertPlainObject(termination, 'termination');
  const keys = Object.keys(termination);
  if (keys.length === 0 || keys.some((key) => !['reason', 'signal'].includes(key))) {
    throw new TypeError('termination has unexpected field');
  }
  if ('reason' in termination && termination.reason !== 'timeout') {
    throw new TypeError('termination reason must be timeout');
  }
  if ('signal' in termination && !['SIGINT', 'SIGTERM'].includes(termination.signal)) {
    throw new TypeError('termination signal is unknown');
  }
}

function validateRelativeResultPath(value, field) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    throw new TypeError(`${field} must be a relative path`);
  }
  if (value !== value.trim() || /[\u0000-\u001f\u007f\\]/u.test(value) || value.startsWith('/')
      || /^[a-z]:/iu.test(value)) {
    throw new TypeError(`${field} must be a relative path`);
  }
  const parts = value.split('/');
  if (parts.some((part) => part === '' || part === '.' || part === '..')) {
    throw new TypeError(`${field} must be a relative path`);
  }
}

export function validateResultEnvelope(value) {
  assertPlainObject(value, 'result envelope');
  const keys = Object.keys(value);
  for (const field of REQUIRED_FIELDS) {
    if (!Object.hasOwn(value, field)) throw new TypeError(`result envelope missing ${field}`);
  }
  for (const field of keys) {
    if (!REQUIRED_FIELDS.includes(field) && !OPTIONAL_FIELDS.has(field)) {
      throw new TypeError(`unexpected field: ${field}`);
    }
  }
  if (value.schema_version !== 1) throw new TypeError('schema_version must be 1');
  if (!COMMANDS.has(value.command)) throw new TypeError('command is unknown');
  if (!Object.values(RUN_STATUS).includes(value.status)) throw new TypeError('status is unknown');
  if (typeof value.code !== 'string' || !ALLOWED_CODES[value.status]?.has(value.code)) {
    throw new TypeError(`code does not match status: ${value.status}`);
  }
  if (typeof value.message !== 'string') throw new TypeError('message must be a string');
  if (!Array.isArray(value.route)) throw new TypeError('route must be an array');
  if (!Array.isArray(value.capabilities)) throw new TypeError('capabilities must be an array');
  if (!Array.isArray(value.warnings) || value.warnings.some((item) => typeof item !== 'string')) {
    throw new TypeError('warnings must contain strings');
  }
  copyJson(value.route, 'route');
  copyJson(value.capabilities, 'capabilities');
  if (value.termination !== undefined) validateTermination(value.termination);
  if (value.manifest_path !== undefined) {
    validateRelativeResultPath(value.manifest_path, 'manifest_path');
  }
  if (value.artifact_path !== undefined) {
    validateRelativeResultPath(value.artifact_path, 'artifact_path');
  }
  if (value.source_hash !== undefined
      && (typeof value.source_hash !== 'string' || !SHA256.test(value.source_hash))) {
    throw new TypeError('source_hash must be a lowercase sha256 marker');
  }
  if (value.cache_status !== undefined && !CACHE_STATUS.has(value.cache_status)) {
    throw new TypeError('cache_status is unknown');
  }
  if (value.status === RUN_STATUS.INTERRUPTED && value.termination === undefined) {
    throw new TypeError('interrupted result requires termination');
  }
  return true;
}

export function createResultEnvelope(fields) {
  assertPlainObject(fields, 'result fields');
  const value = {
    schema_version: fields.schema_version ?? 1,
    command: fields.command,
    status: fields.status,
    code: fields.code,
    message: fields.message,
    route: copyJson(fields.route, 'route'),
    capabilities: copyJson(fields.capabilities, 'capabilities'),
    warnings: copyJson(fields.warnings, 'warnings'),
  };
  for (const field of OPTIONAL_FIELDS) {
    if (fields[field] !== undefined) value[field] = copyJson(fields[field], field);
  }
  for (const field of Object.keys(fields)) {
    if (!REQUIRED_FIELDS.includes(field) && !OPTIONAL_FIELDS.has(field)) {
      throw new TypeError(`unexpected field: ${field}`);
    }
  }
  validateResultEnvelope(value);
  return deepFreeze(value);
}

export function exitCodeForStatus(status, termination) {
  switch (status) {
    case RUN_STATUS.OK: return EXIT_CODE.OK;
    case RUN_STATUS.INVALID_INPUT: return EXIT_CODE.INVALID_INPUT;
    case RUN_STATUS.PARTIAL: return EXIT_CODE.PARTIAL;
    case RUN_STATUS.EXHAUSTED: return EXIT_CODE.EXHAUSTED;
    case RUN_STATUS.BLOCKED: return EXIT_CODE.BLOCKED;
    case RUN_STATUS.INTERNAL_ERROR: return EXIT_CODE.INTERNAL_ERROR;
    case RUN_STATUS.OUTPUT_FAILURE: return EXIT_CODE.OUTPUT_FAILURE;
    case RUN_STATUS.INTERRUPTED:
      if (termination?.reason === 'timeout') return EXIT_CODE.TIMEOUT;
      if (termination?.signal === 'SIGINT') return EXIT_CODE.SIGINT;
      if (termination?.signal === 'SIGTERM') return EXIT_CODE.SIGTERM;
      throw new TypeError('interrupted status requires known termination');
    default:
      throw new TypeError(`unknown run status: ${String(status)}`);
  }
}
