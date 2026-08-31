import { createHash, randomUUID } from 'node:crypto';
import { constants as FS_CONSTANTS } from 'node:fs';
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  rename,
  unlink,
} from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep, win32 } from 'node:path';

const DIRECTORY_MODE = 0o700;
const FILE_MODE = 0o600;
const IGNORE_CONTENT = '*\n!.gitignore\n';
const MAX_INDEX_BYTES = 1024 * 1024;
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_OBJECT_BYTES = 50 * 1024 * 1024;
// ponytail: 16 MiB journal ceiling for recovery; raise if real runs log more.
const MAX_JOURNAL_BYTES = 16 * 1024 * 1024;
const HASH_PATTERN = /^sha256:([0-9a-f]{64})$/;
const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;
const RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const FORBIDDEN_HEADERS = new Set([
  'authorization',
  'cookie',
  'proxy-authorization',
  'set-cookie',
]);
const SENSITIVE_KEY = /(?:^|[-_])(api[-_]?key|authorization|cookie|credential|password|proxy[-_]?authorization|secret|session|token)(?:$|[-_])/i;
const SENSITIVE_QUERY = /^(?:access_token|api[-_]?key|auth|authorization|code|credential|key|password|secret|session|signature|token)$/i;
const PROTECTED_OUTPUT_ROOTS = new Set([
  '.gitignore',
  'cache',
  'objects',
  'runs',
  'security',
  'tmp',
]);
const MANIFEST_STATUSES = new Set([
  'ok',
  'partial',
  'exhausted',
  'blocked',
  'internal_error',
  'output_failure',
  'interrupted',
]);

function storageError(code, message, cause) {
  const error = new Error(message, cause === undefined ? undefined : { cause });
  error.code = code;
  return error;
}

// Recovery treats a broken run as evidence to quarantine, never a fatal fault.
const RECOVERY_CORRUPTION_CODES = new Set([
  'RECOVERY_CORRUPT',
  'SYMLINK_PATH',
  'PATH_ESCAPE',
  'INVALID_RUN',
  'INVALID_HASH',
  'INVALID_PATH',
  'INVALID_OBJECT_REFERENCE',
  'INTEGRITY_MISMATCH',
]);

function recoveryCorruption(message, cause) {
  const error = storageError('RECOVERY_CORRUPT', message, cause);
  error.corruption = true;
  return error;
}

function isRecoveryCorruption(error) {
  return error?.corruption === true || RECOVERY_CORRUPTION_CODES.has(error?.code);
}

function isMissing(error) {
  return error?.code === 'ENOENT';
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalValue(value, label, seen = new WeakSet()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw storageError('INVALID_JSON', `${label} contains a non-finite number`);
    return value;
  }
  if (value instanceof Date) {
    if (Number.isNaN(value.valueOf())) throw storageError('INVALID_JSON', `${label} contains an invalid date`);
    return value.toISOString();
  }
  if (typeof value !== 'object') {
    throw storageError('INVALID_JSON', `${label} contains a non-JSON value`);
  }
  if (seen.has(value)) throw storageError('INVALID_JSON', `${label} contains a cycle`);
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item, index) => canonicalValue(item, `${label}[${index}]`, seen));
    }
    if (!isPlainObject(value)) throw storageError('INVALID_JSON', `${label} must contain plain objects`);
    const result = {};
    for (const key of Object.keys(value).sort()) {
      if (value[key] === undefined) continue;
      result[key] = canonicalValue(value[key], `${label}.${key}`, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

function canonicalJson(value, label) {
  const normalized = canonicalValue(value, label);
  return {
    normalized,
    bytes: Buffer.from(`${JSON.stringify(normalized)}\n`),
  };
}

function sanitizeUrl(value) {
  if (typeof value !== 'string') return value;
  let url;
  try {
    url = new URL(value);
  } catch {
    return value;
  }
  if (!['http:', 'https:'].includes(url.protocol)) return value;
  url.username = '';
  url.password = '';
  for (const name of [...url.searchParams.keys()]) {
    if (SENSITIVE_QUERY.test(name)) url.searchParams.set(name, '[redacted]');
  }
  return url.href;
}

function sanitizeForStorage(value, key = '', seen = new WeakSet()) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return /url$/i.test(key) ? sanitizeUrl(value) : value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw storageError('INVALID_JSON', `${key || 'value'} is not finite`);
    return value;
  }
  if (value instanceof Date) return canonicalValue(value, key || 'value');
  if (typeof value !== 'object') {
    if (value === undefined) return undefined;
    throw storageError('INVALID_JSON', `${key || 'value'} is not JSON`);
  }
  if (seen.has(value)) throw storageError('INVALID_JSON', `${key || 'value'} contains a cycle`);
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => sanitizeForStorage(item, key, seen));
    }
    if (!isPlainObject(value)) throw storageError('INVALID_JSON', `${key || 'value'} must be plain`);
    const result = {};
    for (const [childKey, child] of Object.entries(value)) {
      if (child === undefined) continue;
      result[childKey] = SENSITIVE_KEY.test(childKey)
        ? '[redacted]'
        : sanitizeForStorage(child, childKey, seen);
    }
    return result;
  } finally {
    seen.delete(value);
  }
}

function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha256Ref(bytes) {
  return `sha256:${sha256Hex(bytes)}`;
}

function normalizeBytes(bytes, label = 'bytes') {
  if (Buffer.isBuffer(bytes)) return bytes;
  if (bytes instanceof Uint8Array) return Buffer.from(bytes);
  if (typeof bytes === 'string') return Buffer.from(bytes);
  throw new TypeError(`${label} must be a Buffer, Uint8Array or string`);
}

function validateRelativePath(relativePath) {
  if (typeof relativePath !== 'string' || relativePath.length === 0) {
    throw storageError('INVALID_PATH', 'path must be a non-empty relative string');
  }
  if (relativePath.includes('\0') || relativePath.includes('\\')) {
    throw storageError('INVALID_PATH', 'path contains an unsafe separator');
  }
  if (isAbsolute(relativePath) || win32.isAbsolute(relativePath)) {
    throw storageError('INVALID_PATH', 'absolute paths are forbidden');
  }
  const segments = relativePath.split('/');
  if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
    throw storageError('INVALID_PATH', 'path traversal is forbidden');
  }
  return segments.join('/');
}

function validateFingerprint(fingerprint) {
  if (typeof fingerprint !== 'string' || !FINGERPRINT_PATTERN.test(fingerprint)) {
    throw storageError('INVALID_FINGERPRINT', 'fingerprint must be a lowercase SHA-256 hex value');
  }
  return fingerprint;
}

function validateRunId(runId) {
  if (
    typeof runId !== 'string'
    || !RUN_ID_PATTERN.test(runId)
    || runId === '.'
    || runId === '..'
  ) {
    throw storageError('INVALID_RUN', 'run id is invalid');
  }
  return runId;
}

function normalizeRun(run) {
  if (!isPlainObject(run)) throw storageError('INVALID_RUN', 'run handle is invalid');
  const id = validateRunId(run.id ?? run.runId);
  if (run.runId !== undefined && run.runId !== id) {
    throw storageError('INVALID_RUN', 'run handle ids disagree');
  }
  if (run.path !== `runs/${id}`) throw storageError('INVALID_RUN', 'run path is invalid');
  return { id, runId: id, path: `runs/${id}` };
}

function objectPathForHash(hash) {
  const match = HASH_PATTERN.exec(hash);
  if (!match) throw storageError('INVALID_HASH', 'object hash must be a sha256 reference');
  const hex = match[1];
  return `objects/sha256/${hex.slice(0, 2)}/${hex}`;
}

function nowIso(clock) {
  const value = clock();
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.valueOf())) throw storageError('INVALID_CLOCK', 'clock returned an invalid date');
  return date.toISOString();
}

function buildRunId(clock) {
  const timestamp = nowIso(clock).replaceAll('-', '').replaceAll(':', '');
  return `${timestamp}-${randomUUID()}`;
}

function escapesRoot(fromRoot) {
  return fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot);
}

function assertNoFingerprintSecrets(value, label = 'fingerprint', seen = new WeakSet()) {
  if (!value || typeof value !== 'object') return;
  if (seen.has(value)) throw storageError('INVALID_FINGERPRINT', `${label} contains a cycle`);
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      value.forEach((item, index) => assertNoFingerprintSecrets(item, `${label}[${index}]`, seen));
      return;
    }
    if (!isPlainObject(value)) {
      throw storageError('INVALID_FINGERPRINT', `${label} must contain plain objects`);
    }
    for (const [key, child] of Object.entries(value)) {
      if (SENSITIVE_KEY.test(key)) {
        throw storageError('UNSAFE_HEADER', `${key} is a secret or unsafe header`);
      }
      assertNoFingerprintSecrets(child, `${label}.${key}`, seen);
    }
  } finally {
    seen.delete(value);
  }
}

export function createRequestFingerprint(spec) {
  if (!isPlainObject(spec)) throw new TypeError('fingerprint input must be an object');
  assertNoFingerprintSecrets(spec);

  let url;
  try {
    url = new URL(spec.canonicalUrl);
  } catch (cause) {
    throw storageError('INVALID_FINGERPRINT', 'canonicalUrl must be an absolute URL', cause);
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw storageError('INVALID_FINGERPRINT', 'canonicalUrl must be a credential-free HTTP(S) URL');
  }
  for (const name of url.searchParams.keys()) {
    if (SENSITIVE_QUERY.test(name)) {
      throw storageError('INVALID_FINGERPRINT', 'canonicalUrl contains a secret query parameter');
    }
  }
  url.hash = '';

  const method = String(spec.method ?? 'GET').toUpperCase();
  if (!['GET', 'HEAD'].includes(method)) {
    throw storageError('INVALID_FINGERPRINT', 'fingerprint method must be GET or HEAD');
  }

  const headers = {};
  if (spec.headers !== undefined) {
    if (!isPlainObject(spec.headers)) {
      throw storageError('INVALID_FINGERPRINT', 'headers must be an object');
    }
    for (const [rawName, rawValue] of Object.entries(spec.headers)) {
      const name = rawName.toLowerCase();
      if (FORBIDDEN_HEADERS.has(name) || SENSITIVE_KEY.test(name)) {
        throw storageError('UNSAFE_HEADER', `${name} is a secret or unsafe header`);
      }
      if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name)) {
        throw storageError('INVALID_FINGERPRINT', 'header name is invalid');
      }
      if (typeof rawValue !== 'string' || /[\r\n\0]/.test(rawValue)) {
        throw storageError('INVALID_FINGERPRINT', `${name} header value is invalid`);
      }
      headers[name] = rawValue.trim();
    }
  }

  const normalized = {
    ...spec,
    canonicalUrl: url.href,
    method,
    headers,
  };
  const bytes = canonicalJson(normalized, 'fingerprint').bytes;
  return sha256Hex(bytes);
}

export function createStorage({
  dataRoot = join(process.cwd(), '.lynceuz'),
  clock = () => new Date(),
  faultInjector = () => {},
} = {}) {
  if (typeof dataRoot !== 'string' || basename(resolve(dataRoot)) !== '.lynceuz') {
    throw storageError('INVALID_DATA_ROOT', 'data root must end with .lynceuz');
  }
  if (typeof clock !== 'function') throw new TypeError('clock must be a function');
  if (typeof faultInjector !== 'function') throw new TypeError('faultInjector must be a function');

  const root = resolve(dataRoot);
  let rootReal;
  let initialization;

  function absolutePath(relativePath) {
    const safe = validateRelativePath(relativePath);
    const candidate = join(root, ...safe.split('/'));
    const fromRoot = relative(root, candidate);
    if (escapesRoot(fromRoot)) {
      throw storageError('PATH_ESCAPE', 'path escapes the data root');
    }
    return { safe, candidate };
  }

  function assertInsideRealRoot(path) {
    const fromRoot = relative(rootReal, path);
    if (escapesRoot(fromRoot)) {
      throw storageError('PATH_ESCAPE', 'real path escapes the data root');
    }
  }

  async function ensureRoot() {
    let info;
    try {
      info = await lstat(root);
    } catch (error) {
      if (!isMissing(error)) throw error;
      await mkdir(root, { recursive: true, mode: DIRECTORY_MODE });
      info = await lstat(root);
    }
    if (info.isSymbolicLink() || !info.isDirectory()) {
      throw storageError('UNSAFE_DATA_ROOT', 'data root must be a real directory');
    }
    await chmod(root, DIRECTORY_MODE);
    rootReal = await realpath(root);
  }

  async function inspectSafePath(relativePath, { allowMissing = true } = {}) {
    const { safe, candidate } = absolutePath(relativePath);
    let current = root;
    const segments = safe.split('/');
    for (let index = 0; index < segments.length; index += 1) {
      current = join(current, segments[index]);
      let info;
      try {
        info = await lstat(current);
      } catch (error) {
        if (allowMissing && isMissing(error)) return { safe, candidate, exists: false };
        throw error;
      }
      if (info.isSymbolicLink()) {
        throw storageError('SYMLINK_PATH', `symlink path component is forbidden: ${safe}`);
      }
      if (index < segments.length - 1 && !info.isDirectory()) {
        throw storageError('INVALID_PATH', `non-directory path component: ${safe}`);
      }
      assertInsideRealRoot(await realpath(current));
    }
    return { safe, candidate, exists: true };
  }

  async function ensureDirectory(relativeDirectory) {
    if (relativeDirectory === '.' || relativeDirectory === '') return root;
    const safe = validateRelativePath(relativeDirectory);
    let current = root;
    for (const segment of safe.split('/')) {
      current = join(current, segment);
      let info;
      try {
        info = await lstat(current);
      } catch (error) {
        if (!isMissing(error)) throw error;
        try {
          await mkdir(current, { mode: DIRECTORY_MODE });
        } catch (mkdirError) {
          if (mkdirError?.code !== 'EEXIST') throw mkdirError;
        }
        info = await lstat(current);
      }
      if (info.isSymbolicLink()) {
        throw storageError('SYMLINK_PATH', `symlink path component is forbidden: ${safe}`);
      }
      if (!info.isDirectory()) {
        throw storageError('INVALID_PATH', `non-directory path component: ${safe}`);
      }
      assertInsideRealRoot(await realpath(current));
      await chmod(current, DIRECTORY_MODE);
    }
    return current;
  }

  async function syncDirectory(path) {
    let handle;
    try {
      handle = await open(path, FS_CONSTANTS.O_RDONLY);
      await handle.sync();
    } catch (error) {
      if (!['EINVAL', 'ENOTSUP', 'EBADF'].includes(error?.code)) throw error;
    } finally {
      await handle?.close();
    }
  }

  async function inject(label, context) {
    await faultInjector(label, Object.freeze({ ...context }));
  }

  async function atomicWriteBytesInternal(relativePath, bytes, {
    renameLabel,
    replaceExisting = true,
  } = {}) {
    const safe = validateRelativePath(relativePath);
    const parent = dirname(safe);
    await ensureDirectory(parent);
    const target = absolutePath(safe).candidate;
    const targetState = await inspectSafePath(safe);
    if (targetState.exists && !replaceExisting) {
      throw storageError('IMMUTABLE_FILE', `refusing to replace immutable file: ${safe}`);
    }
    if (targetState.exists) {
      const info = await lstat(target);
      if (!info.isFile()) throw storageError('INVALID_PATH', `target is not a file: ${safe}`);
    }

    const tempName = `.${basename(safe)}.${randomUUID()}.tmp`;
    const tempRelative = parent === '.' ? tempName : `${parent}/${tempName}`;
    const temp = absolutePath(tempRelative).candidate;
    let handle;
    let renamed = false;
    try {
      const flags = FS_CONSTANTS.O_CREAT
        | FS_CONSTANTS.O_EXCL
        | FS_CONSTANTS.O_WRONLY
        | (FS_CONSTANTS.O_NOFOLLOW ?? 0);
      handle = await open(temp, flags, FILE_MODE);
      await handle.chmod(FILE_MODE);
      await handle.writeFile(bytes);
      await inject('temp_flush', { path: safe });
      await handle.sync();
      await handle.close();
      handle = undefined;

      await inspectSafePath(safe);
      if (renameLabel) await inject(renameLabel, { path: safe });
      await rename(temp, target);
      renamed = true;
      await chmod(target, FILE_MODE);
      await syncDirectory(dirname(target));
      return { path: safe };
    } finally {
      await handle?.close().catch(() => {});
      if (!renamed) await unlink(temp).catch(() => {});
    }
  }

  async function initialize() {
    await ensureRoot();
    let needsIgnore = true;
    const ignore = await inspectSafePath('.gitignore');
    if (ignore.exists) {
      const info = await lstat(ignore.candidate);
      if (!info.isFile()) throw storageError('INVALID_PATH', '.gitignore must be a file');
      await chmod(ignore.candidate, FILE_MODE);
      needsIgnore = (await readFile(ignore.candidate, 'utf8')) !== IGNORE_CONTENT;
    }
    if (needsIgnore) {
      await atomicWriteBytesInternal('.gitignore', Buffer.from(IGNORE_CONTENT));
    }
  }

  async function ensureInitialized() {
    if (!initialization) {
      initialization = initialize().catch((error) => {
        initialization = undefined;
        throw error;
      });
    }
    await initialization;
  }

  async function verifyFileHash(
    relativePath,
    expectedHash,
    maxBytes,
    { returnBytes = false } = {},
  ) {
    const state = await inspectSafePath(relativePath, { allowMissing: false });
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
      throw storageError('INVALID_OBJECT_REFERENCE', 'referenced file limit is invalid');
    }
    const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0);
    const handle = await open(state.candidate, flags);
    try {
      const info = await handle.stat();
      if (!info.isFile()) throw storageError('INTEGRITY_MISMATCH', 'referenced object is not a file');
      if (info.size > maxBytes) throw storageError('INTEGRITY_MISMATCH', 'referenced file is too large');
      const digest = createHash('sha256');
      const chunks = [];
      let size = 0;
      let position = 0;
      while (true) {
        const buffer = Buffer.allocUnsafe(64 * 1024);
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
        if (bytesRead === 0) break;
        position += bytesRead;
        size += bytesRead;
        if (size > maxBytes) throw storageError('INTEGRITY_MISMATCH', 'referenced file is too large');
        const chunk = buffer.subarray(0, bytesRead);
        digest.update(chunk);
        if (returnBytes) chunks.push(Buffer.from(chunk));
      }
      const actual = `sha256:${digest.digest('hex')}`;
      if (actual !== expectedHash) {
        throw storageError('INTEGRITY_MISMATCH', 'hash mismatch for referenced file');
      }
      return {
        bytes: returnBytes ? Buffer.concat(chunks, size) : null,
        info,
        size,
      };
    } finally {
      await handle.close();
    }
  }

  async function verifyObjectReference(reference, { maxBytes = MAX_OBJECT_BYTES, returnBytes = false } = {}) {
    if (!isPlainObject(reference)) {
      throw storageError('INVALID_OBJECT_REFERENCE', 'object reference must be an object');
    }
    if (!Number.isSafeInteger(reference.bytes) || reference.bytes < 0) {
      throw storageError('INVALID_OBJECT_REFERENCE', 'object byte count is invalid');
    }
    const expectedPath = objectPathForHash(reference.hash);
    if (reference.path !== expectedPath) {
      throw storageError('INTEGRITY_MISMATCH', 'object path does not match its hash');
    }
    const { bytes, info, size } = await verifyFileHash(
      expectedPath,
      reference.hash,
      Math.min(maxBytes, reference.bytes, MAX_OBJECT_BYTES),
      { returnBytes },
    );
    if (reference.bytes !== size) {
      throw storageError('INTEGRITY_MISMATCH', 'object byte count does not match');
    }
    if ((info.mode & 0o777) !== FILE_MODE) await chmod(join(root, expectedPath), FILE_MODE);
    return bytes;
  }

  async function assertRunExists(run) {
    const jobPath = `${run.path}/job.json`;
    const state = await inspectSafePath(jobPath, { allowMissing: false });
    const info = await lstat(state.candidate);
    if (!info.isFile()) throw storageError('INVALID_RUN', 'run job is not a file');
  }

  async function validateManifest(manifest, runId, { requireCacheable = false } = {}) {
    if (!isPlainObject(manifest) || manifest.schema_version !== 1) {
      throw storageError('INVALID_MANIFEST', 'manifest schema_version must be 1');
    }
    if (manifest.run_id !== runId) throw storageError('INVALID_MANIFEST', 'manifest run id mismatch');
    if (!MANIFEST_STATUSES.has(manifest.status)) {
      throw storageError('INVALID_MANIFEST', 'manifest status is invalid');
    }
    if (requireCacheable && manifest.status !== 'ok') {
      throw storageError('INVALID_MANIFEST', 'cacheable manifest must be ok');
    }
    if (!Array.isArray(manifest.artifacts)) {
      throw storageError('INVALID_MANIFEST', 'manifest artifacts must be an array');
    }
    for (const artifact of manifest.artifacts) await verifyObjectReference(artifact);
    const source = manifest.artifacts.find(({ hash }) => hash === manifest.source_hash);
    const artifact = manifest.artifacts.find(({ hash, path }) => (
      hash === manifest.artifact_hash && path === manifest.artifact_path
    ));
    if ((manifest.status === 'ok' || requireCacheable) && !source) {
      throw storageError('INVALID_MANIFEST', 'source hash is not present in artifacts');
    }
    if ((manifest.status === 'ok' || requireCacheable) && !artifact) {
      throw storageError('INVALID_MANIFEST', 'selected artifact is not present in artifacts');
    }
    if (manifest.source_hash !== null && manifest.source_hash !== undefined && !source) {
      throw storageError('INVALID_MANIFEST', 'declared source hash is not present in artifacts');
    }
    for (const artifact of manifest.artifacts) {
      if (
        artifact.derived_from !== null
        && artifact.derived_from !== undefined
        && !manifest.artifacts.some(({ hash }) => hash === artifact.derived_from)
      ) {
        throw storageError('INVALID_MANIFEST', 'derived artifact source is missing');
      }
    }
    return source ?? null;
  }

  async function validateCacheRecord(record, expectedFingerprint) {
    if (!isPlainObject(record) || record.schema_version !== 1) {
      throw storageError('INVALID_CACHE_RECORD', 'cache record schema_version must be 1');
    }
    if (record.request_fingerprint !== expectedFingerprint) {
      throw storageError('INVALID_CACHE_RECORD', 'cache request fingerprint does not match index');
    }
    let canonicalUrl;
    try {
      canonicalUrl = new URL(record.canonical_url);
    } catch (cause) {
      throw storageError('INVALID_CACHE_RECORD', 'cache canonical URL is invalid', cause);
    }
    if (
      !['http:', 'https:'].includes(canonicalUrl.protocol)
      || canonicalUrl.username
      || canonicalUrl.password
      || canonicalUrl.hash
    ) {
      throw storageError('INVALID_CACHE_RECORD', 'cache canonical URL is unsafe');
    }
    if (typeof record.requested_format !== 'string' || typeof record.format !== 'string') {
      throw storageError('INVALID_CACHE_RECORD', 'cache formats are invalid');
    }
    const runId = validateRunId(record.run_id);
    const expectedManifestPath = `runs/${runId}/manifest.json`;
    if (record.manifest_path !== expectedManifestPath) {
      throw storageError('INVALID_CACHE_RECORD', 'cache manifest path is invalid');
    }
    if (!HASH_PATTERN.test(record.manifest_hash) || !HASH_PATTERN.test(record.source_hash)) {
      throw storageError('INVALID_CACHE_RECORD', 'cache hashes are invalid');
    }
    const { bytes } = await verifyFileHash(
      expectedManifestPath,
      record.manifest_hash,
      MAX_MANIFEST_BYTES,
      { returnBytes: true },
    );
    let manifest;
    try {
      manifest = JSON.parse(bytes);
    } catch (cause) {
      throw storageError('INVALID_CACHE_RECORD', 'committed manifest is not JSON', cause);
    }
    const source = await validateManifest(manifest, runId, { requireCacheable: true });
    if (manifest.source_hash !== record.source_hash || source.hash !== record.source_hash) {
      throw storageError('INTEGRITY_MISMATCH', 'cache source hash does not match manifest');
    }
    if (record.source_path !== source.path) {
      throw storageError('INTEGRITY_MISMATCH', 'cache source path does not match manifest');
    }
    const artifact = manifest.artifacts.find(({ hash, path }) => (
      hash === record.artifact_hash && path === record.artifact_path
    ));
    if (
      !HASH_PATTERN.test(record.artifact_hash)
      || record.artifact_hash !== manifest.artifact_hash
      || record.artifact_path !== manifest.artifact_path
      || !artifact
    ) {
      throw storageError('INTEGRITY_MISMATCH', 'cache artifact binding does not match manifest');
    }
    if (
      manifest.requested_url !== record.canonical_url
      || manifest.requested_format !== record.requested_format
      || manifest.format !== record.format
    ) {
      throw storageError('INTEGRITY_MISMATCH', 'cache request binding does not match manifest');
    }
    return manifest;
  }

  async function resolvePath(relativePath) {
    await ensureInitialized();
    const state = await inspectSafePath(relativePath);
    return state.candidate;
  }

  async function readObject(reference, { maxBytes } = {}) {
    await ensureInitialized();
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
      throw storageError('INVALID_OBJECT_REFERENCE', 'object read limit is invalid');
    }
    return verifyObjectReference(reference, { maxBytes, returnBytes: true });
  }

  async function publishPrivateJson(relativePath, value) {
    await ensureInitialized();
    const { bytes } = canonicalJson(value, 'private JSON');
    return atomicWriteBytesInternal(relativePath, bytes);
  }

  async function publishOutput(relativePath, bytes) {
    await ensureInitialized();
    const safe = validateRelativePath(relativePath);
    if (PROTECTED_OUTPUT_ROOTS.has(safe.split('/')[0])) {
      throw storageError('INVALID_OUTPUT_PATH', 'output path overlaps protected storage state');
    }
    return atomicWriteBytesInternal(safe, normalizeBytes(bytes, 'output bytes'));
  }

  async function beginRun(job) {
    await ensureInitialized();
    const id = buildRunId(clock);
    const run = Object.freeze({ id, runId: id, path: `runs/${id}` });
    await ensureDirectory(run.path);
    await ensureDirectory(`tmp/${id}`);
    const sanitizedJob = sanitizeForStorage(job);
    const jobBytes = canonicalJson(sanitizedJob, 'job').bytes;
    await atomicWriteBytesInternal(`${run.path}/job.json`, jobBytes, { replaceExisting: false });
    await atomicWriteBytesInternal(`${run.path}/attempts.ndjson`, Buffer.alloc(0), {
      replaceExisting: false,
    });
    return run;
  }

  async function putObject(runHandle, bytes, metadata = {}) {
    await ensureInitialized();
    const run = normalizeRun(runHandle);
    await assertRunExists(run);
    if (!isPlainObject(metadata)) throw new TypeError('object metadata must be an object');
    const body = normalizeBytes(bytes);
    if (body.length > MAX_OBJECT_BYTES) {
      throw storageError('OBJECT_TOO_LARGE', 'object exceeds the storage byte limit');
    }
    const hash = sha256Ref(body);
    const path = objectPathForHash(hash);
    const safeMetadata = canonicalValue(metadata, 'object metadata');
    const reference = {
      ...safeMetadata,
      hash,
      path,
      bytes: body.length,
    };

    const existing = await inspectSafePath(path);
    if (existing.exists) {
      await verifyObjectReference(reference);
      return Object.freeze(reference);
    }
    await atomicWriteBytesInternal(path, body, {
      renameLabel: 'object_rename',
      replaceExisting: false,
    });
    return Object.freeze(reference);
  }

  async function appendAttempt(runHandle, event) {
    await ensureInitialized();
    const run = normalizeRun(runHandle);
    const path = `${run.path}/attempts.ndjson`;
    const state = await inspectSafePath(path, { allowMissing: false });
    const info = await lstat(state.candidate);
    if (!info.isFile()) throw storageError('INVALID_JOURNAL', 'attempt journal is not a file');
    const safeEvent = sanitizeForStorage(event);
    const line = canonicalJson(safeEvent, 'attempt event').bytes;
    const flags = FS_CONSTANTS.O_APPEND
      | FS_CONSTANTS.O_WRONLY
      | (FS_CONSTANTS.O_NOFOLLOW ?? 0);
    const handle = await open(state.candidate, flags);
    try {
      await handle.chmod(FILE_MODE);
      await handle.writeFile(line);
      await inject('journal_flush', { path });
      await handle.sync();
    } finally {
      await handle.close();
    }
    return { path };
  }

  async function commitManifest(runHandle, manifestValue) {
    await ensureInitialized();
    const run = normalizeRun(runHandle);
    await assertRunExists(run);
    const manifest = canonicalValue(sanitizeForStorage(manifestValue), 'manifest');
    await validateManifest(manifest, run.id);
    const { normalized, bytes } = canonicalJson(manifest, 'manifest');
    const path = `${run.path}/manifest.json`;
    await atomicWriteBytesInternal(path, bytes, {
      renameLabel: 'manifest_rename',
      replaceExisting: false,
    });
    return Object.freeze({
      hash: sha256Ref(bytes),
      path,
      manifest: normalized,
    });
  }

  async function commitCache(fingerprintValue, recordValue) {
    await ensureInitialized();
    const fingerprint = validateFingerprint(fingerprintValue);
    const record = canonicalValue(sanitizeForStorage(recordValue), 'cache record');
    await validateCacheRecord(record, fingerprint);
    const path = `cache/requests/${fingerprint.slice(0, 2)}/${fingerprint}.json`;
    await atomicWriteBytesInternal(path, canonicalJson(record, 'cache record').bytes, {
      renameLabel: 'cache_index_rename',
    });
    return { path };
  }

  async function readCache(fingerprintValue) {
    await ensureInitialized();
    const fingerprint = validateFingerprint(fingerprintValue);
    const path = `cache/requests/${fingerprint.slice(0, 2)}/${fingerprint}.json`;
    let state;
    try {
      state = await inspectSafePath(path, { allowMissing: false });
    } catch (error) {
      if (isMissing(error)) return { hit: false, warnings: [] };
      return { hit: false, warnings: ['cache_record_corrupt'] };
    }

    try {
      const info = await lstat(state.candidate);
      if (!info.isFile() || info.size > MAX_INDEX_BYTES) {
        throw storageError('INVALID_CACHE_RECORD', 'cache record file is invalid');
      }
      const record = JSON.parse(await readFile(state.candidate, 'utf8'));
      const manifest = await validateCacheRecord(record, fingerprint);
      return { hit: true, record, manifest, warnings: [] };
    } catch {
      return { hit: false, warnings: ['cache_record_corrupt'] };
    }
  }

  async function readJournalEvents(relativePath) {
    const state = await inspectSafePath(relativePath, { allowMissing: false });
    const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0);
    const handle = await open(state.candidate, flags);
    let content;
    try {
      const info = await handle.stat();
      if (!info.isFile()) throw recoveryCorruption('attempt journal is not a file');
      if (info.size > MAX_JOURNAL_BYTES) {
        throw recoveryCorruption('attempt journal exceeds the recovery limit');
      }
      content = await handle.readFile('utf8');
    } finally {
      await handle.close();
    }
    const events = [];
    for (const line of content.split('\n')) {
      if (line === '') continue; // trailing newline every appended record ends with
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch (cause) {
        throw recoveryCorruption('attempt journal has a malformed NDJSON line', cause);
      }
      if (!isPlainObject(parsed)) {
        throw recoveryCorruption('attempt journal event is not an object');
      }
      events.push(parsed);
    }
    return events;
  }

  // Every hash a journal references must point at a real, integral object.
  async function verifyJournalObjects(events) {
    const refs = new Map();
    const hashes = new Set();
    const scan = (node) => {
      if (Array.isArray(node)) {
        for (const item of node) scan(item);
        return;
      }
      if (!isPlainObject(node)) return;
      if (
        typeof node.hash === 'string' && HASH_PATTERN.test(node.hash)
        && typeof node.path === 'string' && Number.isSafeInteger(node.bytes)
      ) {
        refs.set(node.hash, { hash: node.hash, path: node.path, bytes: node.bytes });
      }
      for (const [key, value] of Object.entries(node)) {
        if (typeof value === 'string' && HASH_PATTERN.test(value) && /(?:^|_)hash$/i.test(key)) {
          hashes.add(value);
        }
        scan(value);
      }
    };
    for (const event of events) scan(event);

    const verified = new Set();
    for (const ref of refs.values()) {
      try {
        await verifyObjectReference(ref);
      } catch (cause) {
        throw recoveryCorruption('a journal object reference failed integrity', cause);
      }
      verified.add(ref.hash);
    }
    for (const hash of hashes) {
      if (verified.has(hash)) continue;
      try {
        await verifyFileHash(objectPathForHash(hash), hash, MAX_OBJECT_BYTES);
      } catch (cause) {
        throw recoveryCorruption('a journal object hash failed integrity', cause);
      }
      verified.add(hash);
    }
    return verified;
  }

  async function recoverOneRun(name, detectedAt) {
    validateRunId(name); // a non-run-id directory under runs/ is anomalous state
    const runPath = `runs/${name}`;
    const dirState = await inspectSafePath(runPath); // throws on symlink components
    if (!dirState.exists) return null; // removed mid-scan
    if (!(await lstat(dirState.candidate)).isDirectory()) return null; // stray non-run file

    // A committed manifest is authoritative even if cache publication was interrupted.
    const manifestState = await inspectSafePath(`${runPath}/manifest.json`);
    if (manifestState.exists) return null;

    const jobState = await inspectSafePath(`${runPath}/job.json`);
    const journalState = await inspectSafePath(`${runPath}/attempts.ndjson`);
    const hasJob = jobState.exists && (await lstat(jobState.candidate)).isFile();
    if (!hasJob && !journalState.exists) return null; // no durable job/journal: not a run

    const events = journalState.exists
      ? await readJournalEvents(`${runPath}/attempts.ndjson`)
      : [];
    const sourceHashes = await verifyJournalObjects(events);

    return {
      run_id: name,
      manifest_committed: false,
      detected_at: detectedAt,
      event_count: events.length,
      last_event: events.length ? events[events.length - 1] : null,
      source_hashes: [...sourceHashes].sort(),
    };
  }

  async function recoverIncompleteRuns() {
    await ensureInitialized();
    const detectedAt = nowIso(clock);
    const incomplete = [];
    const corrupt = [];
    const runsState = await inspectSafePath('runs');
    if (runsState.exists) {
      if (!(await lstat(runsState.candidate)).isDirectory()) {
        throw storageError('INVALID_PATH', 'runs is not a directory');
      }
      for (const name of (await readdir(runsState.candidate)).sort()) {
        try {
          const entry = await recoverOneRun(name, detectedAt);
          if (entry) incomplete.push(entry);
        } catch (error) {
          if (!isRecoveryCorruption(error)) throw error;
          corrupt.push({ run_id: name, corruption: { code: error.code, message: error.message } });
        }
      }
    }
    const report = { schema_version: 1, detected_at: detectedAt, incomplete, corrupt };
    if (incomplete.length || corrupt.length) {
      const { bytes } = canonicalJson(report, 'incomplete recovery report');
      await atomicWriteBytesInternal('incomplete.json', bytes, { renameLabel: 'incomplete_rename' });
    }
    return report;
  }

  return Object.freeze({
    dataRoot: root,
    resolve: resolvePath,
    readObject,
    publishPrivateJson,
    publishOutput,
    beginRun,
    putObject,
    appendAttempt,
    commitManifest,
    commitCache,
    readCache,
    recoverIncompleteRuns,
  });
}
