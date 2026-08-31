import { createHash, randomUUID } from 'node:crypto';
import { constants as FS_CONSTANTS } from 'node:fs';
import { mkdir, open, realpath, rm } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative } from 'node:path';

import {
  ATTEMPT_CODE,
  ATTEMPT_KIND,
  CAPABILITY_STATE,
  deepFreeze,
} from '../contracts.mjs';
import { parsePublicUrl } from '../policy.mjs';
import { PYTHON_HELPER_PATH, createProcessSupervisor } from '../process.mjs';

const MAX_SCHEMA_FIELDS = 64;
const MAX_SELECTOR_LENGTH = 256;
const MAX_PATH_SEGMENTS = 16;
const DEFAULT_INPUT_BYTES = 16 * 1024 * 1024;
const DEFAULT_OUTPUT_BYTES = 2 * 1024 * 1024;
const FIELD_NAME = /^(?!__proto__$|prototype$|constructor$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$/u;
const PATH_KEY = /^(?!__proto__$|prototype$|constructor$)[@A-Za-z_][@A-Za-z0-9_.:-]{0,63}$/u;
const SAFE_SELECTOR = /^[A-Za-z0-9_.*#\-[\]="'\s>+~,]+$/u;
const SAFE_ATTR = /^(?:href|src|content|datetime|value|title|alt|name|id|class|role|itemprop|property|type|data-[A-Za-z0-9_.:-]+|aria-[A-Za-z0-9_.:-]+)$/u;
const PRIMITIVE_TYPES = new Set(['string', 'number', 'boolean', 'null']);
const TOP_LEVEL_SCHEMA_KEYS = new Set(['schema_version', 'fields']);
const FIELD_KEYS = new Set(['source', 'selector', 'take', 'path', 'required', 'many', 'type']);
const PARSE_KEYS = new Set([
  'title',
  'canonical_candidate',
  'text',
  'markdown',
  'links',
  'metadata',
  'alternate_candidates',
  'jsonld',
]);

function plainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function schemaError(message) {
  throw new TypeError(`extract schema ${message}`);
}

function setOwn(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

function jsonCopy(value, label, seen = new WeakSet()) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (!value || typeof value !== 'object' || seen.has(value)) {
    throw new TypeError(`${label} is not bounded JSON`);
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) return value.map((item) => jsonCopy(item, label, seen));
    if (!plainObject(value)) throw new TypeError(`${label} must be a plain object`);
    const copy = {};
    for (const key of Object.keys(value).sort()) setOwn(copy, key, jsonCopy(value[key], label, seen));
    return copy;
  } finally {
    seen.delete(value);
  }
}

function stableBytes(value) {
  return Buffer.from(`${JSON.stringify(jsonCopy(value, 'output'))}\n`);
}

function validateSelector(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_SELECTOR_LENGTH
      || !SAFE_SELECTOR.test(value) || /(?:^|\W):|[(){};\\]/u.test(value)) {
    schemaError('selector is invalid or unbounded');
  }
  return value.trim();
}

function validateTake(value) {
  if (value === 'text') return value;
  if (typeof value !== 'string' || !value.startsWith('@') || !SAFE_ATTR.test(value.slice(1))
      || /^@(?:on|style|srcdoc|formaction)/iu.test(value)) {
    schemaError('attr is invalid or unsafe');
  }
  return value;
}

function validatePath(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_PATH_SEGMENTS) {
    schemaError('JSON-LD path is invalid or unbounded');
  }
  return value.map((segment) => {
    if (Number.isSafeInteger(segment) && segment >= 0 && segment <= 10_000) return segment;
    if (typeof segment === 'string' && PATH_KEY.test(segment)) return segment;
    schemaError('JSON-LD path segment is unsafe');
    return null;
  });
}

export function validateExtractSchema(schema) {
  if (!plainObject(schema)) schemaError('must be an object');
  if (Object.keys(schema).some((key) => !TOP_LEVEL_SCHEMA_KEYS.has(key))) {
    schemaError('contains unknown top-level keys');
  }
  if (schema.schema_version !== 1) schemaError('schema_version must be 1');
  if (!plainObject(schema.fields)) schemaError('fields must be an object');
  const names = Object.keys(schema.fields).sort();
  if (names.length === 0 || names.length > MAX_SCHEMA_FIELDS) schemaError('field count is invalid');
  const fields = {};
  for (const name of names) {
    if (!FIELD_NAME.test(name)) schemaError(`field name is unsafe: ${name}`);
    const field = schema.fields[name];
    if (!plainObject(field) || Object.keys(field).some((key) => !FIELD_KEYS.has(key))) {
      schemaError(`field ${name} contains unknown keys`);
    }
    if (!['css', 'jsonld'].includes(field.source)) schemaError(`field ${name} source is invalid`);
    if (field.required !== undefined && typeof field.required !== 'boolean') {
      schemaError(`field ${name} required flag is invalid`);
    }
    if (field.many !== undefined && typeof field.many !== 'boolean') {
      schemaError(`field ${name} many flag is invalid`);
    }
    if (field.type !== undefined && !PRIMITIVE_TYPES.has(field.type)) {
      schemaError(`field ${name} primitive type is invalid`);
    }
    const common = {
      source: field.source,
      required: field.required ?? false,
      many: field.many ?? false,
      ...(field.type === undefined ? {} : { type: field.type }),
    };
    if (field.source === 'css') {
      if (field.path !== undefined) schemaError(`field ${name} mixes CSS and JSON-LD`);
      fields[name] = {
        ...common,
        selector: validateSelector(field.selector),
        take: validateTake(field.take),
      };
    } else {
      if (field.selector !== undefined || field.take !== undefined) {
        schemaError(`field ${name} mixes JSON-LD and CSS`);
      }
      fields[name] = { ...common, path: validatePath(field.path) };
    }
  }
  const normalized = { schema_version: 1, fields };
  if (Buffer.byteLength(JSON.stringify(normalized)) > 64 * 1024) schemaError('is too large');
  return deepFreeze(normalized);
}

function positiveInteger(value, fallback, label) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected <= 0) throw new TypeError(`${label} is invalid`);
  return selected;
}

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function candidateUrl(value) {
  if (value === null) return null;
  if (typeof value !== 'string' || value.length > 8192) throw new TypeError('candidate URL is invalid');
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new TypeError('candidate URL is invalid');
  }
  url.hash = '';
  return url.href;
}

function boundedString(value, limit, label) {
  if (typeof value !== 'string' || Buffer.byteLength(value) > limit) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function validateParseResult(value) {
  if (!plainObject(value) || Object.keys(value).some((key) => !PARSE_KEYS.has(key))) {
    throw new TypeError('parse result has unknown fields');
  }
  if (!Array.isArray(value.links) || value.links.length > 4096) {
    throw new TypeError('parse links are invalid');
  }
  const links = value.links.map(candidateUrl);
  if (!plainObject(value.metadata) || Object.keys(value.metadata).length > 128) {
    throw new TypeError('parse metadata is invalid');
  }
  const metadata = {};
  for (const key of Object.keys(value.metadata).sort()) {
    if (key.length > 128 || ['__proto__', 'prototype', 'constructor'].includes(key)) {
      throw new TypeError('metadata key is invalid');
    }
    setOwn(metadata, key, boundedString(value.metadata[key], 4096, 'metadata value'));
  }
  if (!Array.isArray(value.alternate_candidates) || value.alternate_candidates.length > 128) {
    throw new TypeError('alternate candidates are invalid');
  }
  const alternateCandidates = value.alternate_candidates.map((candidate) => {
    if (!plainObject(candidate)
        || Object.keys(candidate).some((key) => !['type', 'url'].includes(key))) {
      throw new TypeError('alternate candidate is invalid');
    }
    return {
      type: boundedString(candidate.type, 256, 'alternate type'),
      url: candidateUrl(candidate.url),
    };
  });
  if (!Array.isArray(value.jsonld) || value.jsonld.length > 128) {
    throw new TypeError('JSON-LD output is invalid');
  }
  return {
    title: boundedString(value.title, 16 * 1024, 'title'),
    canonicalCandidate: candidateUrl(value.canonical_candidate),
    text: boundedString(value.text, DEFAULT_OUTPUT_BYTES, 'text'),
    markdown: boundedString(value.markdown, DEFAULT_OUTPUT_BYTES, 'markdown'),
    links: [...new Set(links)].sort(),
    metadata,
    alternateCandidates,
    jsonld: jsonCopy(value.jsonld, 'JSON-LD output'),
  };
}

function primitiveMatches(value, expected) {
  if (expected === undefined) {
    return value === null || ['string', 'number', 'boolean'].includes(typeof value);
  }
  if (expected === 'null') return value === null;
  if (expected === 'number') return typeof value === 'number' && Number.isFinite(value);
  return typeof value === expected;
}

function validateSchemaResult(value, schema) {
  if (!plainObject(value) || Object.keys(value).some((name) => !Object.hasOwn(schema.fields, name))) {
    throw new TypeError('schema result contains unknown fields');
  }
  const missing = [];
  const normalized = {};
  for (const [name, field] of Object.entries(schema.fields)) {
    if (!Object.hasOwn(value, name)) {
      if (field.required) missing.push(name);
      continue;
    }
    const selected = value[name];
    const values = field.many ? selected : [selected];
    if ((field.many && !Array.isArray(selected))
        || !Array.isArray(values)
        || values.some((item) => !primitiveMatches(item, field.type))) {
      missing.push(name);
      continue;
    }
    setOwn(normalized, name, jsonCopy(selected, `schema field ${name}`));
  }
  return { missing: missing.sort(), value: normalized };
}

function outcome(kind, code, details = undefined) {
  return deepFreeze({ kind, code, ...(details === undefined ? {} : { details }) });
}

function mapSupervisorFailure(result) {
  if (Object.values(ATTEMPT_KIND).includes(result?.kind) && typeof result?.code === 'string') {
    return result;
  }
  if (result.failure === 'spawn_failed' && result.error?.code === 'ENOENT') {
    return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNAVAILABLE, { reason: 'python_missing' });
  }
  if (result.failure === 'timeout' || result.failure === 'aborted') {
    return outcome(ATTEMPT_KIND.RETRYABLE, ATTEMPT_CODE.TIMEOUT, { reason: result.failure });
  }
  if (result.failure === 'non_zero_exit') {
    return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_CRASH, { reason: 'helper_non_zero_exit' });
  }
  return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
    reason: result.failure ?? 'helper_protocol_error',
  });
}

function mapHelperFailure(response) {
  if (response.code === 'dependency_unavailable') {
    return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNAVAILABLE, response.details);
  }
  if (response.code === 'unsupported') {
    return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNSUPPORTED, response.details);
  }
  if (response.code === 'required_fields_missing') {
    return outcome(ATTEMPT_KIND.INADEQUATE, ATTEMPT_CODE.PARSE_FAILED, {
      reason: 'required_fields_missing',
      missing: Array.isArray(response.details?.missing) ? response.details.missing : [],
    });
  }
  if (response.code === 'parse_failed') {
    return outcome(ATTEMPT_KIND.INADEQUATE, ATTEMPT_CODE.PARSE_FAILED, {
      reason: response.details?.reason ?? 'parse_failed',
    });
  }
  if (response.code === 'hash_mismatch') {
    return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.HASH_MISMATCH, {
      reason: 'helper_input_hash_mismatch',
    });
  }
  if (response.code === 'adapter_error') {
    return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
      reason: 'helper_boundary_failure',
    });
  }
  return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
    reason: 'helper_rejected_request',
  });
}

async function readBoundedFile(path, root, maximum, expectedBytes) {
  if (!Number.isSafeInteger(expectedBytes) || expectedBytes < 1 || expectedBytes > maximum) {
    throw new TypeError('helper output size is invalid');
  }
  const [realRoot, realPath] = await Promise.all([realpath(root), realpath(path)]);
  const fromRoot = relative(realRoot, realPath);
  if (fromRoot === '..' || fromRoot.startsWith('../') || isAbsolute(fromRoot)) {
    throw new TypeError('helper output escaped scratch');
  }
  const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0);
  const handle = await open(realPath, flags);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size !== expectedBytes) throw new TypeError('helper output size mismatch');
    const bytes = Buffer.allocUnsafe(expectedBytes);
    let offset = 0;
    while (offset < expectedBytes) {
      const { bytesRead } = await handle.read(bytes, offset, expectedBytes - offset, offset);
      if (bytesRead === 0) throw new TypeError('helper output ended early');
      offset += bytesRead;
    }
    return bytes;
  } finally {
    await handle.close();
  }
}

function profile(pythonPath, helperPath, cwd) {
  return new Map([[
    'python-parser',
    {
      command: pythonPath,
      args: ['-I', helperPath],
      cwd,
      env: {
        LANG: 'C.UTF-8',
        LC_ALL: 'C.UTF-8',
        PYTHONHASHSEED: '0',
        PYTHONIOENCODING: 'utf-8',
        PYTHONNOUSERSITE: '1',
      },
      maxInputBytes: 128 * 1024,
      maxStdoutBytes: 64 * 1024,
      maxStderrBytes: 64 * 1024,
      timeoutMs: 5_000,
    },
  ]]);
}

export function createPythonTransformAdapter({
  pythonPath,
  helperPath = PYTHON_HELPER_PATH,
  storage,
  supervisor,
  runHandle = null,
  scratchDir = null,
  maxInputBytes,
  maxOutputBytes,
} = {}) {
  if (typeof pythonPath !== 'string' || !isAbsolute(pythonPath)) {
    throw new TypeError('pythonPath must be an absolute path');
  }
  if (helperPath !== PYTHON_HELPER_PATH) {
    throw new TypeError('helperPath must be the built-in Lynceuz helper');
  }
  if (!storage || typeof storage.readObject !== 'function' || typeof storage.resolve !== 'function'
      || typeof storage.putObject !== 'function') {
    throw new TypeError('storage is required');
  }
  const inputLimit = positiveInteger(maxInputBytes, DEFAULT_INPUT_BYTES, 'maxInputBytes');
  const outputLimit = positiveInteger(maxOutputBytes, DEFAULT_OUTPUT_BYTES, 'maxOutputBytes');

  function buildSupervisor(cwd) {
    return supervisor ?? createProcessSupervisor({ profiles: profile(pythonPath, helperPath, cwd) });
  }

  async function probe() {
    try {
      await realpath(helperPath);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return { state: CAPABILITY_STATE.MISSING, reason: 'helper_missing', version: null };
      }
      return { state: CAPABILITY_STATE.MISCONFIGURED, reason: 'helper_unreadable', version: null };
    }
    const result = await buildSupervisor(dirname(helperPath)).run('python-parser', {
      version: 1,
      id: 'self-check',
      operation: 'self_check',
    });
    if (result.kind !== ATTEMPT_KIND.SUCCESS) {
      const mapped = mapSupervisorFailure(result);
      return {
        state: mapped.kind === ATTEMPT_KIND.SKIP
          ? CAPABILITY_STATE.MISSING
          : CAPABILITY_STATE.MISCONFIGURED,
        reason: mapped.details?.reason ?? mapped.code,
        version: null,
      };
    }
    if (!result.response.ok) {
      const mapped = mapHelperFailure(result.response);
      return {
        state: mapped.kind === ATTEMPT_KIND.SKIP
          ? CAPABILITY_STATE.MISSING
          : CAPABILITY_STATE.MISCONFIGURED,
        reason: mapped.details?.reason ?? mapped.code,
        version: null,
      };
    }
    return {
      state: CAPABILITY_STATE.READY,
      reason: 'python_helper_ready',
      version: result.response.payload?.helper_version ?? null,
      details: result.response.payload ?? {},
    };
  }

  async function runHelper({ operation, run, sourceRef, baseUrl, schema, signal }) {
    let canonicalBase;
    try {
      canonicalBase = parsePublicUrl(baseUrl).canonicalUrl;
      await storage.readObject(sourceRef, {
        maxBytes: Math.min(inputLimit, sourceRef?.bytes ?? inputLimit),
      });
    } catch (error) {
      return {
        outcome: outcome(ATTEMPT_KIND.BROKEN,
          error?.code === 'INTEGRITY_MISMATCH'
            ? ATTEMPT_CODE.HASH_MISMATCH
            : ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR,
          { reason: 'stored_input_invalid' }),
      };
    }
    const activeRun = run ?? runHandle;
    if (!activeRun?.id) {
      return {
        outcome: outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
          reason: 'run_missing',
        }),
      };
    }
    let inputPath;
    let scratchRoot;
    try {
      await realpath(helperPath);
      inputPath = await storage.resolve(sourceRef.path);
      scratchRoot = scratchDir ?? await storage.resolve(`tmp/${activeRun.id}`);
      await mkdir(scratchRoot, { recursive: true });
    } catch (error) {
      return {
        outcome: error?.code === 'ENOENT'
          ? outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNAVAILABLE, { reason: 'helper_missing' })
          : outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
            reason: 'path_setup_failed',
          }),
      };
    }
    const outputPath = join(scratchRoot, `${operation}-${randomUUID()}.json`);
    const runner = buildSupervisor(scratchRoot);
    const result = await runner.run('python-parser', {
      request: {
        version: 1,
        id: `${operation}-${randomUUID()}`,
        operation,
        input_path: inputPath,
        input_hash: sourceRef.hash,
        base_url: canonicalBase,
        output_path: outputPath,
        ...(schema === undefined ? {} : { schema }),
      },
      scratchDir: scratchRoot,
      signal,
      inputRoot: storage.dataRoot,
      scratchRoot,
    });
    if (result.kind !== ATTEMPT_KIND.SUCCESS) return { outcome: mapSupervisorFailure(result), outputPath, scratchRoot };
    if (!result.response.ok) return { outcome: mapHelperFailure(result.response), outputPath, scratchRoot };
    if (result.response.payload?.output_path !== outputPath) {
      return {
        outcome: outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
          reason: 'helper_output_path_mismatch',
        }),
        outputPath,
        scratchRoot,
      };
    }
    try {
      const bytes = await readBoundedFile(
        outputPath,
        scratchRoot,
        outputLimit,
        result.response.payload?.bytes,
      );
      return { bytes, outputPath, scratchRoot };
    } catch {
      return {
        outcome: outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
          reason: 'invalid_helper_output',
        }),
        outputPath,
        scratchRoot,
      };
    }
  }

  async function parseHtml({ run, sourceRef, input, baseUrl, signal } = {}) {
    const reference = sourceRef ?? input;
    const execution = await runHelper({
      operation: 'parse_html',
      run,
      sourceRef: reference,
      baseUrl,
      signal,
    });
    try {
      if (execution.outcome) return execution.outcome;
      const parsed = validateParseResult(JSON.parse(execution.bytes));
      const activeRun = run ?? runHandle;
      const artifacts = {
        markdown: await storage.putObject(activeRun, Buffer.from(parsed.markdown), {
          role: 'derived', media_type: 'text/markdown; charset=utf-8', derived_from: reference.hash,
        }),
        text: await storage.putObject(activeRun, Buffer.from(parsed.text), {
          role: 'derived', media_type: 'text/plain; charset=utf-8', derived_from: reference.hash,
        }),
        metadata: await storage.putObject(activeRun, stableBytes(parsed.metadata), {
          role: 'derived', media_type: 'application/json', derived_from: reference.hash,
        }),
        links: await storage.putObject(activeRun, stableBytes(parsed.links), {
          role: 'derived', media_type: 'application/json', derived_from: reference.hash,
        }),
        jsonld: await storage.putObject(activeRun, stableBytes(parsed.jsonld), {
          role: 'derived', media_type: 'application/json', derived_from: reference.hash,
        }),
      };
      return deepFreeze({
        kind: ATTEMPT_KIND.SUCCESS,
        code: ATTEMPT_CODE.OK,
        value: { ...parsed, artifacts },
      });
    } catch {
      return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
        reason: 'invalid_parse_result',
      });
    } finally {
      if (execution.outputPath) await rm(execution.outputPath, { force: true }).catch(() => {});
    }
  }

  async function extractSchema({ run, sourceRef, input, baseUrl, schema, signal } = {}) {
    let normalizedSchema;
    try {
      normalizedSchema = validateExtractSchema(schema);
    } catch {
      return outcome(ATTEMPT_KIND.INADEQUATE, ATTEMPT_CODE.PARSE_FAILED, {
        reason: 'invalid_schema',
      });
    }
    const reference = sourceRef ?? input;
    const execution = await runHelper({
      operation: 'extract_schema',
      run,
      sourceRef: reference,
      baseUrl,
      schema: normalizedSchema,
      signal,
    });
    try {
      if (execution.outcome) return execution.outcome;
      const checked = validateSchemaResult(JSON.parse(execution.bytes), normalizedSchema);
      if (checked.missing.length > 0) {
        return outcome(ATTEMPT_KIND.INADEQUATE, ATTEMPT_CODE.PARSE_FAILED, {
          reason: 'required_fields_missing',
          missing: checked.missing,
        });
      }
      const bytes = stableBytes(checked.value);
      if (bytes.length > outputLimit) {
        return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
          reason: 'schema_output_too_large',
        });
      }
      const activeRun = run ?? runHandle;
      const artifact = await storage.putObject(activeRun, bytes, {
        role: 'derived',
        media_type: 'application/json',
        derived_from: reference.hash,
        transform: {
          id: 'python-schema-v1',
          version: '1',
          options_hash: sha256(stableBytes(normalizedSchema)),
        },
      });
      return deepFreeze({
        kind: ATTEMPT_KIND.SUCCESS,
        code: ATTEMPT_CODE.OK,
        value: { artifact, data: checked.value },
      });
    } catch {
      return outcome(ATTEMPT_KIND.BROKEN, ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR, {
        reason: 'invalid_schema_result',
      });
    } finally {
      if (execution.outputPath) await rm(execution.outputPath, { force: true }).catch(() => {});
    }
  }

  async function transform({ operation, ...input } = {}) {
    if (operation === 'parse_html') {
      const result = await parseHtml(input);
      if (result.kind !== ATTEMPT_KIND.SUCCESS) return result;
      return deepFreeze({
        kind: result.kind,
        code: result.code,
        artifact: result.value.artifacts.metadata,
        representation: result.value,
      });
    }
    if (operation === 'extract_schema') {
      const result = await extractSchema(input);
      if (result.kind !== ATTEMPT_KIND.SUCCESS) return result;
      return deepFreeze({
        kind: result.kind,
        code: result.code,
        artifact: result.value.artifact,
        representation: result.value.data,
      });
    }
    return outcome(ATTEMPT_KIND.SKIP, ATTEMPT_CODE.UNSUPPORTED, { reason: operation ?? null });
  }

  async function health() {
    const state = await probe();
    return deepFreeze({
      id: 'python-parser',
      state: state.state,
      reason: state.reason,
      version: state.version,
      networkModel: 'none',
      details: state.details ?? {},
    });
  }

  return Object.freeze({
    id: 'python-parser',
    version: '1',
    networkModel: 'none',
    deterministic: true,
    probe,
    health,
    parseHtml,
    extractSchema,
    transform,
  });
}
