import { createHash } from 'node:crypto';
import { open } from 'node:fs/promises';

import { createNativeHttpAdapter } from './adapters/native-http.mjs';
import { validateExtractSchema } from './adapters/python-helper.mjs';
import {
  ATTEMPT_CODE,
  ATTEMPT_KIND,
  RUN_STATUS,
  createResultEnvelope,
  exitCodeForStatus,
} from './contracts.mjs';
import { deriveRepresentation, detectRepresentation } from './formats.mjs';
import { parsePublicUrl } from './policy.mjs';
import {
  acceptRepresentation,
  buildRoutePlan,
  createCapabilitySnapshot,
  decideTransition,
  healthReport,
  renderedFallbackSkip,
  runModelRoute,
} from './router.mjs';
import { runBoundedCrawl } from './frontier.mjs';
import { createRobotsGate } from './robots.mjs';
import { createSearchRegistry, runSearchJob } from './search.mjs';
import { createRequestFingerprint } from './storage.mjs';

// One AbortController per run owns every stop signal: SIGINT, SIGTERM and the
// wall deadline all funnel into a single first-wins finalize. The winner aborts
// in-flight egress/children, records one sanitized termination event, commits
// exactly one interrupted manifest (never a cache record), and exits with the
// contract code. Redundant signals — or a signal racing the deadline — are
// dropped by a synchronous claim, so there is always exactly one commit and one
// exit. Listeners and the timer are always detached, so no handler leaks.
const CLEANUP_BUDGET_MS = 500;

export function createInterruptionGuard({
  storage,
  run,
  buildInterruptedManifest,
  emitter = process,
  exit = (code) => process.exit(code),
  scheduler = { setTimeout, clearTimeout },
  wallMs = null,
  gateway = null,
  supervisor = null,
} = {}) {
  if (!storage || typeof storage.commitManifest !== 'function') {
    throw new TypeError('interruption guard requires storage.commitManifest');
  }
  if (!run || typeof run !== 'object') throw new TypeError('interruption guard requires a run');
  if (typeof buildInterruptedManifest !== 'function') {
    throw new TypeError('interruption guard requires buildInterruptedManifest');
  }
  if (!emitter || typeof emitter.on !== 'function' || typeof emitter.removeListener !== 'function') {
    throw new TypeError('interruption guard requires an event emitter');
  }

  const controller = new AbortController();
  let settled = false;      // synchronous first-wins claim — guarantees one commit/exit
  let installed = false;
  let detached = false;
  let commitCount = 0;
  let deadlineTimer = null;
  let resolveDone;
  const done = new Promise((resolve) => { resolveDone = resolve; });

  const diag = (error) => {
    try {
      process.stderr.write(`interruption_guard: ${error?.stack ?? error}\n`);
    } catch {
      // A broken diagnostic stream cannot safely be recovered mid-teardown.
    }
  };

  function detach() {
    if (detached) return;
    detached = true;
    emitter.removeListener('SIGINT', onSigint);
    emitter.removeListener('SIGTERM', onSigterm);
    if (deadlineTimer !== null) {
      scheduler.clearTimeout(deadlineTimer);
      deadlineTimer = null;
    }
  }

  // Bounded so a wedged child or gateway can never delay the interrupted exit.
  async function boundedCleanup() {
    const tasks = [];
    if (gateway && typeof gateway.abort === 'function') tasks.push(gateway.abort());
    if (supervisor && typeof supervisor.terminateAll === 'function') tasks.push(supervisor.terminateAll());
    if (tasks.length === 0) return;
    await Promise.race([
      Promise.allSettled(tasks.map((task) => Promise.resolve(task))),
      new Promise((resolve) => {
        const timer = globalThis.setTimeout(resolve, CLEANUP_BUDGET_MS);
        timer?.unref?.();
      }),
    ]);
  }

  async function appendTermination(termination) {
    if (typeof storage.appendAttempt !== 'function') return;
    try {
      await storage.appendAttempt(run, { type: 'termination', outcome: 'interrupted', ...termination });
    } catch (error) {
      diag(error); // telemetry is best-effort; the manifest is the durable record
    }
  }

  async function finalize(termination) {
    if (settled) return; // claim is synchronous: the first signal/deadline wins
    settled = true;
    const code = exitCodeForStatus(RUN_STATUS.INTERRUPTED, termination);
    try {
      controller.abort(new Error(`run interrupted: ${termination.reason ?? termination.signal}`));
      await boundedCleanup();
      await appendTermination(termination);
      await storage.commitManifest(run, buildInterruptedManifest(termination));
      commitCount += 1;
    } catch (error) {
      diag(error); // still detach + exit; never hang on a failed teardown
    } finally {
      detach();
      exit(code);
      resolveDone();
    }
  }

  function onSigint() { void finalize({ signal: 'SIGINT' }); }
  function onSigterm() { void finalize({ signal: 'SIGTERM' }); }

  function install() {
    if (installed) return guardApi;
    installed = true;
    emitter.on('SIGINT', onSigint);
    emitter.on('SIGTERM', onSigterm);
    if (Number.isFinite(wallMs) && wallMs > 0) {
      deadlineTimer = scheduler.setTimeout(() => { void finalize({ reason: 'timeout' }); }, wallMs);
      deadlineTimer?.unref?.();
    }
    return guardApi;
  }

  function dispose() {
    if (settled) return; // an interrupted run already detached inside finalize
    detach();
  }

  const guardApi = {
    install,
    dispose,
    done,
    get commitCount() { return commitCount; },
    signal: controller.signal,
  };
  return guardApi;
}

function milliseconds(clock) {
  const value = clock();
  const result = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isFinite(result)) throw new TypeError('clock returned invalid time');
  return result;
}

function iso(millisecondsValue) {
  return new Date(millisecondsValue).toISOString();
}

function hardLimit() {
  return { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.HARD_LIMIT };
}

function limitsFor(job) {
  const source = job?.limits ?? {};
  const limits = {
    wallMs: source.wallMs,
    perAttemptMs: source.perAttemptMs,
    retriesPerAdapter: source.retriesPerAdapter,
    maxRetryAfterMs: source.maxRetryAfterMs,
    maxRedirects: source.maxRedirects,
    maxWireBytes: source.maxWireBytes ?? source.maxBytesPerPage,
    maxDecodedBytes: source.maxDecodedBytes ?? source.maxBytesPerPage,
  };
  for (const [name, value] of Object.entries(limits)) {
    const allowsZero = name === 'retriesPerAdapter' || name === 'maxRedirects';
    if (!Number.isSafeInteger(value) || value < (allowsZero ? 0 : 1)) {
      throw new TypeError(`invalid native limit: ${name}`);
    }
  }
  return limits;
}

function retryDecision(outcome, retriesUsed, rateLimitRetries, limits) {
  if (outcome.kind !== ATTEMPT_KIND.RETRYABLE) return null;
  if (outcome.code === ATTEMPT_CODE.RATE_LIMITED) {
    if (rateLimitRetries >= 1 || retriesUsed >= limits.retriesPerAdapter) return null;
    const requested = Number.isFinite(outcome.retryAfterMs) && outcome.retryAfterMs > 0
      ? outcome.retryAfterMs
      : 0;
    return {
      delayMs: Math.min(requested, limits.maxRetryAfterMs),
      capped: requested > limits.maxRetryAfterMs,
      rateLimited: true,
    };
  }
  if (![ATTEMPT_CODE.NETWORK, ATTEMPT_CODE.TIMEOUT, ATTEMPT_CODE.HTTP_5XX].includes(outcome.code)
      || retriesUsed >= limits.retriesPerAdapter) return null;
  return { delayMs: 0, capped: false, rateLimited: false };
}

export async function runNativeAttempts(job, {
  adapter,
  clock = Date.now,
  sleep = async () => {},
  onAttemptStart = async () => {},
  onAttemptFinish = async () => undefined,
} = {}) {
  if (!adapter || typeof adapter.run !== 'function') throw new TypeError('native adapter is required');
  if (typeof clock !== 'function' || typeof sleep !== 'function') throw new TypeError('clock and sleep are required');
  const limits = limitsFor(job);
  const startedMs = milliseconds(clock);
  const deadlineMs = startedMs + limits.wallMs;
  const timeline = [];
  let retriesUsed = 0;
  let rateLimitRetries = 0;
  let completion;

  while (true) {
    const attemptStartedMs = milliseconds(clock);
    if (attemptStartedMs >= deadlineMs) return { outcome: hardLimit(), timeline };
    await onAttemptStart({
      attempt: timeline.length + 1,
      started_at: iso(attemptStartedMs),
    });
    const controller = new AbortController();
    const attemptBudgetMs = Math.min(limits.perAttemptMs, deadlineMs - attemptStartedMs);
    const timer = setTimeout(() => controller.abort(new Error('attempt timeout')), attemptBudgetMs);
    timer.unref?.();
    let outcome;
    try {
      outcome = await adapter.run({
        runId: job.runId ?? 'native-run',
        url: job.target.url,
        method: 'GET',
        conditionalHeaders: job.conditionalHeaders ?? {},
        remaining: {
          wallMs: deadlineMs - attemptStartedMs,
          bytes: limits.maxWireBytes,
          redirects: limits.maxRedirects,
        },
        limits: {
          maxWireBytes: limits.maxWireBytes,
          maxDecodedBytes: limits.maxDecodedBytes,
        },
        signal: controller.signal,
      });
    } catch {
      outcome = { kind: ATTEMPT_KIND.BROKEN, code: ATTEMPT_CODE.ADAPTER_CRASH };
    } finally {
      clearTimeout(timer);
    }
    if (!outcome || typeof outcome.kind !== 'string' || typeof outcome.code !== 'string') {
      outcome = { kind: ATTEMPT_KIND.BROKEN, code: ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR };
    }
    const finishedMs = milliseconds(clock);
    const entry = {
      attempt: timeline.length + 1,
      started_at: iso(attemptStartedMs),
      finished_at: iso(finishedMs),
      duration_ms: Math.max(0, finishedMs - attemptStartedMs),
      outcome: outcome.kind,
      code: outcome.code,
      delay_ms: 0,
      retry_after_capped: false,
    };
    const http = responseEvidence(outcome);
    if (http) entry.http = http;
    timeline.push(entry);
    completion = await onAttemptFinish({ entry: { ...entry }, outcome });

    const retry = retryDecision(outcome, retriesUsed, rateLimitRetries, limits);
    if (!retry) {
      if (outcome.kind === ATTEMPT_KIND.RETRYABLE && outcome.code === ATTEMPT_CODE.RATE_LIMITED) {
        return {
          outcome: { ...outcome, kind: ATTEMPT_KIND.TERMINAL },
          timeline,
        };
      }
      return { outcome, timeline, completion };
    }
    if (finishedMs + retry.delayMs >= deadlineMs) return { outcome: hardLimit(), timeline };
    entry.delay_ms = retry.delayMs;
    entry.retry_after_capped = retry.capped;
    retriesUsed += 1;
    if (retry.rateLimited) rateLimitRetries += 1;
    await sleep(retry.delayMs);
  }
}

const SAFE_RESPONSE_HEADERS = new Set([
  'cache-control',
  'content-encoding',
  'content-length',
  'content-type',
  'date',
  'etag',
  'last-modified',
]);

function hashBytes(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function safeHeaders(headers) {
  const result = {};
  for (const [rawName, rawValue] of Object.entries(headers ?? {})) {
    const name = rawName.toLowerCase();
    if (!SAFE_RESPONSE_HEADERS.has(name)) continue;
    const value = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue);
    if (value.length <= 4096 && !/[\r\n\0]/u.test(value)) result[name] = value;
  }
  return result;
}

function responseEvidence(outcome) {
  const response = outcome?.response ?? outcome?.evidence;
  if (!response) return null;
  return {
    status_code: response.statusCode,
    final_url: response.finalUrl,
    redirect_chain: response.redirectChain ?? [],
    selected_address: response.permit?.selectedAddress ?? null,
    headers: safeHeaders(response.headers),
    wire_bytes: response.wireBytes ?? null,
    decoded_bytes: response.decodedBytes ?? null,
  };
}

function outcomeStatus(outcome) {
  if (outcome?.kind === ATTEMPT_KIND.TERMINAL) {
    if ([ATTEMPT_CODE.NOT_FOUND, ATTEMPT_CODE.GONE].includes(outcome.code)) {
      return { status: RUN_STATUS.EXHAUSTED, code: outcome.code };
    }
    return { status: RUN_STATUS.BLOCKED, code: outcome.code };
  }
  if (outcome?.kind === ATTEMPT_KIND.BROKEN) {
    return { status: RUN_STATUS.INTERNAL_ERROR, code: outcome.code };
  }
  return { status: RUN_STATUS.EXHAUSTED, code: 'exhausted' };
}

function resultFor(job, context, status, code, fields = {}) {
  return createResultEnvelope({
    command: job.kind,
    status,
    code,
    message: fields.message ?? (status === RUN_STATUS.OK
      ? 'Public source captured'
      : 'Native URL path stopped'),
    route: context.route ?? [],
    capabilities: context.capabilities ?? [],
    warnings: fields.warnings ?? [],
    ...(fields.manifestPath ? { manifest_path: fields.manifestPath } : {}),
    ...(fields.artifactPath ? { artifact_path: fields.artifactPath } : {}),
    ...(fields.sourceHash ? { source_hash: fields.sourceHash } : {}),
    ...(fields.cacheStatus ? { cache_status: fields.cacheStatus } : {}),
  });
}

function manifestBase({
  run,
  requestedUrl,
  effectiveUrl,
  requestedFormat,
  format,
  fetchedAt,
  servedAt,
  revalidatedAt = null,
  status,
  attempts,
  sourceRef = null,
  artifactRef = null,
  artifacts = [],
  warnings = [],
  evidence = [],
  cacheStatus,
}) {
  return {
    schema_version: 1,
    run_id: run.id,
    status,
    requested_url: requestedUrl,
    effective_url: effectiveUrl,
    requested_format: requestedFormat,
    format,
    alternatives: [],
    fetched_at: fetchedAt,
    served_at: servedAt,
    revalidated_at: revalidatedAt,
    engine: { id: 'native', version: '1' },
    policy: {
      version: '1',
      network: 'public-only',
      auth: 'none',
      money_budget: 0,
    },
    attempts,
    source_hash: sourceRef?.hash ?? null,
    artifact_hash: artifactRef?.hash ?? null,
    artifact_path: artifactRef?.path ?? null,
    artifacts,
    evidence,
    warnings,
    cost_money: 0,
    credits_used: 0,
    verification: sourceRef ? 'source_captured' : 'no_source_captured',
    cache_status: cacheStatus,
  };
}

function fingerprintFor(job, canonicalUrl) {
  return createRequestFingerprint({
    canonicalUrl,
    method: 'GET',
    headers: {
      accept: 'text/html,application/xhtml+xml,application/json,application/xml,text/xml,text/plain;q=0.9,*/*;q=0.1',
      'accept-encoding': 'gzip, deflate, br',
    },
    adapter: { id: 'native', version: '1' },
    policyVersion: '1',
    format: job.output.format,
    goal: job.goal,
    decode: {
      encodings: ['gzip', 'deflate', 'br'],
      maxBytes: job.limits.maxBytesPerPage,
    },
  });
}

function sourceFromManifest(manifest, sourceHash) {
  return manifest?.artifacts?.find((artifact) => artifact.hash === sourceHash && artifact.role === 'raw')
    ?? manifest?.artifacts?.find((artifact) => artifact.hash === sourceHash)
    ?? null;
}

async function loadVerifiedCachedArtifact(storage, cached, maxBytes) {
  const { record, manifest } = cached;
  const sourceRef = sourceFromManifest(manifest, record.source_hash);
  const artifactRef = manifest?.artifacts?.find((artifact) => (
    artifact.hash === record.artifact_hash && artifact.path === record.artifact_path
  ));
  if (!sourceRef || !artifactRef) throw new Error('cache artifact reference is missing');
  const bytes = await storage.readObject(artifactRef, { maxBytes });
  if (hashBytes(bytes) !== artifactRef.hash) throw new Error('cache artifact hash mismatch');
  return { sourceRef, artifactRef, bytes };
}

function derivedMediaType(format, sourceMediaType) {
  if (format === 'markdown') return 'text/markdown; charset=utf-8';
  if (['metadata', 'links', 'json'].includes(format)) return 'application/json';
  return sourceMediaType;
}

async function publishSelectedOutput(storage, requestedPath, artifactRef, bytes) {
  if (requestedPath === null) return artifactRef.path;
  return (await storage.publishOutput(requestedPath, bytes)).path;
}

function cacheRecord({
  fingerprint,
  canonicalUrl,
  requestedFormat,
  run,
  manifest,
  sourceRef,
  artifactRef,
  fetchedAt,
  expiresAt,
  effectiveUrl,
  mediaType,
  headers,
  format,
}) {
  return {
    schema_version: 1,
    request_fingerprint: fingerprint,
    canonical_url: canonicalUrl,
    requested_format: requestedFormat,
    format,
    run_id: run.id,
    manifest_path: manifest.path,
    manifest_hash: manifest.hash,
    source_hash: sourceRef.hash,
    source_path: sourceRef.path,
    artifact_hash: artifactRef.hash,
    artifact_path: artifactRef.path,
    fetched_at: fetchedAt,
    expires_at: expiresAt,
    effective_url: effectiveUrl,
    media_type: mediaType,
    etag: headers.etag ?? null,
    last_modified: headers['last-modified'] ?? null,
  };
}

function addFinalEvidence(timeline, outcome) {
  const evidence = responseEvidence(outcome);
  return timeline.map((entry, index) => (
    index === timeline.length - 1 && evidence ? { ...entry, http: evidence } : { ...entry }
  ));
}

async function finishCacheHit({
  job,
  context,
  storage,
  fingerprint,
  cached,
  verified,
  canonicalUrl,
  servedAt,
  warnings,
}) {
  const run = await storage.beginRun({
    schema_version: 1,
    command: 'url',
    requested_url: canonicalUrl,
    method: 'GET',
    format: job.output.format,
    cache: job.cache.mode,
  });
  const attempt = {
    type: 'cache_hit',
    at: servedAt,
    source_hash: verified.sourceRef.hash,
    manifest_hash: cached.record.manifest_hash,
  };
  await storage.appendAttempt(run, attempt);
  const manifestValue = manifestBase({
    run,
    requestedUrl: canonicalUrl,
    effectiveUrl: cached.record.effective_url ?? canonicalUrl,
    requestedFormat: job.output.format,
    format: cached.record.format,
    fetchedAt: cached.record.fetched_at,
    servedAt,
    status: RUN_STATUS.OK,
    attempts: [attempt],
    sourceRef: verified.sourceRef,
    artifactRef: verified.artifactRef,
    artifacts: cached.manifest.artifacts,
    warnings,
    evidence: cached.manifest.evidence ?? [],
    cacheStatus: 'hit',
  });
  const manifest = await storage.commitManifest(run, manifestValue);
  await storage.commitCache(fingerprint, {
    ...cached.record,
    run_id: run.id,
    manifest_path: manifest.path,
    manifest_hash: manifest.hash,
  });
  const artifactPath = await publishSelectedOutput(
    storage,
    job.output.path,
    verified.artifactRef,
    verified.bytes,
  );
  return resultFor(job, context, RUN_STATUS.OK, 'ok', {
    manifestPath: manifest.path,
    artifactPath,
    sourceHash: verified.sourceRef.hash,
    cacheStatus: 'hit',
    warnings,
  });
}

function htmlAttribute(tag, name) {
  const match = tag.match(new RegExp(
    `(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\u0060]+))`,
    'iu',
  ));
  return (match?.[1] ?? match?.[2] ?? match?.[3] ?? '')
    .replace(/&amp;/giu, '&')
    .replace(/&quot;/giu, '"')
    .replace(/&#39;|&apos;/giu, "'");
}

function safeCandidate(candidate, finalUrl) {
  if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 8192) return null;
  try {
    return parsePublicUrl(new URL(candidate, finalUrl).href).canonicalUrl;
  } catch {
    return null;
  }
}

function basicHtmlRepresentation(bytes, finalUrl) {
  const source = bytes.toString('utf8');
  const body = source.match(/<body\b[^>]*>([^]*?)<\/body\s*>/iu)?.[1] ?? source;
  const scriptCount = [...body.matchAll(/<script\b/giu)].length;
  const withoutData = body
    .replace(/<(script|style|template|noscript)\b[^>]*>[^]*?<\/\1\s*>/giu, ' ')
    .replace(/<[^>]+>/gu, ' ')
    .replace(/&nbsp;/giu, ' ')
    .replace(/&amp;/giu, '&')
    .replace(/\s+/gu, ' ')
    .trim();
  const title = source.match(/<title\b[^>]*>([^]*?)<\/title\s*>/iu)?.[1]
    ?.replace(/<[^>]+>/gu, ' ').replace(/\s+/gu, ' ').trim() ?? '';
  const links = new Set();
  for (const match of source.matchAll(/<a\b[^>]*>/giu)) {
    const candidate = safeCandidate(htmlAttribute(match[0], 'href'), finalUrl);
    if (candidate) links.add(candidate);
  }
  let canonicalCandidate = null;
  const alternateCandidates = [];
  const seenAlternates = new Set();
  for (const match of source.matchAll(/<link\b[^>]*>/giu)) {
    const rel = htmlAttribute(match[0], 'rel').toLowerCase().split(/\s+/u);
    const candidate = safeCandidate(htmlAttribute(match[0], 'href'), finalUrl);
    if (!candidate) continue;
    if (rel.includes('canonical') && canonicalCandidate === null) canonicalCandidate = candidate;
    if (!rel.includes('alternate')) continue;
    const type = htmlAttribute(match[0], 'type').toLowerCase() || 'text/html';
    const key = `${type}\0${candidate}`;
    if (seenAlternates.has(key)) continue;
    seenAlternates.add(key);
    alternateCandidates.push({ type, url: candidate });
  }
  return {
    kind: 'html',
    title,
    text: withoutData,
    markdown: withoutData,
    links: [...links].sort(),
    metadata: {},
    alternateCandidates: alternateCandidates.sort((left, right) => (
      left.type.localeCompare(right.type) || left.url.localeCompare(right.url)
    )),
    canonicalCandidate,
    jsonld: [],
    scriptCount,
    finalUrl,
  };
}

function discoveredCandidates(representation) {
  const candidates = [];
  if (representation?.canonicalCandidate) {
    candidates.push({ type: 'canonical', url: representation.canonicalCandidate });
  }
  for (const candidate of representation?.alternateCandidates ?? []) {
    if (candidate && typeof candidate.type === 'string' && typeof candidate.url === 'string') {
      candidates.push({ type: candidate.type, url: candidate.url });
    }
  }
  const seen = new Set();
  return candidates.filter((candidate) => {
    const key = `${candidate.type}\0${candidate.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

async function builtinRepresentation({
  job,
  response,
  detected,
  storage,
  run,
  sourceRef,
}) {
  if (job.goal === 'raw') {
    return {
      representation: {
        kind: detected.kind,
        body: response.body,
        byteLength: response.body.length,
        text: '',
      },
    };
  }
  if (detected.kind === 'json') {
    try {
      const data = JSON.parse(response.body.toString('utf8'));
      return { representation: { kind: 'json', data, text: response.body.toString('utf8') } };
    } catch {
      return { outcome: { kind: ATTEMPT_KIND.INADEQUATE, code: ATTEMPT_CODE.PARSE_FAILED } };
    }
  }
  if (detected.kind === 'binary') {
    return {
      representation: {
        kind: 'binary',
        body: response.body,
        byteLength: response.body.length,
        text: '',
      },
    };
  }
  if (!storage || !run || !sourceRef) {
    return { representation: basicHtmlRepresentation(response.body, response.finalUrl) };
  }
  try {
    const sourcePath = await storage.resolve(sourceRef.path);
    const requested = job.goal === 'raw' ? 'raw' : 'markdown';
    const projection = await deriveRepresentation({
      format: requested,
      sourcePath,
      mediaType: detected.mediaType,
      finalUrl: response.finalUrl,
      maxArtifactBytes: job.limits.maxArtifactBytes ?? job.limits.maxBytesPerPage,
    });
    const linkProjection = detected.kind === 'html' ? null : await deriveRepresentation({
      format: 'links',
      sourcePath,
      mediaType: detected.mediaType,
      finalUrl: response.finalUrl,
      maxArtifactBytes: job.limits.maxArtifactBytes ?? job.limits.maxBytesPerPage,
    });
    const links = linkProjection ? JSON.parse(linkProjection.bytes.toString('utf8')) : [];
    const artifactRef = await storage.putObject(run, projection.bytes, {
      role: projection.format,
      media_type: derivedMediaType(projection.format, projection.mediaType),
      derived_from: sourceRef.hash,
      transform: {
        id: `native-${detected.kind}-${projection.format}`,
        version: '1',
        options_hash: hashBytes(Buffer.from(JSON.stringify({ format: projection.format }))),
      },
    });
    const representation = detected.kind === 'html'
      ? { ...basicHtmlRepresentation(response.body, response.finalUrl), markdown: projection.bytes.toString('utf8') }
      : {
        kind: detected.kind,
        text: projection.bytes.toString('utf8').trim(),
        markdown: projection.bytes.toString('utf8'),
        links,
        scriptCount: 0,
      };
    return { representation, artifactRef, artifactBytes: projection.bytes };
  } catch (error) {
    return {
      outcome: error?.code === 'hard_limit'
        ? hardLimit()
        : { kind: ATTEMPT_KIND.INADEQUATE, code: ATTEMPT_CODE.PARSE_FAILED },
    };
  }
}

export async function runUrlPipeline({ job, context = {}, adapters = {} } = {}) {
  if (!job || !job.target || typeof job.target.url !== 'string') {
    return { outcome: { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.POLICY_DENIED } };
  }
  if (context.finalizeUrl === true) return runUrlJobLegacy(job, context.deps);
  let target;
  try {
    target = parsePublicUrl(job.target.url);
  } catch {
    return { outcome: { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.POLICY_DENIED } };
  }
  if (context.robotsGate && context.robotsChecked !== true) {
    const robots = await context.robotsGate.check(target.canonicalUrl, {
      runId: context.run?.id ?? job.runId ?? 'pipeline',
      signal: context.signal,
    });
    if (robots.kind !== ATTEMPT_KIND.SUCCESS) return { outcome: robots, robots };
  }
  const native = adapters.native ?? (context.gateway
    ? createNativeHttpAdapter({ gateway: context.gateway })
    : null);
  if (!native || typeof native.run !== 'function') {
    return { outcome: { kind: ATTEMPT_KIND.SKIP, code: ATTEMPT_CODE.UNAVAILABLE } };
  }
  const storage = context.storage;
  const run = context.run;
  let sourceRef = null;
  let detected = null;
  const attempted = await runNativeAttempts({
    ...job,
    runId: run?.id ?? job.runId ?? 'pipeline',
    target: { url: target.canonicalUrl },
  }, {
    adapter: native,
    clock: context.clock ?? Date.now,
    sleep: context.sleep ?? (async () => {}),
    onAttemptStart: async (event) => {
      if (storage && run) await storage.appendAttempt(run, {
        type: 'attempt_started', adapter: 'native', version: '1', url: target.canonicalUrl, ...event,
      });
    },
    onAttemptFinish: async ({ entry, outcome }) => {
      if (outcome.kind === ATTEMPT_KIND.SUCCESS && outcome.response?.statusCode !== 304) {
        detected = detectRepresentation({
          headers: outcome.response.headers,
          prefixBytes: outcome.response.body,
        });
        if (storage && run) {
          sourceRef = await storage.putObject(run, outcome.response.body, {
            role: 'raw', media_type: detected.mediaType, derived_from: null,
          });
        }
      }
      if (storage && run) await storage.appendAttempt(run, {
        type: 'attempt_finished', url: target.canonicalUrl, ...entry,
        source_hash: sourceRef?.hash ?? null,
      });
    },
  });
  if (attempted.outcome.kind !== ATTEMPT_KIND.SUCCESS) {
    return { outcome: attempted.outcome, timeline: attempted.timeline, sourceRef };
  }
  const response = attempted.outcome.response;
  const timeline = [...attempted.timeline];
  const recordTransform = async (adapter, transformOutcome) => {
    const entry = {
      attempt: timeline.length + 1,
      type: 'transform',
      adapter,
      version: '1',
      outcome: transformOutcome.kind,
      code: transformOutcome.code,
      ...(transformOutcome.details ? { details: transformOutcome.details } : {}),
    };
    timeline.push(entry);
    if (storage && run) await storage.appendAttempt(run, entry);
  };
  if (response.statusCode === 304) {
    return {
      outcome: { kind: ATTEMPT_KIND.BROKEN, code: ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR },
      timeline: attempted.timeline,
    };
  }

  if (job.kind === 'extract') {
    const alternativeCandidates = detected.kind === 'html'
      ? discoveredCandidates(basicHtmlRepresentation(response.body, response.finalUrl))
      : [];
    const parser = adapters.python;
    if (!parser || typeof parser.extractSchema !== 'function' || !sourceRef || !storage || !run) {
      const unavailable = { kind: ATTEMPT_KIND.SKIP, code: ATTEMPT_CODE.UNAVAILABLE };
      await recordTransform('python-parser', unavailable);
      return {
        outcome: unavailable,
        timeline,
        sourceRef,
        alternativeCandidates,
      };
    }
    const extracted = await parser.extractSchema({
      run,
      sourceRef,
      baseUrl: response.finalUrl,
      schema: job.schema,
      signal: context.signal,
    });
    await recordTransform('python-parser', extracted);
    if (extracted.kind !== ATTEMPT_KIND.SUCCESS) {
      return { outcome: extracted, timeline, sourceRef, alternativeCandidates };
    }
    return {
      outcome: { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK },
      representation: { kind: 'schema', data: extracted.value.data },
      sourceRef,
      artifactRef: extracted.value.artifact,
      timeline,
      usage: {
        wireBytes: response.wireBytes,
        decodedBytes: response.decodedBytes,
        artifactBytes: extracted.value.artifact.bytes,
      },
      requestedUrl: target.canonicalUrl,
      effectiveUrl: response.finalUrl,
      alternativeCandidates,
    };
  }

  const builtin = await builtinRepresentation({ job, response, detected, storage, run, sourceRef });
  let representation = builtin.representation;
  let artifactRef = builtin.artifactRef ?? sourceRef;
  let artifactBytes = builtin.artifactBytes ?? response.body;
  let accepted = builtin.outcome ?? acceptRepresentation({ goal: job.goal, representation });
  await recordTransform('builtin', accepted);
  if (accepted.kind === ATTEMPT_KIND.INADEQUATE && adapters.python?.parseHtml && sourceRef && run) {
    const decision = decideTransition(accepted, { hasNext: true, retriesLimit: 0, retriesUsed: 0 });
    if (decision.action === 'next') {
      const parsed = await adapters.python.parseHtml({
        run,
        sourceRef,
        baseUrl: response.finalUrl,
        signal: context.signal,
      });
      if (parsed.kind !== ATTEMPT_KIND.SUCCESS) {
        await recordTransform('python-parser', parsed);
        return { outcome: parsed, timeline, sourceRef };
      }
      representation = { kind: 'html', ...parsed.value };
      artifactRef = parsed.value.artifacts.markdown;
      artifactBytes = Buffer.from(parsed.value.markdown);
      accepted = acceptRepresentation({ goal: job.goal, representation });
      await recordTransform('python-parser', accepted);
    }
  }
  const browserSkip = renderedFallbackSkip(job, context.route ?? [], accepted);
  if (browserSkip) {
    accepted = browserSkip;
    await recordTransform('playwright', browserSkip);
  }
  if (accepted.kind !== ATTEMPT_KIND.SUCCESS) {
    return { outcome: accepted, timeline, sourceRef };
  }
  return {
    outcome: accepted,
    representation,
    sourceRef,
    artifactRef,
    artifactBytes,
    timeline,
    usage: {
      wireBytes: response.wireBytes,
      decodedBytes: response.decodedBytes,
      artifactBytes: artifactRef?.bytes ?? artifactBytes.length,
    },
    requestedUrl: target.canonicalUrl,
    effectiveUrl: response.finalUrl,
    alternativeCandidates: discoveredCandidates(representation),
  };
}

async function runUrlJobLegacy(job, {
  gateway,
  storage,
  pythonAdapter = null,
  clock = Date.now,
  sleep = async () => {},
  route = [],
  capabilities = [],
  interruption = null,
} = {}) {
  const context = { route, capabilities };
  let target;
  try {
    target = parsePublicUrl(job?.target?.url);
  } catch {
    return resultFor(job, context, RUN_STATUS.BLOCKED, ATTEMPT_CODE.POLICY_DENIED);
  }
  if (!storage || typeof storage.beginRun !== 'function') throw new TypeError('storage is required');
  const fingerprint = fingerprintFor(job, target.canonicalUrl);
  const warnings = [];
  let cached = null;
  let verifiedCache = null;
  if (job.cache.mode !== 'off') {
    const lookup = await storage.readCache(fingerprint);
    warnings.push(...(lookup.warnings ?? []));
    if (lookup.hit) {
      try {
        verifiedCache = await loadVerifiedCachedArtifact(
          storage,
          lookup,
          job.limits.maxBytesPerPage,
        );
        cached = lookup;
      } catch {
        warnings.push('cache_artifact_integrity_mismatch');
      }
    }
  }

  const nowMs = milliseconds(clock);
  const servedAt = iso(nowMs);
  if (cached && job.cache.mode === 'use' && Date.parse(cached.record.expires_at) > nowMs) {
    return finishCacheHit({
      job,
      context,
      storage,
      fingerprint,
      cached,
      verified: verifiedCache,
      canonicalUrl: target.canonicalUrl,
      servedAt,
      warnings,
    });
  }

  const run = await storage.beginRun({
    schema_version: 1,
    command: 'url',
    requested_url: target.canonicalUrl,
    method: 'GET',
    format: job.output.format,
    cache: job.cache.mode,
  });
  const conditionalHeaders = cached ? {
    ...(cached.record.etag ? { 'If-None-Match': cached.record.etag } : {}),
    ...(cached.record.last_modified ? { 'If-Modified-Since': cached.record.last_modified } : {}),
  } : {};
  const adapter = createNativeHttpAdapter({ gateway });
  let sourceRef = null;
  let detected = null;
  // Run-scoped guard: one signal/deadline commits the source captured so far as
  // an interrupted manifest and skips cache. Disabled unless the caller wires
  // signals (real CLI), so library/test callers see no process-level handlers.
  // ponytail: the guard body below stays flat rather than re-indenting ~350
  // lines; the try/finally exists only to detach handlers on normal completion.
  const guard = interruption ? createInterruptionGuard({
    storage,
    run,
    gateway,
    wallMs: job.limits.wallMs,
    buildInterruptedManifest: (termination) => ({
      ...manifestBase({
        run,
        requestedUrl: target.canonicalUrl,
        effectiveUrl: target.canonicalUrl,
        requestedFormat: job.output.format,
        format: job.output.format,
        fetchedAt: sourceRef ? iso(milliseconds(clock)) : null,
        servedAt: iso(milliseconds(clock)),
        status: RUN_STATUS.INTERRUPTED,
        attempts: [],
        sourceRef,
        artifacts: sourceRef ? [sourceRef] : [],
        warnings,
        evidence: sourceRef
          ? [{ url: target.canonicalUrl, hash: sourceRef.hash, status: 'source_captured' }]
          : [],
        cacheStatus: job.cache.mode === 'off' ? 'off' : 'miss',
      }),
      termination,
    }),
    ...interruption,
  }) : null;
  guard?.install();
  try {
  const attempted = await runNativeAttempts({
    ...job,
    runId: run.id,
    target: { url: target.canonicalUrl },
    conditionalHeaders,
  }, {
    adapter,
    clock,
    sleep,
    onAttemptStart: async (event) => storage.appendAttempt(run, {
      type: 'attempt_started',
      adapter: 'native',
      version: '1',
      ...event,
    }),
    onAttemptFinish: async ({ entry, outcome }) => {
      const response = outcome.response;
      if (outcome.kind === ATTEMPT_KIND.SUCCESS && response?.statusCode !== 304) {
        detected = detectRepresentation({ headers: response.headers, prefixBytes: response.body });
        sourceRef = await storage.putObject(run, response.body, {
          role: 'raw',
          media_type: detected.mediaType,
          derived_from: null,
        });
      }
      await storage.appendAttempt(run, {
        type: 'attempt_finished',
        ...entry,
        http: responseEvidence(outcome),
        source_hash: sourceRef?.hash ?? null,
      });
      return { sourceRef, detected };
    },
  });
  const attempts = addFinalEvidence(attempted.timeline, attempted.outcome);
  const finalHttp = responseEvidence(attempted.outcome);

  if (attempted.outcome.kind !== ATTEMPT_KIND.SUCCESS) {
    const terminal = outcomeStatus(attempted.outcome);
    const manifestValue = manifestBase({
      run,
      requestedUrl: target.canonicalUrl,
      effectiveUrl: finalHttp?.final_url ?? target.canonicalUrl,
      requestedFormat: job.output.format,
      format: job.output.format,
      fetchedAt: null,
      servedAt: iso(milliseconds(clock)),
      status: terminal.status,
      attempts,
      warnings,
      evidence: finalHttp ? [{ url: finalHttp.final_url, status: 'request_failed' }] : [],
      cacheStatus: job.cache.mode === 'off' ? 'off' : 'miss',
    });
    const manifest = await storage.commitManifest(run, manifestValue);
    return resultFor(job, context, terminal.status, terminal.code, {
      manifestPath: manifest.path,
      cacheStatus: job.cache.mode === 'off' ? 'off' : 'miss',
      warnings,
    });
  }

  const response = attempted.outcome.response;
  if (response.statusCode === 304) {
    if (!cached || !verifiedCache) {
      const broken = { kind: ATTEMPT_KIND.BROKEN, code: ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR };
      const manifest = await storage.commitManifest(run, manifestBase({
        run,
        requestedUrl: target.canonicalUrl,
        effectiveUrl: response.finalUrl,
        requestedFormat: job.output.format,
        format: job.output.format,
        fetchedAt: null,
        servedAt: iso(milliseconds(clock)),
        status: RUN_STATUS.INTERNAL_ERROR,
        attempts,
        warnings: [...warnings, 'unexpected_not_modified'],
        cacheStatus: 'miss',
      }));
      return resultFor(job, context, RUN_STATUS.INTERNAL_ERROR, broken.code, {
        manifestPath: manifest.path,
        cacheStatus: 'miss',
        warnings: [...warnings, 'unexpected_not_modified'],
      });
    }
    const completedAt = iso(milliseconds(clock));
    const manifestValue = manifestBase({
      run,
      requestedUrl: target.canonicalUrl,
      effectiveUrl: response.finalUrl,
      requestedFormat: job.output.format,
      format: cached.record.format,
      fetchedAt: cached.record.fetched_at,
      servedAt: completedAt,
      revalidatedAt: completedAt,
      status: RUN_STATUS.OK,
      attempts,
      sourceRef: verifiedCache.sourceRef,
      artifactRef: verifiedCache.artifactRef,
      artifacts: cached.manifest.artifacts,
      warnings,
      evidence: [{
        url: response.finalUrl,
        hash: verifiedCache.sourceRef.hash,
        status: 'not_modified_source_reused',
        http_status: 304,
      }],
      cacheStatus: 'revalidated',
    });
    const manifest = await storage.commitManifest(run, manifestValue);
    const headers = safeHeaders(response.headers);
    await storage.commitCache(fingerprint, cacheRecord({
      fingerprint,
      canonicalUrl: target.canonicalUrl,
      requestedFormat: job.output.format,
      run,
      manifest,
      sourceRef: verifiedCache.sourceRef,
      artifactRef: verifiedCache.artifactRef,
      fetchedAt: cached.record.fetched_at,
      expiresAt: iso(milliseconds(clock) + job.cache.ttlMs),
      effectiveUrl: response.finalUrl,
      mediaType: cached.record.media_type,
      headers: {
        etag: headers.etag ?? cached.record.etag,
        'last-modified': headers['last-modified'] ?? cached.record.last_modified,
      },
      format: cached.record.format,
    }));
    const artifactPath = await publishSelectedOutput(
      storage,
      job.output.path,
      verifiedCache.artifactRef,
      verifiedCache.bytes,
    );
    return resultFor(job, context, RUN_STATUS.OK, 'ok', {
      manifestPath: manifest.path,
      artifactPath,
      sourceHash: verifiedCache.sourceRef.hash,
      cacheStatus: 'revalidated',
      warnings,
    });
  }

  const fetchedAt = iso(milliseconds(clock));
  const requestedFormat = job.output.format;
  const effectiveFormat = detected.kind === 'binary' ? 'raw' : requestedFormat;
  warnings.push(...detected.warnings);
  let artifactRef = sourceRef;
  let artifactBytes = response.body;
  try {
    if (effectiveFormat !== 'raw') {
      const projection = await deriveRepresentation({
        format: effectiveFormat,
        sourcePath: await storage.resolve(sourceRef.path),
        mediaType: detected.mediaType,
        finalUrl: response.finalUrl,
        maxArtifactBytes: job.limits.maxArtifactBytes ?? job.limits.maxBytesPerPage,
      });
      warnings.push(...projection.warnings.filter((warning) => !warnings.includes(warning)));
      artifactBytes = projection.bytes;
      artifactRef = await storage.putObject(run, artifactBytes, {
        role: projection.format,
        media_type: derivedMediaType(projection.format, projection.mediaType),
        derived_from: sourceRef.hash,
        transform: {
          id: `native-${detected.kind}-${projection.format}`,
          version: '1',
          options_hash: hashBytes(Buffer.from(JSON.stringify({ format: projection.format }))),
        },
      });
    }
  } catch (error) {
    const blocked = error?.code === ATTEMPT_CODE.HARD_LIMIT || error?.code === 'hard_limit';
    const status = blocked ? RUN_STATUS.BLOCKED : RUN_STATUS.OUTPUT_FAILURE;
    const code = blocked ? ATTEMPT_CODE.HARD_LIMIT : 'output_failure';
    const manifest = await storage.commitManifest(run, manifestBase({
      run,
      requestedUrl: target.canonicalUrl,
      effectiveUrl: response.finalUrl,
      requestedFormat,
      format: effectiveFormat,
      fetchedAt,
      servedAt: iso(milliseconds(clock)),
      status,
      attempts,
      sourceRef,
      artifacts: [sourceRef],
      warnings,
      evidence: [{ url: response.finalUrl, hash: sourceRef.hash, status: 'source_captured' }],
      cacheStatus: job.cache.mode === 'off' ? 'off' : 'miss',
    }));
    return resultFor(job, context, status, code, {
      manifestPath: manifest.path,
      sourceHash: sourceRef.hash,
      cacheStatus: job.cache.mode === 'off' ? 'off' : 'miss',
      warnings,
    });
  }

  let parsedJson;
  if (detected.kind === 'json') {
    try {
      parsedJson = JSON.parse(response.body.toString('utf8'));
    } catch {
      parsedJson = undefined;
    }
  }
  let representation = job.goal === 'raw'
    ? { kind: detected.kind, body: response.body, byteLength: response.body.length, text: '' }
    : detected.kind === 'html'
    ? {
      ...basicHtmlRepresentation(response.body, response.finalUrl),
      markdown: artifactBytes.toString('utf8'),
    }
    : detected.kind === 'json'
      ? {
        kind: parsedJson === undefined ? 'invalid-json' : 'json',
        data: parsedJson,
        text: artifactBytes.toString('utf8'),
      }
      : {
          kind: detected.kind,
          text: artifactBytes.toString('utf8').trim(),
          markdown: artifactBytes.toString('utf8'),
        };
  let accepted = acceptRepresentation({ goal: job.goal, representation });
  const recordTransform = async (adapterId, transformOutcome) => {
    const entry = {
      attempt: attempts.length + 1,
      type: 'transform',
      adapter: adapterId,
      version: '1',
      outcome: transformOutcome.kind,
      code: transformOutcome.code,
      ...(transformOutcome.details ? { details: transformOutcome.details } : {}),
    };
    attempts.push(entry);
    await storage.appendAttempt(run, entry);
  };
  await recordTransform('builtin', accepted);
  let parserArtifacts = [];
  let alternatives = discoveredCandidates(representation);
  if (accepted.kind === ATTEMPT_KIND.INADEQUATE && pythonAdapter?.parseHtml
      && detected.kind === 'html') {
    const transition = decideTransition(accepted, { hasNext: true });
    if (transition.action === 'next') {
      const parsed = await pythonAdapter.parseHtml({
        run,
        sourceRef,
        baseUrl: response.finalUrl,
      });
      if (parsed.kind === ATTEMPT_KIND.SUCCESS) {
        representation = { kind: 'html', ...parsed.value };
        accepted = acceptRepresentation({ goal: job.goal, representation });
        const selected = parsed.value.artifacts[job.goal] ?? parsed.value.artifacts.markdown;
        if (accepted.kind === ATTEMPT_KIND.SUCCESS && selected) {
          artifactRef = selected;
          artifactBytes = await storage.readObject(selected, {
            maxBytes: job.limits.maxArtifactBytes ?? job.limits.maxBytesPerPage,
          });
        }
        parserArtifacts = Object.values(parsed.value.artifacts);
        alternatives = discoveredCandidates(parsed.value);
        await recordTransform('python-parser', accepted);
      } else {
        accepted = parsed;
        await recordTransform('python-parser', parsed);
      }
    }
  }
  const browserSkip = renderedFallbackSkip(job, route, accepted);
  if (browserSkip) {
    accepted = browserSkip;
    await recordTransform('playwright', browserSkip);
  }
  if (accepted.kind !== ATTEMPT_KIND.SUCCESS) {
    const stopped = pipelineResultStatus(accepted);
    const completedAt = iso(milliseconds(clock));
    const manifestValue = manifestBase({
      run,
      requestedUrl: target.canonicalUrl,
      effectiveUrl: response.finalUrl,
      requestedFormat,
      format: effectiveFormat,
      fetchedAt,
      servedAt: completedAt,
      status: stopped.status,
      attempts,
      sourceRef,
      artifacts: uniqueArtifacts([sourceRef, ...parserArtifacts]),
      warnings,
      evidence: [{ url: response.finalUrl, hash: sourceRef.hash, status: 'source_captured' }],
      cacheStatus: job.cache.mode === 'off' ? 'off' : 'miss',
    });
    manifestValue.alternatives = alternatives;
    const manifest = await storage.commitManifest(run, manifestValue);
    return resultFor(job, context, stopped.status, stopped.code, {
      manifestPath: manifest.path,
      sourceHash: sourceRef.hash,
      cacheStatus: job.cache.mode === 'off' ? 'off' : 'miss',
      warnings,
    });
  }

  const artifacts = uniqueArtifacts([sourceRef, artifactRef, ...parserArtifacts]);
  const completedAt = iso(milliseconds(clock));
  const cacheStatus = job.cache.mode === 'off' ? 'off' : 'miss';
  const manifestValue = manifestBase({
    run,
    requestedUrl: target.canonicalUrl,
    effectiveUrl: response.finalUrl,
    requestedFormat,
    format: effectiveFormat,
    fetchedAt,
    servedAt: completedAt,
    status: RUN_STATUS.OK,
    attempts,
    sourceRef,
    artifactRef,
    artifacts,
    warnings,
    evidence: [{ url: response.finalUrl, hash: sourceRef.hash, status: 'source_captured' }],
    cacheStatus,
  });
  manifestValue.alternatives = alternatives;
  const manifest = await storage.commitManifest(run, manifestValue);
  if (job.cache.mode !== 'off') {
    await storage.commitCache(fingerprint, cacheRecord({
      fingerprint,
      canonicalUrl: target.canonicalUrl,
      requestedFormat,
      run,
      manifest,
      sourceRef,
      artifactRef,
      fetchedAt,
      expiresAt: iso(milliseconds(clock) + job.cache.ttlMs),
      effectiveUrl: response.finalUrl,
      mediaType: detected.mediaType,
      headers: safeHeaders(response.headers),
      format: effectiveFormat,
    }));
  }
  const artifactPath = await publishSelectedOutput(storage, job.output.path, artifactRef, artifactBytes);
  return resultFor(job, context, RUN_STATUS.OK, 'ok', {
    manifestPath: manifest.path,
    artifactPath,
    sourceHash: sourceRef.hash,
    cacheStatus,
    warnings,
  });
  } finally {
    guard?.dispose(); // detach signal handlers + timer on normal completion
  }
}

export async function runUrlJob(job, deps = {}) {
  return runUrlPipeline({
    job,
    context: { finalizeUrl: true, deps },
    adapters: {},
  });
}

function uniqueArtifacts(values) {
  const seen = new Set();
  return values.filter((value) => {
    if (!value?.hash || seen.has(value.hash)) return false;
    seen.add(value.hash);
    return true;
  });
}

function pipelineResultStatus(outcome) {
  if (outcome?.kind === ATTEMPT_KIND.SUCCESS) return { status: RUN_STATUS.OK, code: 'ok' };
  if (outcome?.kind === ATTEMPT_KIND.TERMINAL) return outcomeStatus(outcome);
  if (outcome?.kind === ATTEMPT_KIND.BROKEN) {
    return { status: RUN_STATUS.INTERNAL_ERROR, code: outcome.code };
  }
  return { status: RUN_STATUS.EXHAUSTED, code: 'exhausted' };
}

export async function runExtractJob(job, {
  gateway,
  storage,
  pythonAdapter,
  clock = Date.now,
  sleep = async () => {},
  route = [],
  capabilities = [],
} = {}) {
  if (!storage || typeof storage.beginRun !== 'function') throw new TypeError('storage is required');
  const schema = validateExtractSchema(job.schema);
  const target = parsePublicUrl(job.target.url);
  const run = await storage.beginRun({
    schema_version: 1,
    command: 'extract',
    requested_url: target.canonicalUrl,
    schema,
  });
  const pipeline = await runUrlPipeline({
    job: { ...job, schema, target: { url: target.canonicalUrl } },
    context: { storage, run, gateway, clock, sleep, route },
    adapters: {
      native: createNativeHttpAdapter({ gateway }),
      ...(pythonAdapter ? { python: pythonAdapter } : {}),
    },
  });
  const terminal = pipelineResultStatus(pipeline.outcome);
  const artifacts = uniqueArtifacts([pipeline.sourceRef, pipeline.artifactRef]);
  const completedAt = iso(milliseconds(clock));
  const manifestValue = manifestBase({
    run,
    requestedUrl: target.canonicalUrl,
    effectiveUrl: pipeline.effectiveUrl ?? target.canonicalUrl,
    requestedFormat: 'json',
    format: 'json',
    fetchedAt: pipeline.sourceRef ? completedAt : null,
    servedAt: completedAt,
    status: terminal.status,
    attempts: pipeline.timeline ?? [],
    sourceRef: pipeline.sourceRef,
    artifactRef: pipeline.artifactRef,
    artifacts,
    evidence: pipeline.sourceRef ? [{
      url: pipeline.effectiveUrl ?? target.canonicalUrl,
      hash: pipeline.sourceRef.hash,
      status: 'source_captured',
    }] : [],
    cacheStatus: 'off',
  });
  manifestValue.alternatives = pipeline.alternativeCandidates ?? [];
  manifestValue.engine = {
    id: pipeline.outcome.kind === ATTEMPT_KIND.SUCCESS ? 'python-parser' : 'native',
    version: '1',
  };
  const manifest = await storage.commitManifest(run, manifestValue);
  let artifactPath;
  if (terminal.status === RUN_STATUS.OK) {
    const bytes = await storage.readObject(pipeline.artifactRef, {
      maxBytes: job.limits.maxArtifactBytes ?? job.limits.maxBytesPerPage,
    });
    artifactPath = await publishSelectedOutput(storage, job.output.path, pipeline.artifactRef, bytes);
  }
  return resultFor(job, { route, capabilities }, terminal.status, terminal.code, {
    manifestPath: manifest.path,
    ...(artifactPath ? { artifactPath } : {}),
    ...(pipeline.sourceRef ? { sourceHash: pipeline.sourceRef.hash } : {}),
    cacheStatus: 'off',
  });
}

export async function runCrawlJob(job, {
  gateway,
  storage,
  pythonAdapter,
  robotsGate,
  clock = Date.now,
  sleep = async () => {},
  route = [],
  capabilities = [],
} = {}) {
  if (!storage || typeof storage.beginRun !== 'function') throw new TypeError('storage is required');
  const target = parsePublicUrl(job.target.url);
  const run = await storage.beginRun({
    schema_version: 1,
    command: 'crawl',
    requested_url: target.canonicalUrl,
    scope: job.scope,
    discovery: job.discovery,
  });
  const gate = robotsGate ?? createRobotsGate({
    gateway,
    clock,
    sleep,
    maxBodyBytes: Math.min(job.limits.maxBytesPerPage, 512 * 1024),
    maxRedirects: job.limits.maxRedirects,
    retries: job.limits.retriesPerAdapter,
    timeoutMs: Math.min(job.limits.perAttemptMs, job.limits.wallMs),
  });
  const collected = [];
  const crawl = await runBoundedCrawl({
    job: { ...job, target: { url: target.canonicalUrl } },
    context: { storage, run, gateway, clock, sleep, robotsChecked: true },
    adapters: {
      native: createNativeHttpAdapter({ gateway }),
      ...(pythonAdapter ? { python: pythonAdapter } : {}),
    },
    robotsGate: gate,
    runUrlPipeline: async (input) => {
      const result = await runUrlPipeline({
        ...input,
        context: {
          ...input.context,
          storage,
          run,
          gateway,
          clock,
          sleep,
          route,
          robotsChecked: true,
        },
        adapters: {
          native: createNativeHttpAdapter({ gateway }),
          ...(pythonAdapter ? { python: pythonAdapter } : {}),
        },
      });
      collected.push(result.sourceRef, result.artifactRef);
      return result;
    },
    limits: job.limits,
    include: job.scope?.include ?? ['/**'],
    exclude: job.scope?.exclude ?? [],
    discovery: job.discovery,
    clock,
    sleep,
  });
  const crawlBytes = Buffer.from(`${JSON.stringify(crawl)}\n`);
  const crawlRef = await storage.putObject(run, crawlBytes, {
    role: 'crawl',
    media_type: 'application/json',
    derived_from: null,
  });
  const artifacts = uniqueArtifacts([...collected, crawlRef]);
  const completedAt = iso(milliseconds(clock));
  const status = crawl.status === 'ok'
    ? RUN_STATUS.OK
    : crawl.status === 'partial'
      ? RUN_STATUS.PARTIAL
      : crawl.status === 'blocked'
        ? RUN_STATUS.BLOCKED
        : RUN_STATUS.EXHAUSTED;
  const code = status === RUN_STATUS.OK
    ? 'ok'
    : status === RUN_STATUS.PARTIAL
      ? 'partial'
      : status === RUN_STATUS.BLOCKED
        ? (crawl.code ?? 'blocked')
        : 'exhausted';
  const manifestValue = manifestBase({
    run,
    requestedUrl: target.canonicalUrl,
    effectiveUrl: target.canonicalUrl,
    requestedFormat: job.output.format,
    format: 'crawl',
    fetchedAt: crawl.accepted?.length > 0 ? completedAt : null,
    servedAt: completedAt,
    status,
    attempts: crawl.ledger ?? [],
    sourceRef: crawlRef,
    artifactRef: crawlRef,
    artifacts,
    evidence: (crawl.accepted ?? []).map((entry) => ({
      url: entry.url, status: 'page_accepted', hash: entry.source_hash ?? null,
    })),
    cacheStatus: 'off',
  });
  manifestValue.crawl = crawl;
  const manifest = await storage.commitManifest(run, manifestValue);
  const artifactPath = await publishSelectedOutput(storage, job.output.path, crawlRef, crawlBytes);
  return resultFor(job, { route, capabilities }, status, code, {
    manifestPath: manifest.path,
    artifactPath,
    sourceHash: crawlRef.hash,
    cacheStatus: 'off',
  });
}

async function resolveStorage(storage, job) {
  const resolved = typeof storage === 'function' ? await storage(job) : storage;
  if (!resolved || typeof resolved.beginRun !== 'function') throw new TypeError('storage is unavailable');
  return resolved;
}

async function loadSchema(path) {
  const handle = await open(path, 'r');
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size < 2 || info.size > 64 * 1024) throw new TypeError('schema file is invalid');
    return validateExtractSchema(JSON.parse(await handle.readFile('utf8')));
  } finally {
    await handle.close();
  }
}

function invalidJobResult(job, capabilities, route) {
  return createResultEnvelope({
    command: job.kind,
    status: RUN_STATUS.INVALID_INPUT,
    code: 'invalid_input',
    message: 'Invalid schema or local job input',
    route,
    capabilities,
    warnings: [],
  });
}

function recoveryWarnings(recovery) {
  const warnings = [];
  if (recovery?.incomplete?.length) warnings.push(`incomplete_runs:${recovery.incomplete.length}`);
  if (recovery?.corrupt?.length) warnings.push(`corrupt_runs:${recovery.corrupt.length}`);
  return warnings;
}

// Startup recovery runs once per storage-backed command, before that run's first
// cache lookup, so a fresh run can never mask a crashed predecessor. A scan
// failure never blocks the run — the report is informational.
async function recoverOnce(resolved) {
  try {
    return await resolved.recoverIncompleteRuns();
  } catch {
    return null;
  }
}

export function createProductionExecutor({
  gateway,
  storage,
  pythonAdapter = null,
  robotsGate = null,
  clock = Date.now,
  sleep = async () => {},
  interruption = null,
}) {
  if (!gateway || typeof gateway.execute !== 'function') throw new TypeError('gateway is required');
  return async function executeJob(job, { registry = [] } = {}) {
    const snapshot = createCapabilitySnapshot(registry);
    const capabilities = healthReport(snapshot);
    if (job.kind === 'health') {
      return createResultEnvelope({
        command: 'health',
        status: RUN_STATUS.OK,
        code: 'health',
        message: 'Capability snapshot ready',
        route: [],
        capabilities,
        // Health surfaces the same startup recovery scan as an additive field.
        warnings: recoveryWarnings(await recoverOnce(await resolveStorage(storage, job))),
      });
    }
    const plan = buildRoutePlan(job, snapshot);
    if (job.routing.explain) {
      return createResultEnvelope({
        command: job.kind,
        status: RUN_STATUS.OK,
        code: 'route_explained',
        message: 'Deterministic route plan',
        route: plan.candidates,
        capabilities,
        warnings: [],
      });
    }
    if (job.kind === 'search') {
      // Free search fails closed: the default registry is empty, so no provider
      // is auto-selected and no network/SERP call happens — an absent provider is
      // terminal exhaustion, never internal_error or a paid/env-derived fallback.
      const searchStorage = await resolveStorage(storage, job);
      await recoverOnce(searchStorage); // before the search run touches cache
      const outcome = await runSearchJob(job, {
        registry: createSearchRegistry([]),
        storage: searchStorage,
        clock,
        runUrlJob: (childJob) => runUrlJob(childJob, {
          gateway, storage: searchStorage, clock, sleep, route: plan.candidates, capabilities,
        }),
      });
      return createResultEnvelope({
        command: 'search',
        status: outcome.status,
        code: outcome.code,
        message: outcome.message,
        route: plan.candidates,
        capabilities,
        warnings: [...(outcome.warnings ?? [])],
        ...(outcome.manifest_path ? { manifest_path: outcome.manifest_path } : {}),
      });
    }
    const localCommand = ['url', 'extract', 'crawl'].includes(job.kind);
    const eligibleNative = plan.candidates.some((candidate) => (
      candidate.id === 'native' && candidate.eligible
    ));
    if (!localCommand || job.routing.forcedEngine !== null && job.routing.forcedEngine !== 'native'
        || !eligibleNative) {
      return runModelRoute(job, snapshot);
    }
    let executableJob = job;
    if (job.kind === 'extract') {
      try {
        executableJob = { ...job, schema: await loadSchema(job.target.schemaPath) };
      } catch {
        return invalidJobResult(job, capabilities, plan.candidates);
      }
    }
    const resolvedStorage = await resolveStorage(storage, executableJob);
    await recoverOnce(resolvedStorage); // before beginRun/cache in the run below
    const parser = typeof pythonAdapter === 'function'
      ? await pythonAdapter({ storage: resolvedStorage, job: executableJob })
      : pythonAdapter;
    const common = {
      gateway,
      storage: resolvedStorage,
      pythonAdapter: parser,
      clock,
      sleep,
      route: plan.candidates,
      capabilities,
    };
    if (job.kind === 'extract') return runExtractJob(executableJob, common);
    if (job.kind === 'crawl') {
      return runCrawlJob(executableJob, {
        ...common,
        robotsGate: typeof robotsGate === 'function'
          ? await robotsGate({ storage: resolvedStorage, job: executableJob })
          : robotsGate,
      });
    }
    // Only the url orchestrator arms the interruption guard today; extract/crawl
    // interruptions fall through to the startup recovery scan above.
    // ponytail: url-only guard; wire extract/crawl the same way if signals must
    // commit their partial artifacts instead of leaning on recoverIncompleteRuns.
    return runUrlJob(executableJob, { ...common, interruption });
  };
}
