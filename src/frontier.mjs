import {
  ATTEMPT_CODE,
  ATTEMPT_KIND,
  RUN_STATUS,
} from './contracts.mjs';

const DEFAULT_LIMITS = Object.freeze({
  maxPages: 100,
  maxDepth: 3,
  wallMs: 60_000,
  maxTotalBytes: 64 * 1024 * 1024,
  maxFrontier: 1_000,
  concurrency: 1,
  delayMs: 250,
  retriesPerAdapter: 2,
  maxRedirects: 5,
});

const GLOB_MAX_LENGTH = 1_024;
const UNSAFE_GLOB = /[\u0000-\u001f\u007f\\?#\[\]{}()^|]/u;

function positiveInteger(value, fallback, label) {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new TypeError(`${label} must be a positive finite integer`);
  }
  return resolved;
}

function positiveFinite(value, fallback, label) {
  const resolved = value ?? fallback;
  if (!Number.isFinite(resolved) || resolved <= 0) {
    throw new TypeError(`${label} must be a positive finite number`);
  }
  return resolved;
}

function nonnegativeInteger(value, fallback, label) {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < 0) {
    throw new TypeError(`${label} must be a non-negative finite integer`);
  }
  return resolved;
}

function normalizeLimits(input = {}) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new TypeError('crawl limits must be an object');
  }
  return Object.freeze({
    maxPages: positiveInteger(input.maxPages, DEFAULT_LIMITS.maxPages, 'maxPages'),
    maxDepth: positiveInteger(input.maxDepth, DEFAULT_LIMITS.maxDepth, 'maxDepth'),
    wallMs: positiveFinite(input.wallMs, DEFAULT_LIMITS.wallMs, 'wallMs'),
    maxTotalBytes: positiveInteger(
      input.maxTotalBytes,
      DEFAULT_LIMITS.maxTotalBytes,
      'maxTotalBytes',
    ),
    maxFrontier: positiveInteger(
      input.maxFrontier,
      DEFAULT_LIMITS.maxFrontier,
      'maxFrontier',
    ),
    concurrency: positiveInteger(
      input.concurrency,
      DEFAULT_LIMITS.concurrency,
      'concurrency',
    ),
    delayMs: positiveFinite(input.delayMs, DEFAULT_LIMITS.delayMs, 'delayMs'),
    retriesPerAdapter: nonnegativeInteger(
      input.retriesPerAdapter,
      DEFAULT_LIMITS.retriesPerAdapter,
      'retriesPerAdapter',
    ),
    maxRedirects: nonnegativeInteger(
      input.maxRedirects,
      DEFAULT_LIMITS.maxRedirects,
      'maxRedirects',
    ),
  });
}

function originOf(value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError('crawl origin must be an absolute HTTP URL');
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) {
    throw new TypeError('crawl origin must be an absolute HTTP URL');
  }
  return url.origin;
}

/**
 * Return the narrow WHATWG identity used by a single crawl.
 * Query bytes and ordering are intentionally preserved; fragments are not sent on HTTP.
 */
export function canonicalFrontierKey(candidate, exactOrigin) {
  const origin = originOf(exactOrigin);
  let url;
  try {
    url = new URL(candidate, `${origin}/`);
  } catch {
    throw new TypeError('candidate must belong to the crawl exact origin');
  }
  if (url.origin !== origin || !['http:', 'https:'].includes(url.protocol)
      || url.username || url.password) {
    throw new TypeError('candidate must belong to the crawl exact origin');
  }
  url.hash = '';
  return url.href;
}

function validateGlob(glob) {
  if (typeof glob !== 'string' || glob.length === 0 || glob.length > GLOB_MAX_LENGTH
      || !glob.startsWith('/') || UNSAFE_GLOB.test(glob) || /\*{3,}/u.test(glob)) {
    throw new TypeError('crawl glob must be an anchored safe pathname glob');
  }
  const segments = glob.split('/');
  if (segments.some((segment) => segment === '..' || segment === '.')) {
    throw new TypeError('crawl glob must be an anchored safe pathname glob');
  }
  return glob;
}

function escapeRegex(value) {
  return value.replace(/[.+$]/gu, '\\$&');
}

function compileGlob(glob) {
  const validated = validateGlob(glob);
  let expression = '';
  for (let index = 0; index < validated.length; index += 1) {
    const character = validated[index];
    if (character !== '*') {
      expression += escapeRegex(character);
      continue;
    }
    if (validated[index + 1] === '*') {
      expression += '.*';
      index += 1;
    } else {
      expression += '[^/]*';
    }
  }
  return new RegExp(`^${expression}$`, 'u');
}

function copyLedgerEntry(entry, extra = {}) {
  return {
    url: entry.url,
    depth: entry.depth,
    source: entry.source,
    ...(entry.provenance === undefined ? {} : { provenance: entry.provenance }),
    ...extra,
  };
}

/**
 * FIFO crawl frontier. It owns canonical dedupe and scope; it never performs I/O.
 */
export function createFrontier({
  seedUrl,
  include = ['/**'],
  exclude = [],
  limits = {},
} = {}) {
  const origin = originOf(seedUrl);
  if (!Array.isArray(include) || !Array.isArray(exclude) || include.length === 0) {
    throw new TypeError('crawl include/exclude must be non-empty arrays');
  }
  const normalizedLimits = normalizeLimits(limits);
  const includeMatchers = include.map(compileGlob);
  const excludeMatchers = exclude.map(compileGlob);
  const queue = [];
  const seen = new Set();

  function enqueue(candidate, {
    depth = 0,
    source = seedUrl,
    provenance,
    seed = false,
  } = {}) {
    if (!Number.isSafeInteger(depth) || depth < 0) {
      return { accepted: false, reason: 'invalid_depth', url: String(candidate), depth, source };
    }

    let key;
    try {
      const resolved = typeof source === 'string'
        ? new URL(candidate, source).href
        : candidate;
      key = canonicalFrontierKey(resolved, origin);
    } catch {
      return { accepted: false, reason: 'off_origin', url: String(candidate), depth, source };
    }
    const pathname = new URL(key).pathname;
    const entry = { url: key, depth, source, provenance };

    if (depth > normalizedLimits.maxDepth) {
      return { accepted: false, reason: 'max_depth', ...entry };
    }
    if (excludeMatchers.some((matcher) => matcher.test(pathname))) {
      return { accepted: false, reason: 'excluded', ...entry };
    }
    // The seed is allowed to act as a discovery index for a narrower include scope.
    if (!seed && !includeMatchers.some((matcher) => matcher.test(pathname))) {
      return { accepted: false, reason: 'not_included', ...entry };
    }
    if (seen.has(key)) return { accepted: false, reason: 'duplicate', ...entry };
    if (queue.length >= normalizedLimits.maxFrontier) {
      return { accepted: false, reason: 'max_frontier', ...entry };
    }

    seen.add(key);
    queue.push(entry);
    return { accepted: true, ...entry };
  }

  const seed = enqueue(seedUrl, { depth: 0, source: null, provenance: 'seed', seed: true });

  return Object.freeze({
    origin,
    limits: normalizedLimits,
    seed,
    enqueue,
    dequeue() {
      return queue.shift() ?? null;
    },
    drain() {
      return queue.splice(0, queue.length);
    },
    snapshot() {
      return queue.map((entry) => ({ ...entry }));
    },
    hasSeen(candidate) {
      try {
        return seen.has(canonicalFrontierKey(candidate, origin));
      } catch {
        return false;
      }
    },
    get size() {
      return queue.length;
    },
  });
}

function outcomeOf(result) {
  if (result?.outcome && typeof result.outcome === 'object') return result.outcome;
  if (result?.status === RUN_STATUS.OK || result?.status === 'ok') {
    return { kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK };
  }
  if (result?.status === RUN_STATUS.BLOCKED || result?.status === 'blocked') {
    return { kind: ATTEMPT_KIND.TERMINAL, code: result.code ?? ATTEMPT_CODE.ACCESS_DENIED };
  }
  return {
    kind: ATTEMPT_KIND.BROKEN,
    code: result?.code ?? ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR,
  };
}

function isAccepted(outcome) {
  return outcome.kind === ATTEMPT_KIND.SUCCESS && outcome.code === ATTEMPT_CODE.OK;
}

function isBlocked(outcome) {
  return outcome.kind === ATTEMPT_KIND.TERMINAL;
}

function byteUsage(usage = {}) {
  const finite = (value) => Number.isFinite(value) && value >= 0 ? value : 0;
  const wireBytes = finite(usage.wireBytes ?? usage.wire_bytes);
  const decodedBytes = finite(usage.decodedBytes ?? usage.decoded_bytes);
  const artifactBytes = finite(usage.artifactBytes ?? usage.artifact_bytes);
  const explicit = finite(usage.totalBytes ?? usage.total_bytes);
  return {
    wireBytes,
    decodedBytes,
    artifactBytes,
    totalBytes: explicit > 0 ? explicit : wireBytes + decodedBytes + artifactBytes,
  };
}

function discoverySources(job, explicit) {
  const raw = explicit?.sources ?? explicit ?? job?.discovery?.sources ?? [];
  return new Set(Array.isArray(raw) ? raw : []);
}

function candidateUrl(candidate) {
  if (typeof candidate === 'string') return candidate;
  if (!candidate || typeof candidate !== 'object') return null;
  return candidate.url ?? candidate.href ?? null;
}

function candidateKind(candidate, fallback) {
  if (!candidate || typeof candidate !== 'object') return fallback;
  const raw = String(
    candidate.kind ?? candidate.type ?? candidate.sourceType ?? candidate.rel ?? fallback,
  ).toLowerCase();
  if (raw.includes('rss')) return 'rss';
  if (raw.includes('atom')) return 'atom';
  if (raw.includes('json') || raw === 'api') return 'api';
  if (raw.includes('sitemap')) return 'sitemap';
  if (raw.includes('html')) return 'html';
  return raw;
}

function alternativeCandidates(result) {
  const lists = [
    result?.alternativeCandidates,
    result?.alternative_candidates,
    result?.representation?.alternativeCandidates,
    result?.representation?.alternative_candidates,
    result?.representation?.alternatives,
  ];
  return lists.flatMap((list) => Array.isArray(list) ? list : []);
}

function pageLinks(result) {
  const links = result?.representation?.links ?? result?.links;
  return Array.isArray(links) ? links : [];
}

function appendEnqueueResult(result, ledgers, setLimit) {
  if (result.accepted) return;
  const entry = copyLedgerEntry(result, { reason: result.reason });
  if (result.reason === 'max_depth' || result.reason === 'max_frontier') {
    ledgers.unvisited.push(entry);
    setLimit(result.reason);
  } else {
    ledgers.skipped.push(entry);
  }
}

function resultStatus(accepted, blocked, failed, unvisited, limit) {
  if (accepted.length > 0) {
    return limit || blocked.length > 0 || failed.length > 0 || unvisited.length > 0
      ? RUN_STATUS.PARTIAL
      : RUN_STATUS.OK;
  }
  if (blocked.length > 0) return RUN_STATUS.BLOCKED;
  return RUN_STATUS.EXHAUSTED;
}

/**
 * Schedule a bounded exact-origin crawl. All network work is delegated to the
 * injected robots gate and shared URL pipeline, in that order.
 */
export async function runBoundedCrawl({
  job,
  context,
  adapters,
  robotsGate,
  runUrlPipeline,
  limits = job?.limits ?? {},
  include = job?.scope?.include ?? ['/**'],
  exclude = job?.scope?.exclude ?? [],
  discover,
  discovery,
  clock = Date.now,
  sleep = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
  signal = context?.signal,
} = {}) {
  if (!job?.target?.url || typeof robotsGate?.check !== 'function'
      || typeof runUrlPipeline !== 'function' || typeof clock !== 'function'
      || typeof sleep !== 'function') {
    throw new TypeError('bounded crawl requires a job, robots gate and URL pipeline');
  }

  const normalizedLimits = normalizeLimits(limits);
  const frontier = createFrontier({
    seedUrl: job.target.url,
    include,
    exclude,
    limits: normalizedLimits,
  });
  const sources = discoverySources(job, discover ?? discovery);
  const ledgers = { accepted: [], skipped: [], blocked: [], failed: [], unvisited: [] };
  const usage = {
    wireBytes: 0,
    decodedBytes: 0,
    artifactBytes: 0,
    totalBytes: 0,
    retriesUsed: 0,
    redirectsUsed: 0,
  };
  const startedAt = clock();
  const deadline = startedAt + normalizedLimits.wallMs;
  let limit = null;
  let pipelineCalls = 0;
  let nextPageStartAt = startedAt;
  let retriesRemaining = normalizedLimits.retriesPerAdapter;
  let redirectsRemaining = normalizedLimits.maxRedirects;
  const seenRobotsSitemaps = new Set();

  const setLimit = (reason) => {
    if (limit === null) {
      limit = reason === 'max_depth' ? 'max_depth'
        : reason === 'max_frontier' ? 'max_frontier'
          : reason;
    }
  };
  const recordEnqueue = (candidate, metadata) => {
    const result = frontier.enqueue(candidate, metadata);
    appendEnqueueResult(result, ledgers, setLimit);
    return result;
  };
  if (!frontier.seed.accepted) appendEnqueueResult(frontier.seed, ledgers, setLimit);

  const addDiscoveries = (result, parent) => {
    for (const link of pageLinks(result)) {
      const url = candidateUrl(link);
      if (url === null) continue;
      recordEnqueue(url, {
        depth: parent.depth + 1,
        source: parent.url,
        provenance: candidateKind(link, 'html_link'),
      });
    }
    for (const candidate of alternativeCandidates(result)) {
      const kind = candidateKind(candidate, 'alternate');
      if (!sources.has(kind) && !(kind === 'alternate' && sources.has('html'))) continue;
      const url = candidateUrl(candidate);
      if (url === null) continue;
      recordEnqueue(url, {
        depth: parent.depth + 1,
        source: parent.url,
        provenance: kind,
      });
    }
  };

  let stop = false;
  while (!stop && frontier.size > 0) {
    if (signal?.aborted) {
      setLimit('aborted');
      break;
    }
    if (clock() >= deadline) {
      setLimit('max_time');
      break;
    }

    const running = [];
    let batchRetryAllowance = retriesRemaining;
    let batchRedirectAllowance = redirectsRemaining;
    while (!stop && running.length < normalizedLimits.concurrency && frontier.size > 0) {
      const entry = frontier.dequeue();
      if (signal?.aborted) {
        ledgers.unvisited.push(copyLedgerEntry(entry, { reason: 'aborted' }));
        setLimit('aborted');
        stop = true;
        break;
      }
      if (clock() >= deadline) {
        ledgers.unvisited.push(copyLedgerEntry(entry, { reason: 'max_time' }));
        setLimit('max_time');
        stop = true;
        break;
      }

      let robots;
      try {
        robots = await robotsGate.check(entry.url, {
          runId: context?.runId ?? context?.run?.id,
          signal,
        });
      } catch {
        robots = { kind: ATTEMPT_KIND.TERMINAL, code: ATTEMPT_CODE.ROBOTS_DENIED };
      }
      if (!robots || robots.kind !== ATTEMPT_KIND.SUCCESS) {
        ledgers.blocked.push(copyLedgerEntry(entry, {
          reason: robots?.code ?? ATTEMPT_CODE.ROBOTS_DENIED,
        }));
        continue;
      }

      if (sources.has('sitemap') && Array.isArray(robots.sitemaps)) {
        for (const sitemap of robots.sitemaps) {
          if (seenRobotsSitemaps.has(sitemap)) continue;
          seenRobotsSitemaps.add(sitemap);
          recordEnqueue(sitemap, {
            depth: entry.depth + 1,
            source: entry.url,
            provenance: 'robots_sitemap',
          });
        }
      }

      // Policy/robots are gates, not pages. Page/byte caps are checked after them.
      if (pipelineCalls >= normalizedLimits.maxPages) {
        ledgers.unvisited.push(copyLedgerEntry(entry, { reason: 'max_pages' }));
        setLimit('max_pages');
        stop = true;
        break;
      }
      if (usage.totalBytes >= normalizedLimits.maxTotalBytes) {
        ledgers.unvisited.push(copyLedgerEntry(entry, { reason: 'max_total_bytes' }));
        setLimit('max_total_bytes');
        stop = true;
        break;
      }

      const crawlDelayMs = Number.isFinite(robots.crawlDelayMs) && robots.crawlDelayMs >= 0
        ? robots.crawlDelayMs
        : 0;
      const effectiveDelayMs = Math.max(normalizedLimits.delayMs, crawlDelayMs);
      const now = clock();
      const waitMs = Math.max(0, nextPageStartAt - now);
      if (now + waitMs >= deadline) {
        ledgers.unvisited.push(copyLedgerEntry(entry, { reason: 'max_time' }));
        setLimit('max_time');
        stop = true;
        break;
      }
      if (waitMs > 0) {
        try {
          await sleep(waitMs, { signal });
        } catch {
          ledgers.unvisited.push(copyLedgerEntry(entry, { reason: 'aborted' }));
          setLimit('aborted');
          stop = true;
          break;
        }
      }
      nextPageStartAt = now + waitMs + effectiveDelayMs;

      pipelineCalls += 1;
      const remainingWallMs = Math.max(1, Math.floor(deadline - clock()));
      const retryAllowance = batchRetryAllowance;
      const redirectAllowance = batchRedirectAllowance;
      batchRetryAllowance = 0;
      batchRedirectAllowance = 0;
      const pageJob = {
        ...job,
        kind: 'url',
        target: { ...job.target, url: entry.url },
        limits: {
          ...job.limits,
          wallMs: Math.min(job.limits?.wallMs ?? remainingWallMs, remainingWallMs),
          retriesPerAdapter: retryAllowance,
          maxRedirects: redirectAllowance,
        },
      };
      const promise = Promise.resolve()
        .then(() => runUrlPipeline({ job: pageJob, context, adapters }))
        .then((result) => ({ entry, result }))
        .catch(() => ({
          entry,
          result: {
            outcome: { kind: ATTEMPT_KIND.BROKEN, code: ATTEMPT_CODE.ADAPTER_CRASH },
          },
        }));
      running.push(promise);
    }

    const completed = await Promise.all(running);
    for (const { entry, result } of completed) {
      const outcome = outcomeOf(result);
      const acquisitionAttempts = Array.isArray(result?.timeline)
        ? result.timeline.filter((attempt) => attempt?.type !== 'transform')
        : [];
      const retriesUsed = Math.max(0, acquisitionAttempts.length - 1);
      const redirectsUsed = acquisitionAttempts.reduce((total, attempt) => (
        total + (Array.isArray(attempt?.http?.redirect_chain) ? attempt.http.redirect_chain.length : 0)
      ), 0);
      usage.retriesUsed += retriesUsed;
      usage.redirectsUsed += redirectsUsed;
      retriesRemaining = Math.max(0, retriesRemaining - retriesUsed);
      redirectsRemaining = Math.max(0, redirectsRemaining - redirectsUsed);
      const pageUsage = byteUsage(result?.usage);
      const nextTotal = usage.totalBytes + pageUsage.totalBytes;
      usage.wireBytes += pageUsage.wireBytes;
      usage.decodedBytes += pageUsage.decodedBytes;
      usage.artifactBytes += pageUsage.artifactBytes;
      usage.totalBytes = nextTotal;
      if (nextTotal > normalizedLimits.maxTotalBytes) {
        ledgers.blocked.push(copyLedgerEntry(entry, { reason: ATTEMPT_CODE.HARD_LIMIT }));
        setLimit('max_total_bytes');
        stop = true;
        continue;
      }

      if (isAccepted(outcome)) {
        ledgers.accepted.push(copyLedgerEntry(entry, {
          reason: ATTEMPT_CODE.OK,
          requestedUrl: entry.url,
          effectiveUrl: result?.effectiveUrl ?? result?.effective_url ?? entry.url,
          source_hash: result?.sourceRef?.hash ?? result?.source_hash ?? null,
          artifact_hash: result?.artifactRef?.hash ?? result?.artifact_hash ?? null,
          usage: pageUsage,
        }));
        addDiscoveries(result, entry);
      } else if (isBlocked(outcome)) {
        ledgers.blocked.push(copyLedgerEntry(entry, { reason: outcome.code }));
      } else {
        ledgers.failed.push(copyLedgerEntry(entry, { reason: outcome.code }));
      }
    }
    if (clock() > deadline) {
      setLimit('max_time');
      stop = true;
    }
  }

  const remainingReason = limit ?? 'not_visited';
  for (const entry of frontier.drain()) {
    ledgers.unvisited.push(copyLedgerEntry(entry, { reason: remainingReason }));
  }

  const status = resultStatus(
    ledgers.accepted,
    ledgers.blocked,
    ledgers.failed,
    ledgers.unvisited,
    limit,
  );
  const code = status === RUN_STATUS.OK ? ATTEMPT_CODE.OK
    : status === RUN_STATUS.PARTIAL ? 'partial'
      : status === RUN_STATUS.BLOCKED
        ? ledgers.blocked[0]?.reason ?? ATTEMPT_CODE.HARD_LIMIT
        : 'exhausted';

  const ledger = Object.entries(ledgers).flatMap(([state, entries]) => (
    entries.map((entry) => ({ state, ...entry }))
  ));
  return {
    status,
    code,
    limit,
    ...ledgers,
    ledger,
    usage,
    pagesAttempted: pipelineCalls,
  };
}
