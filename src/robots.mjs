import { ATTEMPT_CODE, ATTEMPT_KIND, deepFreeze } from './contracts.mjs';
import { parsePublicUrl } from './policy.mjs';

const ROBOTS_USER_AGENT = 'Lynceuz/1.0';
const MAX_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_BODY_BYTES = 512 * 1024;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CACHE_ENTRIES = 256;
const MAX_LINE_BYTES = 16 * 1024;
const MAX_RULES = 10_000;
const UNRESERVED = /^[A-Za-z0-9._~-]$/u;
const HEX_PAIR = /^[0-9A-Fa-f]{2}$/u;
const POLICY_FAILURE_CODES = new Set([
  'ambiguous_url',
  'dns_family_mismatch',
  'dns_non_public',
  'empty_host',
  'invalid_dns_answer',
  'invalid_redirect',
  'invalid_url',
  'non_public_ip',
  'peer_mismatch',
  'port_denied',
  'redirect_downgrade',
  'redirect_loop',
  'scheme_denied',
  'sensitive_query',
  'special_hostname',
  'userinfo_denied',
  'zone_identifier_denied',
]);

function finiteInteger(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} is invalid`);
  }
  return value;
}

function nowMilliseconds(clock) {
  const value = clock();
  const milliseconds = value instanceof Date ? value.valueOf() : value;
  if (!Number.isFinite(milliseconds)) throw new TypeError('robots clock returned an invalid value');
  return milliseconds;
}

function normalizePercentEncoding(value) {
  let normalized = '';
  for (let index = 0; index < value.length;) {
    if (value[index] === '%' && index + 2 < value.length) {
      const pair = value.slice(index + 1, index + 3);
      if (HEX_PAIR.test(pair)) {
        const character = String.fromCharCode(Number.parseInt(pair, 16));
        normalized += UNRESERVED.test(character) ? character : `%${pair.toUpperCase()}`;
        index += 3;
        continue;
      }
    }

    const codePoint = value.codePointAt(index);
    const character = String.fromCodePoint(codePoint);
    if (codePoint <= 0x7f) normalized += character;
    else normalized += encodeURIComponent(character).toUpperCase();
    index += character.length;
  }
  return normalized;
}

function regexEscape(character) {
  return /[\\^$.*+?()[\]{}|]/u.test(character) ? `\\${character}` : character;
}

function compileRule(rawPattern, allow) {
  const endAnchored = rawPattern.endsWith('$');
  const withoutAnchor = endAnchored ? rawPattern.slice(0, -1) : rawPattern;
  const pattern = normalizePercentEncoding(withoutAnchor);
  let expression = '^';
  let previousStar = false;
  for (const character of pattern) {
    if (character === '*') {
      if (!previousStar) expression += '.*';
      previousStar = true;
    } else {
      expression += regexEscape(character);
      previousStar = false;
    }
  }
  if (endAnchored) expression += '$';
  const specificity = Buffer.byteLength(pattern.replaceAll('*', ''));
  return Object.freeze({
    allow,
    pattern: rawPattern,
    matcher: new RegExp(expression, 'u'),
    specificity,
  });
}

function targetPath(value) {
  let parsed;
  try {
    parsed = value.startsWith('/')
      ? new URL(value, 'https://robots.invalid')
      : new URL(value);
  } catch {
    throw new TypeError('robots target URL is invalid');
  }
  return normalizePercentEncoding(`${parsed.pathname}${parsed.search}`);
}

function parseSitemap(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return null;
  parsed.hash = '';
  return parsed.href;
}

function selectGroups(groups, userAgent) {
  const productToken = userAgent.toLowerCase().split(/[\s/]/u, 1)[0];
  const wildcard = [];
  let bestLength = -1;
  let specific = [];

  for (const group of groups) {
    let groupBest = -1;
    for (const agent of group.agents) {
      const token = agent.toLowerCase();
      if (token === '*') continue;
      if (productToken.includes(token)) groupBest = Math.max(groupBest, token.length);
    }
    if (group.agents.includes('*')) wildcard.push(group);
    if (groupBest > bestLength) {
      bestLength = groupBest;
      specific = groupBest < 0 ? [] : [group];
    } else if (groupBest >= 0 && groupBest === bestLength) {
      specific.push(group);
    }
  }

  return specific.length > 0 ? specific : wildcard;
}

export function parseRobots(source, {
  userAgent = ROBOTS_USER_AGENT,
  maxBytes = DEFAULT_BODY_BYTES,
} = {}) {
  if (typeof source !== 'string' || typeof userAgent !== 'string'
      || userAgent.length === 0 || userAgent.length > 128
      || /[\u0000-\u001f\u007f]/u.test(userAgent)) {
    throw new TypeError('robots input is invalid');
  }
  finiteInteger(maxBytes, 'robots maxBytes', { minimum: 1 });
  if (Buffer.byteLength(source) > maxBytes || source.includes('\0')) {
    throw new TypeError('robots body is invalid');
  }

  const groups = [];
  const sitemaps = [];
  const sitemapSet = new Set();
  let current = null;
  let directivesStarted = false;
  let ruleCount = 0;

  for (let rawLine of source.replace(/^\uFEFF/u, '').split(/\r?\n/u)) {
    if (Buffer.byteLength(rawLine) > MAX_LINE_BYTES) throw new TypeError('robots line is too large');
    const comment = rawLine.indexOf('#');
    if (comment >= 0) rawLine = rawLine.slice(0, comment);
    const separator = rawLine.indexOf(':');
    if (separator < 0) continue;
    const field = rawLine.slice(0, separator).trim().toLowerCase();
    const value = rawLine.slice(separator + 1).trim();

    if (field === 'sitemap') {
      const sitemap = parseSitemap(value);
      if (sitemap && !sitemapSet.has(sitemap)) {
        sitemapSet.add(sitemap);
        sitemaps.push(sitemap);
      }
      continue;
    }

    if (field === 'user-agent') {
      const agent = value.toLowerCase();
      if (agent.length === 0 || agent.length > 128 || /[^\x21-\x7e]/u.test(agent)) continue;
      if (!current || directivesStarted) {
        current = { agents: [], rules: [], crawlDelays: [] };
        groups.push(current);
        directivesStarted = false;
      }
      if (!current.agents.includes(agent)) current.agents.push(agent);
      continue;
    }

    if (!current || current.agents.length === 0) continue;
    if (field === 'allow' || field === 'disallow') {
      directivesStarted = true;
      if (value === '') continue;
      ruleCount += 1;
      if (ruleCount > MAX_RULES) throw new TypeError('robots has too many rules');
      current.rules.push(compileRule(value, field === 'allow'));
      continue;
    }
    if (field === 'crawl-delay') {
      directivesStarted = true;
      if (!/^(?:\d+\.?\d*|\.\d+)$/u.test(value)) continue;
      const seconds = Number(value);
      if (Number.isFinite(seconds) && seconds >= 0 && seconds <= 86_400) {
        current.crawlDelays.push(Math.ceil(seconds * 1000));
      }
    }
  }

  const selected = selectGroups(groups, userAgent);
  const rules = selected.flatMap((group) => group.rules);
  const selectedDelays = selected
    .filter((group) => group.agents.some((agent) => agent !== '*'))
    .flatMap((group) => group.crawlDelays);
  const fallbackDelays = selected.flatMap((group) => group.crawlDelays);
  const delays = selectedDelays.length > 0 ? selectedDelays : fallbackDelays;
  const crawlDelayMs = delays.length === 0 ? 0 : Math.max(...delays);

  function decide(url) {
    const path = targetPath(url);
    let winner = null;
    for (const rule of rules) {
      if (!rule.matcher.test(path)) continue;
      if (!winner || rule.specificity > winner.specificity
          || (rule.specificity === winner.specificity && rule.allow && !winner.allow)) {
        winner = rule;
      }
    }
    return Object.freeze({
      allowed: winner?.allow ?? true,
      matchedRule: winner?.pattern ?? null,
    });
  }

  return Object.freeze({
    allows: (url) => decide(url).allowed,
    decide,
    crawlDelayMs,
    sitemaps: Object.freeze([...sitemaps]),
  });
}

function singleHeader(headers, wantedName) {
  if (!headers || typeof headers !== 'object') return null;
  const matches = Object.entries(headers)
    .filter(([name]) => name.toLowerCase() === wantedName)
    .map(([, value]) => value);
  if (matches.length !== 1) return null;
  const value = matches[0];
  if (Array.isArray(value)) return value.length === 1 ? String(value[0]) : null;
  return value === undefined ? null : String(value);
}

function abortable(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(signal.reason ?? new Error('robots request aborted'));
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(signal.reason ?? new Error('robots request aborted'));
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

async function readBoundedBody(body, maxBytes, signal) {
  if (body === null || body === undefined) return Buffer.alloc(0);
  if (Buffer.isBuffer(body) || body instanceof Uint8Array || typeof body === 'string') {
    const bytes = Buffer.from(body);
    if (bytes.length > maxBytes) throw new TypeError('robots body exceeds limit');
    return bytes;
  }

  const chunks = [];
  let total = 0;
  try {
    if (typeof body[Symbol.asyncIterator] === 'function') {
      const iterator = body[Symbol.asyncIterator]();
      while (true) {
        const { done, value: chunk } = await abortable(iterator.next(), signal);
        if (done) break;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        total += bytes.length;
        if (total > maxBytes) throw new TypeError('robots body exceeds limit');
        chunks.push(bytes);
      }
    } else if (typeof body.getReader === 'function') {
      const reader = body.getReader();
      try {
        while (true) {
          const { done, value } = await abortable(reader.read(), signal);
          if (done) break;
          const bytes = Buffer.from(value);
          total += bytes.length;
          if (total > maxBytes) throw new TypeError('robots body exceeds limit');
          chunks.push(bytes);
        }
      } finally {
        reader.releaseLock?.();
      }
    } else {
      throw new TypeError('robots response body is invalid');
    }
  } catch (error) {
    try {
      body.destroy?.();
      await body.cancel?.();
    } catch {
      // The fail-closed result below is more important than cleanup diagnostics.
    }
    throw error;
  }
  return Buffer.concat(chunks, total);
}

function discardBody(body) {
  try {
    body?.destroy?.();
    const cancellation = body?.cancel?.();
    cancellation?.catch?.(() => {});
  } catch {
    // Decision remains fail-closed if response cleanup itself fails.
  }
}

function terminal(code, reason, details = {}) {
  return deepFreeze({
    kind: ATTEMPT_KIND.TERMINAL,
    code,
    cacheStatus: 'miss',
    details: { reason, ...details },
  });
}

function success({ cacheStatus, crawlDelayMs = 0, sitemaps = [], reason, matchedRule = null }) {
  return deepFreeze({
    kind: ATTEMPT_KIND.SUCCESS,
    code: ATTEMPT_CODE.OK,
    cacheStatus,
    crawlDelayMs,
    sitemaps: [...sitemaps],
    details: { reason, matchedRule },
  });
}

function retryAfterMilliseconds(headers, now) {
  const value = singleHeader(headers, 'retry-after');
  if (value === null) return 0;
  if (/^\d+$/u.test(value.trim())) return Number(value.trim()) * 1000;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - now) : 0;
}

async function defaultSleep(milliseconds, { signal } = {}) {
  if (milliseconds <= 0) return;
  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (action, value) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener?.('abort', onAbort);
      action(value);
    };
    const timer = setTimeout(() => finish(resolve), milliseconds);
    const onAbort = () => {
      clearTimeout(timer);
      finish(reject, signal?.reason ?? new Error('robots retry aborted'));
    };
    if (signal?.aborted) onAbort();
    else signal?.addEventListener?.('abort', onAbort, { once: true });
  });
}

export function createRobotsGate({
  gateway,
  clock = Date.now,
  ttlMs = MAX_CACHE_TTL_MS,
  maxBodyBytes = DEFAULT_BODY_BYTES,
  maxRedirects = 5,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxCacheEntries = DEFAULT_CACHE_ENTRIES,
  retries = 0,
  sleep = defaultSleep,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  if (!gateway || typeof gateway.execute !== 'function') {
    throw new TypeError('robots gate requires EgressGateway');
  }
  if (typeof clock !== 'function' || typeof sleep !== 'function'
      || typeof setTimer !== 'function' || typeof clearTimer !== 'function') {
    throw new TypeError('robots gate ports are invalid');
  }
  if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new TypeError('robots ttlMs is invalid');
  finiteInteger(maxBodyBytes, 'robots maxBodyBytes', { minimum: 1 });
  finiteInteger(maxRedirects, 'robots maxRedirects');
  finiteInteger(maxCacheEntries, 'robots maxCacheEntries', { minimum: 1, maximum: 4096 });
  finiteInteger(retries, 'robots retries', { maximum: 8 });
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new TypeError('robots timeoutMs is invalid');

  const effectiveTtlMs = Math.min(ttlMs, MAX_CACHE_TTL_MS);
  const cache = new Map();

  function remember(origin, entry, now) {
    if (effectiveTtlMs === 0) return;
    cache.delete(origin);
    cache.set(origin, { ...entry, expiresAt: now + effectiveTtlMs });
    while (cache.size > maxCacheEntries) cache.delete(cache.keys().next().value);
  }

  function cached(origin, now) {
    const entry = cache.get(origin);
    if (!entry) return null;
    if (now >= entry.expiresAt) {
      cache.delete(origin);
      return null;
    }
    cache.delete(origin);
    cache.set(origin, entry);
    return entry;
  }

  function decide(entry, targetUrl, cacheStatus) {
    if (entry.kind === 'allow_all') {
      return success({ cacheStatus, reason: entry.reason });
    }
    const decision = entry.parsed.decide(targetUrl);
    if (!decision.allowed) {
      return deepFreeze({
        kind: ATTEMPT_KIND.TERMINAL,
        code: ATTEMPT_CODE.ROBOTS_DENIED,
        cacheStatus,
        crawlDelayMs: entry.parsed.crawlDelayMs,
        sitemaps: [...entry.parsed.sitemaps],
        details: { reason: 'rule_denied', matchedRule: decision.matchedRule },
      });
    }
    return success({
      cacheStatus,
      crawlDelayMs: entry.parsed.crawlDelayMs,
      sitemaps: entry.parsed.sitemaps,
      reason: 'rule_allowed',
      matchedRule: decision.matchedRule,
    });
  }

  async function check(inputUrl, { runId = 'robots', signal } = {}) {
    let target;
    try {
      target = parsePublicUrl(inputUrl);
    } catch (error) {
      return terminal(ATTEMPT_CODE.POLICY_DENIED, error?.code ?? 'invalid_url');
    }
    const targetUrl = target.canonicalUrl;
    const origin = new URL(targetUrl).origin;
    const now = nowMilliseconds(clock);
    const hit = cached(origin, now);
    if (hit) return decide(hit, targetUrl, 'hit');

    const controller = new AbortController();
    const onAbort = () => controller.abort(signal?.reason ?? new Error('robots request aborted'));
    if (signal?.aborted) onAbort();
    else signal?.addEventListener?.('abort', onAbort, { once: true });
    const timer = setTimer(() => controller.abort(new Error('robots request timed out')), timeoutMs);

    try {
      const robotsUrl = new URL('/robots.txt', origin).href;
      for (let attempt = 0; attempt <= retries; attempt += 1) {
        let response;
        try {
          response = await gateway.execute({
            runId,
            purpose: 'robots',
            url: robotsUrl,
            method: 'GET',
            headers: {
              Accept: 'text/plain, text/*;q=0.9, */*;q=0.1',
              'User-Agent': ROBOTS_USER_AGENT,
            },
            remaining: {
              wallMs: timeoutMs,
              bytes: maxBodyBytes,
              redirects: maxRedirects,
            },
          }, { signal: controller.signal });
        } catch (error) {
          if (POLICY_FAILURE_CODES.has(error?.code)) {
            return terminal(ATTEMPT_CODE.POLICY_DENIED, error.code, { stage: 'robots_fetch' });
          }
          const reason = error?.code === 'redirect_limit'
            ? 'robots_redirect_limit'
            : 'robots_unreachable';
          return terminal(ATTEMPT_CODE.ROBOTS_DENIED, reason);
        }

        const statusCode = response.statusCode;
        if (controller.signal.aborted) {
          discardBody(response.body);
          return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_timeout');
        }
        if (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599) {
          discardBody(response.body);
          return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_protocol_error');
        }
        if (statusCode === 429 && attempt < retries) {
          discardBody(response.body);
          const delayMs = retryAfterMilliseconds(response.headers, nowMilliseconds(clock));
          if (delayMs >= timeoutMs || controller.signal.aborted) {
            return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_rate_limited');
          }
          try {
            await sleep(delayMs, { signal: controller.signal });
          } catch {
            return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_timeout');
          }
          continue;
        }

        if (statusCode === 404 || (statusCode >= 400 && statusCode < 500
            && ![401, 403, 429].includes(statusCode))) {
          discardBody(response.body);
          const entry = { kind: 'allow_all', reason: statusCode === 404 ? 'robots_not_found' : 'robots_unavailable' };
          remember(origin, entry, nowMilliseconds(clock));
          return decide(entry, targetUrl, 'miss');
        }

        if ([401, 403, 429].includes(statusCode)) {
          discardBody(response.body);
          const reason = statusCode === 429 ? 'robots_rate_limited' : 'robots_access_denied';
          return terminal(ATTEMPT_CODE.ROBOTS_DENIED, reason, { statusCode });
        }
        if (statusCode >= 500 || statusCode < 200 || statusCode >= 300) {
          discardBody(response.body);
          return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_unreachable', { statusCode });
        }

        const contentLength = singleHeader(response.headers, 'content-length');
        if (contentLength !== null
            && (!/^\d+$/u.test(contentLength.trim()) || Number(contentLength) > maxBodyBytes)) {
          discardBody(response.body);
          return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_body_limit');
        }

        let parsed;
        try {
          const bytes = await readBoundedBody(response.body, maxBodyBytes, controller.signal);
          const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
          parsed = parseRobots(text, { userAgent: ROBOTS_USER_AGENT, maxBytes: maxBodyBytes });
        } catch {
          return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_parse_failed');
        }
        const entry = { kind: 'parsed', parsed };
        remember(origin, entry, nowMilliseconds(clock));
        return decide(entry, targetUrl, 'miss');
      }
      return terminal(ATTEMPT_CODE.ROBOTS_DENIED, 'robots_rate_limited');
    } finally {
      clearTimer(timer);
      signal?.removeEventListener?.('abort', onAbort);
    }
  }

  return Object.freeze({
    check,
    ttlMs: effectiveTtlMs,
    clearCache: () => cache.clear(),
    cacheInfo: () => Object.freeze({ size: cache.size, maxEntries: maxCacheEntries }),
  });
}
