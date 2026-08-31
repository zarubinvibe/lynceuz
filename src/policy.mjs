import { RUN_STATUS, deepFreeze } from './contracts.mjs';

const SENSITIVE_QUERY_KEY = /(?:access.?token|api.?key|auth(?:orization)?|client.?secret|credential|cookie|passw(?:or)?d|pwd|secret|session(?:id)?|signature|token)$/i;
const SPECIAL_HOSTS = new Set(['localhost', 'local', 'test', 'invalid', 'example', 'onion', 'home.arpa']);
const TERMINAL_BLOCKED = new Set([
  'policy_denied',
  'robots_denied',
  'access_denied',
  'auth_required',
  'captcha',
  'paywall',
  'paid_required',
  'hard_limit',
]);

export class PolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PolicyError';
    this.code = code;
  }
}

function deny(code, message) {
  throw new PolicyError(code, message);
}

function isDecimal(text) {
  if (text.length === 0) return false;
  for (const char of text) {
    if (char < '0' || char > '9') return false;
  }
  return true;
}

function parseIpv4(text) {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!isDecimal(part) || (part.length > 1 && part[0] === '0')) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value > 255) return null;
    bytes.push(value);
  }
  return bytes;
}

function isHex(text) {
  if (text.length === 0 || text.length > 4) return false;
  for (const char of text.toLowerCase()) {
    if (!((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f'))) return false;
  }
  return true;
}

function parseIpv6(text) {
  let source = text;
  if (source.startsWith('[') && source.endsWith(']')) source = source.slice(1, -1);
  if (source.includes('%')) return null;
  if (source.includes('.')) {
    const splitAt = source.lastIndexOf(':');
    if (splitAt < 0) return null;
    const ipv4 = parseIpv4(source.slice(splitAt + 1));
    if (!ipv4) return null;
    source = `${source.slice(0, splitAt)}:${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }

  const halves = source.split('::');
  if (halves.length > 2) return null;
  const parseHalf = (half) => {
    if (half === '') return [];
    const groups = half.split(':');
    if (groups.some((group) => !isHex(group))) return null;
    return groups.map((group) => Number.parseInt(group, 16));
  };
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves[1] ?? '');
  if (!left || !right) return null;
  if (halves.length === 1) {
    if (left.length !== 8) return null;
    return left;
  }
  const missing = 8 - left.length - right.length;
  if (missing < 1) return null;
  return [...left, ...Array(missing).fill(0), ...right];
}

function wordsToBytes(words) {
  const bytes = [];
  for (const word of words) bytes.push(word >>> 8, word & 0xff);
  return bytes;
}

function formatIpv6(words) {
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < words.length;) {
    if (words[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < words.length && words[end] === 0) end += 1;
    if (end - index > bestLength && end - index >= 2) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  const rendered = words.map((word) => word.toString(16));
  if (bestStart < 0) return rendered.join(':');
  const before = rendered.slice(0, bestStart).join(':');
  const after = rendered.slice(bestStart + bestLength).join(':');
  if (before === '' && after === '') return '::';
  if (before === '') return `::${after}`;
  if (after === '') return `${before}::`;
  return `${before}::${after}`;
}

function prefixMatches(bytes, prefix, bits) {
  const fullBytes = Math.floor(bits / 8);
  for (let index = 0; index < fullBytes; index += 1) {
    if (bytes[index] !== prefix[index]) return false;
  }
  const remaining = bits % 8;
  if (remaining === 0) return true;
  const mask = (0xff << (8 - remaining)) & 0xff;
  return (bytes[fullBytes] & mask) === (prefix[fullBytes] & mask);
}

const IPV4_SPECIAL = [
  ['0.0.0.0', 8, 'current-network'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'shared-address-space'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local'],
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'special-purpose'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.31.196.0', 24, 'special-purpose'],
  ['192.52.193.0', 24, 'special-purpose'],
  ['192.88.99.0', 24, 'deprecated-relay'],
  ['192.168.0.0', 16, 'private'],
  ['192.175.48.0', 24, 'special-purpose'],
  ['198.18.0.0', 15, 'benchmark'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
].map(([address, bits, reason]) => ({ prefix: parseIpv4(address), bits, reason }));

const IPV6_SPECIAL = [
  ['::', 96, 'ipv4-compatible'],
  ['::ffff:0:0', 96, 'ipv4-mapped'],
  ['64:ff9b::', 96, 'translation'],
  ['64:ff9b:1::', 48, 'translation-local'],
  ['100::', 64, 'discard-only'],
  ['2001::', 23, 'special-purpose'],
  ['2001:db8::', 32, 'documentation'],
  ['2002::', 16, 'deprecated-6to4'],
  ['2620:4f:8000::', 48, 'special-purpose'],
  ['3fff::', 20, 'documentation'],
  ['5f00::', 16, 'segment-routing'],
  ['fc00::', 7, 'unique-local'],
  ['fe80::', 10, 'link-local'],
  ['fec0::', 10, 'deprecated-site-local'],
  ['ff00::', 8, 'multicast'],
].map(([address, bits, reason]) => ({ prefix: wordsToBytes(parseIpv6(address)), bits, reason }));

export function classifyIpAddress(address) {
  if (typeof address !== 'string' || address.length === 0) deny('invalid_ip', 'invalid IP address');
  const source = address.startsWith('[') && address.endsWith(']') ? address.slice(1, -1) : address;
  const ipv4 = parseIpv4(source);
  if (ipv4) {
    const special = IPV4_SPECIAL.find((range) => prefixMatches(ipv4, range.prefix, range.bits));
    return deepFreeze({
      family: 4,
      normalized: ipv4.join('.'),
      bytes: ipv4,
      public: !special,
      reason: special?.reason ?? 'global',
    });
  }
  const words = parseIpv6(source.toLowerCase());
  if (!words) deny('invalid_ip', 'invalid IP address');
  const bytes = wordsToBytes(words);
  const special = IPV6_SPECIAL.find((range) => prefixMatches(bytes, range.prefix, range.bits));
  return deepFreeze({
    family: 6,
    normalized: formatIpv6(words),
    bytes,
    public: !special,
    reason: special?.reason ?? 'global',
  });
}

function normalizeHostname(hostname) {
  const bracketed = hostname.startsWith('[') && hostname.endsWith(']');
  if (bracketed) return hostname.toLowerCase();
  return hostname.toLowerCase().replace(/\.+$/, '');
}

function specialHostname(hostname) {
  const labels = hostname.split('.');
  const suffix = labels.at(-1);
  return SPECIAL_HOSTS.has(hostname)
    || SPECIAL_HOSTS.has(suffix)
    || hostname.endsWith('.localhost')
    || hostname.endsWith('.internal')
    || hostname === 'metadata.google.internal';
}

function maybeClassifyIp(hostname) {
  const source = hostname.startsWith('[') && hostname.endsWith(']') ? hostname.slice(1, -1) : hostname;
  if (!source.includes(':') && !isDecimal(source.replaceAll('.', ''))) return null;
  try {
    return classifyIpAddress(source);
  } catch {
    return null;
  }
}

export function parsePublicUrl(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 8192) {
    deny('invalid_url', 'invalid target URL');
  }
  if (input !== input.trim() || /[\u0000-\u001f\u007f\\]/u.test(input) || /%(?:00|0a|0d)/i.test(input)) {
    deny('ambiguous_url', 'target URL contains ambiguous bytes');
  }
  const authorityStart = input.indexOf('://');
  const afterScheme = authorityStart >= 0 ? input.slice(authorityStart + 3) : '';
  const authorityEnd = afterScheme.search(/[/?#]/u);
  const authority = authorityEnd < 0 ? afterScheme : afterScheme.slice(0, authorityEnd);
  if (/%(?:25|2f|3a|40|5c)/i.test(authority)) {
    deny('ambiguous_url', 'target URL contains encoded authority delimiter');
  }

  let url;
  try {
    url = new URL(input);
  } catch {
    deny('invalid_url', 'invalid target URL');
  }
  if (!['http:', 'https:'].includes(url.protocol)) deny('scheme_denied', 'target scheme is not allowed');
  if (url.username !== '' || url.password !== '') deny('userinfo_denied', 'target credentials are not allowed');
  if (url.hostname === '') deny('empty_host', 'target hostname is empty');
  if (url.hostname.includes('%')) deny('zone_identifier_denied', 'target zone identifier is not allowed');
  if (url.port !== '' && !['80', '443'].includes(url.port)) deny('port_denied', 'target port is not allowed');
  for (const key of url.searchParams.keys()) {
    const normalized = key.normalize('NFKC').replace(/[\s._-]/gu, '');
    if (SENSITIVE_QUERY_KEY.test(normalized)) deny('sensitive_query', 'target has a sensitive query key');
  }

  const hostname = normalizeHostname(url.hostname);
  if (specialHostname(hostname)) deny('special_hostname', 'target hostname is not public');
  const literal = maybeClassifyIp(hostname);
  if (literal && !literal.public) deny('non_public_ip', 'target IP is not public');
  url.hostname = hostname;
  url.hash = '';
  const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
  return deepFreeze({
    canonicalUrl: url.href,
    protocol: url.protocol,
    hostname,
    port,
    isIpLiteral: literal !== null,
  });
}

function compareBytes(left, right) {
  if (left.family !== right.family) return left.family - right.family;
  for (let index = 0; index < left.bytes.length; index += 1) {
    if (left.bytes[index] !== right.bytes[index]) return left.bytes[index] - right.bytes[index];
  }
  return 0;
}

export function authorizeResolvedTarget(target, records) {
  if (!target || typeof target !== 'object' || typeof target.hostname !== 'string') {
    deny('invalid_target', 'invalid canonical target');
  }
  if (!Array.isArray(records) || records.length === 0) deny('empty_dns', 'DNS answer set is empty');
  const classified = records.map((record) => {
    if (!record || typeof record.address !== 'string' || ![4, 6].includes(record.family)) {
      deny('invalid_dns_answer', 'DNS answer is invalid');
    }
    const result = classifyIpAddress(record.address);
    if (result.family !== record.family) deny('dns_family_mismatch', 'DNS address family mismatch');
    if (!result.public) deny('dns_non_public', 'DNS answer is not public');
    return result;
  }).sort(compareBytes);
  const unique = classified.filter((entry, index) => (
    index === 0 || entry.family !== classified[index - 1].family || entry.normalized !== classified[index - 1].normalized
  ));
  return deepFreeze({
    resolved: unique.map(({ normalized, family }) => ({ address: normalized, family })),
    selectedAddress: unique[0].normalized,
  });
}

export function authorizeCost(descriptor) {
  const allowed = descriptor?.cost === 'local-zero' && descriptor?.price === 0;
  return deepFreeze(allowed
    ? { allowed: true, state: 'allowed_zero', reason: 'proven_local_zero' }
    : { allowed: false, state: 'unknown_and_blocked', reason: 'price_not_proven_zero' });
}

// A balance/price reading is trustworthy only while fresh; a stale figure is a
// silent overdraft waiting to happen, so it fails closed like an unknown one.
const CLOUD_BALANCE_MAX_AGE_MS = 5 * 60 * 1000;

function isFreshBalance(balance, observedAt, now) {
  if (!Number.isFinite(balance) || typeof observedAt !== 'string') return false;
  const at = Date.parse(observedAt);
  if (Number.isNaN(at)) return false;
  const age = now - at;
  return age >= 0 && age <= CLOUD_BALANCE_MAX_AGE_MS;
}

// Additive credit-cost proof for provider-managed (cloud) descriptors. Credentials
// or a binary never grant authority — only a fresh free balance, a proven-zero
// money price, a hard no-overage ceiling, and a bounded worst case that fits both
// the ceiling and the run-ledger's remaining credits do. Anything unknown, stale,
// negative, impossible, or over-reserve fails closed. Pure: never mutates ledger.
export function authorizeCloudCost(descriptor, ledger, clock = () => new Date()) {
  const provider = descriptor ?? {};
  const runLedger = ledger ?? {};
  const now = clock().getTime();
  const block = (reason) => deepFreeze({ allowed: false, state: 'unknown_and_blocked', reason, reserve: 0 });

  if (!isFreshBalance(provider.balance, provider.balanceObservedAt, now)
    || !isFreshBalance(runLedger.balance, runLedger.observedAt, now)) {
    return block('balance_unknown_or_stale');
  }
  if (!Number.isFinite(provider.price) || provider.price !== 0) return block('price_unknown');
  const ceiling = Math.min(...[provider.hardCeiling, runLedger.hardCeiling].filter(Number.isFinite));
  if (!Number.isFinite(ceiling) || ceiling <= 0) return block('no_hard_ceiling');
  const worst = provider.worstCaseCredits;
  const committed = Number.isFinite(runLedger.committed) ? runLedger.committed : 0;
  const available = runLedger.balance - committed;
  if (!(Number.isInteger(worst) && worst > 0 && worst <= ceiling && worst <= available)) {
    return block('worst_case_unbounded');
  }
  if (!(Number.isFinite(provider.freeCredits) && provider.freeCredits >= worst)) {
    return block('insufficient_free_credits');
  }
  if (provider.preflightMayCharge !== false) return block('preflight_may_charge');
  return deepFreeze({ allowed: true, state: 'reservable_free', reason: 'cost_proven', reserve: worst });
}

export function classifyTerminalOutcome(outcome) {
  const code = outcome?.code;
  if (TERMINAL_BLOCKED.has(code)) {
    return deepFreeze({ terminal: true, status: RUN_STATUS.BLOCKED, code });
  }
  if (code === 'not_found' || code === 'gone') {
    return deepFreeze({ terminal: true, status: RUN_STATUS.EXHAUSTED, code });
  }
  if (code === 'rate_limited' && outcome?.exhausted === true) {
    return deepFreeze({ terminal: true, status: RUN_STATUS.BLOCKED, code });
  }
  return deepFreeze({ terminal: false, status: null, code: code ?? null });
}
