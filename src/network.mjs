import { deepFreeze } from './contracts.mjs';
import { connect as connectTcp } from 'node:net';
import {
  PolicyError,
  authorizeResolvedTarget,
  classifyIpAddress,
  parsePublicUrl,
} from './policy.mjs';

const PURPOSES = new Set(['robots', 'page', 'subresource', 'search-api', 'cloud-api']);
const METHODS = new Set(['GET', 'HEAD']);
const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const MAX_REQUEST_HEADER_BYTES = 16 * 1024;
const MAX_RESPONSE_HEADER_BYTES = 32 * 1024;
const MAX_HEADER_VALUE_BYTES = 8 * 1024;
const HEADER_TIMEOUT_MS = 10_000;
const SAFE_REQUEST_HEADERS = new Map([
  ['accept', 'Accept'],
  ['accept-encoding', 'Accept-Encoding'],
  ['if-modified-since', 'If-Modified-Since'],
  ['if-none-match', 'If-None-Match'],
  ['user-agent', 'User-Agent'],
]);

function policyError(code, message) {
  return new PolicyError(code, message);
}

function normalizeRequestHeaders(headers) {
  if (headers === undefined) return Object.freeze({});
  if (!headers || typeof headers !== 'object' || Array.isArray(headers)) {
    throw policyError('invalid_headers', 'request headers are invalid');
  }

  const normalized = {};
  const seen = new Set();
  let totalBytes = 0;
  for (const [rawName, value] of Object.entries(headers)) {
    const name = rawName.toLowerCase();
    const canonicalName = SAFE_REQUEST_HEADERS.get(name);
    if (!canonicalName || seen.has(name) || typeof value !== 'string') {
      throw policyError('invalid_headers', 'request headers are not allowed');
    }
    const valueBytes = Buffer.byteLength(value);
    if (valueBytes === 0 || valueBytes > MAX_HEADER_VALUE_BYTES
        || /[\u0000-\u001f\u007f]/u.test(value)) {
      throw policyError('invalid_headers', 'request header value is invalid');
    }
    totalBytes += Buffer.byteLength(canonicalName) + valueBytes + 4;
    if (totalBytes > MAX_REQUEST_HEADER_BYTES) {
      throw policyError('invalid_headers', 'request headers are too large');
    }
    seen.add(name);
    normalized[canonicalName] = value;
  }
  return Object.freeze(normalized);
}

function normalizeIntent(intent) {
  if (!intent || typeof intent !== 'object') throw policyError('invalid_intent', 'network intent is invalid');
  if (typeof intent.runId !== 'string' || intent.runId.length === 0 || intent.runId.length > 128) {
    throw policyError('invalid_intent', 'network intent run id is invalid');
  }
  if (!PURPOSES.has(intent.purpose) || !METHODS.has(intent.method)) {
    throw policyError('invalid_intent', 'network intent authority is invalid');
  }
  const remaining = intent.remaining;
  if (!remaining || !Number.isFinite(remaining.wallMs) || remaining.wallMs <= 0
      || !Number.isFinite(remaining.bytes) || remaining.bytes <= 0
      || !Number.isInteger(remaining.redirects) || remaining.redirects < 0) {
    throw policyError('invalid_intent', 'network intent budget is invalid');
  }
  return {
    runId: intent.runId,
    purpose: intent.purpose,
    url: intent.url,
    method: intent.method,
    headers: normalizeRequestHeaders(intent.headers),
    remaining: {
      wallMs: remaining.wallMs,
      bytes: remaining.bytes,
      redirects: remaining.redirects,
    },
  };
}

function validateRequestPermit(permit, method) {
  if (!permit || typeof permit !== 'object' || !METHODS.has(method)
      || !['http:', 'https:'].includes(permit.protocol)
      || typeof permit.canonicalUrl !== 'string'
      || typeof permit.hostname !== 'string' || permit.hostname.length === 0
      || !Number.isInteger(permit.port) || ![80, 443].includes(permit.port)
      || typeof permit.selectedAddress !== 'string') {
    throw new TypeError('pinned request requires a valid permit');
  }

  let target;
  try {
    target = new URL(permit.canonicalUrl);
  } catch {
    throw new TypeError('pinned request requires a valid permit');
  }
  const canonicalPort = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  if (target.protocol !== permit.protocol || target.hostname !== permit.hostname
      || canonicalPort !== permit.port || target.username !== '' || target.password !== '') {
    throw new TypeError('pinned request permit is inconsistent');
  }
  const selected = classifyIpAddress(permit.selectedAddress);
  return { target, family: selected.family, address: permit.selectedAddress };
}

function requestHost(target) {
  const defaultPort = target.protocol === 'https:' ? '443' : '80';
  return target.port === '' || target.port === defaultPort
    ? target.hostname
    : `${target.hostname}:${target.port}`;
}

function requestTimeout(permit) {
  if (!Number.isFinite(permit.expiresAtMs)) return HEADER_TIMEOUT_MS;
  return Math.max(1, Math.min(HEADER_TIMEOUT_MS, permit.expiresAtMs - Date.now()));
}

export function createNodeRequestPinned({ httpRequest, httpsRequest }) {
  if (typeof httpRequest !== 'function' || typeof httpsRequest !== 'function') {
    throw new TypeError('pinned request requires HTTP and HTTPS request functions');
  }

  return async function requestPinned({ permit, method, headers, signal } = {}) {
    const { target, family, address } = validateRequestPermit(permit, method);
    const safeHeaders = normalizeRequestHeaders(headers);
    const timeoutMs = requestTimeout(permit);
    const request = permit.protocol === 'https:' ? httpsRequest : httpRequest;
    const lookup = (hostname, options, callback) => {
      if (typeof options === 'function') {
        callback = options;
        options = {};
      }
      if (typeof callback !== 'function') throw new TypeError('lookup callback is required');
      queueMicrotask(() => {
        if (hostname !== permit.hostname) {
          callback(new Error('pinned lookup hostname mismatch'));
          return;
        }
        if (options?.all === true) callback(null, [{ address, family }]);
        else callback(null, address, family);
      });
    };

    return new Promise((resolve, reject) => {
      let settled = false;
      let clientRequest;
      let timer;
      const finish = (action, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener?.('abort', onAbort);
        action(value);
      };
      const fail = (error) => finish(reject, error instanceof Error ? error : new Error('request failed'));
      const onAbort = () => {
        const reason = signal?.reason instanceof Error ? signal.reason : new Error('request aborted');
        try {
          clientRequest?.destroy?.(reason);
        } catch {
          fail(reason);
          return;
        }
        fail(reason);
      };
      const onTimeout = () => {
        const error = new Error('response header timeout');
        error.code = 'ERR_RESPONSE_HEADER_TIMEOUT';
        try {
          clientRequest?.destroy?.(error);
        } catch {
          fail(error);
          return;
        }
        fail(error);
      };

      if (signal?.aborted) {
        onAbort();
        return;
      }

      const options = {
        protocol: permit.protocol,
        hostname: permit.hostname,
        port: permit.port,
        path: `${target.pathname}${target.search}`,
        method,
        headers: { ...safeHeaders, Host: requestHost(target) },
        setHost: false,
        agent: false,
        signal,
        lookup,
        maxHeaderSize: MAX_RESPONSE_HEADER_BYTES,
        timeout: timeoutMs,
        ...(permit.protocol === 'https:' ? { servername: permit.hostname } : {}),
      };

      try {
        clientRequest = request(options, (response) => {
          const peerAddress = response?.socket?.remoteAddress;
          if (typeof peerAddress !== 'string') {
            response?.destroy?.();
            fail(new Error('response peer address is unavailable'));
            return;
          }
          let normalizedPeer;
          try {
            normalizedPeer = classifyIpAddress(peerAddress).normalized;
          } catch {
            response?.destroy?.();
            fail(new Error('response peer address is invalid'));
            return;
          }
          clientRequest?.setTimeout?.(0);
          finish(resolve, {
            statusCode: response.statusCode,
            headers: response.headers ?? {},
            body: response,
            peerAddress: normalizedPeer,
          });
        });
        clientRequest.once('error', fail);
        if (settled) return;
        signal?.addEventListener?.('abort', onAbort, { once: true });
        if (signal?.aborted) {
          onAbort();
          return;
        }
        clientRequest.setTimeout?.(timeoutMs, onTimeout);
        timer = setTimeout(onTimeout, timeoutMs);
        clientRequest.end();
      } catch (error) {
        fail(error);
      }
    });
  };
}

export function createNodeConnectPinned({ connect = connectTcp, now = Date.now } = {}) {
  if (typeof connect !== 'function' || typeof now !== 'function') {
    throw new TypeError('pinned connector requires a TCP connector and clock');
  }

  return async function connectPinned({ permit, signal } = {}) {
    if (!permit || typeof permit !== 'object' || !['http:', 'https:'].includes(permit.protocol)
        || !Number.isInteger(permit.port) || ![80, 443].includes(permit.port)
        || typeof permit.selectedAddress !== 'string') {
      throw new TypeError('pinned connector requires a valid permit');
    }
    const selected = classifyIpAddress(permit.selectedAddress);
    const remainingMs = Number.isFinite(permit.expiresAtMs) ? permit.expiresAtMs - now() : 10_000;
    if (remainingMs <= 0) throw policyError('permit_expired', 'network permit expired');
    const timeoutMs = Math.min(10_000, remainingMs);

    return new Promise((resolve, reject) => {
      let socket;
      let settled = false;
      let timer;
      const finish = (action, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener?.('abort', onAbort);
        action(value);
      };
      const fail = (error) => {
        try { socket?.destroy?.(); } catch {}
        finish(reject, error instanceof Error ? error : new Error('TCP connection failed'));
      };
      const onAbort = () => fail(signal?.reason ?? new Error('TCP connection aborted'));
      if (signal?.aborted) {
        onAbort();
        return;
      }
      try {
        socket = connect({
          host: selected.normalized,
          port: permit.port,
          family: selected.family,
        });
        socket.once('connect', () => {
          const peerAddress = socket.remoteAddress;
          if (typeof peerAddress !== 'string') {
            fail(new Error('TCP peer address is unavailable'));
            return;
          }
          finish(resolve, { socket, peerAddress });
        });
        socket.once('error', fail);
        signal?.addEventListener?.('abort', onAbort, { once: true });
        timer = setTimeout(() => fail(new Error('TCP connection timeout')), timeoutMs);
        timer.unref?.();
      } catch (error) {
        fail(error);
      }
    });
  };
}

function literalRecord(target) {
  if (!target.isIpLiteral) return null;
  const hostname = target.hostname.startsWith('[') && target.hostname.endsWith(']')
    ? target.hostname.slice(1, -1)
    : target.hostname;
  const classified = classifyIpAddress(hostname);
  return [{ address: classified.normalized, family: classified.family }];
}

function peerMatches(selectedAddress, peerAddress) {
  if (typeof peerAddress !== 'string') return false;
  try {
    const selected = classifyIpAddress(selectedAddress);
    const peer = classifyIpAddress(peerAddress);
    if (selected.family === peer.family) return selected.normalized === peer.normalized;
    const mapped = peer.family === 6 && peer.reason === 'ipv4-mapped'
      ? peer.bytes.slice(12).join('.')
      : null;
    return selected.family === 4 && selected.normalized === mapped;
  } catch {
    return false;
  }
}

function redirectLocation(headers) {
  if (!headers || typeof headers !== 'object') return null;
  const matches = Object.entries(headers).filter(([name]) => name.toLowerCase() === 'location');
  if (matches.length !== 1) return null;
  const value = matches[0][1];
  if (Array.isArray(value)) {
    if (value.length !== 1 || typeof value[0] !== 'string') return null;
    return validLocation(value[0]) ? value[0] : null;
  }
  return typeof value === 'string' && validLocation(value) ? value : null;
}

function validLocation(value) {
  return value.length > 0 && value.length <= 8192 && !/[\u0000-\u001f\u007f]/u.test(value);
}

async function closeRedirectBody(body) {
  try {
    if (!body) return;
    if (typeof body.destroy === 'function') {
      body.destroy();
      return;
    }
    if (typeof body.cancel === 'function') await body.cancel();
  } catch {
    throw policyError('invalid_port_result', 'response body cleanup failed');
  }
}

function closeSocket(socket) {
  try {
    socket?.destroy?.();
  } catch {
    // The policy decision remains fail-closed even when cleanup fails.
  }
}

function assertPortResult(value, kind) {
  if (!value || typeof value !== 'object' || typeof value.peerAddress !== 'string') {
    throw policyError('invalid_port_result', `${kind} port returned an invalid peer`);
  }
}

export function createEgressGateway({ lookupAll, connectPinned, requestPinned, now = Date.now }) {
  if (typeof lookupAll !== 'function' || typeof connectPinned !== 'function' || typeof requestPinned !== 'function') {
    throw new TypeError('egress gateway requires injected ports');
  }
  if (typeof now !== 'function') throw new TypeError('egress gateway requires a clock');

  async function authorizeIntent(rawIntent, { signal } = {}) {
    const intent = normalizeIntent(rawIntent);
    const target = parsePublicUrl(intent.url);
    let records = literalRecord(target);
    if (!records) {
      try {
        records = await lookupAll(target.hostname, { signal });
      } catch {
        throw policyError('dns_resolution_failed', 'DNS resolution failed');
      }
    }
    const authorized = authorizeResolvedTarget(target, records);
    return deepFreeze({
      canonicalUrl: target.canonicalUrl,
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port,
      resolved: authorized.resolved,
      selectedAddress: authorized.selectedAddress,
      policyVersion: '1',
      purpose: intent.purpose,
      method: intent.method,
      expiresAtMs: now() + Math.min(intent.remaining.wallMs, 10_000),
    });
  }

  function assertFresh(permit) {
    if (now() > permit.expiresAtMs) throw policyError('permit_expired', 'network permit expired');
  }

  async function openAuthorizedTunnel(intent, { signal } = {}) {
    const permit = await authorizeIntent(intent, { signal });
    assertFresh(permit);
    let opened;
    try {
      opened = await connectPinned({ permit, signal });
    } catch {
      throw policyError('connect_failed', 'pinned connection failed');
    }
    assertPortResult(opened, 'connector');
    if (!peerMatches(permit.selectedAddress, opened.peerAddress)) {
      closeSocket(opened.socket);
      throw policyError('peer_mismatch', 'peer address mismatch');
    }
    return { socket: opened.socket, permit, peerAddress: opened.peerAddress };
  }

  async function execute(rawIntent, { signal } = {}) {
    let intent = normalizeIntent(rawIntent);
    const redirectChain = [];
    const visited = new Set();

    while (true) {
      const permit = await authorizeIntent(intent, { signal });
      assertFresh(permit);
      visited.add(permit.canonicalUrl);
      let response;
      try {
        response = await requestPinned({
          permit,
          method: intent.method,
          headers: intent.headers,
          signal,
        });
      } catch {
        throw policyError('request_failed', 'pinned request failed');
      }
      assertPortResult(response, 'request');
      if (!peerMatches(permit.selectedAddress, response.peerAddress)) {
        await closeRedirectBody(response.body);
        throw policyError('peer_mismatch', 'peer address mismatch');
      }
      if (!Number.isInteger(response.statusCode) || response.statusCode < 100 || response.statusCode > 599) {
        await closeRedirectBody(response.body);
        throw policyError('invalid_port_result', 'request port returned an invalid status');
      }

      const isRedirect = REDIRECT_STATUS.has(response.statusCode);
      const location = isRedirect ? redirectLocation(response.headers) : null;
      if (isRedirect && location === null) {
        await closeRedirectBody(response.body);
        throw policyError('invalid_redirect', 'redirect response is invalid');
      }
      if (!isRedirect) {
        return {
          statusCode: response.statusCode,
          headers: response.headers ?? {},
          body: response.body,
          finalUrl: permit.canonicalUrl,
          redirectChain: deepFreeze(redirectChain),
          permit,
        };
      }

      await closeRedirectBody(response.body);
      if (intent.remaining.redirects === 0) throw policyError('redirect_limit', 'redirect limit exhausted');
      let nextAbsolute;
      try {
        nextAbsolute = new URL(location, permit.canonicalUrl).href;
      } catch {
        throw policyError('invalid_redirect', 'redirect target is invalid');
      }
      const next = parsePublicUrl(nextAbsolute);
      if (permit.protocol === 'https:' && next.protocol === 'http:') {
        throw policyError('redirect_downgrade', 'redirect downgrade is not allowed');
      }
      if (visited.has(next.canonicalUrl)) throw policyError('redirect_loop', 'redirect loop detected');
      redirectChain.push(deepFreeze({
        statusCode: response.statusCode,
        from: permit.canonicalUrl,
        to: next.canonicalUrl,
      }));
      intent = {
        ...intent,
        url: next.canonicalUrl,
        method: response.statusCode === 303 ? 'GET' : intent.method,
        headers: intent.headers,
        remaining: { ...intent.remaining, redirects: intent.remaining.redirects - 1 },
      };
    }
  }

  return Object.freeze({ authorizeIntent, openAuthorizedTunnel, execute });
}
