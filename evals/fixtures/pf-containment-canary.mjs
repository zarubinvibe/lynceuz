import { once } from 'node:events';
import { createSocket } from 'node:dgram';
import { connect, createServer } from 'node:net';
import { networkInterfaces } from 'node:os';

const LOOPBACK = '127.0.0.1';
const MAX_MESSAGE_BYTES = 256;

export const CANARY_PROTOCOLS = Object.freeze({
  proxy_tcp: Object.freeze({ request: 'LYNCEUZ_PROXY_TCP?', response: 'LYNCEUZ_PROXY_TCP_OK' }),
  direct_tcp: Object.freeze({ request: 'LYNCEUZ_DIRECT_TCP?', response: 'LYNCEUZ_DIRECT_TCP_LEAK' }),
  udp: Object.freeze({ request: 'LYNCEUZ_UDP?', response: 'LYNCEUZ_UDP_LEAK' }),
  quic: Object.freeze({ request: 'LYNCEUZ_QUIC_INITIAL?', response: 'LYNCEUZ_QUIC_RETRY_LEAK' }),
});

function selectNonLoopbackIpv4(interfaces = networkInterfaces()) {
  const candidates = Object.entries(interfaces)
    .sort(([left], [right]) => left.localeCompare(right))
    .flatMap(([name, addresses]) => (addresses ?? []).map((address) => ({ name, ...address })))
    .filter(({ address, family, internal }) => (
      (family === 'IPv4' || family === 4)
      && internal === false
      && !address.startsWith('127.')
      && address !== '0.0.0.0'
    ));
  const routed = candidates.find(({ netmask }) => netmask !== '255.255.255.255');
  const selected = routed ?? candidates[0];
  if (!selected) throw new Error('local_non_loopback_ipv4_missing');
  return selected.address;
}

async function closeTcp(server, sockets) {
  for (const socket of sockets) socket.destroy();
  if (!server.listening) return;
  const closed = once(server, 'close');
  server.close();
  await closed;
}

async function createTcpResponder(host, protocol, port = 0) {
  const sockets = new Set();
  const stats = { requests: 0, responses: 0 };
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    const chunks = [];
    let bytes = 0;
    socket.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > MAX_MESSAGE_BYTES) {
        socket.destroy();
        return;
      }
      chunks.push(Buffer.from(chunk));
      const request = Buffer.concat(chunks).toString('utf8');
      if (request === protocol.request) {
        stats.requests += 1;
        stats.responses += 1;
        socket.end(protocol.response);
      }
    });
  });
  server.listen(port, host);
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('tcp_responder_address_missing');
  return {
    endpoint: Object.freeze({ host, port: address.port }),
    stats,
    close: () => closeTcp(server, sockets),
  };
}

async function createUdpResponder(host, protocol) {
  const socket = createSocket('udp4');
  const stats = { requests: 0, responses: 0 };
  socket.on('message', (message, peer) => {
    if (message.length > MAX_MESSAGE_BYTES || message.toString('utf8') !== protocol.request) return;
    stats.requests += 1;
    socket.send(protocol.response, peer.port, peer.address, (error) => {
      if (!error) stats.responses += 1;
    });
  });
  socket.bind(0, host);
  await once(socket, 'listening');
  const address = socket.address();
  return {
    endpoint: Object.freeze({ host, port: address.port }),
    stats,
    async close() {
      const closed = once(socket, 'close');
      socket.close();
      await closed;
    },
  };
}

function observation(channel, operationSucceeded, response) {
  const expected = CANARY_PROTOCOLS[channel].response;
  return Object.freeze({
    channel,
    operation_succeeded: operationSucceeded,
    response,
    response_confirmed: response === expected,
  });
}

export async function exchangeTcp(channel, endpoint, { timeoutMs = 250 } = {}) {
  const protocol = CANARY_PROTOCOLS[channel];
  return new Promise((resolve) => {
    let operationSucceeded = false;
    let settled = false;
    const chunks = [];
    const socket = connect(endpoint);
    const finish = (response = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(observation(channel, operationSucceeded, response));
    };
    const timer = setTimeout(() => finish(), timeoutMs);
    socket.once('connect', () => {
      operationSucceeded = true;
      socket.write(protocol.request);
    });
    socket.on('data', (chunk) => {
      if (Buffer.concat(chunks).length + chunk.length > MAX_MESSAGE_BYTES) return finish();
      chunks.push(Buffer.from(chunk));
    });
    socket.once('end', () => finish(Buffer.concat(chunks).toString('utf8')));
    socket.once('error', () => finish());
  });
}

export async function exchangeUdp(channel, endpoint, { timeoutMs = 250 } = {}) {
  const protocol = CANARY_PROTOCOLS[channel];
  return new Promise((resolve) => {
    const socket = createSocket('udp4');
    let operationSucceeded = false;
    let settled = false;
    const finish = (response = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      resolve(observation(channel, operationSucceeded, response));
    };
    const timer = setTimeout(() => finish(), timeoutMs);
    socket.once('error', () => finish());
    socket.on('message', (message, peer) => {
      if (peer.port === endpoint.port && message.length <= MAX_MESSAGE_BYTES) {
        finish(message.toString('utf8'));
      }
    });
    socket.send(protocol.request, endpoint.port, endpoint.host, (error) => {
      operationSucceeded = !error;
      if (error) finish();
    });
  });
}

export function evaluateCanaryObservations(observations, { negativeControl = false } = {}) {
  const proxyAllowed = observations.proxy_tcp?.response_confirmed === true;
  const directChannels = ['direct_tcp', 'udp', 'quic'];
  const confirmed = directChannels.filter((channel) => observations[channel]?.response_confirmed === true);
  if (negativeControl) {
    const detectedEveryChannel = confirmed.length === directChannels.length;
    return Object.freeze({
      passed: false,
      status: detectedEveryChannel ? 'red' : 'invalid_negative_control',
      reason: detectedEveryChannel
        ? 'containment_removed_channels_reachable'
        : 'negative_control_channel_unconfirmed',
      exit_code: detectedEveryChannel ? 1 : 2,
      detected_channels: Object.freeze(confirmed),
      observations,
    });
  }
  const passed = proxyAllowed && confirmed.length === 0;
  return Object.freeze({
    passed,
    status: passed ? 'passed' : 'red',
    reason: passed ? 'containment_canary_passed' : 'containment_canary_failed',
    exit_code: passed ? 0 : 1,
    detected_channels: Object.freeze(confirmed),
    observations,
  });
}

export async function probeContainmentCanary({
  endpoints,
  negativeControl = false,
  tcpExchange = exchangeTcp,
  udpExchange = exchangeUdp,
  timeoutMs = 250,
} = {}) {
  if (!endpoints || typeof tcpExchange !== 'function' || typeof udpExchange !== 'function') {
    throw new TypeError('canary dependencies are invalid');
  }
  const [proxyTcp, directTcp, udp, quic] = await Promise.all([
    tcpExchange('proxy_tcp', endpoints.proxy_tcp, { timeoutMs }),
    tcpExchange('direct_tcp', endpoints.direct_tcp, { timeoutMs }),
    udpExchange('udp', endpoints.udp, { timeoutMs }),
    udpExchange('quic', endpoints.quic, { timeoutMs }),
  ]);
  return evaluateCanaryObservations({
    proxy_tcp: proxyTcp,
    direct_tcp: directTcp,
    udp,
    quic,
  }, { negativeControl });
}

export async function createContainmentCanaryHarness({
  nonLoopbackHost = selectNonLoopbackIpv4(),
  proxyPort = 0,
} = {}) {
  if (typeof nonLoopbackHost !== 'string' || nonLoopbackHost.startsWith('127.')
      || nonLoopbackHost === '0.0.0.0') {
    throw new TypeError('canary responder must use a local non-loopback IPv4 address');
  }
  if (!Number.isInteger(proxyPort) || proxyPort < 0 || proxyPort > 65_535) {
    throw new TypeError('proxy responder port must be a valid TCP port');
  }
  const responders = [];
  try {
    // proxyPort 0 (default) keeps the ephemeral-port behaviour every existing caller relies on;
    // the receipt emitter pins it to the guard-proxy port so a contained uid can actually reach it.
    responders.push(await createTcpResponder(LOOPBACK, CANARY_PROTOCOLS.proxy_tcp, proxyPort));
    responders.push(await createTcpResponder(nonLoopbackHost, CANARY_PROTOCOLS.direct_tcp));
    responders.push(await createUdpResponder(nonLoopbackHost, CANARY_PROTOCOLS.udp));
    responders.push(await createUdpResponder(nonLoopbackHost, CANARY_PROTOCOLS.quic));
  } catch (error) {
    await Promise.allSettled(responders.map((responder) => responder.close()));
    throw error;
  }
  return Object.freeze({
    non_loopback_host: nonLoopbackHost,
    endpoints: Object.freeze({
      proxy_tcp: responders[0].endpoint,
      direct_tcp: responders[1].endpoint,
      udp: responders[2].endpoint,
      quic: responders[3].endpoint,
    }),
    stats: Object.freeze({
      proxy_tcp: responders[0].stats,
      direct_tcp: responders[1].stats,
      udp: responders[2].stats,
      quic: responders[3].stats,
    }),
    async close() {
      await Promise.all(responders.map((responder) => responder.close()));
    },
  });
}
