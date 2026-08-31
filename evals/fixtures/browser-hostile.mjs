import { once } from 'node:events';
import { createServer as createHttpServer } from 'node:http';
import { createServer as createTcpServer, connect as connectTcp } from 'node:net';
import { createSocket } from 'node:dgram';
import { Readable } from 'node:stream';

import { createEgressGateway } from '../../src/network.mjs';

export const SYNTHETIC_PUBLIC_ADDRESS = '93.184.216.34';
export const SYNTHETIC_PUBLIC_HOST = 'public.example.com';
export const REQUIRED_BROWSER_CHANNELS = Object.freeze([
  'navigation',
  'redirect',
  'iframe',
  'popup',
  'worker',
  'service_worker',
  'websocket',
  'webrtc_udp',
  'webtransport',
  'quic',
]);

function hostileHtml(tcpPort, udpPort) {
  const privateHttp = `http://127.0.0.1:${tcpPort}`;
  return `<!doctype html>
<html><body><main id="rendered">rendered through GuardProxy</main>
<script>
globalThis.__lynceuzChannels = ${JSON.stringify(REQUIRED_BROWSER_CHANNELS)};
const privateHttp = ${JSON.stringify(privateHttp)};
const udpPort = ${JSON.stringify(udpPort)};
fetch(privateHttp + '/fetch').catch(() => {});
const image = new Image(); image.src = privateHttp + '/image';
const frame = document.createElement('iframe'); frame.src = privateHttp + '/iframe'; document.body.append(frame);
try { window.open(privateHttp + '/popup'); } catch {}
try { new Worker('/hostile-worker.js'); } catch {}
navigator.serviceWorker?.register('/hostile-sw.js').catch(() => {});
try { new WebSocket('ws://127.0.0.1:${tcpPort}/socket'); } catch {}
try {
  const peer = new RTCPeerConnection({iceServers:[{urls:'stun:127.0.0.1:' + udpPort}]});
  peer.createDataChannel('probe'); peer.createOffer().then((offer) => peer.setLocalDescription(offer)).catch(() => {});
} catch {}
try { new WebTransport('https://127.0.0.1:${tcpPort}/transport'); } catch {}
</script></body></html>`;
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function closeServer(server) {
  if (!server.listening) return;
  server.close();
  await once(server, 'close');
}

function responseForPath(path, ports) {
  if (path === '/redirect') {
    return { statusCode: 302, headers: { location: `http://${SYNTHETIC_PUBLIC_HOST}/` }, body: '' };
  }
  if (path === '/hostile-worker.js' || path === '/hostile-sw.js') {
    return { statusCode: 200, headers: { 'content-type': 'text/javascript' }, body: 'fetch("http://127.0.0.1:9/").catch(()=>{});' };
  }
  return {
    statusCode: 200,
    headers: { 'content-type': 'text/html; charset=utf-8' },
    body: hostileHtml(ports.tcpCanary, ports.udpCanary),
  };
}

export async function createBrowserHostileHarness() {
  const counters = { public: 0, privateTcp: 0, privateUdp: 0 };
  const sockets = new Set();
  const tcpCanary = createTcpServer((socket) => {
    counters.privateTcp += 1;
    socket.destroy();
  });
  const tcpCanaryPort = await listen(tcpCanary);

  const udpCanary = createSocket('udp4');
  udpCanary.on('message', () => { counters.privateUdp += 1; });
  udpCanary.bind(0, '127.0.0.1');
  await once(udpCanary, 'listening');
  const udpCanaryPort = udpCanary.address().port;

  const publicServer = createHttpServer((request, response) => {
    counters.public += 1;
    const fixture = responseForPath(new URL(request.url, 'http://fixture').pathname, {
      tcpCanary: tcpCanaryPort,
      udpCanary: udpCanaryPort,
    });
    response.writeHead(fixture.statusCode, fixture.headers);
    response.end(request.method === 'HEAD' ? undefined : fixture.body);
  });
  publicServer.on('connection', (socket) => {
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
  });
  const publicPort = await listen(publicServer);

  const lookupAll = async () => [{ address: SYNTHETIC_PUBLIC_ADDRESS, family: 4 }];
  const connectPinned = async ({ permit, signal }) => new Promise((resolve, reject) => {
    const socket = connectTcp({ host: '127.0.0.1', port: publicPort });
    const abort = () => socket.destroy(signal.reason ?? new Error('aborted'));
    signal?.addEventListener('abort', abort, { once: true });
    socket.once('connect', () => {
      signal?.removeEventListener('abort', abort);
      resolve({ socket, peerAddress: permit.selectedAddress });
    });
    socket.once('error', reject);
  });
  const requestPinned = async ({ permit, method }) => {
    const path = new URL(permit.canonicalUrl).pathname;
    const fixture = responseForPath(path, {
      tcpCanary: tcpCanaryPort,
      udpCanary: udpCanaryPort,
    });
    counters.public += 1;
    return {
      statusCode: fixture.statusCode,
      headers: fixture.headers,
      body: Readable.from(method === 'HEAD' ? [] : [fixture.body]),
      peerAddress: permit.selectedAddress,
    };
  };
  const gateway = createEgressGateway({ lookupAll, connectPinned, requestPinned });

  return Object.freeze({
    gateway,
    counters,
    publicUrl: `http://${SYNTHETIC_PUBLIC_HOST}/`,
    tcpCanaryPort,
    udpCanaryPort,
    hostileHtml: hostileHtml(tcpCanaryPort, udpCanaryPort),
    async close() {
      for (const socket of sockets) socket.destroy();
      udpCanary.close();
      await Promise.all([closeServer(publicServer), closeServer(tcpCanary), once(udpCanary, 'close')]);
    },
  });
}

export async function requestViaGuardProxy(proxy, targetUrl, token, method = 'GET') {
  const { host, port } = proxy;
  return new Promise((resolve, reject) => {
    const socket = connectTcp({ host, port });
    const chunks = [];
    socket.setTimeout(2_000, () => socket.destroy(new Error('proxy fixture timeout')));
    socket.once('connect', () => {
      const target = new URL(targetUrl);
      socket.write(
        `${method} ${target.href} HTTP/1.1\r\nHost: ${target.host}\r\n`
        + `Proxy-Authorization: Bearer ${token}\r\nConnection: close\r\n\r\n`,
      );
    });
    socket.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    socket.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.once('error', reject);
  });
}

export async function connectViaGuardProxy(proxy, token) {
  return new Promise((resolve, reject) => {
    const socket = connectTcp({ host: proxy.host, port: proxy.port });
    const chunks = [];
    let tunnelReady = false;
    socket.setTimeout(2_000, () => socket.destroy(new Error('proxy tunnel fixture timeout')));
    socket.once('connect', () => {
      socket.write(
        `CONNECT ${SYNTHETIC_PUBLIC_HOST}:443 HTTP/1.1\r\n`
        + `Host: ${SYNTHETIC_PUBLIC_HOST}:443\r\n`
        + `Proxy-Authorization: Bearer ${token}\r\n\r\n`,
      );
    });
    socket.on('data', (chunk) => {
      chunks.push(Buffer.from(chunk));
      const current = Buffer.concat(chunks).toString('utf8');
      if (!tunnelReady && current.includes('\r\n\r\n')) {
        tunnelReady = true;
        socket.write(`GET / HTTP/1.1\r\nHost: ${SYNTHETIC_PUBLIC_HOST}\r\nConnection: close\r\n\r\n`);
      }
    });
    socket.once('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.once('error', reject);
  });
}
