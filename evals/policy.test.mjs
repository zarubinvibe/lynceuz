import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { createEgressGateway } from '../src/network.mjs';
import {
  PolicyError,
  authorizeCost,
  authorizeResolvedTarget,
  classifyIpAddress,
  classifyTerminalOutcome,
  parsePublicUrl,
} from '../src/policy.mjs';
import { createNoNetworkPorts } from './fixtures/no-network.mjs';

const corpus = JSON.parse(await readFile(
  new URL('./fixtures/hostile-urls.json', import.meta.url),
  'utf8',
));

const intent = (url, redirects = 3) => ({
  runId: 'run-test',
  purpose: 'page',
  url,
  method: 'GET',
  remaining: { wallMs: 10_000, bytes: 1_000_000, redirects },
});

test('public URL parser canonicalizes allowed targets and strips fragments', () => {
  for (const item of corpus.allow) {
    const parsed = parsePublicUrl(item.input);
    assert.equal(parsed.canonicalUrl, item.canonical);
    assert.equal(parsed.canonicalUrl.includes('#'), false);
    assert.ok([80, 443].includes(parsed.port));
  }
});

test('hostile URL corpus is rejected with sanitized typed errors', () => {
  for (const input of corpus.deny) {
    assert.throws(
      () => parsePublicUrl(input),
      (error) => {
        assert.ok(error instanceof PolicyError, input);
        assert.equal(typeof error.code, 'string');
        assert.equal(error.message.includes(input), false);
        assert.equal(error.message.includes('secret-value'), false);
        return true;
      },
    );
  }
});

test('IP classifier allows global addresses and blocks special-use ranges', () => {
  for (const address of ['8.8.8.8', '93.184.216.34', '2606:4700:4700::1111']) {
    assert.equal(classifyIpAddress(address).public, true, address);
  }
  for (const address of [
    '0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254',
    '172.16.0.1', '192.0.2.1', '192.168.1.1', '198.18.0.1', '198.51.100.2',
    '203.0.113.1', '224.0.0.1', '255.255.255.255', '::', '::1', '::ffff:8.8.8.8',
    '64:ff9b::808:808', '100::1', '2001:db8::1', '2002::1', '3fff::1',
    'fc00::1', 'fe80::1', 'fec0::1', 'ff00::1',
  ]) {
    assert.equal(classifyIpAddress(address).public, false, address);
  }
  for (const invalidAddress of ['999.1.1.1', '1.2.3', 'gggg::1', '1::2::3', 'fe80::1%en0']) {
    assert.throws(() => classifyIpAddress(invalidAddress), /IP address/);
  }
});

test('all DNS answers must be public and deterministic selection is stable', () => {
  const parsed = parsePublicUrl('https://example.com/');
  const first = authorizeResolvedTarget(parsed, [
    { address: '2606:4700:4700::1111', family: 6 },
    { address: '93.184.216.35', family: 4 },
    { address: '93.184.216.34', family: 4 },
  ]);
  const second = authorizeResolvedTarget(parsed, [
    { address: '93.184.216.34', family: 4 },
    { address: '2606:4700:4700::1111', family: 6 },
    { address: '93.184.216.35', family: 4 },
  ]);
  assert.equal(first.selectedAddress, '93.184.216.34');
  assert.deepEqual(first, second);
  assert.ok(Object.isFrozen(first));
  assert.throws(
    () => authorizeResolvedTarget(parsed, [
      { address: '93.184.216.34', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]),
    /DNS answer is not public/,
  );
  assert.throws(() => authorizeResolvedTarget(parsed, []), /DNS answer set is empty/);
  assert.throws(
    () => authorizeResolvedTarget(parsed, [{ address: '93.184.216.34', family: 6 }]),
    /DNS address family mismatch/,
  );
});

test('only proven local zero cost is eligible', () => {
  assert.deepEqual(authorizeCost({ cost: 'local-zero', price: 0 }), {
    allowed: true,
    state: 'allowed_zero',
    reason: 'proven_local_zero',
  });
  for (const descriptor of [
    { cost: 'local-zero' },
    { cost: 'local-zero', price: 1 },
    { cost: 'paid', price: 1 },
    { cost: 'free-credit', price: 0, balance: 100 },
    { cost: 'free-credit', price: 0 },
    {},
  ]) {
    assert.equal(authorizeCost(descriptor).allowed, false);
    assert.equal(authorizeCost(descriptor).state, 'unknown_and_blocked');
  }
});

test('terminal policy/access outcomes cannot enter fallback', () => {
  for (const code of [
    'policy_denied', 'robots_denied', 'access_denied', 'auth_required', 'captcha',
    'paywall', 'paid_required', 'hard_limit',
  ]) {
    assert.deepEqual(classifyTerminalOutcome({ code }), {
      terminal: true,
      status: 'blocked',
      code,
    });
  }
  for (const code of ['not_found', 'gone']) {
    assert.equal(classifyTerminalOutcome({ code }).status, 'exhausted');
  }
  assert.equal(classifyTerminalOutcome({ code: 'rate_limited', exhausted: false }).terminal, false);
  assert.equal(classifyTerminalOutcome({ code: 'rate_limited', exhausted: true }).status, 'blocked');
});

test('gateway denies unsafe input before lookup or request ports', async () => {
  const ports = createNoNetworkPorts();
  const gateway = createEgressGateway(ports);
  await assert.rejects(
    gateway.execute(intent('http://169.254.169.254/latest/meta-data/')),
    /target IP is not public/,
  );
  await assert.rejects(
    gateway.execute(intent('https://example.com/?token=secret-value')),
    /sensitive query key/,
  );
  assert.deepEqual(ports.counters, {
    lookupAll: 0,
    connectPinned: 0,
    requestPinned: 0,
    spawn: 0,
  });
});

test('gateway pins deterministic address and verifies request peer', async () => {
  let receivedPermit;
  const ports = createNoNetworkPorts({
    lookupAll: async () => [
      { address: '93.184.216.35', family: 4 },
      { address: '93.184.216.34', family: 4 },
    ],
    requestPinned: async ({ permit }) => {
      receivedPermit = permit;
      return { statusCode: 200, headers: {}, body: Buffer.from('ok'), peerAddress: '93.184.216.34' };
    },
  });
  const gateway = createEgressGateway(ports);
  const response = await gateway.execute(intent('https://example.com/'));
  assert.equal(receivedPermit.selectedAddress, '93.184.216.34');
  assert.equal(response.permit.selectedAddress, '93.184.216.34');
  assert.equal(response.finalUrl, 'https://example.com/');
  assert.equal(ports.counters.lookupAll, 1);
  assert.equal(ports.counters.requestPinned, 1);

  const mismatch = createNoNetworkPorts({
    lookupAll: async () => [{ address: '93.184.216.34', family: 4 }],
    requestPinned: async () => ({ statusCode: 200, headers: {}, body: null, peerAddress: '93.184.216.35' }),
  });
  await assert.rejects(
    createEgressGateway(mismatch).execute(intent('https://example.com/')),
    /peer address mismatch/,
  );

  const mappedPeer = createNoNetworkPorts({
    lookupAll: async () => [{ address: '93.184.216.34', family: 4 }],
    requestPinned: async () => ({
      statusCode: 200,
      headers: {},
      body: null,
      peerAddress: '::ffff:93.184.216.34',
    }),
  });
  assert.equal(
    (await createEgressGateway(mappedPeer).execute(intent('https://example.com/'))).statusCode,
    200,
  );
});

test('tunnel uses a fresh permit and rejects peer mismatch', async () => {
  let receivedPermit;
  const ports = createNoNetworkPorts({
    lookupAll: async () => [{ address: '2606:4700:4700::1111', family: 6 }],
    connectPinned: async ({ permit }) => {
      receivedPermit = permit;
      return { socket: { id: 1 }, peerAddress: '2606:4700:4700::1111' };
    },
  });
  const opened = await createEgressGateway(ports).openAuthorizedTunnel(intent('https://example.com/'));
  assert.equal(opened.socket.id, 1);
  assert.equal(receivedPermit.selectedAddress, '2606:4700:4700::1111');

  const mismatch = createNoNetworkPorts({
    lookupAll: async () => [{ address: '93.184.216.34', family: 4 }],
    connectPinned: async () => ({ socket: {}, peerAddress: '8.8.8.8' }),
  });
  await assert.rejects(
    createEgressGateway(mismatch).openAuthorizedTunnel(intent('https://example.com/')),
    /peer address mismatch/,
  );
});

test('redirects close bodies and cross a new URL, DNS and peer gate', async () => {
  const lookups = [];
  const permits = [];
  let closed = 0;
  const ports = createNoNetworkPorts({
    lookupAll: async (hostname) => {
      lookups.push(hostname);
      return [{ address: hostname === 'example.com' ? '93.184.216.34' : '8.8.8.8', family: 4 }];
    },
    requestPinned: async ({ permit }) => {
      permits.push(permit);
      if (permit.hostname === 'example.com') {
        return {
          statusCode: 302,
          headers: { Location: 'https://example.net/final#frag' },
          body: { destroy: () => { closed += 1; } },
          peerAddress: '93.184.216.34',
        };
      }
      return { statusCode: 200, headers: {}, body: Buffer.from('done'), peerAddress: '8.8.8.8' };
    },
  });
  const result = await createEgressGateway(ports).execute(intent('https://example.com/start'));
  assert.deepEqual(lookups, ['example.com', 'example.net']);
  assert.equal(permits.length, 2);
  assert.notEqual(permits[0], permits[1]);
  assert.equal(closed, 1);
  assert.equal(result.finalUrl, 'https://example.net/final');
  assert.deepEqual(result.redirectChain, [{
    statusCode: 302,
    from: 'https://example.com/start',
    to: 'https://example.net/final',
  }]);
});

test('unsafe redirect, loop, downgrade and hop exhaustion stop before next request', async () => {
  const scenario = async (location, redirects = 3) => {
    const ports = createNoNetworkPorts({
      lookupAll: async () => [{ address: '93.184.216.34', family: 4 }],
      requestPinned: async () => ({
        statusCode: 302,
        headers: { location },
        body: { destroy() {} },
        peerAddress: '93.184.216.34',
      }),
    });
    const promise = createEgressGateway(ports).execute(intent('https://example.com/start', redirects));
    return { ports, promise };
  };

  for (const [location, redirects, message] of [
    ['http://169.254.169.254/latest', 3, /redirect downgrade|target IP is not public/],
    ['https://127.0.0.1/private', 3, /target IP is not public/],
    ['https://example.com/start', 3, /redirect loop/],
    ['https://example.net/next', 0, /redirect limit/],
    ['http://example.net/next', 3, /redirect downgrade/],
  ]) {
    const { ports, promise } = await scenario(location, redirects);
    await assert.rejects(promise, message);
    assert.equal(ports.counters.requestPinned, 1, location);
  }
});

test('malformed redirect headers fail closed and close the response body', async () => {
  for (const headers of [
    {},
    { location: [] },
    { location: ['https://example.net/a', 'https://example.net/b'] },
    { location: 42 },
    { location: 'https://example.net/a', Location: 'https://example.net/b' },
    { location: 'https://example.net/a\r\nX-Test: injected' },
  ]) {
    let closed = 0;
    const ports = createNoNetworkPorts({
      lookupAll: async () => [{ address: '93.184.216.34', family: 4 }],
      requestPinned: async () => ({
        statusCode: 302,
        headers,
        body: { destroy: () => { closed += 1; } },
        peerAddress: '93.184.216.34',
      }),
    });
    await assert.rejects(
      createEgressGateway(ports).execute(intent('https://example.com/')),
      /redirect response is invalid/,
    );
    assert.equal(closed, 1);
    assert.equal(ports.counters.requestPinned, 1);
  }
});

test('resolver failures and empty DNS fail closed without request port', async () => {
  for (const lookupAll of [
    async () => [],
    async () => { throw new Error('resolver leaked secret'); },
  ]) {
    const ports = createNoNetworkPorts({ lookupAll });
    await assert.rejects(
      createEgressGateway(ports).execute(intent('https://example.com/')),
      (error) => {
        assert.ok(error instanceof PolicyError);
        assert.equal(error.message.includes('resolver leaked secret'), false);
        return true;
      },
    );
    assert.equal(ports.counters.requestPinned, 0);
  }
});

test('injected port errors are sanitized at the gateway boundary', async () => {
  const ports = createNoNetworkPorts({
    lookupAll: async () => [{ address: '93.184.216.34', family: 4 }],
    requestPinned: async () => {
      throw new PolicyError('leak', 'leaked https://user:secret@example.com/');
    },
  });
  await assert.rejects(
    createEgressGateway(ports).execute(intent('https://example.com/')),
    (error) => {
      assert.equal(error.code, 'request_failed');
      assert.equal(error.message.includes('secret'), false);
      assert.equal(error.message.includes('example.com'), false);
      return true;
    },
  );
});
