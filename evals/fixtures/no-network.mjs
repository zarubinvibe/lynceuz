import childProcess from 'node:child_process';
import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';

export function createNoNetworkPorts(overrides = {}) {
  const counters = {
    lookupAll: 0,
    connectPinned: 0,
    requestPinned: 0,
    spawn: 0,
  };

  const port = (name) => async (...args) => {
    counters[name] += 1;
    if (overrides[name]) return overrides[name](...args);
    throw new Error(`forbidden test port called: ${name}`);
  };

  return {
    counters,
    lookupAll: port('lookupAll'),
    connectPinned: port('connectPinned'),
    requestPinned: port('requestPinned'),
    spawn: port('spawn'),
  };
}

export function installNetworkTripwire() {
  if (globalThis.__lynceuzNetworkTripwireInstalled) return;
  globalThis.__lynceuzNetworkTripwireInstalled = true;

  const deny = (name) => {
    throw new Error(`network tripwire: ${name}`);
  };
  const denyCallback = (name) => (...args) => {
    const callback = args.findLast((value) => typeof value === 'function');
    const error = new Error(`network tripwire: ${name}`);
    if (callback) return queueMicrotask(() => callback(error));
    throw error;
  };

  globalThis.fetch = async () => deny('fetch');
  dns.lookup = denyCallback('dns.lookup');
  dns.resolve = denyCallback('dns.resolve');
  dnsPromises.lookup = async () => deny('dns.promises.lookup');
  dnsPromises.resolve = async () => deny('dns.promises.resolve');
  http.request = () => deny('http.request');
  http.get = () => deny('http.get');
  https.request = () => deny('https.request');
  https.get = () => deny('https.get');
  net.connect = () => deny('net.connect');
  net.createConnection = () => deny('net.createConnection');
  tls.connect = () => deny('tls.connect');
  childProcess.spawn = () => deny('child_process.spawn');
  childProcess.exec = () => deny('child_process.exec');
  childProcess.execFile = () => deny('child_process.execFile');
  childProcess.fork = () => deny('child_process.fork');
  syncBuiltinESMExports();
}

if (process.env.LYNCEUZ_FORBID_NETWORK === '1') installNetworkTripwire();
