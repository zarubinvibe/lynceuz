#!/usr/bin/env node

import { lookup as dnsLookup } from 'node:dns/promises';
import { constants as FS_CONSTANTS } from 'node:fs';
import { access } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { resolve } from 'node:path';

import { runCli } from './cli.mjs';
import { createPythonTransformAdapter } from './adapters/python-helper.mjs';
import { createProductionExecutor } from './core.mjs';
import { createEgressGateway, createNodeRequestPinned } from './network.mjs';
import { createDefaultRegistry } from './router.mjs';
import { createStorage } from './storage.mjs';

const registry = createDefaultRegistry(process.version).map((capability) => (
  capability.id === 'native'
    ? {
      ...capability,
      version: '1',
      state: 'ready',
      reason: 'native_http_ready',
      commands: ['url', 'crawl', 'extract'],
    }
    : capability
));

async function lookupAll(hostname, { signal } = {}) {
  if (signal?.aborted) throw signal.reason ?? new Error('DNS lookup aborted');
  const lookup = dnsLookup(hostname, { all: true, verbatim: true });
  if (!signal) return lookup;
  return new Promise((resolveLookup, rejectLookup) => {
    const abort = () => rejectLookup(signal.reason ?? new Error('DNS lookup aborted'));
    signal.addEventListener('abort', abort, { once: true });
    lookup.then(resolveLookup, rejectLookup).finally(() => signal.removeEventListener('abort', abort));
  });
}

const gateway = createEgressGateway({
  lookupAll,
  requestPinned: createNodeRequestPinned({ httpRequest, httpsRequest }),
  connectPinned: async () => { throw new Error('tunnel transport is not enabled'); },
});

const executeJob = createProductionExecutor({
  gateway,
  storage: (job) => createStorage({
    dataRoot: job.output.dataRoot ?? resolve(process.cwd(), '.lynceuz'),
    clock: Date.now,
  }),
  clock: Date.now,
  sleep: (milliseconds) => new Promise((resolveSleep) => setTimeout(resolveSleep, milliseconds)),
  // Real process only: SIGINT/SIGTERM and the run's wall deadline funnel through
  // one guard that commits an interrupted manifest and exits 130/143/124.
  interruption: { emitter: process, exit: (code) => process.exit(code) },
  pythonAdapter: async ({ storage, job }) => {
    if (!['url', 'extract', 'crawl'].includes(job.kind)) return null;
    const candidates = [
      '/opt/homebrew/bin/python3',
      '/usr/local/bin/python3',
      '/Library/Frameworks/Python.framework/Versions/3.13/bin/python3',
      '/Library/Frameworks/Python.framework/Versions/3.12/bin/python3',
      '/Library/Frameworks/Python.framework/Versions/3.11/bin/python3',
      '/Library/Frameworks/Python.framework/Versions/3.10/bin/python3',
      '/usr/bin/python3',
    ];
    for (const pythonPath of candidates) {
      try {
        await access(pythonPath, FS_CONSTANTS.X_OK);
        const adapter = createPythonTransformAdapter({ pythonPath, storage });
        if ((await adapter.probe()).state === 'ready') return adapter;
      } catch {
        // Optional local capability: continue to the next fixed executable.
      }
    }
    return null;
  },
});

process.exitCode = await runCli(process.argv.slice(2), {
  io: { stdout: process.stdout, stderr: process.stderr },
  registry,
  executeJob,
  now: () => new Date(),
});
