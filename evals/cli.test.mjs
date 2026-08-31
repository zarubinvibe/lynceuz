import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ATTEMPT_CODE,
  ATTEMPT_KIND,
  CAPABILITY_STATE,
  EXIT_CODE,
  RUN_STATUS,
  createResultEnvelope,
  exitCodeForStatus,
  validateResultEnvelope,
} from '../src/contracts.mjs';
import { compileJobSpec, parseArgv, runCli, writeResult } from '../src/cli.mjs';

function memoryIo({ failStdout = false } = {}) {
  let stdout = '';
  let stderr = '';
  return {
    io: {
      stdout: { write: (value) => {
        if (failStdout) throw new Error('disk full');
        stdout += value;
      } },
      stderr: { write: (value) => { stderr += value; } },
    },
    read: () => ({ stdout, stderr }),
  };
}

function validResult(overrides = {}) {
  return createResultEnvelope({
    command: 'url',
    status: RUN_STATUS.OK,
    code: 'ok',
    message: 'captured',
    route: [],
    capabilities: [],
    warnings: [],
    ...overrides,
  });
}

test('contract enums and exit mapping are frozen and stable', () => {
  assert.deepEqual(RUN_STATUS, {
    OK: 'ok',
    INVALID_INPUT: 'invalid_input',
    PARTIAL: 'partial',
    EXHAUSTED: 'exhausted',
    BLOCKED: 'blocked',
    INTERNAL_ERROR: 'internal_error',
    OUTPUT_FAILURE: 'output_failure',
    INTERRUPTED: 'interrupted',
  });
  assert.deepEqual(EXIT_CODE, {
    OK: 0,
    INVALID_INPUT: 2,
    PARTIAL: 3,
    EXHAUSTED: 4,
    BLOCKED: 5,
    INTERNAL_ERROR: 70,
    OUTPUT_FAILURE: 74,
    TIMEOUT: 124,
    SIGINT: 130,
    SIGTERM: 143,
  });
  assert.ok(Object.isFrozen(RUN_STATUS));
  assert.ok(Object.isFrozen(EXIT_CODE));
  assert.ok(Object.isFrozen(ATTEMPT_KIND));
  assert.ok(Object.isFrozen(ATTEMPT_CODE));
  assert.ok(Object.isFrozen(CAPABILITY_STATE));

  assert.equal(exitCodeForStatus('ok'), 0);
  assert.equal(exitCodeForStatus('exhausted'), 4);
  assert.equal(exitCodeForStatus('interrupted', { reason: 'timeout' }), 124);
  assert.equal(exitCodeForStatus('interrupted', { signal: 'SIGINT' }), 130);
  assert.equal(exitCodeForStatus('interrupted', { signal: 'SIGTERM' }), 143);
  assert.throws(() => exitCodeForStatus('wat'), /unknown run status/);
});

test('result envelope is strict, schema-versioned and deeply frozen', () => {
  const result = validResult({ route: [{ adapter: 'native' }] });
  assert.equal(result.schema_version, 1);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.route));
  assert.ok(Object.isFrozen(result.route[0]));
  assert.equal(validateResultEnvelope(result), true);

  assert.throws(() => createResultEnvelope({ ...result, status: 'wat' }), /status/);
  assert.throws(() => createResultEnvelope({ ...result, code: 'wat' }), /code/);
  assert.throws(() => createResultEnvelope({ ...result, manifest: {} }), /unexpected field/);
  assert.throws(
    () => createResultEnvelope({ ...result, status: 'blocked', code: 'ok' }),
    /does not match status/,
  );
});

test('all Phase 1 command forms compile into immutable zero-authority JobSpec', () => {
  const cases = [
    { argv: ['https://example.com/a#frag'], kind: 'url', target: { url: 'https://example.com/a#frag' } },
    { argv: ['url', 'https://example.com'], kind: 'url', target: { url: 'https://example.com' } },
    { argv: ['crawl', 'https://example.com'], kind: 'crawl', target: { url: 'https://example.com' } },
    {
      argv: ['extract', 'https://example.com', '--schema', 'schema.json'],
      kind: 'extract',
      target: { url: 'https://example.com', schemaPath: 'schema.json' },
    },
    { argv: ['search', 'public records'], kind: 'search', target: { query: 'public records' } },
    { argv: ['health'], kind: 'health', target: {} },
  ];

  for (const item of cases) {
    const spec = compileJobSpec(parseArgv(item.argv));
    assert.equal(spec.schemaVersion, 1);
    assert.equal(spec.kind, item.kind);
    assert.deepEqual(spec.target, item.target);
    assert.equal(spec.policy.network, 'public-only');
    assert.equal(spec.policy.auth, 'none');
    assert.equal(spec.policy.moneyBudget, 0);
    assert.equal(spec.policy.allowFreeCloud, false);
    assert.equal(spec.policy.allowRendered, false);
    assert.equal(spec.limits.maxRetryAfterMs, 15_000);
    for (const value of Object.values(spec.limits)) {
      assert.equal(Number.isFinite(value), true);
      assert.ok(value > 0);
    }
    assert.ok(Object.isFrozen(spec));
    assert.ok(Object.isFrozen(spec.target));
    assert.ok(Object.isFrozen(spec.limits));
    assert.ok(Object.isFrozen(spec.policy));
  }
});

test('flags are explicit, scoped and cannot expand authority', () => {
  const spec = compileJobSpec(parseArgv([
    'https://example.com', '--json', '--explain', '--engine', 'native',
  ]));
  assert.deepEqual(spec.output, { json: true });
  assert.deepEqual(spec.routing, { explain: true, forcedEngine: 'native' });
  assert.equal(spec.policy.moneyBudget, 0);
  assert.equal(spec.policy.allowFreeCloud, false);
  assert.equal(spec.policy.allowRendered, false);

  const invalid = [
    [],
    ['url'],
    ['health', 'extra'],
    ['extract', 'https://example.com'],
    ['crawl', 'https://example.com', '--schema', 'x.json'],
    ['search', 'one', 'two'],
    ['https://example.com', '--wat'],
    ['https://example.com', '--engine'],
    ['https://example.com', '--engine', '../bad'],
    ['ftp://example.com'],
  ];
  for (const argv of invalid) assert.throws(() => parseArgv(argv), /invalid input/);
});

test('runCli rejects malformed argv before dependencies', async () => {
  const output = memoryIo();
  let calls = 0;
  const code = await runCli(['health', '--wat', '--json'], {
    io: output.io,
    registry: [],
    executeJob: async () => { calls += 1; },
    now: () => new Date(0),
  });
  const written = output.read();
  assert.equal(code, EXIT_CODE.INVALID_INPUT);
  assert.equal(calls, 0);
  assert.equal(written.stdout.endsWith('\n'), true);
  assert.equal(written.stdout.split('\n').filter(Boolean).length, 1);
  assert.equal(JSON.parse(written.stdout).status, RUN_STATUS.INVALID_INPUT);
  assert.equal(written.stderr.includes('--wat'), false);
});

test('JSON output is one document while warnings stay on stderr', async () => {
  const output = memoryIo();
  const result = validResult({ warnings: ['adapter missing'] });
  const code = await runCli(['https://example.com', '--json'], {
    io: output.io,
    registry: [],
    executeJob: async () => result,
    now: () => new Date(0),
  });
  const written = output.read();
  assert.equal(code, 0);
  assert.deepEqual(JSON.parse(written.stdout), result);
  assert.equal(written.stdout.match(/\n/g)?.length, 1);
  assert.equal(written.stdout.includes('adapter missing'), true);
  assert.match(written.stderr, /warning: adapter missing/);
});

test('write failure is distinct from result failure', async () => {
  const output = memoryIo({ failStdout: true });
  const code = await runCli(['health', '--json'], {
    io: output.io,
    registry: [],
    executeJob: async () => validResult({ command: 'health' }),
    now: () => new Date(0),
  });
  assert.equal(code, EXIT_CODE.OUTPUT_FAILURE);
  assert.match(output.read().stderr, /output_failure/);
});

test('writeResult rejects an invalid executable payload', () => {
  const output = memoryIo();
  assert.throws(
    () => writeResult({ status: 'ok', code: 'ok' }, output.io, { json: true }),
    /result envelope/,
  );
});
