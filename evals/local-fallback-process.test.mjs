import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createPythonTransformAdapter, validateExtractSchema } from '../src/adapters/python-helper.mjs';
import { createProcessSupervisor } from '../src/process.mjs';
import { createStorage } from '../src/storage.mjs';

const PYTHON_PROBE = spawnSync('python3', ['-c', 'import sys; print(sys.executable)'], {
  encoding: 'utf8',
});
const PYTHON_AVAILABLE = PYTHON_PROBE.status === 0;
const PYTHON = PYTHON_AVAILABLE ? PYTHON_PROBE.stdout.trim() : '/usr/bin/python3';
const HELPER = fileURLToPath(new URL('../src/lynceuz-helper.py', import.meta.url));
const PARSER_AVAILABLE = PYTHON_AVAILABLE
  && spawnSync(PYTHON, ['-I', HELPER, '--self-check'], { encoding: 'utf8' }).status === 0;
const OPTIONAL_SKIP = PARSER_AVAILABLE ? false : 'optional Python parser is unavailable';

function processProfile(helperPath, overrides = {}) {
  return {
    command: PYTHON,
    args: ['-I', helperPath],
    cwd: dirname(helperPath),
    env: {
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      PYTHONHASHSEED: '0',
      PYTHONIOENCODING: 'utf-8',
      PYTHONNOUSERSITE: '1',
    },
    maxInputBytes: 128 * 1024,
    maxStdoutBytes: 64 * 1024,
    maxStderrBytes: 64 * 1024,
    timeoutMs: 2_000,
    ...overrides,
  };
}

async function prepareHtmlRun() {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-phase3-'));
  const storage = createStorage({ dataRoot: join(workspace, '.lynceuz') });
  const run = await storage.beginRun({ command: 'extract', requested_url: 'https://public.example.com/' });
  const sourceRef = await storage.putObject(
    run,
    Buffer.from(`<!doctype html>
<html>
  <head>
    <title>Collector</title>
    <link rel="canonical" href="/main" />
    <meta name="description" content="Free facts" />
    <script type="application/ld+json">{"@type":"Article","headline":"Collector story","author":{"name":"Fil"}}</script>
    <script>globalThis.PWNED = true</script>
  </head>
  <body>
    <article>
      <h1>Collector story</h1>
      <p>Find public data.</p>
      <a href="/next">Next</a>
      <span class="price">19.5</span>
    </article>
  </body>
</html>`),
    { role: 'raw', media_type: 'text/html', derived_from: null },
  );
  return { workspace, storage, run, sourceRef };
}

test('helper self-check works in isolated mode', { skip: OPTIONAL_SKIP }, () => {
  const result = spawnSync(PYTHON, ['-I', HELPER, '--self-check'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const payload = JSON.parse(result.stdout.trim());
  assert.equal(payload.ok, true);
  assert.equal(typeof payload.payload.python, 'string');
});

test('validateExtractSchema rejects hostile shapes', () => {
  assert.throws(
    () => validateExtractSchema({
      schema_version: 1,
      fields: { price: { source: 'css', selector: '.price', take: '@onclick' } },
    }),
    /attr is invalid/u,
  );
  assert.throws(
    () => validateExtractSchema({ schema_version: 2, fields: {} }),
    /schema_version/u,
  );
});

test('python adapter parses stored HTML and commits derived artifacts', { skip: OPTIONAL_SKIP }, async () => {
  const { workspace, storage, run, sourceRef } = await prepareHtmlRun();
  try {
    const adapter = createPythonTransformAdapter({
      pythonPath: PYTHON,
      helperPath: HELPER,
      storage,
    });
    const health = await adapter.probe();
    assert.equal(health.state, 'ready');

    const result = await adapter.parseHtml({
      run,
      sourceRef,
      baseUrl: 'https://public.example.com/start',
    });

    assert.equal(result.kind, 'success');
    assert.equal(result.value.title, 'Collector');
    assert.equal(result.value.canonicalCandidate, 'https://public.example.com/main');
    assert.deepEqual(result.value.links, ['https://public.example.com/next']);
    assert.equal(result.value.jsonld[0].headline, 'Collector story');
    assert.doesNotMatch(result.value.text, /PWNED/u);

    const markdown = await storage.readObject(result.value.artifacts.markdown, { maxBytes: 64 * 1024 });
    assert.match(markdown.toString('utf8'), /Collector story/u);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('invalid schema is rejected before the helper can spawn', async () => {
  const { workspace, storage, run, sourceRef } = await prepareHtmlRun();
  let spawnCalls = 0;
  try {
    const adapter = createPythonTransformAdapter({
      pythonPath: PYTHON,
      helperPath: HELPER,
      storage,
      supervisor: {
        async run() {
          spawnCalls += 1;
          throw new Error('must not spawn');
        },
      },
    });
    const result = await adapter.extractSchema({
      run,
      sourceRef,
      baseUrl: 'https://public.example.com/start',
      schema: {
        schema_version: 1,
        fields: { unsafe: { source: 'css', selector: ':has(*)', take: 'text' } },
      },
    });
    assert.equal(result.kind, 'inadequate');
    assert.equal(result.details.reason, 'invalid_schema');
    assert.equal(spawnCalls, 0);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('helper output and scratch failures remain broken, never inadequate fallback', async () => {
  const { workspace, storage, run, sourceRef } = await prepareHtmlRun();
  try {
    const adapter = createPythonTransformAdapter({
      pythonPath: PYTHON,
      storage,
      supervisor: {
        async run(_profile, payload) {
          return {
            kind: 'success',
            code: 'ok',
            response: {
              version: 1,
              id: payload.request.id,
              ok: false,
              code: 'adapter_error',
            },
          };
        },
      },
    });
    const result = await adapter.parseHtml({
      run,
      sourceRef,
      baseUrl: 'https://public.example.com/start',
    });
    assert.equal(result.kind, 'broken');
    assert.equal(result.code, 'adapter_protocol_error');
    assert.equal(result.details.reason, 'helper_boundary_failure');
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('schema extract publishes only valid JSON and required-field miss is typed inadequate', { skip: OPTIONAL_SKIP }, async () => {
  const { workspace, storage, run, sourceRef } = await prepareHtmlRun();
  try {
    const adapter = createPythonTransformAdapter({
      pythonPath: PYTHON,
      helperPath: HELPER,
      storage,
    });

    const ok = await adapter.extractSchema({
      run,
      sourceRef,
      baseUrl: 'https://public.example.com/start',
      schema: {
        schema_version: 1,
        fields: {
          title: { source: 'jsonld', path: ['headline'], required: true, type: 'string' },
          price: { source: 'css', selector: '.price', take: 'text', required: true, type: 'number' },
        },
      },
    });
    assert.equal(ok.kind, 'success');
    assert.deepEqual(ok.value.data, { title: 'Collector story', price: 19.5 });

    const saved = await storage.readObject(ok.value.artifact, { maxBytes: 64 * 1024 });
    assert.deepEqual(JSON.parse(saved.toString('utf8')), { price: 19.5, title: 'Collector story' });

    const missing = await adapter.extractSchema({
      run,
      sourceRef,
      baseUrl: 'https://public.example.com/start',
      schema: {
        schema_version: 1,
        fields: {
          sku: { source: 'css', selector: '.sku', take: 'text', required: true },
        },
      },
    });
    assert.equal(missing.kind, 'inadequate');
    assert.equal(missing.code, 'parse_failed');
    assert.deepEqual(missing.details.missing, ['sku']);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('process supervisor bounds protocol and maps extra stdout to protocol error', {
  skip: PYTHON_AVAILABLE ? false : 'optional Python is unavailable',
}, async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-process-'));
  try {
    const script = join(workspace, 'lynceuz-helper.py');
    await writeFile(script, 'import sys\nprint("{\\"version\\":1,\\"id\\":\\"x\\",\\"ok\\":true}")\nprint("noise")\n');
    const supervisor = createProcessSupervisor({
      profiles: new Map([[
        'python-parser',
        processProfile(HELPER, { maxInputBytes: 4096, maxStdoutBytes: 4096 }),
      ]]),
      spawnImpl(_command, _args, options) {
        return spawn(PYTHON, ['-I', script], options);
      },
    });
    const result = await supervisor.run('python-parser', {
      request: { version: 1, id: 'x', operation: 'self_check' },
      scratchDir: workspace,
    });
    assert.equal(result.kind, 'broken');
    assert.equal(result.code, 'adapter_protocol_error');
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('process registry rejects arbitrary argv and inherited PATH', () => {
  assert.throws(
    () => createPythonTransformAdapter({
      pythonPath: PYTHON,
      helperPath: '/tmp/lynceuz-helper.py',
      storage: {},
    }),
    /built-in Lynceuz helper/u,
  );
  assert.throws(
    () => createProcessSupervisor({
      profiles: new Map([['python-parser', {
        ...processProfile(HELPER),
        args: ['-c', 'print(1)'],
      }]]),
    }),
    /fixed helper argv/u,
  );
  assert.throws(
    () => createProcessSupervisor({
      profiles: new Map([['python-parser', {
        ...processProfile(HELPER),
        env: { PATH: '/usr/bin' },
      }]]),
    }),
    /not allowlisted/u,
  );
});

test('stored page bytes travel over stdin only and path escape is rejected before spawn', async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-process-boundary-'));
  try {
    const storageRoot = join(workspace, 'objects');
    const scratchRoot = join(workspace, 'scratch');
    const outside = join(workspace, 'outside.html');
    const output = join(scratchRoot, 'result.json');
    await Promise.all([
      mkdir(storageRoot),
      mkdir(scratchRoot),
      writeFile(outside, '<p>SECRET-PAGE-BODY</p>'),
    ]);
    let spawnCalls = 0;
    const supervisor = createProcessSupervisor({
      profiles: new Map([['python-parser', processProfile(HELPER)]]),
      spawnImpl(...args) {
        spawnCalls += 1;
        return spawn(...args);
      },
    });
    const result = await supervisor.run('python-parser', {
      request: {
        version: 1,
        id: 'escape',
        operation: 'parse_html',
        input_path: outside,
        input_hash: `sha256:${createHash('sha256').update('<p>SECRET-PAGE-BODY</p>').digest('hex')}`,
        base_url: 'https://public.example.com/',
        output_path: output,
      },
      inputRoot: storageRoot,
      scratchDir: scratchRoot,
    });
    assert.equal(result.kind, 'broken');
    assert.equal(result.details.reason, 'invalid_request');
    assert.equal(spawnCalls, 0);
    assert.doesNotMatch(JSON.stringify(processProfile(HELPER)), /SECRET-PAGE-BODY/u);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('timeout kills the Python process tree and waits for close', {
  skip: PYTHON_AVAILABLE ? false : 'optional Python is unavailable',
}, async () => {
  const workspace = await mkdtemp(join(tmpdir(), 'lynceuz-process-timeout-'));
  try {
    const script = join(workspace, 'lynceuz-helper.py');
    const pidFile = join(workspace, 'pid.txt');
    await writeFile(script, `import os,time\nopen(${JSON.stringify(pidFile)}, "w").write(str(os.getpid()))\nwhile True: time.sleep(1)\n`);
    const supervisor = createProcessSupervisor({
      profiles: new Map([['python-parser', processProfile(HELPER, { timeoutMs: 200 })]]),
      spawnImpl(_command, _args, options) {
        return spawn(PYTHON, ['-I', script], options);
      },
    });
    const result = await supervisor.run('python-parser', {
      request: { version: 1, id: 'timeout', operation: 'self_check' },
      scratchDir: workspace,
    });
    assert.equal(result.kind, 'retryable');
    assert.equal(result.code, 'timeout');
    const pid = Number(await readFile(pidFile, 'utf8'));
    assert.throws(() => process.kill(pid, 0), /ESRCH/u);
  } finally {
    await rm(workspace, { recursive: true, force: true });
  }
});

test('missing Python is a typed unavailable capability', async () => {
  const supervisor = createProcessSupervisor({
    profiles: new Map([['python-parser', {
      ...processProfile(HELPER),
      command: '/definitely-missing/python3',
    }]]),
  });
  const result = await supervisor.run('python-parser', {
    request: { version: 1, id: 'missing', operation: 'self_check' },
  });
  assert.equal(result.kind, 'skip');
  assert.equal(result.code, 'unavailable');
});

test('missing optional parser dependency is a typed missing capability', async () => {
  const adapter = createPythonTransformAdapter({
    pythonPath: PYTHON,
    storage: {
      readObject() {},
      resolve() {},
      putObject() {},
    },
    supervisor: {
      async run() {
        return {
          kind: 'success',
          code: 'ok',
          response: {
            version: 1,
            id: 'self-check',
            ok: false,
            code: 'dependency_unavailable',
            details: { parser: 'beautifulsoup4' },
          },
        };
      },
    },
  });
  const health = await adapter.probe();
  assert.equal(health.state, 'missing');
  assert.equal(health.reason, 'unavailable');
});

test('helper source installs the network tripwire before parser imports and exposes no runner', async () => {
  const source = await readFile(HELPER, 'utf8');
  assert.ok(source.indexOf('install_network_tripwire()') < source.indexOf('from bs4 import'));
  assert.doesNotMatch(source, /\b(?:subprocess|eval|exec)\s*\(/u);
  assert.doesNotMatch(source, /\b(?:requests|urllib\.request|httpx|aiohttp)\b/u);
});
