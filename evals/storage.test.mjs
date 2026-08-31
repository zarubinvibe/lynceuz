import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import test from 'node:test';

import { createRequestFingerprint, createStorage } from '../src/storage.mjs';

const FIXED_TIME = '2026-08-26T12:15:40.123Z';
const clock = () => new Date(FIXED_TIME);

function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

function hashHex(hash) {
  assert.match(hash, /^sha256:[0-9a-f]{64}$/);
  return hash.slice('sha256:'.length);
}

function makeJob(overrides = {}) {
  return {
    schema_version: 1,
    command: 'url',
    requested_url: 'https://example.com/',
    method: 'GET',
    format: 'markdown',
    cache: 'use',
    ...overrides,
  };
}

function makeFingerprint(overrides = {}) {
  return createRequestFingerprint({
    canonicalUrl: 'https://example.com/',
    method: 'GET',
    headers: {
      accept: 'text/html,application/xhtml+xml',
      'accept-encoding': 'gzip, br',
    },
    adapter: { id: 'native', version: '1' },
    policyVersion: '1',
    format: 'markdown',
    goal: 'markdown',
    decode: { encodings: ['gzip', 'br'], maxBytes: 1_048_576 },
    ...overrides,
  });
}

function makeManifest(run, source, overrides = {}) {
  return {
    schema_version: 1,
    run_id: run.id,
    status: 'ok',
    requested_url: 'https://example.com/',
    effective_url: 'https://example.com/',
    alternatives: [],
    fetched_at: FIXED_TIME,
    served_at: FIXED_TIME,
    revalidated_at: null,
    engine: { id: 'native', version: '1' },
    requested_format: 'markdown',
    format: 'raw',
    policy: {
      version: '1',
      network: 'public-only',
      auth: 'none',
      money_budget: 0,
    },
    attempts: [],
    source_hash: source.hash,
    artifact_hash: source.hash,
    artifact_path: source.path,
    artifacts: [source],
    evidence: [{
      url: 'https://example.com/',
      hash: source.hash,
      status: 'source_captured',
    }],
    warnings: [],
    cost_money: 0,
    credits_used: 0,
    ...overrides,
  };
}

function makeCacheRecord(run, manifest, source) {
  return {
    schema_version: 1,
    request_fingerprint: makeFingerprint(),
    canonical_url: 'https://example.com/',
    requested_format: 'markdown',
    format: 'raw',
    run_id: run.id,
    manifest_path: manifest.path,
    manifest_hash: manifest.hash,
    source_hash: source.hash,
    source_path: source.path,
    artifact_hash: source.hash,
    artifact_path: source.path,
    fetched_at: FIXED_TIME,
    expires_at: '2026-08-26T13:15:40.123Z',
  };
}

async function withSandbox(fn, options = {}) {
  const sandbox = await mkdtemp(join(tmpdir(), 'lynceuz-storage-'));
  const dataRoot = join(sandbox, '.lynceuz');
  const storage = createStorage({ dataRoot, clock, ...options });
  try {
    await fn({ sandbox, dataRoot, storage });
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }
}

async function walk(root) {
  const entries = [];
  async function visit(path) {
    const info = await lstat(path);
    entries.push({ path, info });
    if (!info.isDirectory()) return;
    for (const name of await readdir(path)) await visit(join(path, name));
  }
  await visit(root);
  return entries;
}

async function assertCacheMiss(storage, fingerprint) {
  const result = await storage.readCache(fingerprint);
  assert.equal(result.hit, false);
  assert.equal(result.record, undefined);
  assert.ok(Array.isArray(result.warnings));
  return result;
}

async function assertRejected(call, pattern) {
  await assert.rejects(async () => call(), pattern);
}

test('request fingerprint is canonical, secret-free and sensitive to acquisition semantics', () => {
  const first = makeFingerprint({ canonicalUrl: 'https://example.com/#first' });
  const reordered = createRequestFingerprint({
    goal: 'markdown',
    decode: { maxBytes: 1_048_576, encodings: ['gzip', 'br'] },
    format: 'markdown',
    policyVersion: '1',
    adapter: { version: '1', id: 'native' },
    headers: {
      'accept-encoding': 'gzip, br',
      accept: 'text/html,application/xhtml+xml',
    },
    method: 'get',
    canonicalUrl: 'https://example.com/#second',
  });

  assert.match(first, /^[0-9a-f]{64}$/);
  assert.equal(reordered, first, 'key order, method case and fragments cannot split the cache');
  assert.notEqual(makeFingerprint({ format: 'raw', goal: 'raw' }), first);
  assert.notEqual(makeFingerprint({ policyVersion: '2' }), first);
  assert.notEqual(makeFingerprint({ adapter: { id: 'native', version: '2' } }), first);
  assert.notEqual(
    makeFingerprint({ decode: { encodings: ['gzip', 'br'], maxBytes: 2_048_576 } }),
    first,
  );

  for (const headers of [
    { authorization: 'Bearer secret' },
    { cookie: 'session=secret' },
    { 'proxy-authorization': 'Basic secret' },
  ]) {
    assert.throws(
      () => makeFingerprint({ headers }),
      /authorization|cookie|secret|unsafe header/i,
    );
  }
});

test('data root is a private .lynceuz tree and never edits the caller gitignore', async () => {
  const sandbox = await mkdtemp(join(tmpdir(), 'lynceuz-root-'));
  try {
    assert.throws(
      () => createStorage({ dataRoot: join(sandbox, 'state'), clock }),
      /\.lynceuz/i,
    );
    assert.throws(
      () => createStorage({ dataRoot: join(sandbox, '.lynceuz', 'nested'), clock }),
      /\.lynceuz/i,
    );
  } finally {
    await rm(sandbox, { recursive: true, force: true });
  }

  await withSandbox(async ({ sandbox: callerRoot, dataRoot, storage }) => {
    const run = await storage.beginRun(makeJob());
    const source = await storage.putObject(run, Buffer.from('private evidence'), {
      role: 'raw',
      media_type: 'text/plain',
      derived_from: null,
    });
    await storage.appendAttempt(run, {
      type: 'attempt_finished',
      at: FIXED_TIME,
      outcome: 'ok',
      source_hash: source.hash,
    });
    const manifest = await storage.commitManifest(run, makeManifest(run, source));
    const fingerprint = makeFingerprint();
    await storage.commitCache(fingerprint, makeCacheRecord(run, manifest, source));
    await storage.publishPrivateJson('security/proof.json', { status: 'passed' });
    await storage.publishOutput('exports/result.txt', Buffer.from('result'));

    assert.equal(await readFile(join(dataRoot, '.gitignore'), 'utf8'), '*\n!.gitignore\n');
    await assert.rejects(lstat(join(callerRoot, '.gitignore')), { code: 'ENOENT' });

    const gitignores = (await walk(dataRoot))
      .filter(({ path }) => path.endsWith('/.gitignore'))
      .map(({ path }) => relative(dataRoot, path));
    assert.deepEqual(gitignores, ['.gitignore']);

    for (const { path, info } of await walk(dataRoot)) {
      if (info.isSymbolicLink()) continue;
      const mode = info.mode & 0o777;
      if (info.isDirectory()) assert.equal(mode, 0o700, path);
      if (info.isFile()) assert.equal(mode, 0o600, path);
    }
  });
});

test('objects are content-addressed, deduplicated without rewriting and reverified before reuse', async () => {
  await withSandbox(async ({ dataRoot, storage }) => {
    const run = await storage.beginRun(makeJob());
    const rawBytes = Buffer.from('<h1>source</h1>');
    const derivedBytes = Buffer.from('# source\n');
    const raw = await storage.putObject(run, rawBytes, {
      role: 'raw',
      media_type: 'text/html',
      derived_from: null,
    });
    const derived = await storage.putObject(run, derivedBytes, {
      role: 'markdown',
      media_type: 'text/markdown',
      derived_from: raw.hash,
      transform: { id: 'native-html-markdown', version: '1', options_hash: sha256('{}') },
    });

    assert.equal(raw.hash, sha256(rawBytes));
    assert.equal(derived.hash, sha256(derivedBytes));
    assert.notEqual(raw.hash, derived.hash);
    assert.equal(raw.bytes, rawBytes.length);
    assert.equal(derived.derived_from, raw.hash);

    const rawHex = hashHex(raw.hash);
    const derivedHex = hashHex(derived.hash);
    assert.equal(raw.path, `objects/sha256/${rawHex.slice(0, 2)}/${rawHex}`);
    assert.equal(derived.path, `objects/sha256/${derivedHex.slice(0, 2)}/${derivedHex}`);
    assert.deepEqual(await readFile(join(dataRoot, raw.path)), rawBytes);
    assert.deepEqual(await readFile(join(dataRoot, derived.path)), derivedBytes);
    await assertRejected(
      () => storage.readObject(raw, { maxBytes: rawBytes.length - 1 }),
      /large|limit|bytes|integrity/i,
    );
    assert.deepEqual(await storage.readObject(raw, { maxBytes: rawBytes.length }), rawBytes);

    const before = await stat(join(dataRoot, raw.path), { bigint: true });
    const duplicate = await storage.putObject(run, rawBytes, {
      role: 'raw',
      media_type: 'text/html',
      derived_from: null,
    });
    const after = await stat(join(dataRoot, raw.path), { bigint: true });
    assert.equal(duplicate.hash, raw.hash);
    assert.equal(duplicate.path, raw.path);
    assert.equal(after.ino, before.ino);
    assert.equal(after.mtimeNs, before.mtimeNs, 'dedupe must not rewrite an immutable object');

    await writeFile(join(dataRoot, raw.path), Buffer.from('tampered'), { mode: 0o600 });
    await assertRejected(
      () => storage.putObject(run, rawBytes, {
        role: 'raw',
        media_type: 'text/html',
        derived_from: null,
      }),
      /hash|integrity|corrupt|mismatch/i,
    );
    assert.deepEqual(await readFile(join(dataRoot, raw.path)), Buffer.from('tampered'));
  });
});

test('cache becomes visible only after a hash-bound committed manifest', async () => {
  const events = [];
  await withSandbox(async ({ dataRoot, storage }) => {
    const fingerprint = makeFingerprint();
    const run = await storage.beginRun(makeJob());
    assert.match(run.id, /^[A-Za-z0-9._-]+$/);
    assert.equal(run.path, `runs/${run.id}`);

    const source = await storage.putObject(run, Buffer.from('verified source'), {
      role: 'raw',
      media_type: 'text/plain',
      derived_from: null,
    });
    const alternate = await storage.putObject(run, Buffer.from('other valid artifact'), {
      role: 'raw',
      media_type: 'text/plain',
      derived_from: null,
    });
    await storage.appendAttempt(run, {
      type: 'attempt_finished',
      at: FIXED_TIME,
      outcome: 'ok',
      source_hash: source.hash,
    });
    await assertCacheMiss(storage, fingerprint);

    const manifest = await storage.commitManifest(run, makeManifest(run, source, {
      artifacts: [source, alternate],
    }));
    assert.equal(manifest.path, `runs/${run.id}/manifest.json`);
    assert.equal(manifest.hash, sha256(await readFile(join(dataRoot, manifest.path))));
    await assertCacheMiss(storage, fingerprint);

    const record = makeCacheRecord(run, manifest, source);
    await storage.commitCache(fingerprint, record);
    const cached = await storage.readCache(fingerprint);
    assert.equal(cached.hit, true);
    assert.deepEqual(cached.record, record);
    assert.deepEqual(cached.warnings, []);

    const indexPath = join(
      dataRoot,
      'cache',
      'requests',
      fingerprint.slice(0, 2),
      `${fingerprint}.json`,
    );
    assert.deepEqual(JSON.parse(await readFile(indexPath, 'utf8')), record);
    assert.equal(record.manifest_hash, sha256(await readFile(join(dataRoot, record.manifest_path))));
    assert.equal(record.source_hash, sha256(await readFile(join(dataRoot, source.path))));

    await assertRejected(
      () => storage.commitCache(fingerprint, {
        ...record,
        artifact_hash: alternate.hash,
        artifact_path: alternate.path,
      }),
      /artifact|binding|manifest|integrity|mismatch/i,
    );
    assert.deepEqual((await storage.readCache(fingerprint)).record, record);

    const invalidFingerprint = makeFingerprint({ format: 'raw', goal: 'raw' });
    await assertRejected(
      () => storage.commitCache(invalidFingerprint, record),
      /fingerprint|request|cache/i,
    );
    await assertCacheMiss(storage, invalidFingerprint);
    await assertRejected(
      () => storage.commitCache(invalidFingerprint, {
        ...record,
        request_fingerprint: invalidFingerprint,
        manifest_hash: `sha256:${'0'.repeat(64)}`,
      }),
      /manifest|hash|integrity|mismatch/i,
    );
    await assertCacheMiss(storage, invalidFingerprint);
  }, {
    faultInjector(label, context) {
      events.push({ label, context });
    },
  });

  const labels = events.map(({ label }) => label);
  assert.ok(labels.includes('object_rename'));
  assert.ok(labels.includes('journal_flush'));
  assert.ok(labels.includes('manifest_rename'));
  assert.ok(labels.includes('cache_index_rename'));
  assert.ok(
    labels.lastIndexOf('manifest_rename') < labels.lastIndexOf('cache_index_rename'),
    'cache index must be renamed only after the manifest is durable',
  );
});

test('missing, malformed and hash-mismatched cache records are safe misses', async () => {
  await withSandbox(async ({ dataRoot, storage }) => {
    const fingerprint = makeFingerprint();
    await assertCacheMiss(storage, fingerprint);

    const run = await storage.beginRun(makeJob());
    const source = await storage.putObject(run, Buffer.from('cache source'), {
      role: 'raw',
      media_type: 'text/plain',
      derived_from: null,
    });
    await storage.appendAttempt(run, {
      type: 'attempt_finished',
      at: FIXED_TIME,
      outcome: 'ok',
      source_hash: source.hash,
    });
    const manifest = await storage.commitManifest(run, makeManifest(run, source));
    await storage.commitCache(fingerprint, makeCacheRecord(run, manifest, source));

    const indexPath = join(
      dataRoot,
      'cache',
      'requests',
      fingerprint.slice(0, 2),
      `${fingerprint}.json`,
    );
    await writeFile(indexPath, '{truncated', { mode: 0o600 });
    const malformed = await assertCacheMiss(storage, fingerprint);
    assert.ok(malformed.warnings.length > 0);

    await writeFile(indexPath, JSON.stringify({
      ...makeCacheRecord(run, manifest, source),
      source_hash: `sha256:${'f'.repeat(64)}`,
    }), { mode: 0o600 });
    const mismatched = await assertCacheMiss(storage, fingerprint);
    assert.ok(mismatched.warnings.length > 0);
  });
});

test('every durability fault leaves no false cache hit before a valid index', async (t) => {
  for (const failureLabel of [
    'temp_flush',
    'object_rename',
    'journal_flush',
    'manifest_rename',
    'cache_index_rename',
  ]) {
    await t.test(failureLabel, async () => {
      const seen = [];
      const injected = new Error(`injected:${failureLabel}`);
      await withSandbox(async ({ dataRoot, storage }) => {
        const fingerprint = makeFingerprint();
        let failure;
        try {
          const run = await storage.beginRun(makeJob());
          const source = await storage.putObject(run, Buffer.from('fault source'), {
            role: 'raw',
            media_type: 'text/plain',
            derived_from: null,
          });
          await storage.appendAttempt(run, {
            type: 'attempt_finished',
            at: FIXED_TIME,
            outcome: 'ok',
            source_hash: source.hash,
          });
          const manifest = await storage.commitManifest(run, makeManifest(run, source));
          await storage.commitCache(fingerprint, makeCacheRecord(run, manifest, source));
        } catch (error) {
          failure = error;
        }

        assert.equal(failure, injected, `fault ${failureLabel} must escape its publication step`);
        assert.ok(seen.includes(failureLabel), `fault hook ${failureLabel} was not reached`);

        const reopened = createStorage({ dataRoot, clock });
        await assertCacheMiss(reopened, fingerprint);
      }, {
        faultInjector(label) {
          seen.push(label);
          if (label === failureLabel) throw injected;
        },
      });
    });
  }
});

test('private and user output paths reject traversal, absolute paths and symlink components', async () => {
  await withSandbox(async ({ sandbox, dataRoot, storage }) => {
    const output = await storage.publishOutput('exports/result.md', Buffer.from('# result\n'));
    assert.equal(output.path, 'exports/result.md');
    assert.equal(await storage.resolve(output.path), join(dataRoot, output.path));
    assert.equal(await readFile(join(dataRoot, output.path), 'utf8'), '# result\n');

    const absoluteEscape = join(sandbox, 'absolute-escape.txt');
    for (const unsafePath of [
      '../escape.txt',
      'exports/../../escape.txt',
      absoluteEscape,
    ]) {
      await assertRejected(
        () => storage.publishOutput(unsafePath, Buffer.from('escape')),
        /absolute|contain|escape|path|traversal/i,
      );
      await assertRejected(
        () => storage.publishPrivateJson(unsafePath, { escape: true }),
        /absolute|contain|escape|path|traversal/i,
      );
      await assertRejected(
        () => storage.resolve(unsafePath),
        /absolute|contain|escape|path|traversal/i,
      );
    }

    const outside = join(sandbox, 'outside');
    await mkdir(outside, { recursive: true, mode: 0o700 });
    await mkdir(join(dataRoot, 'exports'), { recursive: true, mode: 0o700 });
    await symlink(outside, join(dataRoot, 'exports', 'linked'));
    await assertRejected(
      () => storage.publishOutput('exports/linked/pwned.txt', Buffer.from('escape')),
      /symlink|contain|escape|path/i,
    );
    await assertRejected(
      () => storage.resolve('exports/linked/pwned.txt'),
      /symlink|contain|escape|path/i,
    );
    assert.deepEqual(await readdir(outside), []);
    await assert.rejects(lstat(resolve(dataRoot, '..', 'escape.txt')), { code: 'ENOENT' });
    await assert.rejects(lstat(absoluteEscape), { code: 'ENOENT' });
  });
});
