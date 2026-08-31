import {
  EXIT_CODE,
  RUN_STATUS,
  createResultEnvelope,
  deepFreeze,
  exitCodeForStatus,
  validateResultEnvelope,
} from './contracts.mjs';

const COMMANDS = new Set(['url', 'crawl', 'extract', 'search', 'health']);
const ENGINE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const FORMATS = new Set(['raw', 'markdown', 'metadata', 'links', 'json']);
const CACHE_MODES = new Set(['use', 'refresh', 'off']);
const DISCOVERY_SOURCES = new Set(['alternate', 'api', 'atom', 'html', 'rss', 'sitemap']);
const DEFAULT_TTL_MS = 3_600_000;
const MAX_TTL_MS = 8_000_000_000_000_000;
const MAX_QUERY_LENGTH = 100_000;
const MAX_SCRAPE_RESULTS = 100;
const DEFAULT_SEARCH = Object.freeze({ limit: 10, scrapeResults: 0 });
const DEFAULT_LIMITS = Object.freeze({
  wallMs: 60_000,
  perAttemptMs: 15_000,
  maxBytesPerPage: 5 * 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
  maxPages: 100,
  maxDepth: 3,
  concurrency: 2,
  maxRedirects: 5,
  retriesPerAdapter: 2,
  maxRetryAfterMs: 15_000,
  maxFrontier: 1_000,
  delayMs: 250,
  maxArtifactBytes: 5 * 1024 * 1024,
});

class CliInputError extends Error {
  constructor() {
    super('invalid input');
    this.name = 'CliInputError';
  }
}

function invalid() {
  throw new CliInputError();
}

function takeValue(argv, index) {
  const value = argv[index + 1];
  if (value === undefined || value.startsWith('--')) invalid();
  return value;
}

function isSafeOutputPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096
      || value !== value.trim() || /[\u0000-\u001f\u007f\\]/u.test(value)
      || value.startsWith('/') || /^[a-z]:/iu.test(value)) {
    return false;
  }
  const parts = value.split('/');
  return parts.every((part) => part !== '' && part !== '.' && part !== '..');
}

function isDataRoot(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096
      || value !== value.trim() || /[\u0000-\u001f\u007f]/u.test(value)) {
    return false;
  }
  const withoutTrailingSeparators = value.replace(/[\\/]+$/u, '');
  if (withoutTrailingSeparators === '') return false;
  return withoutTrailingSeparators.split(/[\\/]/u).at(-1) === '.lynceuz';
}

function ttlMilliseconds(value) {
  if (value === null) return DEFAULT_TTL_MS;
  if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/u.test(value)) invalid();
  const milliseconds = Number(value) * 1_000;
  if (!Number.isFinite(milliseconds) || milliseconds <= 0 || milliseconds > MAX_TTL_MS) {
    invalid();
  }
  return milliseconds;
}

function positiveNumber(value, { integer = false, scale = 1, max = Infinity } = {}) {
  if (!/^(?:\d+(?:\.\d*)?|\.\d+)$/u.test(value)) invalid();
  const number = Number(value) * scale;
  if (!Number.isFinite(number) || number <= 0 || number > max
      || (integer && !Number.isSafeInteger(number))) invalid();
  return number;
}

function safePathGlob(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512
      || !value.startsWith('/') || /[\0-\x1f\x7f\\?\[\]{}]/u.test(value)
      || value.split('/').some((part) => part === '..')
      || !/^\/[A-Za-z0-9._~!$&'()+,;=:@%/*-]*$/u.test(value)) {
    invalid();
  }
  return value;
}

function discoverySources(value) {
  const sources = value.split(',');
  if (sources.length === 0 || sources.some((source) => !DISCOVERY_SOURCES.has(source))) invalid();
  return [...new Set(sources)].sort();
}

export function parseArgv(argv) {
  if (!Array.isArray(argv) || argv.some((item) => typeof item !== 'string')) invalid();
  const positional = [];
  const flags = {
    json: false,
    explain: false,
    engine: null,
    schema: null,
    format: null,
    output: null,
    dataRoot: null,
    cache: null,
    ttl: null,
    include: [],
    exclude: [],
    discover: null,
    preferDiscoveredSource: false,
    maxPages: null,
    maxDepth: null,
    maxTime: null,
    maxBytes: null,
    maxFrontier: null,
    concurrency: null,
    delay: null,
    maxRedirects: null,
    retries: null,
    allowRendered: false,
    limit: null,
    scrapeResults: null,
    allowFreeCloud: false,
  };
  const seen = new Set();

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) {
      positional.push(token);
      continue;
    }
    const repeatable = token === '--include' || token === '--exclude';
    if (!repeatable && seen.has(token)) invalid();
    if (!repeatable) seen.add(token);
    switch (token) {
      case '--json': flags.json = true; break;
      case '--explain': flags.explain = true; break;
      case '--engine':
        flags.engine = takeValue(argv, index);
        index += 1;
        break;
      case '--schema':
        flags.schema = takeValue(argv, index);
        index += 1;
        break;
      case '--format':
        flags.format = takeValue(argv, index);
        index += 1;
        break;
      case '--output':
        flags.output = takeValue(argv, index);
        index += 1;
        break;
      case '--data-root':
        flags.dataRoot = takeValue(argv, index);
        index += 1;
        break;
      case '--cache':
        flags.cache = takeValue(argv, index);
        index += 1;
        break;
      case '--ttl':
        flags.ttl = takeValue(argv, index);
        index += 1;
        break;
      case '--include':
        flags.include.push(takeValue(argv, index));
        index += 1;
        break;
      case '--exclude':
        flags.exclude.push(takeValue(argv, index));
        index += 1;
        break;
      case '--discover':
        flags.discover = takeValue(argv, index);
        index += 1;
        break;
      case '--prefer-discovered-source': flags.preferDiscoveredSource = true; break;
      case '--max-pages': flags.maxPages = takeValue(argv, index); index += 1; break;
      case '--max-depth': flags.maxDepth = takeValue(argv, index); index += 1; break;
      case '--max-time': flags.maxTime = takeValue(argv, index); index += 1; break;
      case '--max-bytes': flags.maxBytes = takeValue(argv, index); index += 1; break;
      case '--max-frontier': flags.maxFrontier = takeValue(argv, index); index += 1; break;
      case '--concurrency': flags.concurrency = takeValue(argv, index); index += 1; break;
      case '--delay': flags.delay = takeValue(argv, index); index += 1; break;
      case '--max-redirects': flags.maxRedirects = takeValue(argv, index); index += 1; break;
      case '--retries': flags.retries = takeValue(argv, index); index += 1; break;
      case '--allow-rendered': flags.allowRendered = true; break;
      case '--limit': flags.limit = takeValue(argv, index); index += 1; break;
      case '--scrape-results': flags.scrapeResults = takeValue(argv, index); index += 1; break;
      case '--allow-free-cloud': flags.allowFreeCloud = true; break;
      default: invalid();
    }
  }

  if (positional.length === 0) invalid();
  let command;
  let args;
  if (COMMANDS.has(positional[0])) {
    [command, ...args] = positional;
  } else if (/^https?:\/\//i.test(positional[0])) {
    command = 'url';
    args = positional;
  } else {
    invalid();
  }

  if (flags.engine !== null && !ENGINE_ID.test(flags.engine)) invalid();
  if (flags.schema !== null && (flags.schema.includes('\0') || flags.schema.length > 4096)) invalid();
  if (flags.format !== null && !FORMATS.has(flags.format)) invalid();
  if (flags.output !== null && !isSafeOutputPath(flags.output)) invalid();
  if (flags.dataRoot !== null && !isDataRoot(flags.dataRoot)) invalid();
  if (flags.cache !== null && !CACHE_MODES.has(flags.cache)) invalid();
  if (flags.ttl !== null) ttlMilliseconds(flags.ttl);
  flags.include = flags.include.map(safePathGlob);
  flags.exclude = flags.exclude.map(safePathGlob);
  if (flags.discover !== null) discoverySources(flags.discover);
  for (const name of ['maxPages', 'maxDepth', 'maxBytes', 'maxFrontier', 'concurrency', 'maxRedirects', 'retries']) {
    if (flags[name] !== null) positiveNumber(flags[name], { integer: true });
  }
  if (flags.maxTime !== null) positiveNumber(flags.maxTime, { scale: 1_000 });
  if (flags.delay !== null) positiveNumber(flags.delay, { scale: 1_000 });
  if (flags.limit !== null) positiveNumber(flags.limit, { integer: true });
  if (flags.scrapeResults !== null) {
    positiveNumber(flags.scrapeResults, { integer: true, max: MAX_SCRAPE_RESULTS });
  }
  if (command !== 'search' && (flags.limit !== null || flags.scrapeResults !== null)) invalid();
  const hasNativeOption = flags.format !== null || flags.output !== null
    || flags.dataRoot !== null || flags.cache !== null || flags.ttl !== null;
  const hasCrawlOption = flags.include.length > 0 || flags.exclude.length > 0
    || flags.discover !== null || flags.preferDiscoveredSource
    || ['maxPages', 'maxDepth', 'maxTime', 'maxBytes', 'maxFrontier', 'concurrency', 'delay', 'maxRedirects', 'retries']
      .some((name) => flags[name] !== null);
  if (!['url', 'crawl', 'extract'].includes(command) && hasNativeOption) invalid();
  if (!['url', 'crawl', 'extract'].includes(command) && flags.allowRendered) invalid();
  if (command !== 'crawl' && hasCrawlOption) invalid();
  if (flags.explain && (hasNativeOption || hasCrawlOption)) invalid();
  if (command === 'health') {
    if (args.length !== 0 || flags.schema !== null) invalid();
  } else if (command === 'extract') {
    if (args.length !== 1 || flags.schema === null) invalid();
  } else {
    if (args.length !== 1 || flags.schema !== null) invalid();
  }
  if (command === 'search' && (args[0].trim() === '' || args[0].length > MAX_QUERY_LENGTH)) invalid();
  if (['url', 'crawl', 'extract'].includes(command)) {
    try {
      const parsed = new URL(args[0]);
      if (!['http:', 'https:'].includes(parsed.protocol)) invalid();
    } catch {
      invalid();
    }
  }

  return deepFreeze({ command, args, flags });
}

export function compileJobSpec(parsed) {
  if (!parsed || !COMMANDS.has(parsed.command)) invalid();
  const target = parsed.command === 'health'
    ? {}
    : parsed.command === 'search'
      ? { query: parsed.args[0] }
      : parsed.command === 'extract'
        ? { url: parsed.args[0], schemaPath: parsed.flags.schema }
        : { url: parsed.args[0] };
  const goals = {
    url: 'markdown',
    crawl: 'markdown',
    extract: 'json',
    search: 'search-results',
    health: 'status',
  };
  const isLocalRun = ['url', 'crawl', 'extract'].includes(parsed.command) && !parsed.flags.explain;
  const format = parsed.flags.format ?? (parsed.command === 'extract' ? 'json' : 'markdown');
  const limitOverrides = {
    ...(parsed.flags.maxPages === null ? {} : { maxPages: positiveNumber(parsed.flags.maxPages, { integer: true }) }),
    ...(parsed.flags.maxDepth === null ? {} : { maxDepth: positiveNumber(parsed.flags.maxDepth, { integer: true }) }),
    ...(parsed.flags.maxTime === null ? {} : { wallMs: positiveNumber(parsed.flags.maxTime, { scale: 1_000 }) }),
    ...(parsed.flags.maxBytes === null ? {} : { maxTotalBytes: positiveNumber(parsed.flags.maxBytes, { integer: true }) }),
    ...(parsed.flags.maxFrontier === null ? {} : { maxFrontier: positiveNumber(parsed.flags.maxFrontier, { integer: true }) }),
    ...(parsed.flags.concurrency === null ? {} : { concurrency: positiveNumber(parsed.flags.concurrency, { integer: true }) }),
    ...(parsed.flags.delay === null ? {} : { delayMs: positiveNumber(parsed.flags.delay, { scale: 1_000 }) }),
    ...(parsed.flags.maxRedirects === null ? {} : { maxRedirects: positiveNumber(parsed.flags.maxRedirects, { integer: true }) }),
    ...(parsed.flags.retries === null ? {} : { retriesPerAdapter: positiveNumber(parsed.flags.retries, { integer: true }) }),
  };
  const spec = {
    schemaVersion: 1,
    kind: parsed.command,
    target,
    goal: goals[parsed.command],
    limits: { ...DEFAULT_LIMITS, ...limitOverrides },
    policy: {
      network: 'public-only',
      auth: 'none',
      moneyBudget: 0,
      allowFreeCloud: parsed.flags.allowFreeCloud,
      allowRendered: parsed.flags.allowRendered,
      respectRobots: true,
    },
    output: isLocalRun
      ? {
        json: parsed.flags.json,
        format,
        path: parsed.flags.output,
        dataRoot: parsed.flags.dataRoot,
      }
      : { json: parsed.flags.json },
    routing: {
      explain: parsed.flags.explain,
      forcedEngine: parsed.flags.engine,
    },
    scope: {
      include: parsed.flags.include.length > 0 ? [...parsed.flags.include] : ['/**'],
      exclude: [...parsed.flags.exclude],
    },
    discovery: {
      sources: parsed.flags.discover === null ? [] : discoverySources(parsed.flags.discover),
      preferDiscoveredSource: parsed.flags.preferDiscoveredSource,
    },
  };
  if (parsed.command === 'search') {
    spec.search = {
      limit: parsed.flags.limit === null
        ? DEFAULT_SEARCH.limit
        : positiveNumber(parsed.flags.limit, { integer: true }),
      scrapeResults: parsed.flags.scrapeResults === null
        ? DEFAULT_SEARCH.scrapeResults
        : positiveNumber(parsed.flags.scrapeResults, { integer: true, max: MAX_SCRAPE_RESULTS }),
    };
  }
  if (isLocalRun) {
    spec.goal = format;
    spec.cache = {
      mode: parsed.flags.cache ?? 'use',
      ttlMs: ttlMilliseconds(parsed.flags.ttl),
    };
  }
  for (const value of Object.values(spec.limits)) {
    if (!Number.isFinite(value) || value <= 0) invalid();
  }
  return deepFreeze(spec);
}

export function writeResult(result, io, { json = false } = {}) {
  try {
    validateResultEnvelope(result);
  } catch (error) {
    throw new TypeError(`invalid result envelope: ${error.message}`);
  }
  if (!io?.stdout || typeof io.stdout.write !== 'function') {
    throw new TypeError('invalid output stream');
  }
  if (!io?.stderr || typeof io.stderr.write !== 'function') {
    throw new TypeError('invalid diagnostic stream');
  }
  for (const warning of result.warnings) io.stderr.write(`warning: ${warning}\n`);
  let output = `${result.status}: ${result.message}\n`;
  if (result.code === 'health') {
    output += result.capabilities
      .map((entry) => `${entry.id}\t${entry.state}\t${entry.version ?? '-'}\t${entry.reason}`)
      .join('\n');
    output += '\n';
  } else if (result.code === 'route_explained') {
    output += result.route
      .map((entry) => `${entry.id}\t${entry.eligible ? 'eligible' : 'blocked'}\t${entry.reason}`)
      .join('\n');
    output += '\n';
  }
  if (json) output = `${JSON.stringify(result)}\n`;
  io.stdout.write(output);
}

function safeDiagnostic(io, value) {
  try {
    io?.stderr?.write(value);
  } catch {
    // A broken diagnostic stream cannot safely be recovered here.
  }
}

function invalidInputResult(command = 'health', message = 'Invalid command line') {
  return createResultEnvelope({
    command: COMMANDS.has(command) ? command : 'health',
    status: RUN_STATUS.INVALID_INPUT,
    code: 'invalid_input',
    message,
    route: [],
    capabilities: [],
    warnings: [],
  });
}

function internalErrorResult(command) {
  return createResultEnvelope({
    command,
    status: RUN_STATUS.INTERNAL_ERROR,
    code: 'internal_error',
    message: 'Internal contract error',
    route: [],
    capabilities: [],
    warnings: [],
  });
}

export async function runCli(argv, { io, registry, executeJob, now }) {
  const jsonRequested = Array.isArray(argv) && argv.includes('--json');
  let spec;
  try {
    spec = compileJobSpec(parseArgv(argv));
  } catch {
    const result = invalidInputResult(Array.isArray(argv) ? argv[0] : undefined);
    try {
      writeResult(result, io, { json: jsonRequested });
      return EXIT_CODE.INVALID_INPUT;
    } catch {
      safeDiagnostic(io, 'output_failure: unable to write result\n');
      return EXIT_CODE.OUTPUT_FAILURE;
    }
  }

  const forcedEngine = spec.routing.forcedEngine;
  if (forcedEngine !== null && (!Array.isArray(registry)
      || !registry.some((entry) => entry?.id === forcedEngine))) {
    const result = invalidInputResult(spec.kind, 'Unknown engine');
    try {
      writeResult(result, io, { json: spec.output.json });
      return EXIT_CODE.INVALID_INPUT;
    } catch {
      safeDiagnostic(io, 'output_failure: unable to write result\n');
      return EXIT_CODE.OUTPUT_FAILURE;
    }
  }

  let result;
  try {
    if (typeof executeJob !== 'function') throw new TypeError('executeJob is required');
    result = await executeJob(spec, { registry, now });
    validateResultEnvelope(result);
    if (result.command !== spec.kind) throw new TypeError('result command mismatch');
  } catch {
    result = internalErrorResult(spec.kind);
  }

  try {
    writeResult(result, io, { json: spec.output.json });
  } catch {
    safeDiagnostic(io, 'output_failure: unable to write result\n');
    return EXIT_CODE.OUTPUT_FAILURE;
  }
  return exitCodeForStatus(result.status, result.termination);
}
