import {
  ATTEMPT_CODE,
  ATTEMPT_KIND,
  CAPABILITY_STATE,
  RUN_STATUS,
  createResultEnvelope,
  deepFreeze,
} from './contracts.mjs';
import { authorizeCost } from './policy.mjs';

const COMMANDS = new Set(['url', 'crawl', 'extract', 'search', 'health']);
const STATES = new Set(Object.values(CAPABILITY_STATE));
const NETWORK_MODELS = new Set(['core-http', 'guard-proxy', 'provider-managed', 'none']);
const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;

function assertDescriptor(descriptor) {
  if (!descriptor || typeof descriptor !== 'object' || !ID.test(descriptor.id ?? '')) {
    throw new TypeError('capability descriptor has invalid id');
  }
  if (!STATES.has(descriptor.state)) throw new TypeError('capability descriptor has invalid state');
  if (descriptor.version !== null && typeof descriptor.version !== 'string') {
    throw new TypeError('capability descriptor has invalid version');
  }
  if (typeof descriptor.reason !== 'string' || descriptor.reason.length === 0) {
    throw new TypeError('capability descriptor has invalid reason');
  }
  if (typeof descriptor.automatic !== 'boolean') throw new TypeError('capability descriptor has invalid routing flag');
  if (!Array.isArray(descriptor.commands) || descriptor.commands.some((command) => !COMMANDS.has(command))) {
    throw new TypeError('capability descriptor has invalid commands');
  }
  if (typeof descriptor.cost !== 'string' || !NETWORK_MODELS.has(descriptor.networkModel)) {
    throw new TypeError('capability descriptor has invalid boundary');
  }
  if (descriptor.proofFingerprint !== undefined && descriptor.proofFingerprint !== null
      && typeof descriptor.proofFingerprint !== 'string') {
    throw new TypeError('capability descriptor has invalid proof fingerprint');
  }
  if (descriptor.enable_with !== undefined && descriptor.enable_with !== null
      && typeof descriptor.enable_with !== 'string') {
    throw new TypeError('capability descriptor has invalid enable hint');
  }
}

export function createCapabilitySnapshot(registry) {
  if (!Array.isArray(registry)) throw new TypeError('registry must be an array');
  const seen = new Set();
  const snapshot = registry.map((descriptor) => {
    assertDescriptor(descriptor);
    if (seen.has(descriptor.id)) throw new TypeError('registry contains duplicate adapter id');
    seen.add(descriptor.id);
    return {
      id: descriptor.id,
      version: descriptor.version,
      state: descriptor.state,
      reason: descriptor.reason,
      automatic: descriptor.automatic,
      commands: [...descriptor.commands],
      cost: descriptor.cost,
      price: Number.isFinite(descriptor.price) ? descriptor.price : null,
      networkModel: descriptor.networkModel,
      ...(descriptor.proofFingerprint === undefined
        ? {} : { proofFingerprint: descriptor.proofFingerprint }),
      ...(descriptor.enable_with === undefined ? {} : { enable_with: descriptor.enable_with }),
    };
  });
  return deepFreeze(snapshot);
}

function candidateFor(job, capability) {
  const supported = capability.commands.includes(job.kind);
  const cost = authorizeCost(capability);
  const renderedAllowed = capability.networkModel !== 'guard-proxy' || job.policy.allowRendered;
  const cloudAllowed = capability.networkModel !== 'provider-managed' || job.policy.allowFreeCloud;
  const eligible = supported
    && capability.state === CAPABILITY_STATE.READY
    && cost.allowed
    && renderedAllowed
    && cloudAllowed;
  let reason = 'eligible';
  if (!supported) reason = 'unsupported_command';
  else if (capability.state !== CAPABILITY_STATE.READY) reason = capability.reason;
  else if (!cost.allowed) reason = cost.state;
  else if (!renderedAllowed) reason = 'rendered_not_allowed';
  else if (!cloudAllowed) reason = 'free_cloud_not_allowed';
  return {
    id: capability.id,
    version: capability.version,
    state: capability.state,
    reason,
    automatic: capability.automatic,
    cost: capability.cost,
    costState: cost.state,
    networkModel: capability.networkModel,
    eligible,
    ...(capability.proofFingerprint === undefined
      ? {} : { proofFingerprint: capability.proofFingerprint }),
    ...(capability.enable_with === undefined ? {} : { enable_with: capability.enable_with }),
  };
}

export function buildRoutePlan(job, capabilitySnapshot, options = {}) {
  if (!job || !COMMANDS.has(job.kind) || !Array.isArray(capabilitySnapshot)) {
    throw new TypeError('cannot build route for invalid input');
  }
  const forcedEngine = options.forcedEngine ?? job.routing?.forcedEngine ?? null;
  const selected = forcedEngine === null
    ? capabilitySnapshot.filter((entry) => entry.automatic && entry.commands.includes(job.kind))
    : capabilitySnapshot.filter((entry) => entry.id === forcedEngine);
  return deepFreeze({
    schemaVersion: 1,
    kind: job.kind,
    goal: job.goal,
    forcedEngine,
    candidates: selected.map((entry) => candidateFor(job, entry)),
  });
}

function decision(action, delayMs, status, code) {
  return deepFreeze({ action, delayMs, status, code });
}

function invalidOutcome() {
  return decision('stop', 0, RUN_STATUS.INTERNAL_ERROR, 'unknown_attempt_code');
}

function nextOrExhausted(code, hasNext) {
  return hasNext
    ? decision('next', 0, null, code)
    : decision('stop', 0, RUN_STATUS.EXHAUSTED, 'exhausted');
}

export function decideTransition(outcome, context = {}) {
  if (!outcome || typeof outcome !== 'object') return invalidOutcome();
  const hasNext = context.hasNext === true;
  const retriesUsed = Number.isInteger(context.retriesUsed) && context.retriesUsed >= 0
    ? context.retriesUsed
    : 0;
  const retriesLimit = Number.isInteger(context.retriesLimit) && context.retriesLimit >= 0
    ? context.retriesLimit
    : 0;
  const maxRetryAfterMs = Number.isFinite(context.maxRetryAfterMs) && context.maxRetryAfterMs >= 0
    ? context.maxRetryAfterMs
    : 15_000;

  switch (outcome.code) {
    case ATTEMPT_CODE.OK:
      return outcome.kind === ATTEMPT_KIND.SUCCESS
        ? decision('stop', 0, RUN_STATUS.OK, ATTEMPT_CODE.OK)
        : invalidOutcome();

    case ATTEMPT_CODE.UNAVAILABLE:
    case ATTEMPT_CODE.UNSUPPORTED:
    case ATTEMPT_CODE.CLOUD_DISABLED:
    case ATTEMPT_CODE.POLICY_UNENFORCEABLE:
      return outcome.kind === ATTEMPT_KIND.SKIP
        ? nextOrExhausted(outcome.code, hasNext)
        : invalidOutcome();

    case ATTEMPT_CODE.TIMEOUT:
    case ATTEMPT_CODE.NETWORK:
    case ATTEMPT_CODE.HTTP_5XX:
      if (outcome.kind !== ATTEMPT_KIND.RETRYABLE) return invalidOutcome();
      if (retriesUsed < retriesLimit) return decision('retry_same', 0, null, outcome.code);
      return nextOrExhausted(outcome.code, hasNext);

    case ATTEMPT_CODE.RATE_LIMITED: {
      if (outcome.kind !== ATTEMPT_KIND.RETRYABLE) return invalidOutcome();
      if (retriesUsed >= retriesLimit) {
        return decision('stop', 0, RUN_STATUS.BLOCKED, ATTEMPT_CODE.RATE_LIMITED);
      }
      const requested = Number.isFinite(outcome.retryAfterMs) && outcome.retryAfterMs > 0
        ? outcome.retryAfterMs
        : 0;
      return decision(
        'retry_same',
        Math.min(requested, maxRetryAfterMs),
        null,
        ATTEMPT_CODE.RATE_LIMITED,
      );
    }

    case ATTEMPT_CODE.JS_SHELL:
    case ATTEMPT_CODE.EMPTY:
    case ATTEMPT_CODE.WRONG_MIME:
    case ATTEMPT_CODE.PARSE_FAILED:
      return outcome.kind === ATTEMPT_KIND.INADEQUATE
        ? nextOrExhausted(outcome.code, hasNext)
        : invalidOutcome();

    case ATTEMPT_CODE.POLICY_DENIED:
    case ATTEMPT_CODE.ROBOTS_DENIED:
    case ATTEMPT_CODE.ACCESS_DENIED:
    case ATTEMPT_CODE.AUTH_REQUIRED:
    case ATTEMPT_CODE.CAPTCHA:
    case ATTEMPT_CODE.PAYWALL:
    case ATTEMPT_CODE.PAID_REQUIRED:
    case ATTEMPT_CODE.HARD_LIMIT:
      return outcome.kind === ATTEMPT_KIND.TERMINAL
        ? decision('stop', 0, RUN_STATUS.BLOCKED, outcome.code)
        : invalidOutcome();

    case ATTEMPT_CODE.NOT_FOUND:
    case ATTEMPT_CODE.GONE:
      return outcome.kind === ATTEMPT_KIND.TERMINAL
        ? decision('stop', 0, RUN_STATUS.EXHAUSTED, outcome.code)
        : invalidOutcome();

    case ATTEMPT_CODE.ADAPTER_CRASH:
    case ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR:
    case ATTEMPT_CODE.HASH_MISMATCH:
      return outcome.kind === ATTEMPT_KIND.BROKEN
        ? decision('stop', 0, RUN_STATUS.INTERNAL_ERROR, outcome.code)
        : invalidOutcome();

    default:
      return invalidOutcome();
  }
}

function inadequate(code, reason, fields = {}) {
  return deepFreeze({
    kind: ATTEMPT_KIND.INADEQUATE,
    code,
    details: { reason, ...fields },
  });
}

export function acceptRepresentation({ goal, representation } = {}) {
  if (!representation || typeof representation !== 'object' || Array.isArray(representation)) {
    return inadequate(ATTEMPT_CODE.PARSE_FAILED, 'invalid_representation');
  }
  const missing = representation.requiredMissing ?? representation.missingRequired;
  if (Array.isArray(missing) && missing.length > 0) {
    return inadequate(ATTEMPT_CODE.PARSE_FAILED, 'required_fields_missing', {
      missing: [...new Set(missing.filter((name) => typeof name === 'string'))].sort(),
    });
  }
  const text = typeof representation.text === 'string'
    ? representation.text.trim()
    : typeof representation.markdown === 'string'
      ? representation.markdown.trim()
      : '';
  const scriptCount = Number.isSafeInteger(representation.scriptCount)
    ? representation.scriptCount
    : representation.jsShell === true ? 1 : 0;
  if (['markdown', 'text'].includes(goal) && text.length === 0) {
    return scriptCount > 0
      ? inadequate(ATTEMPT_CODE.JS_SHELL, 'proven_js_shell')
      : inadequate(ATTEMPT_CODE.EMPTY, 'empty_main_content');
  }
  if (goal === 'json') {
    const validJson = ['json', 'jsonld', 'schema'].includes(representation.kind)
      || (representation.data !== null && typeof representation.data === 'object');
    if (!validJson) return inadequate(ATTEMPT_CODE.WRONG_MIME, 'wrong_representation');
  }
  if (goal === 'links' && !Array.isArray(representation.links)) {
    return inadequate(ATTEMPT_CODE.WRONG_MIME, 'wrong_representation');
  }
  if (goal === 'metadata' && (!representation.metadata || typeof representation.metadata !== 'object')) {
    return inadequate(ATTEMPT_CODE.WRONG_MIME, 'wrong_representation');
  }
  if (goal === 'raw') {
    const length = representation.bytes?.length ?? representation.body?.length ?? representation.byteLength;
    if (!Number.isSafeInteger(length) || length <= 0) {
      return inadequate(ATTEMPT_CODE.EMPTY, 'empty_main_content');
    }
  }
  if (!['raw', 'markdown', 'text', 'metadata', 'links', 'json'].includes(goal)) {
    return inadequate(ATTEMPT_CODE.WRONG_MIME, 'wrong_representation');
  }
  return deepFreeze({ kind: ATTEMPT_KIND.SUCCESS, code: ATTEMPT_CODE.OK });
}

export function healthReport(capabilitySnapshot) {
  if (!Array.isArray(capabilitySnapshot)) throw new TypeError('capability snapshot must be an array');
  return deepFreeze(capabilitySnapshot.map((entry) => ({
    id: entry.id,
    state: entry.state,
    version: entry.version,
    reason: entry.reason,
    automatic: entry.automatic,
    commands: [...entry.commands],
    cost: entry.cost,
    networkModel: entry.networkModel,
    ...(entry.proofFingerprint === undefined ? {} : { proofFingerprint: entry.proofFingerprint }),
    ...(entry.enable_with === undefined ? {} : { enable_with: entry.enable_with }),
  })));
}

const RENDERABLE_INADEQUATE = new Set([
  ATTEMPT_CODE.JS_SHELL,
  ATTEMPT_CODE.EMPTY,
  ATTEMPT_CODE.PARSE_FAILED,
]);

export function renderedFallbackSkip(job, route, outcome) {
  if (job?.policy?.allowRendered !== true || !Array.isArray(route)
      || outcome?.kind !== ATTEMPT_KIND.INADEQUATE || !RENDERABLE_INADEQUATE.has(outcome.code)) {
    return null;
  }
  const candidate = route.find((entry) => entry?.id === 'playwright');
  if (!candidate || candidate.eligible === true) return null;
  return deepFreeze({
    kind: ATTEMPT_KIND.SKIP,
    code: ATTEMPT_CODE.POLICY_UNENFORCEABLE,
    details: {
      reason: candidate.reason || 'browser_security_gate_unavailable',
      ...(candidate.proofFingerprint ? { proofFingerprint: candidate.proofFingerprint } : {}),
    },
  });
}

function resultMessage(status) {
  switch (status) {
    case RUN_STATUS.OK: return 'Route completed';
    case RUN_STATUS.BLOCKED: return 'Route stopped by policy';
    case RUN_STATUS.EXHAUSTED: return 'No eligible route completed';
    default: return 'Route contract failed';
  }
}

function modelResult(job, plan, capabilities, status, code) {
  return createResultEnvelope({
    command: job.kind,
    status,
    code,
    message: resultMessage(status),
    route: plan.candidates,
    capabilities,
    warnings: [],
  });
}

function adapterFrom(adapters, id) {
  return adapters instanceof Map ? adapters.get(id) : adapters?.[id];
}

export async function runModelRoute(job, capabilitySnapshot, {
  adapters = new Map(),
  sleep = async () => {},
} = {}) {
  const plan = buildRoutePlan(job, capabilitySnapshot);
  const capabilities = healthReport(capabilitySnapshot);
  const eligible = plan.candidates.filter((candidate) => candidate.eligible);
  if (eligible.length === 0) {
    return modelResult(job, plan, capabilities, RUN_STATUS.EXHAUSTED, 'no_eligible_engine');
  }

  for (let index = 0; index < eligible.length; index += 1) {
    const candidate = eligible[index];
    const adapter = adapterFrom(adapters, candidate.id);
    if (!adapter || typeof adapter.run !== 'function') {
      return modelResult(
        job,
        plan,
        capabilities,
        RUN_STATUS.INTERNAL_ERROR,
        ATTEMPT_CODE.ADAPTER_PROTOCOL_ERROR,
      );
    }
    let retriesUsed = 0;
    while (true) {
      let outcome;
      try {
        outcome = await adapter.run(job);
      } catch {
        outcome = { kind: ATTEMPT_KIND.BROKEN, code: ATTEMPT_CODE.ADAPTER_CRASH };
      }
      const transition = decideTransition(outcome, {
        hasNext: index < eligible.length - 1,
        retriesUsed,
        retriesLimit: job.limits.retriesPerAdapter,
        maxRetryAfterMs: job.limits.maxRetryAfterMs,
      });
      if (transition.action === 'retry_same') {
        retriesUsed += 1;
        try {
          await sleep(transition.delayMs);
        } catch {
          return modelResult(job, plan, capabilities, RUN_STATUS.INTERNAL_ERROR, 'internal_error');
        }
        continue;
      }
      if (transition.action === 'next') break;
      return modelResult(job, plan, capabilities, transition.status, transition.code);
    }
  }
  return modelResult(job, plan, capabilities, RUN_STATUS.EXHAUSTED, 'exhausted');
}

export function createDefaultRegistry(nodeVersion) {
  if (typeof nodeVersion !== 'string' || nodeVersion.length === 0) {
    throw new TypeError('node version is required');
  }
  return deepFreeze([
    {
      id: 'core', version: nodeVersion, state: 'ready', reason: 'node_runtime', automatic: false,
      commands: ['health'], cost: 'local-zero', price: 0, networkModel: 'none',
    },
    {
      id: 'native', version: null, state: 'disabled', reason: 'phase_2_not_connected', automatic: true,
      commands: ['url', 'crawl', 'extract'], cost: 'local-zero', price: 0, networkModel: 'core-http',
    },
    {
      id: 'beautifulsoup', version: null, state: 'missing', reason: 'optional_parser_not_probed', automatic: false,
      commands: ['extract'], cost: 'local-zero', price: 0, networkModel: 'none',
    },
    {
      id: 'playwright', version: null, state: 'unavailable_security_gate',
      reason: process.platform === 'darwin'
        ? 'hostile_egress_proof_missing:sandbox_loopback_scope_unproven'
        : 'hostile_egress_proof_missing:sandbox_platform_unsupported',
      proofFingerprint: null, enable_with: null, automatic: true,
      commands: ['url', 'crawl', 'extract'], cost: 'local-zero', price: 0, networkModel: 'guard-proxy',
    },
    {
      id: 'crawl4ai', version: null, state: 'unavailable_security_gate', reason: 'independent_security_proof_missing', automatic: true,
      commands: ['url', 'crawl', 'extract'], cost: 'local-zero', price: 0, networkModel: 'guard-proxy',
    },
    {
      id: 'browser-use', version: null, state: 'disabled', reason: 'automatic_path_forbidden', automatic: false,
      commands: ['url', 'crawl', 'extract'], cost: 'local-zero', price: 0, networkModel: 'guard-proxy',
    },
    {
      id: 'firecrawl', version: null, state: 'disabled', reason: 'free_cloud_not_allowed', automatic: true,
      commands: ['url', 'crawl', 'extract', 'search'], cost: 'free-credit', price: null, networkModel: 'provider-managed',
    },
    {
      id: 'scrapegraphai', version: null, state: 'disabled', reason: 'free_cloud_not_allowed', automatic: true,
      commands: ['url', 'extract', 'search'], cost: 'free-credit', price: null, networkModel: 'provider-managed',
    },
  ]);
}
