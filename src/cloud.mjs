// Fail-closed free-cloud gate (COST-02 opt-in, COST-03 worst-case ledger).
//
// v1 forbids any network provider, so cloud is a MODEL, never runtime: this gate
// consumes only the frozen JobSpec/policy, a provider descriptor, and the shared
// credit ledger — never ambient credentials — and always keeps cloud closed. It
// exists to prove the invariants: zero money, a provider-managed trust boundary,
// provider bodies/hashes that are never local public-only evidence, and a ledger
// that can never be over-debited. When a real free provider ships and runtime
// cloud is wired, `eligible` flips true on a proven cost; nothing here executes.
//
// ponytail: dead model on purpose — no preflight/execute is ever invoked, so the
// billable path stays a single unbuilt branch. Upgrade path: wire a real provider
// behind evaluateCloudEligibility === eligible and add a compare-and-swap commit
// on ledger.committed in reserveWorstCase before any real oversubscription exists.

import { deepFreeze } from './contracts.mjs';
import { authorizeCloudCost } from './policy.mjs';

const BLOCKED = 'unknown_and_blocked';

function moneyStamp() {
  return { cost_money: 0, credits_used: BLOCKED };
}

function boundaryStamp() {
  return {
    trust_boundary: { kind: 'provider-managed', evidence_is_local_public_only: false },
    local_public_only_equivalent: false,
  };
}

// Pure eligibility: opt-in AND a proven-free bounded cost are necessary, but in v1
// the provider never runs, so the outcome is always blocked. The reason is honest:
// the missing opt-in, the first unproven cost axis, or the disabled runtime.
export function evaluateCloudEligibility(job, { provider, ledger, clock = () => new Date() } = {}) {
  const optIn = job?.policy?.allowFreeCloud === true;
  const cost = authorizeCloudCost(provider, ledger, clock);
  const reason = !optIn
    ? 'free_cloud_not_allowed'
    : cost.allowed ? 'cloud_runtime_disabled' : cost.reason;
  return deepFreeze({
    eligible: false,
    outcome: BLOCKED,
    reason,
    cost_proven: cost.allowed,
    ...moneyStamp(),
    ...boundaryStamp(),
  });
}

// Opt-in gate run BEFORE any provider preflight/execute. Returns the local-first
// route and eligibility byte-for-byte — cloud adds no hop when it stays closed.
export async function evaluateCloudGate(job, { provider, ledger, baseline, clock = () => new Date() } = {}) {
  const elig = evaluateCloudEligibility(job, { provider, ledger, clock });
  return deepFreeze({
    outcome: elig.outcome,
    reason: elig.reason,
    executed: false,
    route: baseline.route,
    eligibility: baseline.eligibility,
    ...moneyStamp(),
    ...boundaryStamp(),
  });
}

// Inspects the provider's declared worst-case reservation against the shared run
// ledger. A negative, non-finite, over-ceiling, or over-balance figure is a broken
// provider contract — never "cost went down → free success". v1 never commits, so
// the ledger is never debited and oversubscription is structurally impossible.
export function reserveWorstCase(ledger, { job, provider, clock = () => new Date() } = {}) {
  const cost = authorizeCloudCost(provider, ledger, clock);
  const broken = cost.reason === 'worst_case_unbounded';
  return deepFreeze({
    outcome: BLOCKED,
    broken,
    committed: false,
    ...moneyStamp(),
  });
}

// Produces the honest attempt + manifest records for a blocked cloud attempt. The
// provider is never invoked; its body/hash is never promoted to local evidence and
// never becomes a top-level source hash.
export async function runCloudAttempt(job, { provider, ledger, clock = () => new Date() } = {}) {
  const elig = evaluateCloudEligibility(job, { provider, ledger, clock });
  const attempt = deepFreeze({
    kind: 'cloud',
    outcome: BLOCKED,
    reason: elig.reason,
    executed: false,
    ...moneyStamp(),
    ...boundaryStamp(),
  });
  const manifest = deepFreeze({
    kind: 'cloud_attempt',
    outcome: BLOCKED,
    reason: elig.reason,
    provider: {
      id: provider?.id ?? null,
      version: provider?.version ?? null,
      network_model: 'provider-managed',
    },
    ...moneyStamp(),
    ...boundaryStamp(),
  });
  return { attempt, manifest };
}

// Binds the gate to one shared run ledger so every evaluate/reserve/attempt draws
// from the same credit state — the reservation point that a future runtime makes
// atomic. In v1 every method fails closed.
export function createCloudGate({ ledger, clock = () => new Date() } = {}) {
  return {
    evaluate: (job, { provider, baseline }) => evaluateCloudGate(job, { provider, ledger, baseline, clock }),
    reserve: (job, provider) => reserveWorstCase(ledger, { job, provider, clock }),
    attempt: (job, provider) => runCloudAttempt(job, { provider, ledger, clock }),
  };
}
