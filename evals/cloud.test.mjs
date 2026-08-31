// RED contract for the fail-closed free-cloud gate (COST-02 opt-in, COST-03 ledger).
//
// v1 forbids any network provider, so cloud is a dead model proven by fakes on
// frozen JobSpec/policy literals — never a CLI flag, never live network, never a
// new package. Every test dynamic-imports the future src/cloud.mjs *inside* its
// body; until that model exists they fail with ERR_MODULE_NOT_FOUND, the intended
// red state. They green once src/cloud.mjs ships the additive gate:
//
//   evaluateCloudGate(job, { provider, ledger, baseline, clock }) -> decision
//     Fail-closed opt-in gate, runs BEFORE any provider preflight/execute.
//     { outcome, reason, executed, route, eligibility, cost_money (numeric),
//       credits_used, trust_boundary:{kind,evidence_is_local_public_only},
//       local_public_only_equivalent }
//   reserveWorstCase(ledger, { job, provider, clock }) -> reservation
//     Inspects the provider's declared worst-case reservation only.
//     { outcome, broken, committed, cost_money, credits_used }
//   runCloudAttempt(job, { provider, ledger, clock }) -> { attempt, manifest }
//     Both records stamped with the money/credit/trust-boundary invariants.

import assert from 'node:assert/strict';
import test from 'node:test';

import { deepFreeze } from '../src/contracts.mjs';

const CLOUD_MODEL = '../src/cloud.mjs';
const NOW = '2026-08-26T17:00:00.000Z';

// Frozen policy literal: default v1 stance — zero money budget, free cloud off,
// public-only, no auth. Overrides flip a single field for a given test.
const FROZEN_POLICY = deepFreeze({
  moneyBudget: 0,
  allowFreeCloud: false,
  network: 'public-only',
  auth: 'none',
});

function frozenJob(overrides = {}) {
  const { policy, ...rest } = overrides;
  return deepFreeze({
    schemaVersion: 1,
    command: 'url',
    goal: 'source-capture',
    target: { url: 'https://public.example.test/records' },
    policy: policy ? deepFreeze({ ...FROZEN_POLICY, ...policy }) : FROZEN_POLICY,
    ...rest,
  });
}

// The local-first route/eligibility computed before cloud is ever considered.
// The gate must return these byte-for-byte when it blocks — cloud adds no hop.
function localFirstBaseline() {
  return deepFreeze({
    route: [
      { engine: 'core-http', decision: 'attempted', cost: 'local-zero' },
      { engine: 'rendered-fallback', decision: 'not-needed', cost: 'local-zero' },
    ],
    eligibility: {
      'core-http': 'ready',
      'rendered-fallback': 'ready',
      'fixture-cloud': 'ineligible_cloud_disabled',
    },
  });
}

// A cloud provider fixture with present credentials/binary and call counters.
// Defaults are maximally UNPROVEN (unknown price, unknown/stale balance, no
// hard ceiling, zero free credits) so the base fixture is fail-closed. Its
// preflight() CAN charge and execute() is billable — both must stay uncalled.
function cloudProvider(overrides = {}) {
  const counters = { preflight: 0, billable: 0, sampled: 0 };
  return Object.assign({
    id: 'fixture-cloud',
    version: '1',
    cost: 'cloud-free-credits',
    price: 'unknown',
    balance: 'unknown',
    balanceObservedAt: null,
    hardCeiling: null,
    freeCredits: 0,
    worstCaseCredits: 5,
    preflightMayCharge: true,
    credentials: 'present',
    binary: '/opt/lynceuz/cloud-scraper',
    networkModel: 'provider-managed',
    counters,
    preflight: async () => { counters.preflight += 1; return { charge: 1 }; },
    execute: async () => {
      counters.billable += 1;
      return { body: 'PROVIDER PAID BODY', hash: `sha256:${'b'.repeat(64)}`, charged: 1 };
    },
    sampleEvidence: async () => {
      counters.sampled += 1;
      return { body: 'PROVIDER SAMPLE', hash: `sha256:${'c'.repeat(64)}` };
    },
  }, overrides);
}

// A cloud provider whose cost is fully proven safe on every axis. The base for
// COST-02/COST-03 flip tests: toggling ONE risk field must re-block it.
function provableCloud(overrides = {}) {
  return cloudProvider({
    price: 0,
    balance: 100,
    balanceObservedAt: NOW,
    hardCeiling: 10,
    freeCredits: 100,
    worstCaseCredits: 5,
    preflightMayCharge: false,
    ...overrides,
  });
}

function creditLedger(overrides = {}) {
  return {
    balance: 'unknown',
    observedAt: null,
    hardCeiling: null,
    committed: 0,
    reservations: [],
    ...overrides,
  };
}

function provableLedger(overrides = {}) {
  return creditLedger({ balance: 100, observedAt: NOW, hardCeiling: 10, ...overrides });
}

// --- COST-02: fail-closed cloud opt-in gate ---

test('COST-02 cloud gate leaves route and eligibility untouched and calls nothing when free cloud is off despite a present API key and binary', async () => {
  const { evaluateCloudGate } = await import(CLOUD_MODEL);
  const provider = cloudProvider({ credentials: 'present', binary: '/opt/lynceuz/cloud-scraper' });
  const baseline = localFirstBaseline();

  const decision = await evaluateCloudGate(frozenJob({ policy: { allowFreeCloud: false } }), {
    provider,
    ledger: creditLedger(),
    baseline,
    clock: () => new Date(NOW),
  });

  assert.equal(decision.outcome, 'unknown_and_blocked');
  assert.equal(decision.executed, false);
  // Route and eligibility are returned unchanged — cloud adds no hop when off.
  assert.deepEqual(decision.route, baseline.route);
  assert.deepEqual(decision.eligibility, baseline.eligibility);
  // No billable run and no preflight, even though the credential and binary exist.
  assert.equal(provider.counters.billable, 0);
  assert.equal(provider.counters.preflight, 0);
  assert.equal(decision.cost_money, 0);
  assert.equal(typeof decision.cost_money, 'number');
  assert.equal(decision.local_public_only_equivalent, false);
});

test('COST-02 cloud gate returns unknown_and_blocked before provider execution for every unproven-cost condition', async () => {
  const { evaluateCloudGate } = await import(CLOUD_MODEL);
  // The opt-in flag is ON — the block must come from unproven cost, not the flag.
  const optIn = { allowFreeCloud: true };
  const conditions = [
    { label: 'unknown or stale balance', provider: { balance: 'unknown', balanceObservedAt: null }, ledger: { balance: 'unknown', observedAt: null } },
    { label: 'unknown price', provider: { price: 'unknown' } },
    { label: 'absent hard ceiling', provider: { hardCeiling: null }, ledger: { hardCeiling: null } },
    { label: 'insufficient free credits', provider: { freeCredits: 1, worstCaseCredits: 5 } },
    { label: 'preflight able to charge', provider: { preflightMayCharge: true } },
  ];

  for (const { label, provider: p, ledger: l } of conditions) {
    const provider = provableCloud(p);
    const decision = await evaluateCloudGate(frozenJob({ policy: optIn }), {
      provider,
      ledger: provableLedger(l),
      baseline: localFirstBaseline(),
      clock: () => new Date(NOW),
    });
    assert.equal(decision.outcome, 'unknown_and_blocked', label);
    assert.equal(decision.executed, false, label);
    assert.equal(provider.counters.billable, 0, label);
    assert.equal(provider.counters.preflight, 0, label);
    assert.equal(decision.cost_money, 0, label);
  }
});

// --- COST-03: worst-case reservation ledger ---

test('COST-03 credit ledger refuses two worst-case reservations without over-debiting the shared ledger', async () => {
  const { reserveWorstCase } = await import(CLOUD_MODEL);
  // Balance leaves room for at most one 5-credit worst case; two must not both pass.
  const ledger = provableLedger({ balance: 8 });
  const a = provableCloud({ id: 'cloud-a', worstCaseCredits: 5 });
  const b = provableCloud({ id: 'cloud-b', worstCaseCredits: 5 });
  const job = frozenJob({ policy: { allowFreeCloud: true } });

  const first = reserveWorstCase(ledger, { job, provider: a, clock: () => new Date(NOW) });
  const second = reserveWorstCase(ledger, { job, provider: b, clock: () => new Date(NOW) });

  // v1 fail-closed: neither reservation commits, the shared ledger is never debited.
  assert.equal(ledger.committed, 0);
  assert.deepEqual(ledger.reservations, []);
  for (const reservation of [first, second]) {
    assert.equal(reservation.outcome, 'unknown_and_blocked');
    assert.equal(reservation.committed, false);
    assert.equal(reservation.cost_money, 0);
    assert.equal(reservation.credits_used, 'unknown_and_blocked');
  }
  assert.equal(a.counters.billable, 0);
  assert.equal(b.counters.billable, 0);
});

test('COST-03 credit ledger treats an impossible, negative, or over-reserve report as a broken provider contract not a free success', async () => {
  const { reserveWorstCase } = await import(CLOUD_MODEL);
  const brokenReports = [
    { label: 'negative worst case', provider: { worstCaseCredits: -5 } },
    { label: 'NaN worst case', provider: { worstCaseCredits: Number.NaN } },
    { label: 'non-finite worst case', provider: { worstCaseCredits: Number.POSITIVE_INFINITY } },
    { label: 'over-reserve above hard ceiling', provider: { worstCaseCredits: 999, hardCeiling: 10 } },
    { label: 'over-reserve above balance', provider: { worstCaseCredits: 999, balance: 100 } },
  ];

  for (const { label, provider: p } of brokenReports) {
    const provider = provableCloud(p);
    const ledger = provableLedger({ balance: 100 });
    const reservation = reserveWorstCase(ledger, {
      job: frozenJob({ policy: { allowFreeCloud: true } }),
      provider,
      clock: () => new Date(NOW),
    });
    // A negative/impossible charge is a broken contract, never "cost went down → free success".
    assert.equal(reservation.broken, true, label);
    assert.equal(reservation.outcome, 'unknown_and_blocked', label);
    assert.notEqual(reservation.outcome, 'reserved', label);
    assert.equal(reservation.committed, false, label);
    assert.equal(ledger.committed, 0, label);
    assert.equal(provider.counters.billable, 0, label);
  }
});

test('COST-03 credit ledger stamps every attempt and manifest with numeric zero cost, provider-managed boundary and non-local evidence', async () => {
  const { runCloudAttempt } = await import(CLOUD_MODEL);
  const provider = cloudProvider();
  const { attempt, manifest } = await runCloudAttempt(frozenJob({ policy: { allowFreeCloud: true } }), {
    provider,
    ledger: creditLedger(),
    clock: () => new Date(NOW),
  });

  for (const record of [attempt, manifest]) {
    assert.equal(record.cost_money, 0);
    assert.equal(typeof record.cost_money, 'number');
    assert.equal(record.credits_used, 'unknown_and_blocked');
    assert.equal(record.trust_boundary.kind, 'provider-managed');
    assert.equal(record.local_public_only_equivalent, false);
  }
  assert.equal(provider.counters.billable, 0);
  assert.equal(provider.counters.preflight, 0);
});

test('COST-03 credit ledger never accepts a provider-supplied body or hash as local public-only evidence', async () => {
  const { runCloudAttempt } = await import(CLOUD_MODEL);
  const providerHash = `sha256:${'c'.repeat(64)}`;
  const provider = cloudProvider({
    sampleEvidence: async () => ({ body: 'PROVIDER SUPPLIED BODY', hash: providerHash }),
  });

  const { attempt, manifest } = await runCloudAttempt(frozenJob({ policy: { allowFreeCloud: true } }), {
    provider,
    ledger: creditLedger(),
    clock: () => new Date(NOW),
  });

  // Provider content stays quarantined behind the provider-managed boundary,
  // never promoted to local public-only evidence, never a top-level source hash.
  assert.equal(attempt.local_public_only_equivalent, false);
  assert.equal(manifest.local_public_only_equivalent, false);
  assert.equal(manifest.trust_boundary.kind, 'provider-managed');
  assert.equal(manifest.trust_boundary.evidence_is_local_public_only, false);
  assert.equal(manifest.source_hash, undefined);
  assert.notEqual(manifest.source_hash, providerHash);
  assert.equal(provider.counters.billable, 0);
});
