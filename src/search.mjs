// Bounded free-search model (CAP-05/06, DATA-05).
//
// A search run is discovery-then-scrape: one free provider returns candidate
// links, we normalize them through the same public-only policy every URL job
// obeys, then hand the first N permitted unique candidates to the shared URL
// runner. The provider's snippet is discovery metadata only — it never becomes
// captured evidence, and its body is never a top-level source hash. Everything
// fails closed: an empty registry, an ineligible/paid provider, or an
// out-of-bounds provider response all stop before any child or manifest.

import { RUN_STATUS, deepFreeze } from './contracts.mjs';
import { authorizeCost, parsePublicUrl } from './policy.mjs';

const MAX_RESULTS = 100;
const MAX_TEXT = 100_000;

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// A search provider may be auto-selected only when it is ready, free, and proven
// zero-cost. Credentials or a binary never grant authority — a paid or disabled
// provider is filtered out even if present.
function isEligibleSearchProvider(provider) {
  return isObject(provider)
    && provider.state === 'ready'
    && provider.automatic === true
    && Array.isArray(provider.commands)
    && provider.commands.includes('search')
    && typeof provider.search === 'function'
    && authorizeCost(provider).allowed;
}

export function createSearchRegistry(providers) {
  const eligible = Array.isArray(providers) ? providers.filter(isEligibleSearchProvider) : [];
  const frozen = Object.freeze([...eligible]);
  return Object.freeze({
    providers: frozen,
    select() {
      return frozen[0] ?? null;
    },
  });
}

class AdapterProtocolError extends Error {}

// The provider response is a trust boundary: exactly the four expected fields,
// each result exactly {url,title,snippet}, at least one and at most 100 results,
// no unbounded text. Any deviation is a broken adapter contract, not data.
function validateProviderResponse(raw) {
  if (!isObject(raw) || Object.keys(raw).length !== 4) throw new AdapterProtocolError();
  for (const key of ['requestUrl', 'evidenceUrl', 'accessedAt']) {
    const value = raw[key];
    if (typeof value !== 'string' || value.length === 0 || value.length > MAX_TEXT) {
      throw new AdapterProtocolError();
    }
  }
  const { results } = raw;
  if (!Array.isArray(results) || results.length === 0 || results.length > MAX_RESULTS) {
    throw new AdapterProtocolError();
  }
  for (const result of results) {
    if (!isObject(result) || Object.keys(result).length !== 3) throw new AdapterProtocolError();
    if (typeof result.url !== 'string' || result.url.length === 0 || result.url.length > MAX_TEXT) {
      throw new AdapterProtocolError();
    }
    for (const key of ['title', 'snippet']) {
      if (typeof result[key] !== 'string' || result[key].length > MAX_TEXT) {
        throw new AdapterProtocolError();
      }
    }
  }
  return results;
}

// Drop private/invalid candidates, dedup by canonical URL (fragment already
// stripped by parsePublicUrl), and count each rejection reason for the warnings.
function normalizeCandidates(results) {
  const seen = new Set();
  const allowed = [];
  let invalid = 0;
  let duplicate = 0;
  for (const result of results) {
    let parsed;
    try {
      parsed = parsePublicUrl(result.url);
    } catch {
      invalid += 1;
      continue;
    }
    if (seen.has(parsed.canonicalUrl)) {
      duplicate += 1;
      continue;
    }
    seen.add(parsed.canonicalUrl);
    allowed.push({ url: parsed.canonicalUrl, title: result.title, snippet: result.snippet });
  }
  const warnings = [];
  if (invalid > 0) warnings.push(`search_candidate_private_or_invalid:${invalid}`);
  if (duplicate > 0) warnings.push(`search_candidate_duplicate:${duplicate}`);
  return { allowed, warnings };
}

// Each scraped candidate is its own URL JobSpec: same shared run id, but its own
// per-attempt limits object so a child never mutates the search-level limits.
function childScrapeJob(job, run, canonicalUrl) {
  return deepFreeze({
    schemaVersion: 1,
    kind: 'url',
    target: { url: canonicalUrl },
    goal: 'markdown',
    limits: { ...job.limits },
    policy: job.policy,
    output: {
      json: Boolean(job.output?.json),
      format: 'markdown',
      path: null,
      dataRoot: job.output?.dataRoot ?? null,
    },
    routing: { explain: false, forcedEngine: null },
    scope: { include: ['/**'], exclude: [] },
    discovery: { sources: [], preferDiscoveredSource: false },
    cache: { mode: 'use', ttlMs: 3_600_000 },
    runId: run.id,
  });
}

function modelResult(fields) {
  return Object.freeze({ warnings: Object.freeze([]), ...fields });
}

export async function runSearchJob(job, {
  registry,
  storage,
  clock = () => new Date(),
  runUrlJob,
  sharedRunContext,
} = {}) {
  const selected = registry?.select?.() ?? registry?.providers?.[0] ?? null;
  if (!selected) {
    return modelResult({
      status: RUN_STATUS.EXHAUSTED,
      code: 'unavailable_no_free_search_provider',
      message: 'no free search provider is configured',
    });
  }

  const signal = sharedRunContext?.signal;
  const budget = sharedRunContext?.budget;
  if (signal?.aborted) {
    return modelResult({
      status: RUN_STATUS.INTERRUPTED,
      code: 'interrupted',
      message: 'search aborted before the provider was queried',
    });
  }

  let results;
  let providerEvidence;
  try {
    providerEvidence = await selected.search(job, { signal });
    results = validateProviderResponse(providerEvidence);
  } catch (error) {
    return modelResult({
      status: RUN_STATUS.INTERNAL_ERROR,
      code: error instanceof AdapterProtocolError ? 'adapter_protocol_error' : 'adapter_crash',
      message: 'search provider returned an out-of-contract response',
    });
  }

  const { allowed, warnings } = normalizeCandidates(results);
  const scrapePlan = allowed.slice(0, job.search.scrapeResults);

  const run = await storage.beginRun(job);
  const runContext = { ...sharedRunContext, run, runId: run.id };

  const scraped = [];
  const evidence = [];
  for (const candidate of scrapePlan) {
    if (signal?.aborted) break;
    if (Number.isFinite(budget?.deadline) && clock().getTime() >= budget.deadline) break;
    const childResult = await runUrlJob(childScrapeJob(job, run, candidate.url), runContext);
    scraped.push({ url: candidate.url, status: childResult.status });
    if (childResult.status === RUN_STATUS.OK && typeof childResult.source_hash === 'string') {
      evidence.push({
        url: candidate.url,
        status: 'destination_source_captured',
        source_hash: childResult.source_hash,
      });
    }
  }

  const commit = await storage.commitManifest(run, {
    schema_version: 1,
    run_id: run.id,
    status: 'partial',
    artifacts: [],
    provider: {
      id: selected.id,
      version: selected.version,
      request_url: providerEvidence.requestUrl,
      evidence_url: providerEvidence.evidenceUrl,
      accessed_at: providerEvidence.accessedAt,
    },
    cost_money: 0,
    search: {
      results: scrapePlan.map((candidate, index) => ({
        rank: index + 1,
        url: candidate.url,
        title: candidate.title,
        snippet: candidate.snippet,
        snippet_kind: 'discovery_metadata',
      })),
      scraped,
    },
    evidence,
  });

  return modelResult({
    status: RUN_STATUS.PARTIAL,
    code: 'partial',
    message: `discovered ${allowed.length} candidate(s), scraped ${scraped.length}`,
    warnings: Object.freeze(warnings),
    manifest_path: commit.path,
    search_limits: job.limits,
  });
}
