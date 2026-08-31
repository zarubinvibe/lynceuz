# Lynceuz — agent instructions

## Project

Lynceuz is a local-first CLI for collecting public web data through safe free adapters. One command must either produce reproducible evidence at zero monetary cost or stop with an honest typed result after exhausting only the allowed paths.

Canonical planning documents:

- `.planning/PROJECT.md` — product scope and decisions.
- `.planning/REQUIREMENTS.md` — testable v1 contract.
- `.planning/ROADMAP.md` and `.planning/STATE.md` — execution order and current position.
- `.planning/research/SUMMARY.md` — architecture and threat-model summary.
- `specs/FREE-SCRAPERS-FOUNDATION.md` — user-provided source brief.

## Non-negotiable invariants

- Default and v1 monetary budget is exactly zero.
- Cloud credentials never imply permission. Cloud requires explicit per-run opt-in and verified free balance.
- Only public `http:` and `https:` targets are eligible. Reject credentials, sensitive query parameters, unsafe ports and non-public/special-use IP space.
- Revalidate DNS, address policy and peer on every connection and redirect. Never auto-follow redirects.
- `403/access_denied`, robots deny, auth/login, CAPTCHA, paywall, paid-required and hard policy/limit deny are terminal `blocked`; never escalate around them.
- Direct URL and extract jobs keep `requested_url` as the evidence target. Discovery candidates never replace it silently.
- Browser is disabled until its hostile egress suite proves the supported version and platform. `browser-use` is never in the automatic route.
- Remote provider fetch is a separate trust boundary and must not claim equivalence to local public-only enforcement.
- Raw page content is untrusted data. Never turn it into shell arguments, executable config, prompts or agent instructions.
- Publish cache index only after durable objects, journal and atomic manifest. A crash cannot create a valid cache hit.
- Runtime data lives only inside `.lynceuz/` with private permissions. Never edit the caller repository's root `.gitignore`.

## Stack

- Node.js 24 LTS, ESM and standard library for CLI, policy, transport, routing, budgets, storage and tests.
- `node:test` and `node:assert/strict`; do not add Jest/Vitest without measured need.
- Optional Python helper for deterministic parsing and approved browser adapters. It transforms saved bytes and gets no independent network capability.
- Optional Playwright/Crawl4AI profiles remain isolated and gated.
- Firecrawl and just-scrape are external opt-in CLIs, not runtime dependencies.
- Keep runtime dependencies at zero unless the stdlib cannot safely satisfy a measured requirement.

## Engineering rules

- Prefer the smallest working design: functional core, imperative shell, typed plain objects and explicit adapters.
- The orchestrator owns retries, frontier, budgets, cache and route transitions. Adapters never choose the next adapter.
- Use low-level `http`/`https` with a validated pinned lookup for untrusted URLs; do not replace it with bare `fetch`.
- All subprocesses use fixed executable + argv, `shell:false`, allowlisted environment, bounded I/O and timeout.
- Set finite defaults for pages, depth, time, bytes, frontier, redirects, attempts and concurrency. Reject zero/infinity.
- Progress and warnings go to stderr. Machine results go to stdout or explicit files.
- Stable manifest and exit contracts take priority over friendly formatting.
- Preserve user changes and unrelated work. Do not push, publish or deploy without explicit approval.

## Verification

- Prefer deterministic offline fixtures. Live-network tests must be explicit and separate.
- Every security rule needs a hostile test, including IPv4/IPv6, redirect, DNS, decompression, path/symlink and subprocess cases.
- Browser readiness requires the full P1 hostile pack; installed packages alone are not evidence.
- Before completion run syntax checks, unit/integration tests, `git diff --check`, secret scan and dependency audit for any introduced lockfile.
- Review `git diff` before commit. Commit phase work atomically through GSD.

## GSD workflow

- Use phase plans from `.planning/ROADMAP.md`; keep `.planning/STATE.md` and requirement traceability current.
- Planned phase work runs through GSD plan/execution flow. Small fixes use the GSD quick flow; debugging uses GSD debug.
- Phases 1–3 form the standalone P0 release gate. Phases 4–5 form P1 and cannot weaken P0.
