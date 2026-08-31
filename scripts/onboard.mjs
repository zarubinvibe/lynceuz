#!/usr/bin/env node
// Lynceuz onboarding probe — stdlib only, zero dependencies.
//
// Prints a verifiable readiness snapshot and exits non-zero when a mandatory
// check is red. Modes:
//   (no flag)     human-readable report
//   --json        machine snapshot, kind: "lynceuz_onboarding"
//   --selftest    run this script's own assertions, exit 0 when sound
//
// Every path is resolved from this file, so a fresh clone works in any directory.

import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = dirname(SCRIPT_DIR);
const MIN_NODE_MAJOR = 20;

function majorOf(version) {
  const match = /^v?(\d+)\./.exec(String(version));
  return match ? Number(match[1]) : NaN;
}

function countRuntimeDependencies(pkg) {
  return Object.keys(pkg?.dependencies ?? {}).length;
}

function listSourceModules() {
  return readdirSync(join(REPO_ROOT, 'src'))
    .filter((name) => name.endsWith('.mjs'))
    .sort();
}

// node --check every source module. A parse failure means a broken or
// incompatible clone, which is a mandatory red.
function checkSources(files) {
  return files.map((file) => {
    const run = spawnSync(process.execPath, ['--check', join(REPO_ROOT, 'src', file)], {
      encoding: 'utf8',
      timeout: 20_000,
    });
    if (run.status === 0) return { file, ok: true };
    const firstLine = (run.stderr || '').split('\n').find((line) => line.trim() !== '');
    return { file, ok: false, error: firstLine ?? 'node --check failed' };
  });
}

async function capabilitySnapshot() {
  const routerUrl = pathToFileURL(join(REPO_ROOT, 'src', 'router.mjs')).href;
  const { createDefaultRegistry } = await import(routerUrl);
  return createDefaultRegistry(process.version).map((cap) => {
    // Mirror src/lynceuz.mjs: the shipped CLI promotes native to a ready HTTP path.
    const native = cap.id === 'native';
    return {
      id: cap.id,
      state: native ? 'ready' : cap.state,
      reason: native ? 'native_http_ready' : cap.reason,
      automatic: cap.automatic,
      commands: cap.commands ?? [],
    };
  });
}

function browserPathRequirements(platform) {
  const supported = platform === 'darwin';
  return {
    supported_platform: supported,
    gated_engines: ['playwright', 'crawl4ai'],
    requirements: [
      'macOS host — containment is only built for darwin',
      'owner runs ops/macos/install-containment.sh --apply from a root shell',
      'system PF anchor, launchd job and sudoers drop-in installed by that script',
      'hostile egress proof stays green: evals/browser-hostile.test.mjs',
    ],
    note: supported
      ? 'Browser path is closed until the owner installs containment and the hostile proof passes.'
      : 'No supported browser containment on this platform. Use the native HTTP path instead.',
  };
}

// The three checks that decide readiness. Pure, so --selftest can exercise it.
function mandatoryChecks({ nodeMajor, runtimeDeps, sourcesParse }) {
  return {
    node_supported: Number.isFinite(nodeMajor) && nodeMajor >= MIN_NODE_MAJOR,
    zero_runtime_dependencies: runtimeDeps === 0,
    sources_parse: sourcesParse,
  };
}

function isReady(checks) {
  return Object.values(checks).every(Boolean);
}

async function buildReport() {
  const pkg = JSON.parse(readFileSync(join(REPO_ROOT, 'package.json'), 'utf8'));
  const sources = checkSources(listSourceModules());
  const runtimeDeps = countRuntimeDependencies(pkg);
  const nodeMajor = majorOf(process.version);
  const sourcesParse = sources.every((entry) => entry.ok);
  const checks = mandatoryChecks({ nodeMajor, runtimeDeps, sourcesParse });
  return {
    kind: 'lynceuz_onboarding',
    ready: isReady(checks),
    node_version: process.version,
    node_required: `>=${MIN_NODE_MAJOR}`,
    platform: `${process.platform}/${process.arch}`,
    runtime_dependencies: runtimeDeps,
    source_check: {
      command: 'node --check src/*.mjs',
      total: sources.length,
      failed: sources.filter((entry) => !entry.ok),
    },
    capabilities: await capabilitySnapshot(),
    browser_path: browserPathRequirements(process.platform),
    mandatory_checks: checks,
  };
}

function renderHuman(report) {
  const mark = (ok) => (ok ? 'ok' : 'RED');
  const lines = [
    'Lynceuz onboarding snapshot',
    '',
    `  node        ${report.node_version} (need ${report.node_required}) — ${mark(report.mandatory_checks.node_supported)}`,
    `  platform    ${report.platform}`,
    `  deps        ${report.runtime_dependencies} runtime dependencies — ${mark(report.mandatory_checks.zero_runtime_dependencies)}`,
    `  sources     ${report.source_check.total} modules parsed — ${mark(report.mandatory_checks.sources_parse)}`,
    '',
    '  capabilities:',
    ...report.capabilities.map((cap) => `    ${cap.id.padEnd(14)}${cap.state}\t${cap.reason}`),
    '',
    `  browser path: ${report.browser_path.note}`,
    ...report.browser_path.requirements.map((line) => `    - ${line}`),
  ];
  if (report.source_check.failed.length) {
    lines.push('', '  source failures:');
    for (const entry of report.source_check.failed) lines.push(`    ${entry.file}: ${entry.error}`);
  }
  lines.push('', report.ready ? 'Ready: mandatory checks are green.' : 'Not ready: a mandatory check is red (see above).');
  return lines.join('\n');
}

function selftest() {
  const failures = [];
  const assert = (cond, label) => { if (!cond) failures.push(label); };

  assert(majorOf('v20.11.1') === 20, 'majorOf parses v20');
  assert(majorOf('v18.9.0') === 18, 'majorOf parses v18');
  assert(Number.isNaN(majorOf('nonsense')), 'majorOf rejects garbage');

  assert(countRuntimeDependencies({ dependencies: { a: '1', b: '2' } }) === 2, 'counts two deps');
  assert(countRuntimeDependencies({ dependencies: {} }) === 0, 'empty dependency map is zero');
  assert(countRuntimeDependencies({}) === 0, 'missing dependency map is zero');

  const darwin = browserPathRequirements('darwin');
  assert(darwin.supported_platform === true, 'darwin browser path supported');
  assert(browserPathRequirements('linux').supported_platform === false, 'linux browser path unsupported');
  assert(darwin.requirements.length >= 3, 'browser requirements are listed');

  assert(isReady(mandatoryChecks({ nodeMajor: 20, runtimeDeps: 0, sourcesParse: true })) === true, 'green when all pass');
  assert(isReady(mandatoryChecks({ nodeMajor: 20, runtimeDeps: 1, sourcesParse: true })) === false, 'red when a dependency appears');
  assert(isReady(mandatoryChecks({ nodeMajor: 18, runtimeDeps: 0, sourcesParse: true })) === false, 'red on old node');
  assert(isReady(mandatoryChecks({ nodeMajor: 20, runtimeDeps: 0, sourcesParse: false })) === false, 'red on a syntax failure');

  return failures;
}

const mode = process.argv[2] ?? '--human';
if (process.argv.length > 3 || !['--human', '--json', '--selftest', '-h', '--help'].includes(mode)) {
  process.stderr.write('usage: node scripts/onboard.mjs [--json|--selftest]\n');
  process.exit(2);
}

if (mode === '-h' || mode === '--help') {
  process.stdout.write('usage: node scripts/onboard.mjs [--json|--selftest]\n');
} else if (mode === '--selftest') {
  const failures = selftest();
  if (failures.length) {
    process.stderr.write(`onboard selftest: FAILED\n${failures.map((f) => `  - ${f}`).join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write('onboard selftest: ok\n');
} else {
  const report = await buildReport();
  process.stdout.write(mode === '--json' ? `${JSON.stringify(report, null, 2)}\n` : `${renderHuman(report)}\n`);
  process.exitCode = report.ready ? 0 : 1;
}
