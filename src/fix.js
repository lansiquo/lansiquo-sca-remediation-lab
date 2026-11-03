// Plan and apply the smallest safe upgrades, then prove the result: run the
// project's own tests, rescan, and write an evidence folder.

import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { compare } from './semver.js';
import { priorityRank, triage } from './triage.js';
import { formatMarkdown } from './report.js';

const NPM = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function run(cmd, args, cwd) {
  const res = spawnSync(cmd, args, {
    cwd,
    encoding: 'utf8',
    shell: process.platform === 'win32',
    env: { ...process.env, npm_config_fund: 'false', npm_config_audit: 'false', npm_config_update_notifier: 'false' },
  });
  return { code: res.status ?? 1, output: `${res.stdout || ''}${res.stderr || ''}` };
}

// Group findings into one action per package. Direct dependencies get a pinned
// upgrade; transitive ones get an npm "overrides" entry.
export function planFixes(result, { minPriority = 'P3' } = {}) {
  const threshold = priorityRank(minPriority);
  const byName = new Map();
  for (const f of result.findings) {
    if (priorityRank(f.priority) < threshold || !f.fix.target) continue;
    const cur = byName.get(f.package) || { package: f.package, target: f.fix.target, direct: false, dev: true, crossesMajor: false, from: [] };
    if (compare(f.fix.target, cur.target) > 0) cur.target = f.fix.target;
    cur.direct ||= f.direct;
    cur.dev &&= f.devOnly;
    cur.crossesMajor ||= f.fix.crossesMajor;
    cur.from.push(f.version);
    byName.set(f.package, cur);
  }
  const unfixable = result.findings.filter((f) => priorityRank(f.priority) >= threshold && !f.fix.target);
  return { actions: [...byName.values()], unfixable };
}

export async function applyFixes(projectDir, { minPriority = 'P3', evidenceDir, runTests = true, lookups } = {}) {
  const before = await triage(projectDir, lookups);
  const plan = planFixes(before, { minPriority });
  const changes = [];

  const pkgPath = join(projectDir, 'package.json');
  const lockPath = join(projectDir, 'package-lock.json');
  const lockBefore = readFileSync(lockPath, 'utf8');
  const scripts = JSON.parse(readFileSync(pkgPath, 'utf8')).scripts || {};
  const testsEnabled = runTests && Boolean(scripts.test);
  const runProjectTests = () => {
    const r = run(NPM, ['test'], projectDir);
    return { command: 'npm test', code: r.code, passed: r.code === 0, output: r.output };
  };

  // 0) Baseline test run, so the evidence shows what changed.
  const testsBefore = testsEnabled ? runProjectTests() : null;

  // 1) Direct dependencies: pin the safe version.
  for (const a of plan.actions.filter((x) => x.direct)) {
    const args = ['install', `${a.package}@${a.target}`, '--save-exact', '--ignore-scripts', a.dev ? '--save-dev' : '--save-prod'];
    const r = run(NPM, args, projectDir);
    if (r.code !== 0) throw new Error(`npm ${args.join(' ')} failed:\n${r.output}`);
    changes.push(`npm ${args.join(' ')}`);
  }

  // 2) Transitive dependencies: npm overrides, then one install to apply them.
  const transitive = plan.actions.filter((x) => !x.direct);
  if (transitive.length) {
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    pkg.overrides ||= {};
    for (const a of transitive) {
      pkg.overrides[a.package] = a.target;
      changes.push(`package.json overrides: "${a.package}": "${a.target}"`);
    }
    writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + '\n');
    const r = run(NPM, ['install', '--ignore-scripts'], projectDir);
    if (r.code !== 0) throw new Error(`npm install (overrides) failed:\n${r.output}`);
  }

  // 3) The project's own tests decide whether the upgrade is safe to keep.
  const tests = testsEnabled ? runProjectTests() : null;

  // 4) Rescan and write evidence.
  const after = await triage(projectDir, lookups);
  if (evidenceDir) {
    mkdirSync(evidenceDir, { recursive: true });
    writeFileSync(join(evidenceDir, 'before.json'), JSON.stringify(before, null, 2));
    writeFileSync(join(evidenceDir, 'after.json'), JSON.stringify(after, null, 2));
    writeFileSync(join(evidenceDir, 'package-lock.before.json'), lockBefore);
    writeFileSync(join(evidenceDir, 'package-lock.after.json'), readFileSync(lockPath, 'utf8'));
    if (testsBefore) writeFileSync(join(evidenceDir, 'tests.before.txt'), testsBefore.output);
    if (tests) writeFileSync(join(evidenceDir, 'tests.after.txt'), tests.output);
    const sbom = run(NPM, ['sbom', '--sbom-format', 'cyclonedx'], projectDir);
    if (sbom.code === 0) writeFileSync(join(evidenceDir, 'sbom.cdx.json'), sbom.output);
    writeFileSync(join(evidenceDir, 'REPORT.md'), formatMarkdown(before, after, { changes, tests, testsBefore }));
  }

  return { before, after, plan, changes, tests, testsBefore, evidenceWritten: Boolean(evidenceDir && existsSync(evidenceDir)) };
}
