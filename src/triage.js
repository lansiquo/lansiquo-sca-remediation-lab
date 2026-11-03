// Turn an inventory + advisories + import evidence into ranked findings, each with
// the smallest upgrade that clears every known advisory for that package.

import { loadProject } from './lockfile.js';
import { fetchAdvisories, fetchVersions, severityRank } from './advisories.js';
import { findImports, classify, REACHABILITY_RANK } from './reachability.js';
import { satisfies, compare, parse, isPrerelease, sortVersions } from './semver.js';

// P1: high/critical and the code loads it. Fix now.
// P2: high/critical but not loaded at runtime, or moderate and loaded. Schedule it.
// P3: everything else. Batch with routine upgrades.
export function priorityFor(severity, reachability) {
  const sev = severityRank(severity);
  const reach = REACHABILITY_RANK[reachability];
  const loaded = reach >= REACHABILITY_RANK['via-imported'];
  if (sev >= 3 && loaded) return 'P1';
  if (sev >= 3 || (sev === 2 && loaded)) return 'P2';
  return 'P3';
}

const PRIORITY_RANK = { P1: 3, P2: 2, P3: 1 };
export function priorityRank(p) {
  return PRIORITY_RANK[p] || 0;
}

// Smallest published, non-prerelease version above `current` that no advisory covers.
// Prefers staying on the same major version, since that is least likely to break callers.
export function pickSafeVersion(current, versions, advisories) {
  const cur = parse(current);
  const candidates = sortVersions(versions).filter(
    (v) => !isPrerelease(v) && compare(v, current) > 0 && !advisories.some((a) => satisfies(v, a.vulnerableVersions)),
  );
  if (!candidates.length) return { target: null, crossesMajor: false };
  const sameMajor = candidates.find((v) => parse(v).major === cur.major);
  const target = sameMajor || candidates[0];
  return { target, crossesMajor: parse(target).major !== cur.major };
}

export async function triage(projectDir, { advisoryLookup = fetchAdvisories, versionLookup = fetchVersions } = {}) {
  const project = loadProject(projectDir);
  const imports = findImports(projectDir);
  const advisoriesByName = await advisoryLookup(project.installs);

  const findings = [];
  const versionCache = new Map();
  for (const install of project.installs) {
    const all = advisoriesByName[install.name] || [];
    const affecting = all.filter((a) => satisfies(install.version, a.vulnerableVersions));
    if (!affecting.length) continue;

    const reach = classify(install, imports);
    const maxSeverity = affecting.reduce((s, a) => (severityRank(a.severity) > severityRank(s) ? a.severity : s), 'info');
    if (!versionCache.has(install.name)) versionCache.set(install.name, await versionLookup(install.name));
    const fix = pickSafeVersion(install.version, versionCache.get(install.name), all);

    findings.push({
      package: install.name,
      version: install.version,
      path: install.path,
      direct: install.direct,
      devOnly: install.dev,
      via: install.via,
      reachability: reach.level,
      evidence: reach.evidence,
      severity: maxSeverity,
      priority: priorityFor(maxSeverity, reach.level),
      advisories: affecting.sort((a, b) => severityRank(b.severity) - severityRank(a.severity)),
      fix,
    });
  }

  findings.sort(
    (a, b) =>
      priorityRank(b.priority) - priorityRank(a.priority) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      a.package.localeCompare(b.package),
  );

  return {
    project: project.name,
    scannedAt: new Date().toISOString(),
    packagesScanned: project.installs.length,
    summary: {
      P1: findings.filter((f) => f.priority === 'P1').length,
      P2: findings.filter((f) => f.priority === 'P2').length,
      P3: findings.filter((f) => f.priority === 'P3').length,
      advisories: findings.reduce((n, f) => n + f.advisories.length, 0),
    },
    findings,
  };
}

// Does this result fail the gate? failOn is "P1", "P2", "P3" or "none".
export function gateFails(result, failOn = 'P1') {
  if (failOn === 'none') return false;
  const threshold = priorityRank(failOn);
  return result.findings.some((f) => priorityRank(f.priority) >= threshold);
}
