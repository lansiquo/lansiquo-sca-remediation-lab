// Look up known vulnerabilities for installed packages using the npm registry's
// bulk advisory API (the same GitHub Advisory Database data `npm audit` uses),
// and list published versions so we can pick the smallest safe upgrade.

const DEFAULT_REGISTRY = 'https://registry.npmjs.org';
const SEVERITY_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? 0;
}

function registryUrl() {
  return (process.env.SCA_TRIAGE_REGISTRY || DEFAULT_REGISTRY).replace(/\/+$/, '');
}

async function fetchJson(url, init) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`${init?.method || 'GET'} ${url} -> HTTP ${res.status}`);
  return res.json();
}

// installs: [{name, version}] -> { [name]: [{ghsa, title, severity, vulnerableVersions, url, cwe, cvss}] }
export async function fetchAdvisories(installs) {
  const query = {};
  for (const { name, version } of installs) {
    (query[name] ||= new Set()).add(version);
  }
  const body = Object.fromEntries(Object.entries(query).map(([n, v]) => [n, [...v]]));
  if (!Object.keys(body).length) return {};
  const raw = await fetchJson(`${registryUrl()}/-/npm/v1/security/advisories/bulk`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return normalizeAdvisories(raw);
}

export function normalizeAdvisories(raw) {
  const out = {};
  for (const [name, list] of Object.entries(raw || {})) {
    out[name] = list.map((a) => ({
      ghsa: String(a.url || '').split('/').pop() || String(a.id),
      title: a.title,
      severity: a.severity,
      vulnerableVersions: a.vulnerable_versions,
      url: a.url,
      cwe: a.cwe || [],
      cvss: a.cvss?.score ?? null,
    }));
  }
  return out;
}

// All published versions of a package (abbreviated metadata keeps this small).
export async function fetchVersions(name) {
  const encoded = name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  const doc = await fetchJson(`${registryUrl()}/${encoded}`, {
    headers: { accept: 'application/vnd.npm.install-v1+json' },
  });
  return Object.keys(doc.versions || {});
}
