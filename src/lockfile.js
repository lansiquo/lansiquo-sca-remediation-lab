// Read an npm project's package.json + package-lock.json (lockfile v2/v3) into a
// dependency inventory with the dependency graph, so findings can be traced back
// to the direct dependency that pulls them in.

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

// "node_modules/a/node_modules/b" -> "b"; "node_modules/@scope/x" -> "@scope/x"
function nameFromPath(path) {
  const i = path.lastIndexOf('node_modules/');
  return path.slice(i + 'node_modules/'.length);
}

export function loadProject(dir) {
  const pkgPath = join(dir, 'package.json');
  const lockPath = join(dir, 'package-lock.json');
  if (!existsSync(pkgPath)) throw new Error(`no package.json in ${dir}`);
  if (!existsSync(lockPath)) {
    throw new Error(`no package-lock.json in ${dir} (run "npm install --package-lock-only" first)`);
  }
  const pkg = readJson(pkgPath);
  const lock = readJson(lockPath);
  if (!lock.packages) {
    throw new Error('package-lock.json v1 is not supported; regenerate it with npm 7 or newer');
  }

  const direct = new Map(); // name -> "prod" | "dev" | "optional"
  for (const [name] of Object.entries(pkg.dependencies || {})) direct.set(name, 'prod');
  for (const [name] of Object.entries(pkg.optionalDependencies || {})) direct.set(name, 'optional');
  for (const [name] of Object.entries(pkg.devDependencies || {})) if (!direct.has(name)) direct.set(name, 'dev');

  // Every installed copy of every package. The same name can appear at several versions.
  const installs = [];
  const byPath = new Map();
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path || !path.includes('node_modules/') || entry.link) continue;
    const item = {
      name: entry.name || nameFromPath(path),
      version: entry.version,
      path,
      dev: Boolean(entry.dev),
      optional: Boolean(entry.optional),
      dependsOn: Object.keys({ ...(entry.dependencies || {}), ...(entry.optionalDependencies || {}) }),
    };
    if (!item.version) continue;
    installs.push(item);
    byPath.set(path, item);
  }

  // npm resolves a dependency by walking up node_modules folders from the requiring package.
  function resolve(fromPath, depName) {
    let base = fromPath;
    for (;;) {
      const candidate = `${base ? base + '/' : ''}node_modules/${depName}`;
      if (byPath.has(candidate)) return byPath.get(candidate);
      if (!base) return null;
      const i = base.lastIndexOf('/node_modules/');
      base = i === -1 ? '' : base.slice(0, i);
    }
  }

  // For each install, which direct dependencies lead to it (the "via" chains).
  const roots = [...direct.keys()].map((n) => byPath.get(`node_modules/${n}`)).filter(Boolean);
  const reachedBy = new Map(); // path -> Set(direct dependency names)
  for (const root of roots) {
    const stack = [root];
    const seen = new Set();
    while (stack.length) {
      const cur = stack.pop();
      if (seen.has(cur.path)) continue;
      seen.add(cur.path);
      if (!reachedBy.has(cur.path)) reachedBy.set(cur.path, new Set());
      reachedBy.get(cur.path).add(root.name);
      for (const d of cur.dependsOn) {
        const next = resolve(cur.path, d);
        if (next) stack.push(next);
      }
    }
  }

  for (const item of installs) {
    item.direct = byPath.get(`node_modules/${item.name}`) === item && direct.has(item.name);
    item.via = [...(reachedBy.get(item.path) || [])].sort();
  }

  return { dir, name: pkg.name || '(unnamed)', pkg, direct, installs };
}
