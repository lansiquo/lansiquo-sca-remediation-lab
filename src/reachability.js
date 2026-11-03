// Import-level reachability: which packages does the project's own code actually load?
// This is deliberately simple and honest about it. It finds require(), import and
// dynamic import() of package names in the project's source files. It does not build
// a call graph, so "imported" means "the code loads it", not "the vulnerable
// function is proven to run".

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const SOURCE_EXT = /\.(c|m)?(j|t)sx?$/;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage', 'evidence', '.next']);
const TEST_PATH = /(^|[\\/])(test|tests|__tests__|spec)([\\/]|$)|\.(test|spec)\.(c|m)?(j|t)sx?$/;

const PATTERNS = [
  /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // require('x')
  /\bimport\s+(?:[^'"]*?\sfrom\s+)?['"]([^'"]+)['"]/g, // import x from 'x' / import 'x'
  /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g, // import('x')
  /\bexport\s+[^'"]*?\sfrom\s+['"]([^'"]+)['"]/g, // export { x } from 'x'
];

// 'lodash/merge' -> 'lodash', '@scope/pkg/sub' -> '@scope/pkg', './local' -> null
export function packageNameFromSpecifier(spec) {
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) return null;
  const parts = spec.split('/');
  return spec.startsWith('@') ? parts.slice(0, 2).join('/') : parts[0];
}

function walk(dir, root, out) {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    const st = statSync(full);
    if (st.isDirectory()) walk(full, root, out);
    else if (SOURCE_EXT.test(entry) && st.size < 2_000_000) out.push(full);
  }
  return out;
}

// Returns Map(packageName -> { runtime: [file:line], test: [file:line] })
export function findImports(projectDir) {
  const found = new Map();
  for (const file of walk(projectDir, projectDir, [])) {
    const rel = relative(projectDir, file).split(sep).join('/');
    const kind = TEST_PATH.test(rel) ? 'test' : 'runtime';
    const text = readFileSync(file, 'utf8');
    for (const re of PATTERNS) {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text))) {
        const name = packageNameFromSpecifier(m[1]);
        if (!name) continue;
        const line = text.slice(0, m.index).split('\n').length;
        if (!found.has(name)) found.set(name, { runtime: [], test: [] });
        const where = found.get(name)[kind];
        const loc = `${rel}:${line}`;
        if (!where.includes(loc)) where.push(loc);
      }
    }
  }
  return found;
}

// Classify one installed package.
//   imported            - the project's runtime code loads it directly
//   via-imported        - a dependency the runtime code loads pulls it in
//   test-only           - only test code loads it (directly or through a dependency)
//   not-imported        - installed, but nothing in the project loads it or its parents
export function classify(install, imports) {
  // Only the top-level copy is what `require(name)` from project code resolves to.
  const topLevel = install.path === `node_modules/${install.name}`;
  const hit = topLevel ? imports.get(install.name) : undefined;
  if (hit?.runtime.length) {
    return { level: 'imported', evidence: hit.runtime };
  }
  // Direct dependencies that lead here, other than this package itself.
  const parents = install.via.filter((d) => d !== install.name);
  const runtimeParents = parents.filter((d) => imports.get(d)?.runtime.length);
  if (runtimeParents.length) {
    return { level: 'via-imported', evidence: runtimeParents.map((d) => `via ${d} (${imports.get(d).runtime[0]})`) };
  }
  if (hit?.test.length) {
    return { level: 'test-only', evidence: hit.test };
  }
  const testParents = parents.filter((d) => imports.get(d)?.test.length);
  if (testParents.length) {
    return { level: 'test-only', evidence: testParents.map((d) => `via ${d} (${imports.get(d).test[0]})`) };
  }
  return { level: 'not-imported', evidence: [] };
}

export const REACHABILITY_RANK = { 'not-imported': 0, 'test-only': 1, 'via-imported': 2, imported: 3 };
