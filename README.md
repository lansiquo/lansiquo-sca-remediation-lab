# SCA Remediation Lab · `sca-triage`

**Status: functional end-to-end local tool and lab.**

The implemented workflow scans npm dependencies, prioritizes findings using import evidence,
applies proposed upgrades, runs the project’s tests, rescans and saves remediation evidence.
The [CI lab gate](.github/workflows/ci.yml) exercises the vulnerable baseline and remediated copy.
Functional describes this local/CI workflow; the [scope and limits](#limits) still apply.
The [portfolio browser demo](https://dotrobin.dev/demos/sca.html) is a recorded replay, separate
from the working CLI and GitHub Action.

> [!WARNING]
> **This repository contains an intentionally vulnerable application.**
> [`lab/vulnerable-app`](lab/vulnerable-app) pins known-vulnerable versions of `minimist`,
> `axios`, `semver` and `tar` on purpose, so the tool has something real to find and fix.
> Use it locally for learning only. Don't deploy it, don't expose it to a network, and don't
> copy its dependency versions into real projects. Dependabot alerts on this repository are expected.
> The `sca-triage` tool itself (`bin/` and `src/`) has no dependencies and is safe to use.

`sca-triage` is a dependency-free command-line tool and GitHub Action for npm projects. It finds
known vulnerabilities in your installed dependency tree, **ranks them by whether your code
actually loads the vulnerable package**, applies the smallest safe upgrade, and proves the result
with your own tests, with an evidence folder you can hand to an auditor.

## Why

`npm audit` and Dependabot report every advisory with the same urgency, so teams drown in alerts
and start ignoring them. Most of the work in software composition analysis (SCA) is deciding
what matters. `sca-triage` automates that triage:

| | `npm audit` | `sca-triage` |
|---|---|---|
| Finds known vulnerabilities | ✅ | ✅ same GitHub Advisory Database data |
| Ranks by whether your code loads the package | ❌ | ✅ import-level reachability |
| Picks the smallest safe upgrade, flags major bumps | partly | ✅ |
| Verifies the upgrade with your tests | ❌ | ✅ before/after runs |
| Writes audit evidence (reports, SBOM, lockfiles) | ❌ | ✅ |
| CI gate that fails only on what matters | ❌ | ✅ `--fail-on P1` |

## Quick start

Requires Node.js 20 or newer and network access to `registry.npmjs.org`.

```bash
git clone https://github.com/lansiquo/lansiquo-sca-remediation-lab.git
cd lansiquo-sca-remediation-lab
npm run lab:install   # installs the INTENTIONALLY VULNERABLE lab app (no install scripts)
npm run lab:scan      # rank the lab app's vulnerabilities
npm run lab:plan      # show the smallest safe upgrades (dry run)
```

To apply the fixes, use a copy so the lab keeps its vulnerable starting point:

```bash
cp -r lab/vulnerable-app /tmp/lab-copy
node bin/sca-triage.js fix /tmp/lab-copy --apply --evidence /tmp/lab-evidence
```

On your own project:

```bash
node /path/to/lansiquo-sca-remediation-lab/bin/sca-triage.js scan .
```

## What it found in the lab (real output)

```text
intentionally-vulnerable-export-job: 33 packages scanned, 4 vulnerable (P1: 3, P2: 1, P3: 0)

[P1] minimist@1.2.5  CRITICAL, 1 advisory
     reachability: imported by your code (src/export-job.js:7)
     fix: 1.2.5 -> 1.2.6
[P1] axios@1.6.0  HIGH, 31 advisories
     reachability: imported by your code (src/notify.js:7)
     fix: 1.6.0 -> 1.20.0
[P1] semver@7.5.1  HIGH, 1 advisory
     reachability: imported by your code (src/export-job.js:8)
     fix: 7.5.1 -> 7.5.2
[P2] tar@6.1.0  CRITICAL, 18 advisories
     reachability: not imported
     fix: 6.1.0 -> 7.5.21 (major upgrade)

Gate (--fail-on P1): FAIL
```

`tar` has the most severe advisories but drops to P2, because nothing in the app loads it.
After `fix --apply`:

| | Before | After |
|---|---|---|
| Vulnerable packages | 4 (3 × P1, 1 × P2) | 0 |
| Functional tests | 5/5 pass | 5/5 pass |
| Security test (minimist prototype pollution) | **fails** | passes |
| CI gate | fails | passes |

The functional tests pass on both versions. That's the point of the lab: compatibility tests
alone don't catch the vulnerability, so the lab adds a security test for the one advisory it
demonstrates end to end (minimist, GHSA-xvch-5gv4-984h).

Exact counts and fix versions depend on the advisory database on the day you run it.

## Commands

```text
sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
sca-triage fix  [dir] [--apply] [--min-priority P1|P2|P3] [--evidence <dir>] [--no-tests]
```

- **`scan`** exits with code 1 when a finding meets `--fail-on` (default `P1`), so it works as a CI gate.
- **`fix`** is a dry run unless you pass `--apply`. With `--apply` it:
  1. runs `npm test` to record a baseline,
  2. pins direct dependencies to the safe version (`npm install pkg@x.y.z --save-exact --ignore-scripts`),
  3. adds npm `overrides` for vulnerable transitive dependencies,
  4. runs `npm test` again and rescans,
  5. writes `REPORT.md`, `before.json`, `after.json`, both lockfiles, both test logs and a CycloneDX SBOM to the evidence folder.

  It exits with code 1 if the tests fail after the upgrade, so you know not to merge it.

### Priorities

| | Meaning | What to do |
|---|---|---|
| **P1** | High or critical, and your code loads the package directly or through a dependency | Fix now |
| **P2** | High or critical but not loaded at runtime, or moderate and loaded | Schedule it |
| **P3** | Everything else | Batch with routine upgrades |

Reachability levels: `imported` (your runtime code requires or imports it), `via-imported`
(an imported dependency pulls it in), `test-only`, and `not-imported`.

## Use it in GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 22
- run: npm ci --ignore-scripts
- uses: lansiquo/lansiquo-sca-remediation-lab@main
  with:
    path: .
    fail-on: P1
```

The findings table is added to the job summary. This repository's own [CI](.github/workflows/ci.yml)
runs the tool against the lab app on every push: the gate must **fail** on the vulnerable
baseline and **pass** after remediation, and the evidence folder is uploaded as an artifact.

## Limits

- **Reachability is import-level.** "Imported" means your code loads the package, not that the
  vulnerable function is proven to run. It doesn't build a call graph, so treat P2/P3 as
  "lower priority", not "safe".
- **npm only,** using `package-lock.json` v2 or v3. Other ecosystems aren't supported yet.
- **Results reflect the advisory database at scan time.** Zero findings is not a security certification.
- **Major upgrades are applied when no same-major fix exists,** and flagged. Your tests are the
  safety net, so the tool's verdict is only as good as your test suite.

## Layout

```text
bin/sca-triage.js          command-line entry point
src/                       lockfile graph, advisories, reachability, triage, fixes, reports
test/                      unit tests (offline, run with npm test)
action.yml                 reusable GitHub Action
lab/vulnerable-app/        INTENTIONALLY VULNERABLE demo app
```

Write-up: [dotrobin.dev/sca-remediation](https://dotrobin.dev/sca-remediation.html)
