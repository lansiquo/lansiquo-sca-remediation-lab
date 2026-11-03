# Security

## Intentionally vulnerable code

`lab/vulnerable-app` is **intentionally vulnerable**. It pins known-vulnerable dependency
versions so `sca-triage` can demonstrate detection, prioritization and remediation. Dependabot
and code-scanning alerts about that folder are expected and won't be fixed in place, because
they're the point of the lab. Use it locally only.

## Reporting a vulnerability in sca-triage

If you find a security issue in the tool itself (`bin/`, `src/` or `action.yml`), please report
it privately through GitHub (**Security** tab → **Report a vulnerability**) rather than opening a
public issue.
