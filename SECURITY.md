# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/netgoat-xyz/telemetry/security/advisories/new)
for this repository. Include the affected component and version or commit, the
impact, reproduction steps or a proof of concept, and any suggested fix.

You will get an acknowledgement, an assessment, and a disclosure timeline.

## Handling secrets

- Secrets are read from the environment only. `.env` is git-ignored; only
  `.env.example` with placeholders is committed.
- CI runs `gitleaks` on every push and pull request.
- If you believe a secret was committed, rotate it first, then open a private
  report. Removing the commit is not enough.
