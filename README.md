# linebreak-gate — the LineBreak security gate at the git/CI boundary

Blocks merges that carry known vulnerabilities. One tool, two detectors:

- **Dependency CVE scan** — [osv-scanner](https://google.github.io/osv-scanner/)
  across every ecosystem (npm, PyPI, Go, Cargo, Maven, …), with an `npm audit`
  fallback for npm projects (npm-only coverage and no installed-version data —
  the GitHub Action fails closed if osv-scanner can't be installed instead of
  degrading to it).
- **AI SAST** — an LLM security review of first-party source (injection,
  broken auth, secret exposure, SSRF, unsafe deserialization, crypto misuse)
  with adversarial verification, enabled by `LINEBREAK_LICENSE_KEY` (hosted,
  uses credits) or `ANTHROPIC_API_KEY` (your own key, takes precedence).

The gate **blocks and can propose; it never auto-clears on an agent's
say-so**. A human approves the fix or records an override — with a reason and
an approver — in a git-committed audit file.

This is the same scanner core that powers the LineBreak desktop app's in-app
security gate (the desktop backend imports this package), but it is fully
standalone: a team that has never opened the desktop app can add the gate to
their repo and get real enforcement.

> **Where this code lives.** Development happens in the LineBreak monorepo
> (`packages/gate`); every green change to it is automatically mirrored to
> [`Baktun-Studio/linebreak-gate`](https://github.com/Baktun-Studio/linebreak-gate)
> (the public repo the Action snippet uses) and published to PyPI as
> [`linebreak-gate`](https://pypi.org/project/linebreak-gate/). Never edit the
> mirror directly — the next sync overwrites it. Licensed Apache-2.0.

## Quickstart — GitHub Actions

```yaml
# .github/workflows/security-gate.yml
name: Security gate
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write # for the summary comment

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Baktun-Studio/linebreak-gate@v1
        with:
          # fail-on: high # blocking floor; default: critical
          # Optional today; required once license enforcement is enabled.
          license-key: ${{ secrets.LINEBREAK_LICENSE_KEY }}
          # Enables the AI code review; leave unset for dependency scan only.
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

The action runs `linebreak-gate scan`, always runs `report`, posts **one** PR
comment (updated in place on every push, never spammed), uploads the JSON
report + audit artifacts as a workflow artifact, and fails the check per the
scan's exit code.

### Make it a real boundary: require the check

A CI job that can be ignored is a dashboard, not a gate. In your repo:

**Settings → Branches → Branch protection rules → your default branch →
"Require status checks to pass before merging"** → add the `gate` job (the
name of the job that runs this action). From then on a PR carrying a critical
CVE cannot be merged through the GitHub UI.

## Quickstart — any other CI (GitLab example)

The CLI is a plain Python package with strict exit codes — `0` pass, `1`
blocking findings, `2` tool/config error (**fail closed**: a scanner crash
fails the pipeline, it is never a clean pass). Any CI that respects exit codes
gets the same enforcement:

```yaml
# .gitlab-ci.yml
security-gate:
  image: python:3.11
  script:
    - pip install linebreak-gate
    - curl -fsSL -o /usr/local/bin/osv-scanner
      "$(curl -fsSL https://api.github.com/repos/google/osv-scanner/releases/latest
      | python -c "import json,sys;print(next(a['browser_download_url'] for a in json.load(sys.stdin)['assets'] if a['name'].endswith('linux_amd64')))")"
    - chmod +x /usr/local/bin/osv-scanner
    - linebreak-gate scan
    - linebreak-gate report
```

Mark the job as required (no `allow_failure`) and protect the branch.

## CLI

```text
linebreak-gate init     [--path .] [--fail-on critical|high|medium|low] [--force] [--non-interactive]
linebreak-gate scan     [--path .] [--fail-on critical|high|medium|low] [--format summary|json]
linebreak-gate report   [--path .] [--format summary|json]
linebreak-gate override --finding <id> --reason "…" --approver <name/email> [--path .]
```

- `init` sets a repo up in one command: writes the workflow file (never
  clobbers an existing one without `--force`), optionally writes
  `.linebreak/gate.yml`, offers to store the secrets via the GitHub CLI and to
  require the `gate` check — and prints the exact settings links for anything
  it can't do for you.

- `scan` runs both detectors, writes git-native audit artifacts under
  `.linebreak/audit/`, and exits 0/1/2.
- `report` renders the recorded scan: counts by severity and every finding
  with CVE id, CVSS, advisory link, and override status. `--format json` for
  machines.
- `override` records a human-approved acknowledgment of **one exact finding**
  — the package + installed version + CVE tuple. A different CVE, a bumped
  version, or a new finding still blocks. `--reason` and `--approver` are
  required; the record lands in the artifact's approval trail. Commit the
  updated `.linebreak/audit/*.json` so CI sees it.

## Configuration — `.linebreak/gate.yml`

The gate's strictness is governance, so it lives in the repo — changing the
threshold is itself a PR: visible, reviewable, attributable in git history.

```yaml
# .linebreak/gate.yml
fail_on: critical # critical (default) | high | medium | low
exclude_paths: # optional: root-relative globs excluded from scanning
  - fixtures
  - "sandbox/*"
code_scan: auto # auto (run when model credentials are set) | on (required) | off
```

Precedence: explicit `--fail-on` flag / Action input → `.linebreak/gate.yml` →
built-in default (`critical`). An invalid config is a tool error (exit 2) —
a broken governance file never silently falls back to a default.

## Audit records

Every scan and every override is recorded in `.linebreak/audit/security.json`
(dependencies) and `.linebreak/audit/code.json` (AI SAST) — the same versioned
document format the LineBreak desktop app writes, carrying findings (CVE id,
CVSS, advisory link), scanner engine, timestamp, actor, and the approval trail
with each override's reason + approver. Who relaxed the gate, and when, is
itself auditable.

## Licensing

The gate reads `LINEBREAK_LICENSE_KEY` from the environment (the Action's
`license-key` input). Entitlements currently default open: without a key the
gate runs and prints a notice. The check is wired through LineBreak's
entitlements provider, so flipping `LINEBREAK_ENTITLEMENTS_PROVIDER=remote`
enforces licensing without a client change — set the key in CI secrets now so
the gate keeps working then.
