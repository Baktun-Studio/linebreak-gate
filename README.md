# linebreak-gate — the LineBreak security gate at the git/CI boundary

<!-- mcp-name: com.linebreakapp/linebreak-gate -->

## See it run

A real pull request, blocked for real: the gate is a **required check**, so the merge button goes gray until the CVE is fixed or a named human records an override.

![Real pull request blocked by the LineBreak Security Gate: required check failing, merge disabled](https://raw.githubusercontent.com/Baktun-Studio/linebreak-gate/main/assets/pr-blocked.png)

**[See it live — a public PR you can open right now →](https://github.com/Baktun-Studio/gate-demo/pull/1)**

A real recording, no mock: the scan blocks a critical CVE fail-closed, the pin gets fixed, the gate opens.

![linebreak-gate scan blocking a critical CVE, then passing after the fix](https://www.linebreakapp.com/demo/gate.gif)

The spec loop: a named human approves the criteria, `check` blocks until the manual criterion carries a sign-off, then everything passes.

![spec approve, check blocked until sign-off, then all criteria pass](https://www.linebreakapp.com/demo/spec.gif)

Blocks merges that carry known vulnerabilities. One tool, two detectors —
**dependency scanning is free; the AI review is the Pro upgrade**:

- **Dependency CVE scan — free, no key** — [osv-scanner](https://google.github.io/osv-scanner/)
  across every ecosystem (npm, PyPI, Go, Cargo, Maven, …), with an `npm audit`
  fallback for npm projects (npm-only coverage and no installed-version data —
  the GitHub Action fails closed if osv-scanner can't be installed instead of
  degrading to it).
- **AI SAST — Pro** — an LLM security review of first-party source (injection,
  broken auth, secret exposure, SSRF, unsafe deserialization, crypto misuse)
  with adversarial verification, enabled by `LINEBREAK_LICENSE_KEY` (hosted,
  uses credits) or `ANTHROPIC_API_KEY` (your own key, takes precedence). Without
  a key the dependency scan still runs and this pass is skipped with a notice.

The gate **blocks and can propose; it never auto-clears on an agent's
say-so**. A human approves the fix or records an override — with a reason and
an approver — in a git-committed audit file.

This is the same scanner core that powers the rest of LineBreak's in-product
security gate (the desktop backend imports this package), but it is fully
standalone: a team that has never touched anything else from LineBreak can add the gate to
their repo and get real enforcement.

> **Contributing & license.** This repo is the published source of
> [`linebreak-gate`](https://pypi.org/project/linebreak-gate/) (Apache-2.0):
> every release lands here and on PyPI from our CI, and every change passed
> our own gate first — CVE scan and human-approved criteria, the same
> discipline we sell. Bug reports and feature requests: open an issue or
> discussion here; we read everything. Direct PRs to this repo can't be
> merged (releases flow through our review pipeline), so start with an issue
> and we'll take it from there.

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

## The spec loop — author, approve, serve over MCP, enforce

The gate also enforces **approved acceptance criteria**, and the whole loop is
tool-agnostic — no LineBreak account, no desktop app, no server:

```bash
linebreak-gate spec new        # scaffold a draft — fill it with any tool (your
                               # editor, Claude Code, ChatGPT), or distill it
                               # from the PRD you already have in Notion/Jira
linebreak-gate spec approve .linebreak/spec-draft.yml \
  --approver "Ana Lopez <ana@example.com>"   # a human on the record; commits
linebreak-gate mcp install --editor claude-code   # or: cursor · codex
```

`linebreak-gate mcp` serves the **approved** bundle (`.linebreak/spec/`) over
MCP (stdio) to Claude Code, Cursor, Codex, or any MCP client. Six tools:
`list_stories`, `get_story` (criteria as agent context BEFORE code is
written), `next_story`, `set_story_status`, `check_story` (the same
evaluation engine CI runs, scoped to one story), and `spec_status` (approval +
offline signature state). **Git is the transport** — no network, no account,
works on a bare clone — and **nothing in the bridge can write, edit, or
invalidate an approved criterion**: criteria change only by editing the draft
and re-approving, with a human on the record.

Then `linebreak-gate check` enforces the same criteria in CI: machine checks
run for real, `manual` criteria block until a recorded sign-off. Guided first
run with the why of every step:
[linebreakapp.com/en/start](https://www.linebreakapp.com/en/start).

## CLI

```text
linebreak-gate init     [--path .] [--fail-on critical|high|medium|low] [--force] [--non-interactive]
linebreak-gate scan     [--path .] [--fail-on critical|high|medium|low] [--format summary|json]
linebreak-gate report   [--path .] [--format summary|json]
linebreak-gate override --finding <id> --reason "…" --approver <name/email> [--path .]
linebreak-gate override --criterion <id> --reason "…" --approver <name/email> [--path .]
linebreak-gate check    [--path .] [--format summary|json] [--story <id> ...|--started-only] [--manual block|warn] [--stage release|pr]
linebreak-gate signoff  --criterion <id> --approver <name/email> --note "…" [--path .]
linebreak-gate spec new     [--path .] [--out <file>] [--force]
linebreak-gate spec approve <draft> --approver <name/email> [--role architect] [--path .]
linebreak-gate spec list|next [--path .]
linebreak-gate spec show|check <story-id> [--path .]
linebreak-gate mcp      [--path .]            # serve the approved spec over stdio
linebreak-gate mcp install [--editor claude-code|cursor|codex] [--print]
linebreak-gate badge    [--format markdown|html|url]
linebreak-gate publish  --to <governance-url> [--project <id>] [--path .] [--stage pr|release] [--run-id <id>] [--dry-run]
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
- `check` evaluates the approved acceptance criteria (`.linebreak/spec/`,
  landed by `spec approve`) against
  the working tree: `build`/`tests`/`command` run for real, `manual` requires
  a recorded sign-off. Exit 0 all satisfied (or no bundle — a clean no-op), 1
  blocking (fail or needs-signoff), 2 tool/config/bundle error (fail closed).
  Writes `.linebreak/audit/criteria.json`. Scope flags (see
  [Check scope](#check-scope-per-story-on-prs-full-at-release)): `--story <id>`
  (repeatable) evaluates only those stories, `--started-only` evaluates only
  stories with a started local state, `--manual warn` reports missing
  sign-offs without blocking, `--stage pr` skips criteria marked
  `check.when: release` (listed as release-only, not evaluated; the default
  `--stage release` evaluates them). The summary and the JSON state the scope.
- `signoff` records an attributed human sign-off for one `manual` criterion
  under `.linebreak/spec/signoffs/` (additive; `--approver` and `--note`
  required). It binds to the criterion as approved — editing the criterion
  and re-approving the spec makes prior sign-offs stale. Commit the record.
- `override --criterion` records a human-approved override for one failed
  machine criterion in `.linebreak/audit/criteria.json` — same philosophy as
  CVE overrides: possible, always attributed, stale once the criterion is
  edited. Other blocking criteria still block.
- `spec new` / `spec approve` — the tool-agnostic authoring path (see the
  spec-loop section above): scaffold a draft, fill it with any tool, land it
  as the approved bundle with an attributed human approval, committed.
  Unsigned local approvals are marked `identity_source: client`; cryptographic
  signatures come from the governance service (license key).
- `spec list` prints the approved acceptance criteria bundle: each story, its
  criteria with check types, and the approver attribution. Read-only. Exit 0
  on a valid bundle _or when none exists_; exit 2 on a malformed bundle (fail
  closed on structure). `spec next` / `show` / `check` are the CLI twins of
  the MCP bridge tools.

### Publish to the panel

`linebreak-gate publish --to https://governance.example --project <id>` sends
the recorded run (criteria, findings, sign-offs, overrides, attestation) to a
LineBreak governance service so executives and auditors see it in the panel.
The bearer comes from `LINEBREAK_GOV_TOKEN` (a token issued by that service);
`--project` can also come from `LINEBREAK_GOV_PROJECT`. Run it after `scan`
and `check`, as the last step of the job.

Publishing **never blocks a change**: a missing token, an unreachable service,
or a rejected body prints a warning and exits 0. The verdict was already given
by `scan`/`check`; `publish` only reports it. Under GitHub Actions the `run_id`
is derived from the run id and attempt, so re-running the step is idempotent
server-side. `--dry-run` prints the body without sending.

### Badge

Show visitors the repo is gated. `linebreak-gate badge` prints a ready-to-paste
README snippet (no network calls — the shields.io static badge is fully encoded
in its URL); `--format html|url` for the tag or bare-URL variants:

```markdown
[![gated by LineBreak](https://img.shields.io/badge/gated%20by-LineBreak-14120F?labelColor=FAF8F4)](https://www.linebreakapp.com/en/gate)
```

## Check scope: per story on PRs, full at release

A team that approves the whole sprint up front (the flow this gate promotes:
spec approved before code) would otherwise see every PR blocked by criteria of
stories nobody has started. The fix is scope, not a weaker gate:

- **Scan always.** The dependency and code scans run on every PR and on
  release, unchanged.
- **Check the story on PRs.** `linebreak-gate check --story <id>` evaluates
  only that story's criteria (`--story` repeats). `--started-only` evaluates
  only stories whose local state is `doing`, `review`, or `done` (the state
  `spec next` and the MCP bridge write); stories without a state are listed as
  not started and do not count. When no story is started at all (no state
  file, an unreadable one, or an external tracker without local states) the
  scope selects nothing and the check is exit 2, never a vacuous pass.
  `--manual warn` reports `manual` criteria
  without a sign-off as pending instead of blocking, so a sign-off that
  belongs to the release does not hold a PR.
- **Check everything at release.** The release job runs the full bundle with
  `--manual block` (the default): every criterion of every story, every
  `manual` criterion signed off. Every run writes
  `.linebreak/audit/criteria.json` stamped with its `scope` and
  `pending_signoffs`, so a scoped or relaxed run is evidence of that run and
  can never be read as a full verdict (and CI never uploads a stale one).

The summary prints a `scope:` line (mode, stories evaluated, criteria counted,
manual policy, stage), a `release-only (not evaluated at stage pr):` line when
criteria were skipped, and one `pending sign-off:` line per missing sign-off;
the JSON carries the same under `scope` (including `stage` and
`release_only`) and `pending_signoffs`. An unknown `--story` id
is exit 2 (a scope that names nothing is a mistake, never a pass).

In the GitHub Action the same pattern is three inputs (`stage` is described below). `story` is `all` (every
story, the default), `auto` (infer the id from a `feat/<id>` or `story/<id>`
branch, a trailing slug allowed as in `feat/<id>-add-login`, when it is an
approved story; otherwise started stories only), or an explicit id. `manual`
is `warn` or `block`; left empty it is `warn` on `pull_request` and `block` on
every other event. The PR comment shows the resolved scope, the stories not
started, and the pending sign-offs.

**Behavior change for existing `@v1` users (1.11.0):** the `manual` default on
`pull_request` events is now `warn`, so a `manual` criterion without a
sign-off no longer blocks a PR unless the workflow sets `manual: block`. Add
the release job below (or set `manual: block` on the PR job) to keep
sign-offs enforced.

```yaml
# .github/workflows/security-gate.yml, PR gate + release gate
name: Security gate
on:
  pull_request:
  push:
    tags: ["v*"] # the release job runs on release tags

permissions:
  contents: read
  pull-requests: write

jobs:
  gate:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Baktun-Studio/linebreak-gate@v1
        with:
          license-key: ${{ secrets.LINEBREAK_LICENSE_KEY }}
          story: auto # this PR's story, or started stories only
          manual: warn # sign-offs are listed, not blocking, on PRs
          stage: pr # check.when: release criteria are listed, not evaluated

  release-gate:
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: Baktun-Studio/linebreak-gate@v1
        with:
          license-key: ${{ secrets.LINEBREAK_LICENSE_KEY }}
          story: all # every story, every criterion
          manual: block # every manual criterion needs its sign-off
          stage: release # the default; release-only criteria run and block
```

Require the `gate` check on the default branch and the `release-gate` job
before publishing. Generic CI: the same two invocations of the CLI, with the
exit codes respected.

### Release-only criteria: `check.when: release`

A criterion checked by a script against a shared staging environment fails
for every PR the moment staging regresses, including the PR that fixes it.
Mark it `when: release` in the spec:

```yaml
- id: checkout-smoke
  statement: The checkout smoke script passes against staging.
  check:
    type: command
    payload: ./scripts/smoke-staging.sh
    when: release # absent means always
```

With `stage: pr` on the PR job (`check --stage pr`) such criteria are not
evaluated: their checks never run, the report lists them as `[release-only]`
with their own count, and they are neither pass nor fail. The release job
(`stage: release`, the default) evaluates them as always, and a failing one
still blocks the release. The field is part of the criterion's content, so
adding it to an approved criterion re-arms that criterion's sign-offs and
overrides like any other edit.

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
criteria:
  enforce: true # default: true whenever a spec bundle exists; false disables
  # criteria checking only (the security scan is unaffected)
```

Precedence: explicit `--fail-on` flag / Action input → `.linebreak/gate.yml` →
built-in default (`critical`). An invalid config is a tool error (exit 2) —
a broken governance file never silently falls back to a default.

## Audit records

Every scan and every override is recorded in `.linebreak/audit/security.json`
(dependencies) and `.linebreak/audit/code.json` (AI SAST) — the same versioned
document format the LineBreak tools write, carrying findings (CVE id,
CVSS, advisory link), scanner engine, timestamp, actor, and the approval trail
with each override's reason + approver. Who relaxed the gate, and when, is
itself auditable.

## Pricing

**Free, forever:** the dependency CVE scan and the whole spec loop — authoring,
human approval, MCP serving, and CI enforcement. No key, no account.

**Pro — $99/month per team** ([pricing](https://www.linebreakapp.com/en/pricing)):
cryptographically **signed, tamper-evident approvals** (Ed25519, verifiable
offline), required-key enforcement mode, and **hosted AI code review** with no
API key to manage. Buy on the pricing page — your `LINEBREAK_LICENSE_KEY`
arrives by email within seconds (it's the Action's `license-key` input).
Prefer your own model key? `ANTHROPIC_API_KEY` also enables the AI review;
Pro's hosted review is the zero-config path.

The gate runs **open** by default: it works without a key and prints a notice
when no `LINEBREAK_LICENSE_KEY` is set (suppressed for BYOK users). That's
freemium — the dependency scan runs free. Teams that want to _require_ a valid
Pro key for the gate to run at all can opt into
`LINEBREAK_ENTITLEMENTS_PROVIDER=remote`, which checks the entitlement **before**
any scan and fails closed on a missing/invalid/revoked key, wrong plan, or
unreachable service — blocking the whole gate, dependency scan included.
