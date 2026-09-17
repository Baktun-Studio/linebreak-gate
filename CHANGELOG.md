# Changelog

All notable changes to `linebreak-gate` (the PyPI package and the
`Baktun-Studio/linebreak-gate@v1` Action, published together from
`packages/gate`). Versions follow semver: a minor bump for new flags or
inputs, a patch for fixes and metadata.

## 1.12.0

Release-only criteria and the check stage (Katun follow-up to issue #256:
criteria checked against a shared staging environment must not turn every PR
red when staging regresses, including the PR that fixes it).

- Spec: an optional `check.when: release` per criterion (implicit default
  `always`). The spec lint accepts only `always` or `release`; the field
  enters the criterion and bundle hashes like any other check field, so adding
  it to an approved criterion re-arms its sign-offs and overrides. Criteria
  without `when` hash exactly as before (golden-pinned).
- `check --stage pr|release` (default `release`, nobody's behavior changes).
  At `--stage pr`, `when: release` criteria are not evaluated: their checks
  never run, they are listed as `[release-only]` with a `release-only (not
evaluated at stage pr):` line, counted apart in the summary, and count as
  neither pass nor fail. At `--stage release` they are evaluated as always and
  a failing one still blocks the release: fail closed is unchanged.
- Action: new input `stage` (`release` default, or `pr`), passed to `check`;
  the PR comment shows the stage and the release-only criteria. Katun wires
  `stage: pr` in the PR gate and `stage: release` in the release job.
- `spec show`/`spec list` print `when: release`; `spec new` documents it. The
  MCP `check_story` tool and `spec check` take the same `stage` (default
  `release`), so a pre-push check can skip staging criteria too. An explicit
  `when: always` is normalized away (never changes a hash). The desktop
  criteria editor and the spec-authoring prompt know the field.

## 1.11.0

Check scope: per story on PRs, full at release (issue #256).

- `check --story <id>` (repeatable) evaluates only those stories' criteria. An
  unknown id is exit 2 (fail closed).
- `check --started-only` evaluates only stories whose local state is `doing`,
  `review`, or `done` (`_bmad-output/tracker-sync.json`, the store `spec next`
  and the MCP bridge write); stories without a state are listed as not started
  and do not count toward the verdict. Mutually exclusive with `--story`. When
  no story is started at all (state file absent, unreadable, or managed by an
  external tracker without local states) the scope selects nothing and the
  check is exit 2, never a vacuous pass.
- `check --manual block|warn`: with `warn`, `manual` criteria without a
  sign-off are reported as `needs-signoff` and listed as pending, but do not
  block. `block` is the default and the previous behavior.
- The summary prints a `scope:` line, a `not started (not counted):` line, and
  one `pending sign-off:` line per missing sign-off; `--format json` carries
  `scope` and `pending_signoffs`. The same keys are present on every JSON
  path (no-bundle, disabled, signature block), so one schema fits every
  outcome.
- Every run writes `.linebreak/audit/criteria.json` stamped with its `scope`
  and `pending_signoffs`, so a scoped or relaxed run is evidence of that run
  and can never be read as a full verdict, and the CI artifact never carries a
  stale committed record instead of this run's.
- The summary collapses bundle-authored text (statements, sign-off notes,
  override reasons, command output) to one line, so no such text can forge a
  `pending sign-off:` or `scope:` entry the PR comment parses.
- Action: new inputs `story` (`all`, the default and the previous behavior;
  `auto` infers the id from a `feat/<id>` or `story/<id>` branch, a trailing
  slug allowed as in `feat/<id>-add-login`, when it is an approved story and
  otherwise uses `--started-only`; or an explicit id) and `manual` (`warn` or
  `block`; empty means `warn` on `pull_request` and `block` on every other
  event). The resolution lives in `scripts/check-scope.sh` and is the first
  line of the criteria report; the PR comment shows the resolved scope, the
  stories not started, and the pending sign-offs.
- **Behavior change for existing `@v1` users:** because `manual` defaults to
  `warn` on `pull_request`, a `manual` criterion without a sign-off no longer
  blocks a PR unless the workflow sets `manual: block`. Add the release job
  (`story: all`, `manual: block`) or set `manual: block` on the PR job to keep
  sign-offs enforced at the merge.
- Docs: "Check scope: per story on PRs, full at release" in the README with the
  recommended two-job workflow (scan always; `story: auto` + `manual: warn` on
  PRs; `story: all` + `manual: block` in the release job).
- Fix: a corrupt `.linebreak/audit/criteria.json` during `check` is now a clean
  exit 2 instead of an uncaught traceback.

## 1.10.4 and earlier

See the git history of `packages/gate` in `Baktun-Studio/linebreak`
(`git log -- packages/gate`) and the release tags on the mirror.
