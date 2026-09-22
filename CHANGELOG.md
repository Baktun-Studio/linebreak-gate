# Changelog

All notable changes to `linebreak-gate` (the PyPI package and the
`Baktun-Studio/linebreak-gate@v1` Action, published together from
`packages/gate`). Versions follow semver: a minor bump for new flags or
inputs, a patch for fixes and metadata.

## 1.13.4

Bitbucket Pipelines and Azure DevOps: the same gate, one command, no native
Action needed.

- `ci_env`: one reader for the CI environment (GitHub Actions, GitLab CI,
  Bitbucket Pipelines, Azure Pipelines, local shell) exposing provider,
  repository, commit, branch, target branch, PR number, actor, build URL,
  `is_pr`, `is_default_branch` (None when the provider does not name a
  default branch) and `stage`. Every loose variable lookup in the gate goes
  through it; the audit `actor` now comes from it (Bitbucket's triggerer
  UUID, Azure's requested-for email).
- `linebreak-gate ci`: scan, then `check` with the scope resolved like the
  Action's `check-scope.sh` (`--story all|auto|<id>`; `--manual auto` is
  warn on a PR and block elsewhere; `--stage auto` is pr on a PR and release
  elsewhere), evidence in `.linebreak/ci-out/` (`report.txt`,
  `criteria.txt`, `report.json`, `comment.md`, the audit records) for the
  pipeline artifact, the PR comment and the build status through the
  provider's API, and exit with the worse of the two codes. A crash inside a
  step is exit 2 with the trace in the evidence. On GitHub it posts nothing
  (the Action does).
- PR comment content-identical to the Action's, one per pull request and
  updated in place (hidden marker). Bitbucket Cloud API 2.0:
  `BITBUCKET_ACCESS_TOKEN` (repository access token) or
  `BITBUCKET_USERNAME` + `BITBUCKET_APP_PASSWORD`; commit build status
  `linebreak-gate` (`LineBreak gate`). Azure DevOps REST 7.1 on Azure Repos:
  `SYSTEM_ACCESSTOKEN` (the job token, mapped in the step) or
  `AZURE_DEVOPS_PAT`; a comment thread active while blocked and closed on
  pass, plus the PR status `linebreak/gate`. Without credentials, or when
  the API refuses, the run prints a note and the exit code still enforces.
- Credential variables holding an unexpanded Azure `$(NAME)` macro are
  treated as unset (an undefined pipeline variable stays literal in Azure
  and would otherwise look like a real key).
- `init --provider auto|github|bitbucket|azure|all`: `auto` follows the git
  remote (Bitbucket Cloud and Azure Repos URLs are recognized, an unknown
  remote keeps the GitHub default and says how to get the others); writes
  `bitbucket-pipelines.yml` and `azure-pipelines.yml` (idempotent, `--force`
  to overwrite) and prints the variables, the token and the
  branch-protection steps of each provider with deep links.
- `Dockerfile.ci`: the CI image (root, no ENTRYPOINT, bash, git, curl and
  osv-scanner preinstalled, installed from the source tree) for Bitbucket
  steps and Azure container jobs. The MCP `Dockerfile` is unchanged and is
  not usable for CI.
- Docs: README section in Spanish for both providers (the pipeline snippets
  there are the files `init` writes, test-pinned), and the runbook
  `docs/RUNBOOK_BITBUCKET_AZURE.md`. Verified with tests; the live run on a
  real Bitbucket and a real Azure DevOps repository is pending.

## 1.13.3

Vencimiento de riesgos aceptados y tickets en el gestor del equipo (ola de
septiembre, frente `tickets`). Un auditor lo resumió: "la persona que aceptó
el riesgo se va, y el riesgo queda".

- `override --finding|--criterion` acepta `--expires YYYY-MM-DD` o
  `--days N`. Política en `.linebreak/gate.yml`: `risk_acceptance:
{max_days: 90, required: true}`; con `required` un override sin fecha se
  rechaza (exit 2, nada registrado) y una fecha más allá de `max_days`
  también. Sin el bloque, las aceptaciones abiertas siguen permitidas. La
  misma política aplica a hallazgos de seguridad y a excepciones de
  criterios.
- `scan`, `report` y `check` bloquean de nuevo una aceptación vencida con
  motivo `expired_risk` (quién aceptó, cuándo venció, cómo renovar o
  corregir) y avisan sin bloquear a menos de 14 días del vencimiento.
  `expired_risk` entra en `block_reasons` junto a `kev` y `vulnerability`; en
  `check` se suma a `tests_failed`, `command_failed`, `role_denied` y
  `unsigned_manual`. El JSON trae `expired` y `expiring` por detector, y
  `expired_overrides` / `expiring_overrides` en `check`.
- La evidencia guarda `expires`; renovar es un registro nuevo y el anterior
  queda en el historial (la más reciente rige, y bajo `roles.yml` la más
  reciente que la política acepte).
- `tickets: {provider: jira|github, project, labels, main_branch,
issue_type}` en `gate.yml`, credenciales `JIRA_BASE_URL`, `JIRA_EMAIL`,
  `JIRA_API_TOKEN` o `GITHUB_TOKEN`. Al aceptar un riesgo o excusar un
  criterio se crea (o renueva) el ticket con hallazgo, aprobador, motivo,
  vencimiento, repositorio, commit y enlace a la evidencia; la clave queda en
  la entrada (`ticket`, `ticket_url`). Al vencer se comenta y se reabre; al
  corregirse se comenta y se cierra; un `scan` en la rama principal abre un
  ticket de atención por cada hallazgo nuevo respecto del artefacto anterior.
- El gestor nunca bloquea el veredicto: los fallos quedan en la evidencia
  (`ticket_error`) y en `.linebreak/audit/tickets.json`; `linebreak-gate
tickets sync` reintenta. Idempotencia por etiquetas
  `linebreak-target-<hash>` en el propio gestor. Clientes sobre `urllib`, sin
  dependencias nuevas.

## 1.13.2

Prioridad por explotación: EPSS + CISA KEV en los hallazgos de dependencias
(lo pidieron dos clientes bancarios: "la están explotando hoy", "probable en
30 días").

- `scan` enriquece cada hallazgo con CVE con `epss` (probabilidad de
  explotación a 30 días, FIRST) y `kev` (catálogo de vulnerabilidades
  explotadas de CISA), más `epss_percentile`, `kev_date_added` y
  `kev_due_date`. Caché en `.linebreak/cache/` (se ignora sola en git) con
  antigüedad máxima configurable (`security.intel_max_age_hours`, 24 h por
  defecto). Sin red se usa la caché, vencida o no, y sin caché los campos
  quedan vacíos y el reporte dice "sin datos de explotación": el
  enriquecimiento nunca convierte un escaneo en error. `LINEBREAK_OFFLINE=1`
  o `security.intel: false` apagan la red.
- Política nueva en `.linebreak/gate.yml`, bloque `security:` (`fail_on`
  puede vivir ahí o en la raíz, no en ambos): `block_kev: true` (por defecto)
  bloquea cualquier hallazgo del catálogo KEV sin importar su severidad;
  `epss_threshold: 0.5` bloquea desde esa probabilidad (apagado por defecto).
- Motivo de bloqueo por hallazgo (`block_reason`) y agregado
  (`block_reasons`) con exactamente dos valores: `kev` y `vulnerability`
  (piso de severidad o umbral EPSS). KEV gana cuando aplican los dos. El
  artefacto `security.json` registra `exploit_intel` (de dónde salieron los
  datos de esa corrida) y `verdict` (`passes`, `block_reasons`).
- Orden de los hallazgos en `report`, en el veredicto y en el JSON: primero
  KEV, luego por EPSS, luego por severidad/CVSS. Cada hallazgo muestra su
  etiqueta: "explotada activamente (KEV)", "EPSS 0.93" o "sin datos de
  explotación". `risk_score` sube con la explotación y nunca baja: KEV = 100,
  EPSS eleva el puntaje a su probabilidad en porcentaje, la severidad es el
  piso (sin datos, los números son los de siempre).
- `report --format json` y `scan --format json` incluyen los campos nuevos,
  `block_reasons`, `block_kev`, `epss_threshold` y `exploit_intel`.

## 1.13.1

Roles and verified identity for the humans who sign, override, and accept
risk (September wave, `roles` front).

- New `.linebreak/roles.yml`: a roster of roles with `members` and what each
  `can` do (`sign_criteria` / `approve_overrides` as id patterns over the
  criterion, story and epic; `accept_security_risk` as a severity list), plus
  `policy.require_roles` and `policy.require_verified_identity`. Parsed with
  the same fail-closed discipline as `gate.yml` (malformed = exit 2).
- `signoff` and `override` take `--role` (inferred when the person holds
  exactly one role that allows the action) and record it; under
  `require_roles` an unauthorized person is refused with a message naming the
  roles that would be needed. Accepting a security finding is gated by its
  severity.
- `check`, `scan` and `report` re-verify every stored sign-off and override
  against the roles in force. A rejected record yields the new criterion
  result `role-denied` (always blocking, even under `--manual warn`), a
  `denials` list in the JSON and the audit artifact, a `role denied: <id>
(<story>): ...` line in the summary, and `role_denials` per detector for
  findings. Reasons: `role_denied`, `identity_unverified`.
- Identity sources next to `client`: `vcs` (GitHub Actions, GitLab CI,
  Bitbucket Pipelines, Azure Pipelines actor from the job environment) and
  `governance` (`GET /v1/me` with `LINEBREAK_GOVERNANCE_BASE_URL` and
  `LINEBREAK_GOVERNANCE_TOKEN`; a failing token stops the command). Records
  carry `identity_source`, an `identity` block (provider, email, login) and
  `declared_approver` / `declared_by` when the typed name differs.
- Compatibility: no roles file, or both policies `false`, changes nothing;
  the JSON adds keys only where sign-offs, overrides or denials exist.

## 1.13.0

`publish`: report a gate run to the governance panel (September wave,
`panel-servicio` front).

- New `linebreak-gate publish --to <url> [--project] [--stage] [--run-id]
[--dry-run]` sends the run's verdict, findings, sign-offs and overrides to
  `POST /v1/projects/{id}/gate-runs`. Idempotent by `run_id` (deterministic
  under GitHub Actions). Always exits 0: a panel that is down never blocks a
  change.

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
