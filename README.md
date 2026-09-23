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

## Bitbucket Pipelines y Azure DevOps

_The same gate on Bitbucket Pipelines and Azure DevOps: `linebreak-gate ci`
runs scan + check, posts the PR comment and the build status through the
provider's API, and exits 0/1/2. This section is in Spanish for the teams
piloting it; the step-by-step runbook is `docs/RUNBOOK_BITBUCKET_AZURE.md`
in the monorepo._

La compuerta es la misma en cualquier CI. El comando `linebreak-gate ci` hace
en un solo paso lo que la Action de GitHub hace en varios: corre el escaneo de
dependencias y la revisión de código con IA (si hay llave), evalúa los
criterios de aceptación aprobados con el alcance correcto (por historia en el
pull request, todo el paquete en la liberación), deja la evidencia en
`.linebreak/ci-out/` (`report.txt`, `criteria.txt`, `report.json`,
`comment.md` y los registros de auditoría) para publicarla como artefacto,
publica **un** comentario en el pull request (actualizado en cada corrida,
nunca repetido) y un estado de build, y termina con el código `0` (pasa), `1`
(bloquea) o `2` (error de herramienta: la compuerta queda cerrada). El
comentario tiene el mismo contenido que el de GitHub.

Sin credenciales de API, el veredicto se imprime igual, el comentario y el
estado se omiten con un aviso, y el código de salida sigue bloqueando el
pipeline. La compuerta nunca se abre por no poder comentar.

`linebreak-gate init` detecta el proveedor por el remoto de git y escribe el
archivo que corresponde; `--provider bitbucket|azure|all` lo elige a mano.
Los dos archivos que genera son exactamente los de abajo.

### Bitbucket Pipelines

```yaml
# bitbucket-pipelines.yml
# Python image with git and curl; the gate pins osv-scanner itself.
# Alternative: the gate's CI image built from packages/gate/Dockerfile.ci
# (osv-scanner preinstalled), pushed to a registry your workspace can pull.
image: python:3.11

definitions:
  steps:
    - step: &linebreak-gate
        name: LineBreak gate
        script:
          # osv-scanner drives the dependency scan; without it the gate fails closed.
          - curl -fsSL -o /usr/local/bin/osv-scanner https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
          - chmod +x /usr/local/bin/osv-scanner
          - pip install --quiet "linebreak-gate>=1.13.4,<2"
          # Scan + acceptance criteria, PR comment and build status, exit 0/1/2.
          # Repository variables (Repository settings > Pipelines > Repository variables):
          #   LINEBREAK_LICENSE_KEY   optional today; required once enforcement is enabled
          #   ANTHROPIC_API_KEY       enables the AI code review (secured)
          #   BITBUCKET_ACCESS_TOKEN  repository access token, scopes pullrequest:write
          #                           and repository:write, for the PR comment and status
          - linebreak-gate ci
        artifacts:
          - .linebreak/ci-out/**

pipelines:
  pull-requests:
    "**":
      - step: *linebreak-gate
  branches:
    main:
      - step: *linebreak-gate
```

Variables del repositorio (Repository settings > Pipelines > Repository
variables, marcadas como _secured_):

- `LINEBREAK_LICENSE_KEY`: opcional hoy; requerida cuando se active la
  exigencia de licencia.
- `ANTHROPIC_API_KEY`: habilita la revisión de código con IA; sin ella corre
  solo el escaneo de dependencias, con aviso.
- `BITBUCKET_ACCESS_TOKEN`: token de acceso del repositorio (Repository
  settings > Access tokens) con permisos `pullrequest:write` y
  `repository:write`. Es lo que permite el comentario y el estado de build.
  Alternativa: `BITBUCKET_USERNAME` + `BITBUCKET_APP_PASSWORD`.

Protección de rama equivalente a "required check" (Repository settings >
Branch restrictions, rama `main`): el _merge check_ "Check the last commit for
at least 1 successful build and no failed builds". Los merge checks son parte
de Bitbucket Cloud **Premium**; con el plan Standard el build rojo se ve en el
pull request y en el estado `LineBreak gate`, pero no impide el merge por sí
solo (se apoya en revisores obligatorios).

### Azure DevOps (Azure Repos + Azure Pipelines)

```yaml
# azure-pipelines.yml
trigger:
  branches:
    include:
      - main
pr:
  branches:
    include:
      - "*"

pool:
  vmImage: ubuntu-latest
# Container job alternative (image built from packages/gate/Dockerfile.ci):
# container: <registry>/linebreak-gate-ci:1

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.11"
    displayName: Python 3.11

  - script: |
      set -euo pipefail
      mkdir -p "$HOME/bin"
      # osv-scanner drives the dependency scan; without it the gate fails closed.
      curl -fsSL -o "$HOME/bin/osv-scanner" https://github.com/google/osv-scanner/releases/latest/download/osv-scanner_linux_amd64
      chmod +x "$HOME/bin/osv-scanner"
      echo "##vso[task.setvariable variable=LINEBREAK_OSV_SCANNER_BIN]$HOME/bin/osv-scanner"
      pip install --quiet "linebreak-gate>=1.13.4,<2"
    displayName: Install linebreak-gate

  # Scan + acceptance criteria, PR comment thread and PR status, exit 0/1/2.
  # Secret variables are NOT exported automatically: map them here. An
  # undefined $(NAME) stays literal; the gate treats such values as unset.
  - script: linebreak-gate ci
    displayName: LineBreak gate
    env:
      SYSTEM_ACCESSTOKEN: $(System.AccessToken)
      LINEBREAK_LICENSE_KEY: $(LINEBREAK_LICENSE_KEY)
      ANTHROPIC_API_KEY: $(ANTHROPIC_API_KEY)

  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      pathToPublish: .linebreak/ci-out
      artifactName: linebreak-gate-report
    displayName: Publish the gate report
```

Cuatro pasos manuales, en este orden:

1. Crear el pipeline desde `azure-pipelines.yml` (Pipelines > New pipeline >
   Azure Repos Git > Existing YAML) y agregar las variables secretas
   `LINEBREAK_LICENSE_KEY` y `ANTHROPIC_API_KEY` (Edit > Variables). Una
   variable que no existe queda como el texto literal `$(NOMBRE)`; la
   compuerta la trata como no definida.
2. Project settings > Repos > Repositories > el repositorio > Security: dar a
   la identidad `<proyecto> Build Service (<organización>)` el permiso
   **Contribute to pull requests**. Sin eso, el comentario y el estado fallan
   con 403 (y el pipeline sigue bloqueando por código de salida).
3. Repos > Branches > `main` > Branch policies > **Build validation**: agregar
   este pipeline como _Required_, disparo _Automatic_. Esa política es la que
   deja el botón _Complete_ apagado mientras el build esté rojo.
4. Opcional: en la misma página, **Status checks**: exigir el estado
   `linebreak/gate` que la compuerta publica en cada pull request.

En Azure Repos el disparador `pr:` del YAML no aplica: la política de Build
validation es la que corre el pipeline en cada pull request. `pr:` queda para
repositorios alojados en GitHub o Bitbucket y construidos desde Azure
Pipelines (en ese caso el comentario debe publicarse en ese proveedor; la API
de PR de Azure DevOps no aplica y la compuerta lo dice).

### Imagen Docker: dos caminos

1. **Imagen base de Python + `pip install`** (las plantillas de arriba).
   Funciona hoy sin publicar nada; descarga `osv-scanner` desde GitHub en cada
   corrida (si el runner no tiene salida a internet, usar el camino 2).
2. **Imagen de CI de la compuerta**, construida desde `Dockerfile.ci` en este
   directorio y publicada en un registro que el workspace o la organización
   pueda leer:

   ```sh
   docker build -f Dockerfile.ci -t <registro>/linebreak-gate-ci:1 .
   docker push <registro>/linebreak-gate-ci:1
   ```

   En Bitbucket: `image: <registro>/linebreak-gate-ci:1` y se quitan las
   líneas de `curl` y `pip install` del script. En Azure: un _container job_
   (`container: <registro>/linebreak-gate-ci:1` bajo `pool`) y se quita el paso
   de instalación. La imagen trae `osv-scanner`, `git`, `bash` y `curl`, corre
   como root y no define `ENTRYPOINT`: los tres son requisitos de Bitbucket
   Pipelines y de los container jobs de Azure.

   El `Dockerfile` sin sufijo es la imagen del **servidor MCP** (entrypoint
   `linebreak-gate mcp`, usuario sin privilegios, sin `osv-scanner`) y no sirve
   para CI.

### El comando

```text
linebreak-gate ci [--path .] [--fail-on critical|high|medium|low]
                  [--story all|auto|<id>] [--manual auto|warn|block] [--stage auto|release|pr]
                  [--out-dir .linebreak/ci-out] [--no-comment] [--no-status]
```

`--story auto` toma la historia del nombre de rama `feat/<id>` o `story/<id>`
(con sufijo permitido) cuando es una historia aprobada, y si no evalúa solo
las historias iniciadas. `--manual auto` es `warn` en un pull request y
`block` en cualquier otra corrida; `--stage auto` es `pr` en un pull request y
`release` en el resto. Los proveedores detectados son GitHub Actions, GitLab
CI, Bitbucket Pipelines y Azure Pipelines; en GitHub el comentario lo sigue
publicando la Action.

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
linebreak-gate init     [--path .] [--fail-on critical|high|medium|low] [--force] [--non-interactive] [--provider auto|github|bitbucket|azure|all]
linebreak-gate ci       [--path .] [--fail-on ...] [--story all|auto|<id>] [--manual auto|warn|block] [--stage auto|release|pr] [--out-dir DIR] [--no-comment] [--no-status]
linebreak-gate scan     [--path .] [--fail-on critical|high|medium|low] [--format summary|json]
linebreak-gate report   [--path .] [--format summary|json]
linebreak-gate override --finding <id> --reason "…" --approver <name/email> [--expires YYYY-MM-DD|--days N] [--path .]
linebreak-gate override --criterion <id> --reason "…" --approver <name/email> [--expires YYYY-MM-DD|--days N] [--path .]
linebreak-gate check    [--path .] [--format summary|json] [--story <id> ...|--started-only] [--manual block|warn] [--stage release|pr]
linebreak-gate signoff  --criterion <id> --approver <name/email> --note "…" [--path .]
linebreak-gate tickets sync [--path .]         # retry pending ticket-tracker operations
linebreak-gate spec new     [--path .] [--out <file>] [--force]
linebreak-gate spec approve <draft> --approver <name/email> [--role architect] [--path .]
linebreak-gate spec list|next [--path .]
linebreak-gate spec show|check <story-id> [--path .]
linebreak-gate mcp      [--path .]            # serve the approved spec over stdio
linebreak-gate mcp install [--editor claude-code|cursor|codex] [--print]
linebreak-gate badge    [--format markdown|html|url]
linebreak-gate publish  --to <governance-url> [--project <id>] [--path .] [--stage pr|release] [--run-id <id>] [--dry-run]
```

- `init` sets a repo up in one command: writes the pipeline file for the
  repo's CI provider (GitHub Actions workflow, `bitbucket-pipelines.yml` or
  `azure-pipelines.yml`, detected from the git remote or chosen with
  `--provider`; never clobbers an existing one without `--force`), optionally
  writes `.linebreak/gate.yml`, offers to store the secrets via the GitHub CLI
  and to require the `gate` check — and prints the exact settings links for
  anything it can't do for you.
- `ci` is the whole run for CI providers without a native Action (Bitbucket
  Pipelines, Azure DevOps): scan, scoped check, evidence directory, PR comment
  and build status through the provider's API, exit with the worse code. See
  the Bitbucket / Azure section above.

- `scan` runs both detectors, writes git-native audit artifacts under
  `.linebreak/audit/`, and exits 0/1/2.
- `report` renders the recorded scan: counts by severity and every finding
  with CVE id, CVSS, advisory link, and override status. `--format json` for
  machines.
- `override` records a human-approved acknowledgment of **one exact finding**
  — the package + installed version + CVE tuple. A different CVE, a bumped
  version, or a new finding still blocks. `--reason` and `--approver` are
  required; the record lands in the artifact's approval trail. Commit the
  updated `.linebreak/audit/*.json` so CI sees it. `--expires YYYY-MM-DD` (or
  `--days N`) bounds the acceptance in time: past that date the finding
  blocks again as `expired_risk` until the acceptance is renewed or the
  finding is fixed (see [Riesgos aceptados y tickets](#riesgos-aceptados-y-tickets)).
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
security: # exploitation policy, see "Prioridad por explotación" below
  block_kev: true # default: anything in CISA's KEV catalog blocks
  epss_threshold: 0.5 # default: off
criteria:
  enforce: true # default: true whenever a spec bundle exists; false disables
  # criteria checking only (the security scan is unaffected)
risk_acceptance: # optional: accepted risks expire (see the section below)
  max_days: 90 # longest acceptance allowed
  required: true # an override without --expires/--days is refused
tickets: # optional: mirror every acceptance into your tracker
  provider: jira # jira | github
  project: SEC # Jira project key, or "owner/repo" for GitHub Issues
  labels: [linebreak]
```

Precedence: explicit `--fail-on` flag / Action input → `.linebreak/gate.yml` →
built-in default (`critical`). `fail_on` may live at the top level or under
`security:` (not both). An invalid config is a tool error (exit 2):
a broken governance file never silently falls back to a default.

## Prioridad por explotación

Un CVSS alto dice cuánto daño haría una vulnerabilidad; no dice si alguien la
está usando. Desde 1.13.2 la compuerta enriquece cada hallazgo de
dependencias con dos fuentes públicas y ordena y bloquea por explotación real:

- **KEV** (catálogo de vulnerabilidades explotadas conocidas de CISA):
  "la están explotando hoy".
- **EPSS** (FIRST): probabilidad de explotación en los próximos 30 días,
  entre 0 y 1: "probable en 30 días".

### Política

```yaml
# .linebreak/gate.yml
security:
  fail_on: high # piso de severidad (o en la raíz del archivo, no en ambos)
  block_kev: true # cualquier hallazgo en KEV bloquea, sea cual sea su severidad (por defecto)
  epss_threshold: 0.5 # bloquea desde esta probabilidad a 30 días (apagado por defecto)
  intel_max_age_hours: 24 # antigüedad máxima de la caché (por defecto 24 h)
  intel: true # false apaga el enriquecimiento por completo (red y caché)
```

Un hallazgo bloquea por cualquiera de tres disparadores: severidad en o sobre
el piso, presencia en KEV (con `block_kev`) o EPSS en o sobre el umbral. El
motivo queda registrado en cada hallazgo (`block_reason`) y agregado en la
corrida (`block_reasons`) con exactamente dos valores, que el servicio de
gobierno lee por separado: `kev` (en el catálogo) y `vulnerability` (piso de
severidad o umbral EPSS). Cuando aplican los dos, gana `kev`. Un override
registrado con `linebreak-gate override --finding <id>` reconoce el hallazgo
exacto igual que siempre, cualquiera sea el motivo.

### Orden y puntaje

El `report`, el veredicto y el JSON listan los hallazgos en este orden:
primero los que están en KEV, luego por EPSS de mayor a menor, luego por
severidad y CVSS. Un hallazgo sin puntaje EPSS (sin CVE, o un CVE que FIRST
aún no puntúa) va después de los puntuados, ordenado por severidad. Cada uno
muestra su etiqueta: `explotada activamente (KEV)`, `EPSS 0.93` o `sin datos
de explotación`.

```text
  [BLOCKING: kev] CVE-2021-44228  critical cvss 10.0  log4j-core@2.14.1
      explotada activamente (KEV), EPSS 1.00, CISA due 2021-12-24  risk 100
  [BLOCKING: vulnerability] CVE-2024-3094  critical cvss 10.0  xz@5.6.0
      EPSS 0.86  risk 100
  [below floor] CVE-2019-0001  low cvss 2.0  x@1
      EPSS 0.03  risk 20
```

El `risk_score` sube con la explotación y nunca baja: un hallazgo en KEV vale
100 sin importar su severidad; el EPSS eleva el puntaje hasta su probabilidad
en porcentaje (un `medium` con EPSS 0.93 vale 93); la severidad es el piso
(critical 100, high 80, medium 50, low 20). Sin datos de explotación los
números son los de siempre.

### Caché y modo sin red

Las dos fuentes se guardan en `.linebreak/cache/` (la carpeta se ignora sola
en git; el registro de auditoría es `.linebreak/audit/security.json`, no la
caché). Con caché fresca no hay ninguna llamada de red. Con caché vencida se
consulta la red y, si falla, se usa la caché vencida y el reporte lo dice
(`stale`). Sin red y sin caché los campos `epss` y `kev` quedan vacíos
(`null`) y el reporte dice `sin datos de explotación`: el enriquecimiento
nunca convierte un escaneo en error ni cambia el veredicto que habría dado
sin datos. `LINEBREAK_OFFLINE=1` salta la red (la caché sigue usándose), útil
en pipelines sin salida a internet; `security.intel: false` apaga todo.

En el artefacto, `kev: true` es "está en el catálogo", `kev: false` es "se
consultó el catálogo y no está" y `kev: null` es "no se pudo consultar" (o el
hallazgo no tiene CVE): para un auditor son tres hechos distintos. La corrida
registra además `exploit_intel` (fuente y versión del catálogo de esa
corrida) y `verdict` con sus `block_reasons`.

Fuentes: `https://api.first.org/data/v1/epss` (por lotes de CVE) y
`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
Ninguna requiere credenciales.

## Roles e identidad de quien firma (`.linebreak/roles.yml`)

Sin este archivo, cualquiera puede correr `signoff` u `override` y el nombre
que queda en el registro es el que la persona escribió (`identity_source:
client`). Con él, la compuerta sabe quién puede firmar qué:

```yaml
# .linebreak/roles.yml
roles:
  ciso:
    members: [ana@example.com]
    can:
      sign_criteria: ["*"] # patrones sobre el id del criterio, la historia o la épica
      approve_overrides: ["*"]
      accept_security_risk: [critical, high, medium, low]
  qa:
    members: [luis@example.com, "github:luis-qa"]
    can:
      sign_criteria: ["e12-*"]
      approve_overrides: []
      accept_security_risk: [low, medium]
policy:
  require_roles: true # una firma sin rol autorizado se rechaza
  require_verified_identity: false # true: una identidad solo declarada no cuenta
```

- `signoff` y `override` registran el rol con el que se firma: `--role`, o se
  infiere cuando la persona tiene exactamente un rol que lo permite. Si no
  tiene ninguno y `require_roles` está activo, el comando falla y dice qué
  rol haría falta. Aceptar un hallazgo de seguridad se limita por severidad.
- `check`, `scan` y `report` vuelven a evaluar cada firma y cada override
  contra los roles vigentes. Un registro cuyo rol ya no existe, cuyo miembro
  salió, o que no cubre ese criterio, se rechaza con motivo `role_denied` y
  una línea legible (`role denied: <id> (<historia>): ...`); bloquea aunque
  el check corra con `--manual warn`. El registro no se borra: queda como
  evidencia y una firma posterior autorizada lo reemplaza.
- Identidad: además de `client`, la compuerta reconoce `vcs` (en CI toma el
  actor del proveedor: `GITHUB_ACTOR`, `GITLAB_USER_EMAIL`,
  `BITBUCKET_STEP_TRIGGERER_UUID`, `BUILD_REQUESTEDFOREMAIL`) y `governance`
  (con `LINEBREAK_GOVERNANCE_BASE_URL` y `LINEBREAK_GOVERNANCE_TOKEN`
  consulta `GET /v1/me` y usa esa identidad; un token configurado que falla
  detiene el comando, nunca cae en silencio a un nombre escrito). La
  identidad verificada manda; lo que se escribió en `--approver` se guarda
  como `declared_approver`. En la lista de miembros se puede poner un correo
  o la forma `proveedor:login` (`github:luis-qa`).
- `policy.require_verified_identity: true` hace que una firma con
  `identity_source: client` se registre como declarada pero no cuente: el
  comando lo avisa al firmar y `check` la rechaza con motivo
  `identity_unverified`.
- Sin archivo, o con ambas políticas en `false`, nada cambia: nada se rechaza
  y los registros llevan `role: null`. Un archivo malformado es error de
  configuración (exit 2), nunca una omisión silenciosa.

## Audit records

Every scan and every override is recorded in `.linebreak/audit/security.json`
(dependencies) and `.linebreak/audit/code.json` (AI SAST) — the same versioned
document format the LineBreak tools write, carrying findings (CVE id,
CVSS, advisory link), scanner engine, timestamp, actor, and the approval trail
with each override's reason + approver, the role it was made under, and the
identity source (`client`, `vcs`, `governance`). Who relaxed the gate, and
when, is itself auditable.

## Riesgos aceptados y tickets

Una excepción registrada con `override` era para siempre: la persona que
aceptó el riesgo se va y el riesgo se queda. Desde la versión 1.13.3 cada
aceptación puede (o debe) vencer, y cada excepción vive también en el gestor de
tickets del equipo, para que la trazabilidad quede en su herramienta y no solo
en LineBreak.

### Vencimiento

```bash
linebreak-gate override --finding <id> --reason "…" --approver ana@example.com --expires 2026-12-31
linebreak-gate override --criterion <id> --reason "…" --approver ana@example.com --days 30
```

- `--expires YYYY-MM-DD` o `--days N` fijan la fecha en que la aceptación deja
  de valer. Vale hasta ese día inclusive; al día siguiente el hallazgo (o el
  criterio) **vuelve a bloquear** con motivo `expired_risk`. El informe dice
  qué hallazgo es, quién lo aceptó, cuándo venció y las dos salidas: renovar
  con otro `override` o corregir.
- Con menos de 14 días por vencer, `scan`, `report` y `check` avisan sin
  bloquear (`expiring risk` / `expiring exception`).
- La política vive en `.linebreak/gate.yml`:

  ```yaml
  risk_acceptance:
    max_days: 90 # ninguna aceptación puede ir más allá de 90 días
    required: true # un override sin vencimiento se rechaza (exit 2)
  ```

  Sin este bloque, las aceptaciones sin fecha siguen permitidas (el
  comportamiento anterior). La misma política aplica a hallazgos de seguridad
  y a excepciones de criterios.

- Renovar es registrar un `override` nuevo sobre el mismo objetivo. La
  aceptación anterior **no se pisa**: queda en el historial del artefacto
  (`.linebreak/audit/security.json`, `code.json`, `criteria.json`) y la más
  reciente es la que rige. Cada entrada guarda `expires`, y `ticket` cuando
  hay gestor configurado.
- En `--format json`, `scan`/`report` traen `block_reasons` (`vulnerability`,
  `expired_risk`) y, por detector, `expired` y `expiring`; `check` trae
  `block_reasons`, `expired_overrides` y `expiring_overrides`.

### Tickets (Jira primero, GitHub Issues también)

```yaml
# .linebreak/gate.yml
tickets:
  provider: jira # jira | github
  project: SEC # clave del proyecto en Jira, o "owner/repo" para GitHub Issues
  labels: [linebreak] # etiquetas que llevan todos los tickets
  main_branch: main # rama cuyos scans abren tickets de atención (opcional)
  issue_type: Task # solo Jira: tipo de incidencia a crear (opcional)
```

Credenciales por entorno, nunca en el repositorio: `JIRA_BASE_URL`,
`JIRA_EMAIL` y `JIRA_API_TOKEN` para Jira (API REST v2, funciona en Cloud y en
Data Center); `GITHUB_TOKEN` para GitHub Issues.

Qué hace la compuerta cuando hay un `tickets:` configurado:

| Momento                                                                                            | Qué pasa en el gestor                                                                                                                                                                                                                                     |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `override` acepta un hallazgo o excusa un criterio                                                 | Crea un ticket con el hallazgo o criterio, quién aceptó, motivo, vencimiento, repositorio, commit y enlace al registro de evidencia. La clave queda en la entrada de evidencia (`ticket: "SEC-123"`). Si ya existía, lo comenta y lo reabre (renovación). |
| `scan` o `check` ven una aceptación vencida                                                        | Comenta el ticket y lo reabre si estaba cerrado. Un solo comentario por fecha de vencimiento, aunque el gate corra en cada push.                                                                                                                          |
| El hallazgo desaparece del scan, o el criterio pasa por sí solo en un `check` completo             | Comenta y cierra el ticket.                                                                                                                                                                                                                               |
| Un `scan` en la rama principal encuentra un hallazgo que no estaba en el escaneo anterior guardado | Abre un ticket de atención (vulnerabilidad nueva sobre código ya liberado).                                                                                                                                                                               |

Detalles que conviene saber:

- **El gestor nunca bloquea el veredicto.** Sin red, credenciales malas o un
  proyecto que rechaza la incidencia: el veredicto es el que dicen los
  artefactos, se imprime un aviso, el error queda en la evidencia
  (`ticket_error` en la entrada) y la operación queda pendiente en
  `.linebreak/audit/tickets.json`. `linebreak-gate tickets sync` reintenta lo
  pendiente (exit 0 cuando no queda nada; exit 1 si algo sigue pendiente).
- **La idempotencia vive en el gestor.** Cada ticket lleva las etiquetas
  `linebreak-target-<hash>` y `linebreak-artifact-<security|code|criteria>`;
  antes de crear, la compuerta busca por etiqueta. Así un runner de CI que no
  tiene el libro local nunca duplica tickets, y puede cerrar los de hallazgos
  corregidos.
- **"Nuevo" en la rama principal** se mide contra el artefacto anterior en
  `.linebreak/audit/` (el que estaba comprometido antes de reescribirlo). El
  primer scan de un repositorio no abre nada: no hay línea base. Solo cuentan
  hallazgos a la altura del umbral `fail_on` o por encima, y que no tengan ya
  un ticket. En GitHub Actions la rama se lee de `GITHUB_REF_NAME`; un pull
  request (`GITHUB_HEAD_REF`) nunca cuenta como rama principal.
- Conviene comprometer `.linebreak/audit/tickets.json` junto con el
  `override` (igual que `security.json`), para que el historial del ticket
  viaje con la evidencia.

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
