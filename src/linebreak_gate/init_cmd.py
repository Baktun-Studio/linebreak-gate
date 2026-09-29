"""``linebreak-gate init`` — one command sets a repo up with the gate.

Produces the same end state as the manual quickstart: the pipeline file for
the repo's CI provider (GitHub Actions, Bitbucket Pipelines or Azure
Pipelines, detected from the git remote or chosen with ``--provider``), an
optional ``.linebreak/gate.yml``, the secrets (via ``gh`` on GitHub when
available), and the branch-protection requirement (offered on GitHub,
documented with deep links elsewhere; never forced). Everything is
best-effort and idempotent: an existing (possibly customized) file is never
clobbered without ``--force``, and a failed convenience step degrades to
printing the exact link to do it by hand.
"""

from __future__ import annotations

import getpass
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gate_config import CONFIG_RELPATH, FAIL_ON_LEVELS, GateConfigError

PROVIDERS = ("github", "bitbucket", "azure")

WORKFLOW_RELPATH = Path(".github") / "workflows" / "security-gate.yml"
BITBUCKET_RELPATH = Path("bitbucket-pipelines.yml")
AZURE_RELPATH = Path("azure-pipelines.yml")

# The canonical client snippet. Keep in sync with packages/gate/README.md and
# the linebreakapp.com generator page.
WORKFLOW_TEMPLATE = """\
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
"""

# Bitbucket Pipelines. Keep in sync with the README section for Bitbucket.
# `linebreak-gate ci` does scan + check + PR comment + build status and exits
# 0/1/2; the step fails on 1 or 2, and a merge check on "no failed builds"
# turns that into a blocked merge.
BITBUCKET_PIPELINES_TEMPLATE = """\
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
"""

# Azure Pipelines. Keep in sync with the README section for Azure DevOps.
# On Azure Repos, PR runs come from the branch policy (Build validation), not
# from the `pr:` trigger below, which only applies to GitHub/Bitbucket sources.
AZURE_PIPELINES_TEMPLATE = """\
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
"""

PROVIDER_FILES: dict[str, tuple[Path, str]] = {
    "github": (WORKFLOW_RELPATH, WORKFLOW_TEMPLATE),
    "bitbucket": (BITBUCKET_RELPATH, BITBUCKET_PIPELINES_TEMPLATE),
    "azure": (AZURE_RELPATH, AZURE_PIPELINES_TEMPLATE),
}

_REMOTE_RE = re.compile(
    r"(?:git@github\.com:|https://(?:[^@/\s]+@)?github\.com/|ssh://git@github\.com(?::\d+)?/)"
    r"(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_BITBUCKET_RE = re.compile(
    r"(?:git@bitbucket\.org:|https://(?:[^@/\s]+@)?bitbucket\.org/|"
    r"ssh://git@bitbucket\.org(?::\d+)?/)"
    r"(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)
_AZURE_HTTPS_RE = re.compile(
    r"https://(?:[^@/\s]+@)?dev\.azure\.com/(?P<org>[^/\s]+)/(?P<project>[^/\s]+)/_git/"
    r"(?P<repo>[^/\s]+?)/?$",
    re.IGNORECASE,
)
_AZURE_SSH_RE = re.compile(
    r"git@ssh\.dev\.azure\.com:v3/(?P<org>[^/\s]+)/(?P<project>[^/\s]+)/(?P<repo>[^/\s]+?)/?$",
    re.IGNORECASE,
)
_AZURE_VSTS_RE = re.compile(
    r"https://(?:[^@/\s]+@)?(?P<org>[^./\s]+)\.visualstudio\.com/(?:DefaultCollection/)?"
    r"(?P<project>[^/\s]+)/_git/(?P<repo>[^/\s]+?)/?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Remote:
    """The parsed ``origin``: who hosts it and how to name it there. ``owner``
    is the GitHub owner, the Bitbucket workspace or the Azure organization;
    ``project`` is set on Azure only."""

    provider: str
    owner: str
    repo: str
    project: str | None = None

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def _parse_github_remote(url: str | None) -> tuple[str, str] | None:
    if not url:
        return None
    m = _REMOTE_RE.match(url.strip())
    return (m.group("owner"), m.group("repo")) if m else None


def parse_remote(url: str | None) -> Remote | None:
    """Classify a git remote URL as GitHub, Bitbucket Cloud or Azure Repos;
    None for anything else (self-hosted servers, unknown hosts)."""
    if not url:
        return None
    url = url.strip()
    gh = _parse_github_remote(url)
    if gh:
        return Remote("github", gh[0], gh[1])
    m = _BITBUCKET_RE.match(url)
    if m:
        return Remote("bitbucket", m.group("owner"), m.group("repo"))
    for pattern in (_AZURE_HTTPS_RE, _AZURE_SSH_RE, _AZURE_VSTS_RE):
        m = pattern.match(url)
        if m:
            return Remote("azure", m.group("org"), m.group("repo"), project=m.group("project"))
    return None


def _detect_remote(root: Path, run) -> Remote | None:
    try:
        proc = run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            cwd=str(root),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if getattr(proc, "returncode", 1) != 0:
        return None
    return parse_remote((proc.stdout or "").strip())


def _write_once(path: Path, content: str, force: bool) -> bool:
    """Write ``content`` unless the file already exists (idempotent; a client's
    customized file is never clobbered without --force). Returns written?"""
    if path.exists() and not force:
        print(f"  - {path} already exists — left untouched (use --force to overwrite)")
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"  + wrote {path}")
    return True


def _run_ok(run, cmd: list[str], input: str | None = None):
    """Run a convenience command, returning the completed process or None on
    any failure — setup helpers must degrade to deep links, never crash.
    Bounded so an unattended (scripted/CI) init can never hang on a stalled
    network call; a timeout degrades like any other failure."""
    try:
        proc = run(cmd, input=input, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc if proc.returncode == 0 else None


def _set_secret(run, slug: str, name: str, value: str) -> bool:
    return _run_ok(run, ["gh", "secret", "set", name, "--repo", slug], input=value) is not None


def _repo_perms(run, slug: str) -> tuple[bool, bool] | None:
    """(admin, push) for the gh-authenticated account on ``slug`` — GitHub
    hides the secrets and branch-protection settings pages from non-admins
    (they 404), and non-push accounts can't even commit the workflow file.
    None = could not determine (offline, no auth): proceed rather than block."""
    proc = _run_ok(
        run, ["gh", "api", f"repos/{slug}", "--jq", r'"\(.permissions.admin) \(.permissions.push)"']
    )
    out = (proc.stdout or "").strip().lower() if proc else ""
    parts = out.split()
    if len(parts) == 2 and all(p in ("true", "false") for p in parts):
        return (parts[0] == "true", parts[1] == "true")
    return None


def _default_branch(run, slug: str) -> str:
    """The repo's default branch via gh (protection must target the branch
    clients actually merge to — hardcoding main would silently protect the
    wrong branch on master/develop repos); falls back to main."""
    proc = _run_ok(run, ["gh", "api", f"repos/{slug}", "--jq", ".default_branch"])
    name = (proc.stdout or "").strip() if proc else ""
    return name or "main"


def _resolve_providers(provider: str, remote: Remote | None) -> tuple[list[str], str | None]:
    """Which pipeline files to write, and a note when the choice was a
    fallback. ``auto`` follows the remote; an unknown remote falls back to
    GitHub (the historical default) and says how to get the others."""
    if provider == "all":
        return list(PROVIDERS), None
    if provider in PROVIDERS:
        return [provider], None
    if remote is not None:
        return [remote.provider], None
    return ["github"], (
        "no GitHub, Bitbucket or Azure remote detected; wrote the GitHub workflow. "
        "For Bitbucket Pipelines or Azure Pipelines run `linebreak-gate init --provider "
        "bitbucket|azure|all`."
    )


def run_init(
    *,
    path: str | Path = ".",
    fail_on: str | None = None,
    force: bool = False,
    interactive: bool = True,
    provider: str = "auto",
    run=subprocess.run,
    which: Callable[[str], Any] = shutil.which,
    prompt_fn: Callable[[str], str] | None = None,
    confirm_fn: Callable[[str], bool] | None = None,
) -> int:
    """Set the repo at ``path`` up with the security gate. Returns exit code."""
    root = Path(path).resolve()

    if fail_on and fail_on not in FAIL_ON_LEVELS:
        raise GateConfigError(
            f"invalid --fail-on {fail_on!r}; expected one of {', '.join(FAIL_ON_LEVELS)}"
        )
    if provider not in ("auto", "all", *PROVIDERS):
        raise GateConfigError(
            f"invalid --provider {provider!r}; expected auto, all, or one of {', '.join(PROVIDERS)}"
        )
    print("linebreak-gate init")
    remote = _detect_remote(root, run)
    providers, note = _resolve_providers(provider, remote)
    if note:
        print(f"  ! {note}")
    for name in providers:
        relpath, template = PROVIDER_FILES[name]
        _write_once(root / relpath, template, force)
    if fail_on:
        _write_once(
            root / CONFIG_RELPATH,
            f"# LineBreak security gate policy — changing this file is itself a PR.\nfail_on: {fail_on}\n",
            force,
        )

    for name in providers:
        target = remote if remote is not None and remote.provider == name else None
        if name == "github":
            _github_setup(
                target,
                run=run,
                which=which,
                interactive=interactive,
                prompt_fn=prompt_fn,
                confirm_fn=confirm_fn,
            )
        elif name == "bitbucket":
            _bitbucket_setup(target)
        else:
            _azure_setup(target)
    _print_next_steps(providers)
    return 0


# ---------------------------------------------------------------- GitHub


def _github_setup(
    remote: Remote | None,
    *,
    run,
    which: Callable[[str], Any],
    interactive: bool,
    prompt_fn: Callable[[str], str] | None,
    confirm_fn: Callable[[str], bool] | None,
) -> None:
    def _safe(fn, fallback):
        def wrapped(msg):
            try:
                return fn(msg)
            except (EOFError, KeyboardInterrupt):
                return fallback

        return wrapped

    prompt = _safe(prompt_fn or (lambda msg: getpass.getpass(msg)), "")
    confirm = _safe(
        lambda msg: (confirm_fn or (lambda m: input(m).strip().lower().startswith("y")))(msg),
        False,
    )

    if remote is None:
        print(
            "  ! could not detect a GitHub remote — after pushing this repo to GitHub,\n"
            "    add secrets under Settings → Secrets and variables → Actions\n"
            "    (LINEBREAK_LICENSE_KEY, and ANTHROPIC_API_KEY for the AI review),\n"
            "    and require the `gate` check under Settings → Branches."
        )
        return

    slug = remote.slug
    secrets_url = f"https://github.com/{slug}/settings/secrets/actions"
    branches_url = f"https://github.com/{slug}/settings/branches"

    gh = which("gh")
    perms = _repo_perms(run, slug) if gh else None
    if perms is not None and not perms[0]:
        # Warn BEFORE the person walks into GitHub's unexplained 404: the two
        # remaining steps need the admin role on the repo.
        access = (
            "write access but NOT the admin role"
            if perms[1]
            else "read-only access (no push, no admin) — you also can't commit the workflow file yourself"
        )
        print(
            f"  ! your account has {access} on "
            f"{slug} — GitHub will show a 404 on the secrets and branch-"
            "protection settings pages.\n"
            "    Send this to the repo's owner (or ask them for the admin role):\n"
            "    ---\n"
            f"    Please add these two things to {slug} so the LineBreak security\n"
            "    gate can enforce on our pull requests:\n"
            f"    1. secrets LINEBREAK_LICENSE_KEY and ANTHROPIC_API_KEY: {secrets_url}\n"
            f"    2. require the `gate` status check: {branches_url}\n"
            "    ---"
        )
        return
    if gh and interactive:
        for name, label in (
            ("ANTHROPIC_API_KEY", "Anthropic API key (enables the AI code review)"),
            ("LINEBREAK_LICENSE_KEY", "LineBreak license key (optional today)"),
        ):
            value = prompt(f"  ? {label} — paste to set, Enter to skip: ").strip()
            if not value:
                print(f"  - skipped {name} (add later: {secrets_url})")
                continue
            if _set_secret(run, slug, name, value):
                print(f"  + secret {name} set on {slug}")
            else:
                print(f"  ! could not set {name} via gh — add it by hand: {secrets_url}")
        if confirm("  ? Require the `gate` check on your default branch now? [y/N] "):
            branch = _default_branch(run, slug)
            ok = (
                _run_ok(
                    run,
                    [
                        "gh",
                        "api",
                        "-X",
                        "POST",
                        f"repos/{slug}/branches/{branch}/protection/required_status_checks/contexts",
                        "--input",
                        "-",
                    ],
                    input='["gate"]',
                )
                is not None
            )
            if ok:
                print(f"  + `gate` added to the required checks on {branch}")
            else:
                print(
                    "  ! could not update branch protection (no rule yet, or missing "
                    f"permission) — require the `gate` check by hand: {branches_url}"
                )
        else:
            print(
                f"  - branch protection left as-is — the gate only blocks merges once the\n    `gate` check is required: {branches_url}"
            )
    else:
        reason = "GitHub CLI (`gh`) not found" if not gh else "running non-interactively"
        print(f"  ! {reason} — two manual steps remain (the gate is NOT enforced until done):")
        print(f"    1. secrets (LINEBREAK_LICENSE_KEY, ANTHROPIC_API_KEY): {secrets_url}")
        print(f"    2. require the `gate` check: {branches_url}")


# ---------------------------------------------------------------- Bitbucket


def bitbucket_links(remote: Remote | None) -> dict[str, str]:
    base = (
        f"https://bitbucket.org/{remote.slug}"
        if remote
        else "https://bitbucket.org/<workspace>/<repo>"
    )
    return {
        "variables": f"{base}/admin/pipelines/repository-variables",
        "tokens": f"{base}/admin/access-tokens",
        "restrictions": f"{base}/admin/branch-restrictions",
    }


def _bitbucket_setup(remote: Remote | None) -> None:
    links = bitbucket_links(remote)
    where = f"on {remote.slug}" if remote else "on your Bitbucket repository"
    print(f"  ! three manual steps remain {where} (the gate is NOT enforced until done):")
    print(
        "    1. repository variables (mark them secured): LINEBREAK_LICENSE_KEY,\n"
        f"       ANTHROPIC_API_KEY for the AI review: {links['variables']}"
    )
    print(
        "    2. a repository access token with scopes pullrequest:write and repository:write,\n"
        f"       stored as the secured variable BITBUCKET_ACCESS_TOKEN: {links['tokens']}\n"
        "       (without it the pipeline still blocks; only the PR comment and status are skipped)"
    )
    print(
        "    3. merge checks on the main branch: 'Check the last commit for at least 1\n"
        "       successful build and no failed builds' (Bitbucket Cloud Premium; on Standard,\n"
        f"       also require reviewers and watch the red build): {links['restrictions']}"
    )


# ---------------------------------------------------------------- Azure DevOps


def azure_links(remote: Remote | None) -> dict[str, str]:
    if remote and remote.project:
        base = f"https://dev.azure.com/{remote.owner}/{remote.project}"
        repo = remote.repo
    else:
        base = "https://dev.azure.com/<org>/<project>"
        repo = "<repo>"
    return {
        "branches": f"{base}/_git/{repo}/branches",
        "repositories": f"{base}/_settings/repositories",
        "library": f"{base}/_library?itemType=VariableGroups",
        "pipelines": f"{base}/_build",
    }


def _azure_setup(remote: Remote | None) -> None:
    links = azure_links(remote)
    where = (
        f"on {remote.owner}/{remote.project}/{remote.repo}"
        if remote
        else "on your Azure DevOps project"
    )
    print(f"  ! four manual steps remain {where} (the gate is NOT enforced until done):")
    print(
        f"    1. create the pipeline from azure-pipelines.yml: {links['pipelines']}\n"
        "       and add the secret variables LINEBREAK_LICENSE_KEY and ANTHROPIC_API_KEY\n"
        f"       (pipeline Variables, or a variable group: {links['library']})"
    )
    print(
        "    2. repository security: grant the build service identity\n"
        "       '<project> Build Service (<org>)' the permission 'Contribute to pull requests'\n"
        f"       so the gate can post the PR comment and status: {links['repositories']}"
    )
    print(
        "    3. branch policies on main: Build validation with this pipeline, Required,\n"
        f"       trigger Automatic: {links['branches']} (branch menu > Branch policies)"
    )
    print(
        "    4. optional: Status checks policy on the status 'linebreak/gate' posted by the\n"
        "       gate, so the PR also waits for the gate's own verdict"
    )


def _print_next_steps(providers: list[str] | None = None) -> None:
    names = ", ".join(providers or ["github"])
    print(
        "Done. Next steps:\n"
        f"  1. commit and push the new file(s) ({names}), open a pull request\n"
        "  2. the gate runs on every PR from then on: vulnerable code\n"
        "     can't merge without a recorded human override\n"
        "  3. optional: `linebreak-gate badge` prints a README badge that shows the gate"
    )
