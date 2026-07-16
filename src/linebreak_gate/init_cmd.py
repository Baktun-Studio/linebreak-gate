"""``linebreak-gate init`` — one command sets a repo up with the gate.

Produces the same end state as the manual quickstart: the workflow file, an
optional ``.linebreak/gate.yml``, the two GitHub secrets (via ``gh`` when
available), and the branch-protection requirement (offered, never forced).
Everything is best-effort and idempotent: an existing (possibly customized)
file is never clobbered without ``--force``, and a failed convenience step
degrades to printing the exact deep link to do it by hand.
"""

from __future__ import annotations

import getpass
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .gate_config import CONFIG_RELPATH, FAIL_ON_LEVELS, GateConfigError

WORKFLOW_RELPATH = Path(".github") / "workflows" / "security-gate.yml"

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

_REMOTE_RE = re.compile(
    r"(?:git@github\.com:|https://(?:[^@/\s]+@)?github\.com/|ssh://git@github\.com(?::\d+)?/)"
    r"(?P<owner>[^/\s]+)/(?P<repo>[^/\s]+?)(?:\.git)?/?$",
    re.IGNORECASE,
)


def _parse_github_remote(url: str | None) -> tuple[str, str] | None:
    if not url:
        return None
    m = _REMOTE_RE.match(url.strip())
    return (m.group("owner"), m.group("repo")) if m else None


def _detect_remote(root: Path, run) -> tuple[str, str] | None:
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
    return _parse_github_remote((proc.stdout or "").strip())


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


def run_init(
    *,
    path: str | Path = ".",
    fail_on: str | None = None,
    force: bool = False,
    interactive: bool = True,
    run=subprocess.run,
    which: Callable[[str], Any] = shutil.which,
    prompt_fn: Callable[[str], str] | None = None,
    confirm_fn: Callable[[str], bool] | None = None,
) -> int:
    """Set the repo at ``path`` up with the security gate. Returns exit code."""
    root = Path(path).resolve()

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

    if fail_on and fail_on not in FAIL_ON_LEVELS:
        raise GateConfigError(
            f"invalid --fail-on {fail_on!r}; expected one of {', '.join(FAIL_ON_LEVELS)}"
        )
    print("linebreak-gate init")
    _write_once(root / WORKFLOW_RELPATH, WORKFLOW_TEMPLATE, force)
    if fail_on:
        _write_once(
            root / CONFIG_RELPATH,
            f"# LineBreak security gate policy — changing this file is itself a PR.\nfail_on: {fail_on}\n",
            force,
        )

    remote = _detect_remote(root, run)
    if remote is None:
        print(
            "  ! could not detect a GitHub remote — after pushing this repo to GitHub,\n"
            "    add secrets under Settings → Secrets and variables → Actions\n"
            "    (LINEBREAK_LICENSE_KEY, and ANTHROPIC_API_KEY for the AI review),\n"
            "    and require the `gate` check under Settings → Branches."
        )
        _print_next_steps()
        return 0

    owner, repo = remote
    slug = f"{owner}/{repo}"
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
        _print_next_steps()
        return 0
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

    _print_next_steps()
    return 0


def _print_next_steps() -> None:
    print(
        "Done. Next steps:\n"
        "  1. commit and push the new file(s), open a pull request\n"
        "  2. the `gate` check runs on every PR from then on — vulnerable code\n"
        "     can't merge without a recorded human override"
    )
