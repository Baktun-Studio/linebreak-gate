"""Which version of a deployed environment a criterion measured (issue #264).

A ``command`` criterion that runs end-to-end tests against a deployed
environment (staging) gives its verdict about whatever that environment runs,
which is not necessarily the commit being evaluated. A criterion can declare
the environment it measures::

    check:
      type: command
      payload: node scripts/qa/flujos.mjs --base "$STAGING_URL" --flujo f1
      when: release
      environment:
        name: staging
        version_url: ${STAGING_URL}/version   # answers the deployed commit
        field: commit                         # optional, JSON key (dotted)

Before running the check the gate asks ``version_url`` for the deployed
version, runs the check, asks again, and records on the criterion:

* ``version``: what the environment answered (JSON ``field``, else the first
  of ``commit``/``sha``/``git_sha``/``revision``/``version``, else the first
  line of a plain-text body);
* ``status``: ``current`` (the evaluated commit), ``behind`` (an ancestor of
  it, with how many commits), ``ahead``, ``diverged``, ``unknown`` (not a
  commit this clone knows, e.g. a shallow checkout), ``unreachable`` (no
  answer, or a variable in the URL is not set) or ``changed`` (the version
  moved while the check ran);
* ``behind_main``: commits the version is behind the main branch, when known.

Anything but ``current`` is a WARNING in the report and in the record: the
verdict stands, but it now says what it measured. Nothing here blocks.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: url -> (status, body text). Raises on transport trouble.
Fetch = Callable[[str], tuple[int, str]]

VERSION_KEYS = ("commit", "sha", "git_sha", "revision", "version")
_TIMEOUT_S = 10
_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_MAX_VERSION = 120

STATUSES = ("current", "behind", "ahead", "diverged", "unknown", "unreachable", "changed")


def expand(url: str, env: Mapping[str, str]) -> tuple[str, list[str]]:
    """``$VAR`` / ``${VAR}`` expanded from ``env``; returns the URL and the
    names that were not set (an unset variable is never replaced by nothing
    silently: the caller reports the environment as unreachable)."""
    missing: list[str] = []

    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        value = env.get(name)
        if not value:
            missing.append(name)
            return ""
        return value

    return _VAR_RE.sub(sub, url), missing


def _one_line(text: str) -> str:
    return " ".join(text.split())[:_MAX_VERSION]


def parse_version(body: str, field: str | None = None) -> str | None:
    """The version an endpoint answered, or ``None`` when it says nothing usable."""
    text = (body or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        data = None
    if isinstance(data, dict):
        if field:
            node: Any = data
            for part in field.split("."):
                node = node.get(part) if isinstance(node, dict) else None
            return _one_line(str(node)) if isinstance(node, (str, int, float)) else None
        for key in VERSION_KEYS:
            value = data.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                return _one_line(str(value))
        return None
    if isinstance(data, (str, int, float)):
        return _one_line(str(data)) or None
    if field:
        return None
    first = text.splitlines()[0]
    return _one_line(first) or None


def _default_fetch(url: str) -> tuple[int, str]:
    from . import __version__

    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json, text/plain;q=0.9",
            "User-Agent": f"linebreak-gate/{__version__}",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_S) as response:
            return response.status, response.read(64 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, ""


def probe(spec: Mapping[str, Any], env: Mapping[str, str], fetch: Fetch | None = None) -> dict:
    """Ask the environment for its version once. Never raises."""
    url, missing = expand(str(spec.get("version_url") or ""), env)
    out: dict[str, Any] = {"url": url if not missing else str(spec.get("version_url"))}
    if missing:
        out["error"] = f"{', '.join(sorted(set(missing)))} not set"
        return out
    try:
        status, body = (fetch or _default_fetch)(url)
    except Exception as e:  # noqa: BLE001 - an unreachable environment is a warning
        out["error"] = f"unreachable: {e}"
        return out
    if status != 200:
        out["error"] = f"answered {status}"
        return out
    version = parse_version(body, spec.get("field"))
    if version is None:
        field = spec.get("field")
        out["error"] = f"no version in the answer{f' (field {field})' if field else ''}"
        return out
    out["version"] = version
    return out


# ---------------------------------------------------------------- git


def _git(root: Path, *args: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return proc.returncode, proc.stdout.strip()


def _commit_of(root: Path, ref: str) -> str | None:
    if not ref or ref.startswith("-"):
        return None
    code, out = _git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
    return out if code == 0 and out else None


def _is_ancestor(root: Path, a: str, b: str) -> bool:
    code, _ = _git(root, "merge-base", "--is-ancestor", a, b)
    return code == 0


def _count(root: Path, a: str, b: str) -> int | None:
    code, out = _git(root, "rev-list", "--count", f"{a}..{b}")
    return int(out) if code == 0 and out.isdigit() else None


def evaluated_commit(root: Path, env: Mapping[str, str]) -> str | None:
    """The commit this run evaluates: the checkout's HEAD (the code on disk is
    what the checks ran against), else what the CI provider says."""
    from . import ci_env

    return _commit_of(root, "HEAD") or ci_env.detect(env).commit


def main_ref(root: Path, env: Mapping[str, str]) -> str | None:
    """The main branch to compare against: the PR's target branch, the
    provider's default branch, ``origin/HEAD``, then ``origin/main``/``main``."""
    from . import ci_env

    ci = ci_env.detect(env)
    names = [n for n in (ci.target_branch, ci.default_branch) if n]
    for name in names:
        for ref in (f"origin/{name}", name):
            if _commit_of(root, ref):
                return ref
    code, out = _git(root, "symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD")
    if code == 0 and out:
        return out
    for ref in ("origin/main", "main", "origin/master", "master"):
        if _commit_of(root, ref):
            return ref
    return None


def relate(root: Path, version: str, commit: str | None, main: str | None) -> dict[str, Any]:
    """Where ``version`` stands relative to the evaluated commit and main."""
    out: dict[str, Any] = {}
    if (
        commit
        and _HEX_RE.match(version)
        and (
            commit.lower().startswith(version.lower()) or version.lower().startswith(commit.lower())
        )
    ):
        out["status"] = "current"
        return out
    resolved = _commit_of(root, version)
    if resolved is None or commit is None:
        out["status"] = "unknown"
        return out
    out["resolved"] = resolved
    if resolved == commit:
        out["status"] = "current"
    elif _is_ancestor(root, resolved, commit):
        out["status"] = "behind"
        out["behind"] = _count(root, resolved, commit)
    elif _is_ancestor(root, commit, resolved):
        out["status"] = "ahead"
        out["ahead"] = _count(root, commit, resolved)
    else:
        out["status"] = "diverged"
    main_commit = _commit_of(root, main) if main else None
    if main_commit and resolved != main_commit and _is_ancestor(root, resolved, main_commit):
        out["main"] = main
        out["behind_main"] = _count(root, resolved, main_commit)
    return out


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def measure(
    spec: Mapping[str, Any],
    root: Path,
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The record for one criterion from the two probes around its run."""
    env = os.environ if env is None else env
    record: dict[str, Any] = {
        "name": spec.get("name") or "environment",
        "url": before.get("url"),
        "measured_at": _now(),
    }
    commit = evaluated_commit(root, env)
    record["commit"] = commit
    v1, v2 = before.get("version"), after.get("version")
    if v1 is None or v2 is None:
        record["status"] = "unreachable"
        record["version"] = v1 or v2
        record["note"] = before.get("error") or after.get("error") or "no version"
        return record
    record["version"] = v1
    if v1 != v2:
        record["status"] = "changed"
        record["version_after"] = v2
        return record
    record.update(relate(root, v1, commit, main_ref(root, env)))
    return record


def warning(criterion_id: str, record: Mapping[str, Any]) -> str | None:
    """One line saying what a non-current measurement means, or ``None``."""
    name = record.get("name") or "environment"
    version = record.get("version")
    commit = str(record.get("commit") or "?")[:12]
    status = record.get("status")
    main_note = ""
    if record.get("behind_main"):
        main_note = f"; {record['behind_main']} commit(s) behind {record.get('main')}"
    if status == "current":
        return None
    if status == "unreachable":
        return (
            f"{criterion_id} measured {name} without knowing its version "
            f"({record.get('note')}): the verdict does not say what it measured"
        )
    if status == "changed":
        return (
            f"{criterion_id}: {name} changed version while the check ran ({version} then "
            f"{record.get('version_after')}): the verdict mixes two deployments"
        )
    if status == "behind":
        return (
            f"{criterion_id} measured {name} at {version}, {record.get('behind')} commit(s) "
            f"behind the evaluated commit {commit}{main_note}: this verdict is about older code"
        )
    if status == "ahead":
        return (
            f"{criterion_id} measured {name} at {version}, ahead of the evaluated commit "
            f"{commit}: this verdict is about newer code"
        )
    if status == "diverged":
        return (
            f"{criterion_id} measured {name} at {version}, which is not in the history of the "
            f"evaluated commit {commit}{main_note}"
        )
    return (
        f"{criterion_id} measured {name} at {version}, a version this clone cannot relate "
        f"to the evaluated commit {commit} (shallow checkout, or not a commit)"
    )
