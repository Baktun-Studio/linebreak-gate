"""The Action's check step (issue #256): `scripts/check-scope.sh` resolves the
`story` and `manual` inputs into `linebreak-gate check` flags.

* `story: all` runs the full bundle; an explicit id passes `--story <id>`;
  `story: auto` infers the id from a `feat/<id>` or `story/<id>` branch when
  that id is an approved story, and falls back to `--started-only` otherwise.
* `manual` defaults to `warn` on pull_request events and `block` elsewhere;
  any other value is a tool error (exit 2, fail closed).
* The resolved scope is written as the first line of the criteria report so
  the PR comment can show it.

The gate binary is a recording shim on PATH, so these tests exercise the
script's decisions only (the CLI's own behavior is pinned elsewhere).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-scope.sh"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="bash script; POSIX runners")

#: The shim: records every invocation, answers `spec show` per a known-id
#: list, and exits with a configurable code for `check`.
_SHIM = """#!/usr/bin/env bash
echo "$*" >> "$SHIM_LOG"
if [ "$1" = "spec" ] && [ "$2" = "show" ]; then
  case " $KNOWN_STORIES " in *" $3 "*) exit 0 ;; *) echo "unknown story" >&2; exit 1 ;; esac
fi
echo "shim check output"
exit "${CHECK_EXIT:-0}"
"""


@pytest.fixture
def shim(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "linebreak-gate"
    exe.write_text(_SHIM, encoding="utf-8")
    exe.chmod(0o755)
    return bin_dir


def _run(
    shim,
    tmp_path,
    *,
    story,
    manual="",
    event="pull_request",
    branch="main",
    known="S1 S2",
    check_exit=0,
):
    log = tmp_path / "calls.log"
    out = tmp_path / "criteria.txt"
    env = {
        **os.environ,
        "PATH": f"{shim}{os.pathsep}{os.environ['PATH']}",
        "SHIM_LOG": str(log),
        "KNOWN_STORIES": known,
        "CHECK_EXIT": str(check_exit),
        "INPUT_STORY": story,
        "INPUT_MANUAL": manual,
        "EVENT_NAME": event,
        "BRANCH": branch,
    }
    proc = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path), str(out)],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    report = out.read_text(encoding="utf-8") if out.exists() else ""
    return proc.returncode, calls, report, proc.stdout + proc.stderr


def _check_call(calls):
    return next(c for c in calls if c.startswith("check "))


def test_all_runs_the_full_bundle(shim, tmp_path):
    code, calls, report, _ = _run(shim, tmp_path, story="all")
    assert code == 0
    assert _check_call(calls) == f"check --path {tmp_path} --manual warn"
    assert report.splitlines()[0].startswith("linebreak-gate action: scope: all stories")


def test_explicit_story_id_is_passed_through(shim, tmp_path):
    _, calls, report, _ = _run(shim, tmp_path, story="S2")
    assert _check_call(calls) == f"check --path {tmp_path} --manual warn --story S2"
    assert "scope: story S2" in report.splitlines()[0]


def test_auto_infers_the_story_from_a_feat_branch(shim, tmp_path):
    _, calls, report, _ = _run(shim, tmp_path, story="auto", branch="feat/S1")
    assert f"spec show S1 --path {tmp_path}" in calls
    assert _check_call(calls) == f"check --path {tmp_path} --manual warn --story S1"
    assert "story S1 inferred from branch feat/S1" in report.splitlines()[0]


def test_auto_accepts_the_story_prefix(shim, tmp_path):
    _, calls, _, _ = _run(shim, tmp_path, story="auto", branch="story/S2")
    assert _check_call(calls).endswith("--story S2")


def test_auto_falls_back_to_started_only_when_branch_is_not_a_story(shim, tmp_path):
    _, calls, report, _ = _run(shim, tmp_path, story="auto", branch="fix/typo")
    assert not any(c.startswith("spec show") for c in calls)
    assert _check_call(calls) == f"check --path {tmp_path} --manual warn --started-only"
    assert "started stories only" in report.splitlines()[0]


def test_auto_falls_back_when_the_inferred_id_is_not_approved(shim, tmp_path):
    _, calls, report, _ = _run(shim, tmp_path, story="auto", branch="feat/nope")
    assert f"spec show nope --path {tmp_path}" in calls
    assert _check_call(calls).endswith("--started-only")
    assert "no approved story id in branch 'feat/nope'" in report.splitlines()[0]


def test_auto_strips_a_trailing_slug_to_find_the_story(shim, tmp_path):
    # feat/<id>-<slug> is the common convention: try the whole segment, then
    # progressively without its trailing -parts, until an approved id matches.
    _, calls, report, _ = _run(shim, tmp_path, story="auto", branch="feat/S1-add-login")
    shows = [c for c in calls if c.startswith("spec show ")]
    assert shows == [
        f"spec show S1-add-login --path {tmp_path}",
        f"spec show S1-add --path {tmp_path}",
        f"spec show S1 --path {tmp_path}",
    ]
    assert _check_call(calls).endswith("--story S1")
    assert "story S1 inferred from branch feat/S1-add-login" in report.splitlines()[0]


def test_auto_prefers_the_longest_approved_id(shim, tmp_path):
    # Ids may contain hyphens themselves (E1-S1): the longest approved match wins.
    _, calls, _, _ = _run(shim, tmp_path, story="auto", branch="feat/E1-S1-login", known="E1 E1-S1")
    assert _check_call(calls).endswith("--story E1-S1")


def test_auto_ignores_branch_names_that_are_not_slugs(shim, tmp_path):
    _, calls, _, _ = _run(shim, tmp_path, story="auto", branch="feat/S1/extra")
    assert _check_call(calls).endswith("--started-only")


def test_manual_defaults_to_block_outside_pull_request(shim, tmp_path):
    _, calls, _, _ = _run(shim, tmp_path, story="all", event="push")
    assert _check_call(calls) == f"check --path {tmp_path} --manual block"


def test_manual_explicit_value_wins(shim, tmp_path):
    _, calls, _, _ = _run(shim, tmp_path, story="all", manual="block", event="pull_request")
    assert _check_call(calls).endswith("--manual block")


def test_invalid_manual_is_a_tool_error(shim, tmp_path):
    code, calls, report, _ = _run(shim, tmp_path, story="all", manual="ignore")
    assert code == 2
    assert not any(c.startswith("check") for c in calls)
    assert "manual" in report


def test_empty_story_is_a_tool_error(shim, tmp_path):
    code, calls, _, _ = _run(shim, tmp_path, story="")
    assert code == 2
    assert not any(c.startswith("check") for c in calls)


def test_check_exit_code_and_output_are_propagated(shim, tmp_path):
    code, _, report, _ = _run(shim, tmp_path, story="all", check_exit=1)
    assert code == 1
    assert "shim check output" in report
