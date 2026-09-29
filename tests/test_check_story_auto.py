"""``check --story auto`` (issue #256): the per-story scope inferred from the
branch, the same rule the Action and ``ci --story auto`` already follow, now
available to ``check`` itself (a local run, or any CI that calls ``check``).

* On ``feat/<id>`` or ``story/<id>`` (a trailing slug allowed) naming an
  approved story: only that story is evaluated.
* Otherwise: started stories only (and, as always, exit 2 when none is
  started: an unresolvable scope is never a vacuous pass).
* ``auto`` mixed with explicit ids is a usage error.
"""

from __future__ import annotations

import subprocess

from test_check_scope import _sprint
from test_criteria_check import write_bundle

from linebreak_gate import story_state
from linebreak_gate.cli import main


def _git(root, *args):
    subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=True)


def _repo_on(tmp_path, branch: str):
    write_bundle(tmp_path, _sprint())
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-q", "-m", "spec")
    _git(tmp_path, "checkout", "-q", "-b", branch)
    return tmp_path


def test_story_auto_evaluates_the_story_named_by_the_branch(tmp_path, capsys):
    root = _repo_on(tmp_path, "feat/S1-sign-in-form")
    code = main(["check", "--path", str(root), "--story", "auto", "--manual", "warn"])
    captured = capsys.readouterr()
    assert code == 0
    assert "--story auto: story S1 inferred from branch feat/S1-sign-in-form" in captured.err
    assert "scope: story S1 (1 of 3 stories)" in captured.out


def test_story_auto_falls_back_to_started_stories(tmp_path, capsys):
    root = _repo_on(tmp_path, "chore/cleanup")
    story_state.set_state(root, "S1", "doing")
    code = main(["check", "--path", str(root), "--story", "auto", "--manual", "warn"])
    captured = capsys.readouterr()
    assert code == 0
    assert "no approved story id in branch 'chore/cleanup'" in captured.err
    assert "scope: started stories only (1 of 3: S1)" in captured.out


def test_story_auto_with_nothing_started_is_exit_2(tmp_path, capsys):
    root = _repo_on(tmp_path, "chore/cleanup")
    assert main(["check", "--path", str(root), "--story", "auto"]) == 2


def test_story_auto_cannot_be_mixed_with_ids(tmp_path, capsys):
    root = _repo_on(tmp_path, "feat/S1")
    code = main(["check", "--path", str(root), "--story", "auto", "--story", "S2"])
    assert code == 2
    assert "cannot be combined" in capsys.readouterr().err
