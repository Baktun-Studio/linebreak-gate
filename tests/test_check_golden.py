"""Golden output for ``linebreak-gate check`` under each scope (issue #256).

The summary text is what the Action pipes into the PR comment and what a
human reads in the job log; the JSON is the machine contract. Both are pinned
byte-for-byte here so a wording or key change is a deliberate, reviewed diff.

Regenerate after an intentional change:

    UPDATE_GOLDEN=1 python -m pytest tests/test_check_golden.py

Determinism: the fixture manifest carries fixed timestamps, the ASCII icon set
is forced (the unicode set depends on the console encoding), and no sign-off
is recorded (a sign-off carries the wall-clock time it was signed).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from test_check_scope import _sprint
from test_criteria_check import write_bundle

from linebreak_gate import cli, story_state
from linebreak_gate.cli import main

GOLDEN_DIR = Path(__file__).parent / "golden"


def _normalize(text: str) -> str:
    # CRLF-agnostic so the Windows CI cell compares the same bytes.
    return text.replace("\r\n", "\n")


def _assert_golden(name: str, actual: str) -> None:
    path = GOLDEN_DIR / name
    if os.environ.get("UPDATE_GOLDEN"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(actual, encoding="utf-8", newline="\n")
    assert path.exists(), f"missing golden file {path}; run with UPDATE_GOLDEN=1 to create it"
    expected = _normalize(path.read_text(encoding="utf-8"))
    assert _normalize(actual) == expected


@pytest.fixture
def sprint(tmp_path, monkeypatch):
    write_bundle(tmp_path, _sprint())
    monkeypatch.setattr(cli, "_result_icons", lambda: cli._RESULT_ICONS_ASCII)
    return tmp_path


def _run(args: list[str], capsys) -> tuple[int, str]:
    code = main(args)
    return code, capsys.readouterr().out


def test_golden_summary_all_block(sprint, capsys):
    code, out = _run(["check", "--path", str(sprint)], capsys)
    assert code == 1
    _assert_golden("check_all_block.txt", out)


def test_golden_summary_story_warn(sprint, capsys):
    code, out = _run(["check", "--path", str(sprint), "--story", "S1", "--manual", "warn"], capsys)
    assert code == 0
    _assert_golden("check_story_warn.txt", out)


def test_golden_summary_started_only_block(sprint, capsys):
    story_state.set_state(sprint, "S1", "doing")
    story_state.set_state(sprint, "S2", "review")
    code, out = _run(["check", "--path", str(sprint), "--started-only"], capsys)
    assert code == 1
    _assert_golden("check_started_block.txt", out)


def test_golden_json_story_warn(sprint, capsys):
    code, out = _run(
        [
            "check",
            "--path",
            str(sprint),
            "--story",
            "S1",
            "--manual",
            "warn",
            "--format",
            "json",
        ],
        capsys,
    )
    assert code == 0
    payload = json.loads(out)  # must be valid JSON before it is compared
    assert payload["scope"]["mode"] == "story"
    _assert_golden("check_story_warn.json", out)


def test_golden_json_started_only_block(sprint, capsys):
    story_state.set_state(sprint, "S1", "doing")
    code, out = _run(["check", "--path", str(sprint), "--started-only", "--format", "json"], capsys)
    assert code == 1
    json.loads(out)
    _assert_golden("check_started_block.json", out)
