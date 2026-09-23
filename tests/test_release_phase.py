"""Release in two phases inside the tool: the attestation of a release run
can never be a requirement of the run that produces it.

The Katun case (17 sep 2026): a criterion said "the release carries a signed
attestation". The attestation is made ON a green release run, so a single run
demanded of itself an artifact only it could produce. The workaround was a
`--manual warn` "prepare" run, which relaxed EVERY manual criterion. Now:

* ``check.when: attestation`` marks that manual criterion (schema: manual only);
* ``check --stage release --phase prepare`` reports it ``awaiting-attestation``
  (not evaluated, not blocking) and enforces everything else, other manual
  criteria included; the record says ``phase: prepare`` and is not a verdict;
* ``--phase verify`` (the default) enforces it like any manual criterion;
* at ``--stage pr`` it is release-only; ``--phase prepare`` with ``--stage pr``
  is a usage error (exit 2).
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from test_check_scope import _machine, _manual
from test_criteria_check import write_bundle

from linebreak_gate import ci_cmd, ci_env, criteria_check, signoffs, spec_bundle
from linebreak_gate.cli import main

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check-scope.sh"


def _attestation(cid: str = "rel-attestation") -> dict:
    return {
        "id": cid,
        "statement": "The release carries a signed attestation of its green run",
        "check": {"type": "manual", "when": "attestation"},
    }


def _release() -> list[dict]:
    return [
        {
            "id": "QA",
            "title": "Release QA",
            "criteria": [_machine("f1-e2e"), _manual("qa-report"), _attestation()],
        }
    ]


def _sign(root, cid: str) -> None:
    signoffs.record_signoff(root, criterion_id=cid, approver="Ana <ana@example.com>", note="ok")


def _results(payload: dict) -> dict[str, str]:
    return {r["id"]: r["result"] for r in payload["criteria"]}


# ---------------------------------------------------------------- schema


def test_attestation_is_only_for_manual_criteria():
    story = _release()[0]
    assert spec_bundle.validate_story(story) == []
    wrong = {
        "id": "S",
        "title": "t",
        "criteria": [
            {
                "id": "c",
                "statement": "s",
                "check": {"type": "command", "payload": "x", "when": "attestation"},
            }
        ],
    }
    assert any("manual" in e for e in spec_bundle.validate_story(wrong))


# ---------------------------------------------------------------- engine


def test_prepare_does_not_demand_the_attestation_of_itself(tmp_path):
    write_bundle(tmp_path, _release())
    _sign(tmp_path, "qa-report")
    payload = criteria_check.evaluate_bundle(tmp_path, phase="prepare")
    assert _results(payload) == {
        "f1-e2e": "pass",
        "qa-report": "pass",
        "rel-attestation": "awaiting-attestation",
    }
    assert payload["passes"] is True
    assert payload["phase"] == "prepare"
    assert payload["awaiting_attestation"] == [{"id": "rel-attestation", "story": "QA"}]
    assert payload["scope"]["criteria_evaluated"] == 2


def test_prepare_still_enforces_every_other_manual_criterion(tmp_path):
    # Unlike the `--manual warn` workaround, prepare relaxes ONLY the
    # attestation: a missing QA sign-off still blocks.
    write_bundle(tmp_path, _release())
    payload = criteria_check.evaluate_bundle(tmp_path, phase="prepare")
    assert _results(payload)["qa-report"] == "needs-signoff"
    assert payload["passes"] is False
    assert payload["block_reasons"] == ["unsigned_manual"]


def test_verify_demands_the_attestation_and_passes_once_signed(tmp_path):
    write_bundle(tmp_path, _release())
    _sign(tmp_path, "qa-report")
    blocked = criteria_check.evaluate_bundle(tmp_path)
    assert blocked["phase"] == "verify"
    assert _results(blocked)["rel-attestation"] == "needs-signoff"
    assert blocked["passes"] is False
    _sign(tmp_path, "rel-attestation")
    released = criteria_check.evaluate_bundle(tmp_path)
    assert _results(released)["rel-attestation"] == "pass"
    assert released["passes"] is True


def test_at_stage_pr_the_attestation_is_release_only(tmp_path):
    write_bundle(tmp_path, _release())
    payload = criteria_check.evaluate_bundle(tmp_path, stage="pr", manual_policy="warn")
    assert _results(payload)["rel-attestation"] == "release-only"


def test_prepare_only_exists_at_stage_release(tmp_path):
    write_bundle(tmp_path, _release())
    with pytest.raises(ValueError, match="stage 'release'"):
        criteria_check.evaluate_bundle(tmp_path, stage="pr", phase="prepare")


def test_the_prepare_record_is_never_a_release_verdict(tmp_path):
    write_bundle(tmp_path, _release())
    _sign(tmp_path, "qa-report")
    criteria_check.evaluate_bundle(tmp_path, phase="prepare", write_artifact=True)
    audit = json.loads((tmp_path / ".linebreak/audit/criteria.json").read_text(encoding="utf-8"))
    assert audit["phase"] == "prepare"
    assert "phase: prepare; not a full verdict" in audit["summary"]
    assert audit["awaiting_attestation"] == [{"id": "rel-attestation", "story": "QA"}]


# ---------------------------------------------------------------- CLI


def test_cli_prepare_then_sign_then_verify(tmp_path, capsys):
    write_bundle(tmp_path, _release())
    _sign(tmp_path, "qa-report")
    assert main(["check", "--path", str(tmp_path), "--phase", "prepare"]) == 0
    out = capsys.readouterr().out
    assert "[awaiting-attestation] QA/rel-attestation" in out
    assert "awaiting attestation: rel-attestation (QA)" in out
    assert "This run is the one to attest, NOT the release" in out

    assert main(["check", "--path", str(tmp_path)]) == 1
    assert "pending sign-off: rel-attestation (QA)" in capsys.readouterr().out

    _sign(tmp_path, "rel-attestation")
    assert main(["check", "--path", str(tmp_path), "--phase", "verify"]) == 0


def test_cli_prepare_with_stage_pr_is_a_usage_error(tmp_path, capsys):
    write_bundle(tmp_path, _release())
    assert main(["check", "--path", str(tmp_path), "--stage", "pr", "--phase", "prepare"]) == 2
    assert "applies only to --stage release" in capsys.readouterr().err


def test_ci_passes_the_phase_and_rejects_prepare_on_a_pr(tmp_path):
    env = ci_env.CiEnv(provider="local")
    flags, _, _, _ = ci_cmd.resolve_check_scope(
        tmp_path, env=env, story="all", manual="block", stage="release", phase="prepare"
    )
    assert flags == ["--manual", "block", "--stage", "release", "--phase", "prepare"]
    flags, note, _, _ = ci_cmd.resolve_check_scope(
        tmp_path, env=env, story="all", manual="warn", stage="pr", phase="prepare"
    )
    assert flags is None and "gate stays closed" in note


@pytest.mark.skipif(os.name == "nt", reason="the Action runs on bash; covered on Linux/macOS")
def test_action_scope_script_passes_the_phase(tmp_path):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "linebreak-gate"
    fake.write_text('#!/usr/bin/env bash\necho "ARGS: $*"\n', encoding="utf-8")
    fake.chmod(0o755)
    report = tmp_path / "criteria.txt"
    env = {
        **os.environ,
        "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
        "INPUT_STORY": "all",
        "INPUT_MANUAL": "block",
        "INPUT_STAGE": "release",
        "INPUT_PHASE": "prepare",
        "EVENT_NAME": "workflow_dispatch",
        "BRANCH": "main",
    }
    proc = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path), str(report)], env=env, capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = report.read_text(encoding="utf-8")
    # The scope line keeps its exact shape (the PR comment parses it).
    assert (
        "linebreak-gate action: scope: all stories (story: all); manual criteria: block; stage: release\n"
        in text
    )
    assert "release phase: prepare" in text
    assert "--stage release --phase prepare" in text

    env["INPUT_STAGE"] = "pr"
    proc = subprocess.run(
        ["bash", str(SCRIPT), str(tmp_path), str(report)], env=env, capture_output=True, text=True
    )
    assert proc.returncode == 2
