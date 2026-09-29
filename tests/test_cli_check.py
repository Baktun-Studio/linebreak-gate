"""CLI surface for criteria enforcement (LIN-37): `check`, `signoff`, and
`override --criterion`. Exit codes: 0 satisfied/no-bundle, 1 blocking,
2 tool/config/bundle error — fail closed."""

from __future__ import annotations

import json

import yaml
from test_criteria_check import MANIFEST_FIELDS, write_bundle

from linebreak_gate.cli import main

PASSING_CMD = 'python -c "import sys; sys.exit(0)"'
FAILING_CMD = 'python -c "import sys; sys.exit(1)"'


def _story(criteria):
    return {"id": "S1", "title": "Story", "criteria": criteria}


def _machine(payload=PASSING_CMD, cid="S1-AC1"):
    return {"id": cid, "statement": "cmd passes", "check": {"type": "command", "payload": payload}}


def _manual(cid="S1-AC9"):
    return {"id": cid, "statement": "design ok", "check": {"type": "manual"}}


def test_check_all_pass_exit_0(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine()])])
    assert main(["check", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "pass" in out and "S1-AC1" in out


def test_check_failure_exit_1(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine(FAILING_CMD)])])
    assert main(["check", "--path", str(tmp_path)]) == 1
    assert "BLOCKED" in capsys.readouterr().out


def test_check_manual_needs_signoff_blocks_then_signoff_unblocks(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    assert main(["check", "--path", str(tmp_path)]) == 1
    assert "needs-signoff" in capsys.readouterr().out
    assert (
        main(
            [
                "signoff",
                "--path",
                str(tmp_path),
                "--criterion",
                "S1-AC9",
                "--approver",
                "qa@example.com",
                "--note",
                "walked the demo",
            ]
        )
        == 0
    )
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "qa@example.com" in capsys.readouterr().out


def test_signoff_missing_note_refused(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    code = main(
        [
            "signoff",
            "--path",
            str(tmp_path),
            "--criterion",
            "S1-AC9",
            "--approver",
            "qa@example.com",
            "--note",
            "  ",
        ]
    )
    assert code == 2


def test_override_criterion_unblocks_only_it(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine(FAILING_CMD), _machine(FAILING_CMD, "S1-AC2")])])
    assert (
        main(
            [
                "override",
                "--path",
                str(tmp_path),
                "--criterion",
                "S1-AC1",
                "--reason",
                "known-flaky on CI",
                "--approver",
                "lead@example.com",
            ]
        )
        == 0
    )
    assert main(["check", "--path", str(tmp_path)]) == 1  # AC2 still blocks
    out = capsys.readouterr().out
    assert "overridden" in out and "lead@example.com" in out


def test_check_json_format(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine()])])
    assert main(["check", "--path", str(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passes"] is True
    assert payload["criteria"][0]["result"] == "pass"


def test_check_no_bundle_noop_exit_0(tmp_path, capsys):
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "no approved criteria" in capsys.readouterr().out.lower()


def test_check_malformed_bundle_exit_2(tmp_path):
    spec = tmp_path / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "manifest.yml").write_text(": nope [", encoding="utf-8")
    assert main(["check", "--path", str(tmp_path)]) == 2


def test_check_unresolvable_runner_exit_2(tmp_path):
    write_bundle(
        tmp_path,
        [_story([{"id": "S1-AC1", "statement": "builds", "check": {"type": "build"}}])],
    )
    assert main(["check", "--path", str(tmp_path)]) == 2


def test_check_enforce_false_disables(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine(FAILING_CMD)])])
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "criteria:\n  enforce: false\n", encoding="utf-8"
    )
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "disabled" in capsys.readouterr().out.lower()


def test_check_invalid_criteria_config_exit_2(tmp_path):
    write_bundle(tmp_path, [_story([_machine()])])
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "criteria:\n  enforce: sometimes\n", encoding="utf-8"
    )
    assert main(["check", "--path", str(tmp_path)]) == 2


def test_check_writes_audit_artifact(tmp_path):
    write_bundle(tmp_path, [_story([_machine()])])
    main(["check", "--path", str(tmp_path)])
    doc = json.loads(
        (tmp_path / ".linebreak" / "audit" / "criteria.json").read_text(encoding="utf-8")
    )
    assert doc["kind"] == "criteria_check"
    assert doc["findings"][0]["result"] == "pass"


def test_stale_signoff_after_reapproval_blocks_again(tmp_path):
    write_bundle(tmp_path, [_story([_manual()])])
    main(
        [
            "signoff",
            "--path",
            str(tmp_path),
            "--criterion",
            "S1-AC9",
            "--approver",
            "qa@example.com",
            "--note",
            "ok",
        ]
    )
    assert main(["check", "--path", str(tmp_path)]) == 0
    # The app edits the criterion and re-approves → new bundle content.
    edited = _story([{"id": "S1-AC9", "statement": "design ok v2", "check": {"type": "manual"}}])
    write_bundle(tmp_path, [edited])
    assert main(["check", "--path", str(tmp_path)]) == 1


def test_manifest_fields_still_valid_yaml():
    # Guard: the fixture manifest matches what dump_manifest_yaml really emits.
    assert yaml.safe_load(json.dumps(MANIFEST_FIELDS))


# ---------------------------------------------------------------- LIN-37 review hardening


def test_override_empty_criterion_is_clean_exit_2_not_a_crash(tmp_path):
    write_bundle(tmp_path, [_story([_machine()])])
    code = main(
        ["override", "--path", str(tmp_path), "--criterion", "", "--reason", "r", "--approver", "a"]
    )
    assert code == 2  # clean tool error, not an AttributeError traceback (exit 1)


def test_check_json_on_disabled_path(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine()])])
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "criteria:\n  enforce: false\n", encoding="utf-8"
    )
    assert main(["check", "--path", str(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)  # valid JSON, not prose
    assert payload["status"] == "disabled"


def test_check_json_on_no_bundle_path(tmp_path, capsys):
    assert main(["check", "--path", str(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "no-bundle"
