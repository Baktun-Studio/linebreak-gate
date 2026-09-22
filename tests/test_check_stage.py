"""Release-only criteria and the check stage (Katun follow-up to issue #256).

Some criteria are checked by scripts against a shared staging environment. A
regression there must not turn every PR's gate red (including the PR that
fixes it), so:

* a criterion may carry ``check.when: release`` (implicit default ``always``);
  the spec lint validates the vocabulary and the field enters the bundle and
  criterion hashes like any other check field;
* ``check --stage pr`` (default ``release``, so nobody's Action changes
  behavior) skips ``when: release`` criteria, lists them as ``release-only``
  (not evaluated), and never counts them as pass or fail; ``--stage release``
  evaluates everything, and a failing release-only criterion still blocks the
  release (fail closed is unchanged);
* the Action's ``stage`` input passes it through.
"""

from __future__ import annotations

import json
import sys

import pytest
from test_action_check_scope import _run, shim  # noqa: F401 - pytest fixture re-export
from test_check_scope import _machine, _manual, _results
from test_cli_check import FAILING_CMD, PASSING_CMD
from test_criteria_check import write_bundle

from linebreak_gate import cli, criteria_check, spec_bundle
from linebreak_gate.cli import main


def _release(cid: str, payload: str = PASSING_CMD, ctype: str = "command") -> dict:
    check = {"type": ctype, "when": "release"}
    if ctype in ("command", "tests"):
        check["payload"] = payload
    return {"id": cid, "statement": f"{cid} against staging", "check": check}


def _sprint() -> list[dict]:
    """S1: one always criterion, one release-only command, one release-only
    manual. S2: a release-only command that FAILS (a staging regression)."""
    return [
        {
            "id": "S1",
            "title": "Sign in",
            "criteria": [
                _machine("S1-AC1"),
                _release("S1-AC2"),
                _release("S1-AC3", ctype="manual"),
            ],
        },
        {"id": "S2", "title": "Sign out", "criteria": [_release("S2-AC1", FAILING_CMD)]},
        {"id": "S3", "title": "Profile", "criteria": [_manual("S3-AC1")]},
    ]


# ---------------------------------------------------------------- spec lint + hash


@pytest.mark.parametrize("when", ["always", "release"])
def test_check_when_vocabulary_is_accepted(when):
    story = {"id": "S1", "title": "T", "criteria": [_machine("S1-AC1")]}
    story["criteria"][0]["check"]["when"] = when
    assert spec_bundle.validate_story(story) == []


@pytest.mark.parametrize("when", ["pr", "never", "", 1, True])
def test_check_when_rejects_anything_else(when):
    story = {"id": "S1", "title": "T", "criteria": [_machine("S1-AC1")]}
    story["criteria"][0]["check"]["when"] = when
    errors = spec_bundle.validate_story(story)
    assert any("when" in e for e in errors)


def test_check_when_round_trips_through_the_bundle(tmp_path):
    write_bundle(tmp_path, _sprint())
    bundle = spec_bundle.load_bundle(tmp_path)
    checks = {c["id"]: c["check"] for s in bundle["stories"] for c in s["criteria"]}
    assert checks["S1-AC2"]["when"] == "release"
    assert "when" not in checks["S1-AC1"]  # absent stays absent (implicit always)


def test_check_when_enters_the_criterion_hash():
    base = {"id": "S1-AC1", "statement": "s", "check": {"type": "build"}}
    release = {"id": "S1-AC1", "statement": "s", "check": {"type": "build", "when": "release"}}
    assert spec_bundle.criterion_hash(base) != spec_bundle.criterion_hash(release)


def test_criterion_hash_golden_is_unchanged_for_criteria_without_when():
    # Golden vector: the canonical form of a criterion WITHOUT `when` must be
    # byte-identical to what 1.11 hashed, or every recorded sign-off and
    # override would go stale on upgrade. Regenerate deliberately only.
    c = {
        "id": "S1-AC2",
        "statement": "Covered by tests",
        "check": {"type": "tests", "payload": "t.py"},
    }
    assert spec_bundle.criterion_hash(c) == GOLDEN_HASH_WITHOUT_WHEN


GOLDEN_HASH_WITHOUT_WHEN = "f757e794888f0a6dbf7bc13f7ee4830ea02bf59f7561b7a2761ee6ffcd4c129b"


# ---------------------------------------------------------------- engine


def test_default_stage_is_release_and_evaluates_everything(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path)
    assert payload["scope"]["stage"] == "release"
    assert _results(payload) == {
        "S1-AC1": "pass",
        "S1-AC2": "pass",
        "S1-AC3": "needs-signoff",
        "S2-AC1": "fail",
        "S3-AC1": "needs-signoff",
    }
    assert payload["passes"] is False  # a failing release-only criterion still blocks a release


def test_pr_stage_skips_release_only_criteria_without_running_them(tmp_path):
    write_bundle(tmp_path, _sprint())
    ran: list[str] = []

    def spy(criterion, root):  # noqa: ARG001
        ran.append(criterion["id"])
        return criteria_check.RunOutcome(ok=True, detail="")

    payload = criteria_check.evaluate_bundle(tmp_path, run=spy, stage="pr", manual_policy="warn")
    assert ran == ["S1-AC1"]
    assert _results(payload) == {
        "S1-AC1": "pass",
        "S1-AC2": "release-only",
        "S1-AC3": "release-only",
        "S2-AC1": "release-only",
        "S3-AC1": "needs-signoff",
    }
    assert payload["passes"] is True
    assert payload["scope"]["stage"] == "pr"
    assert payload["scope"]["release_only"] == [
        {"id": "S1-AC2", "story": "S1"},
        {"id": "S1-AC3", "story": "S1"},
        {"id": "S2-AC1", "story": "S2"},
    ]
    # A release-only manual criterion is not pending in a PR either.
    assert payload["pending_signoffs"] == [{"id": "S3-AC1", "story": "S3"}]


def test_pr_stage_release_only_never_counts_as_pass_or_fail(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, stage="pr")
    entry = next(r for r in payload["criteria"] if r["id"] == "S2-AC1")
    assert entry["result"] == "release-only"
    assert entry["detail"] == "not evaluated at stage pr (check.when: release)"
    # Still blocked, but only by the always-manual criterion under --manual block.
    assert payload["passes"] is False
    assert payload["pending_signoffs"] == [{"id": "S3-AC1", "story": "S3"}]


def test_pr_stage_composes_with_story_scope(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, stage="pr", story_ids={"S2"})
    assert _results(payload) == {"S2-AC1": "release-only"}
    assert payload["passes"] is True
    assert payload["scope"]["criteria_evaluated"] == 0


def test_cli_pr_stage_with_nothing_evaluated_says_so(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["check", "--path", str(tmp_path), "--stage", "pr", "--story", "S2"]) == 0
    out = capsys.readouterr().out
    assert "VERDICT: PASS. No criterion evaluated at this stage" in out
    assert "1 release-only criterion(s) not evaluated at stage pr" in out


def test_explicit_when_always_is_a_hash_no_op():
    # `always` is the implicit default: spelling it out must not stale
    # sign-offs, overrides, or the signed approval.
    base = {"id": "A", "statement": "s", "check": {"type": "build"}}
    explicit = {"id": "A", "statement": "s", "check": {"type": "build", "when": "always"}}
    assert spec_bundle.criterion_hash(base) == spec_bundle.criterion_hash(explicit)
    assert "when" not in spec_bundle.dump_story_yaml(
        {"id": "S1", "title": "T", "criteria": [explicit]}
    )


def test_bridge_check_story_takes_the_stage(tmp_path):
    from linebreak_gate import bridge

    write_bundle(tmp_path, _sprint())
    ran: list[str] = []

    def spy(criterion, root):  # noqa: ARG001
        ran.append(criterion["id"])
        return criteria_check.RunOutcome(ok=True, detail="")

    out = bridge.check_story(tmp_path, "S2", run=spy, stage="pr")
    assert out["ok"] is True and out["stage"] == "pr"
    assert ran == []  # the staging script never ran from the developer's machine
    assert out["criteria"][0]["result"] == "release-only"
    default = bridge.check_story(tmp_path, "S2", run=spy)
    assert ran == ["S2-AC1"] and default["criteria"][0]["result"] == "pass"
    assert bridge.check_story(tmp_path, "S2", stage="staging")["ok"] is False


def test_spec_check_cli_takes_the_stage(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["spec", "check", "S2", "--path", str(tmp_path), "--stage", "pr"]) == 0
    assert "release-only" in capsys.readouterr().out
    assert main(["spec", "check", "S2", "--path", str(tmp_path)]) == 1  # staging regression


@pytest.mark.asyncio
async def test_mcp_check_story_exposes_stage(tmp_path):
    pytest.importorskip("mcp", reason="mcp SDK not installed")
    from mcp.shared.memory import create_connected_server_and_client_session
    from test_mcp_server import _call

    from linebreak_gate import mcp_server

    write_bundle(tmp_path, _sprint())
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        out = await _call(session, "check_story", {"story_id": "S2", "stage": "pr"})
        assert out["criteria"][0]["result"] == "release-only"


def test_invalid_stage_is_rejected(tmp_path):
    write_bundle(tmp_path, _sprint())
    with pytest.raises(ValueError):
        criteria_check.evaluate_bundle(tmp_path, stage="staging")


def test_artifact_records_release_only_and_stage(tmp_path):
    write_bundle(tmp_path, _sprint())
    criteria_check.evaluate_bundle(tmp_path, stage="pr", write_artifact=True)
    doc = json.loads(
        (tmp_path / ".linebreak" / "audit" / "criteria.json").read_text(encoding="utf-8")
    )
    assert doc["scope"]["stage"] == "pr"
    assert {f["id"]: f["result"] for f in doc["findings"]}["S2-AC1"] == "release-only"


# ---------------------------------------------------------------- CLI


def test_cli_stage_pr_lists_release_only_and_passes(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_result_icons", lambda: cli._RESULT_ICONS_ASCII)
    write_bundle(tmp_path, _sprint())
    code = main(["check", "--path", str(tmp_path), "--stage", "pr", "--manual", "warn"])
    assert code == 0
    out = capsys.readouterr().out
    assert "stage: pr" in out
    assert "[-] [release-only] S2/S2-AC1  (command: " in out and ", when: release)" in out
    assert "release-only (not evaluated at stage pr): S1-AC2 (S1), S1-AC3 (S1), S2-AC1 (S2)" in out
    assert "3 release-only" in out
    assert "VERDICT: PASS. Every evaluated criterion satisfied" in out
    assert "3 release-only criterion(s) not evaluated at stage pr" in out
    # The explanation appears once, on the aggregate line, not under every criterion.
    assert out.count("not evaluated at stage pr") == 2  # scope line + verdict tail


def test_cli_default_stage_release_blocks_on_the_staging_regression(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["check", "--path", str(tmp_path), "--manual", "warn"]) == 1
    out = capsys.readouterr().out
    assert "stage: release" in out
    assert "[fail] S2/S2-AC1" in out
    assert "release-only" not in out


def test_cli_stage_rejects_other_values(tmp_path):
    write_bundle(tmp_path, _sprint())
    with pytest.raises(SystemExit):
        main(["check", "--path", str(tmp_path), "--stage", "staging"])


def test_cli_json_carries_stage_and_release_only(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    main(["check", "--path", str(tmp_path), "--stage", "pr", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["scope"]["stage"] == "pr"
    assert [r["id"] for r in payload["scope"]["release_only"]] == ["S1-AC2", "S1-AC3", "S2-AC1"]


def test_cli_json_no_bundle_states_stage(tmp_path, capsys):
    assert main(["check", "--path", str(tmp_path), "--stage", "pr", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scope"]["stage"] == "pr"
    assert payload["scope"]["release_only"] == []


def test_spec_show_prints_when(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["spec", "show", "S1", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "when: release" in out


def test_spec_new_template_documents_when(tmp_path):
    assert main(["spec", "new", "--path", str(tmp_path)]) == 0
    draft = (tmp_path / ".linebreak" / "spec-draft.yml").read_text(encoding="utf-8")
    assert "when: release" in draft


# ---------------------------------------------------------------- Action script

skip_on_windows = pytest.mark.skipif(sys.platform == "win32", reason="bash script")


@skip_on_windows
def test_action_passes_stage_through(shim, tmp_path):  # noqa: F811 - the imported fixture
    code, calls, report, _ = _run(shim, tmp_path, story="all", stage="pr")
    assert code == 0
    assert calls[-1] == f"check --path {tmp_path} --manual warn --stage pr"
    assert "stage: pr" in report.splitlines()[0]


@skip_on_windows
def test_action_stage_defaults_to_release_when_empty(shim, tmp_path):  # noqa: F811 - the imported fixture
    _, calls, report, _ = _run(shim, tmp_path, story="all", stage="")
    assert calls[-1].endswith("--stage release")
    assert "stage: release" in report.splitlines()[0]


@skip_on_windows
def test_action_invalid_stage_is_a_tool_error(shim, tmp_path):  # noqa: F811 - the imported fixture
    code, calls, report, _ = _run(shim, tmp_path, story="all", stage="staging")
    assert code == 2
    assert not any(c.startswith("check") for c in calls)
    assert "stage" in report
