"""Check scope (issue #256): per-story on PRs, full bundle at release.

A team that approves a whole sprint up front (24 stories, 56 criteria) must
not have every PR blocked by stories nobody has started. These tests pin the
scope semantics of ``evaluate_bundle`` and the ``check`` CLI:

* ``story_ids`` evaluates only those stories; an unknown id is a tool error.
* ``started_only`` evaluates stories whose local state is doing/review/done;
  stories without a state are listed as not started and never count. When NO
  story is started the scope is unusable: exit 2, never a vacuous pass.
* ``manual_policy="warn"`` reports needs-signoff without blocking; ``block``
  (the default) keeps today's behavior.
* Every CLI run writes the criteria audit artifact stamped with its scope, so
  a partial or relaxed run is evidence of that run and never reads as a full
  verdict (and the uploaded CI artifact is never a stale committed one).
* The payload carries a ``scope`` block and ``pending_signoffs`` so the
  summary, the JSON, and the Action comment can all say what was evaluated.
"""

from __future__ import annotations

import json

import pytest
from test_cli_check import FAILING_CMD, PASSING_CMD
from test_criteria_check import write_bundle

from linebreak_gate import criteria_check, signoffs, story_state
from linebreak_gate.cli import main


def _machine(cid: str, payload: str = PASSING_CMD) -> dict:
    return {
        "id": cid,
        "statement": f"{cid} passes",
        "check": {"type": "command", "payload": payload},
    }


def _manual(cid: str) -> dict:
    return {"id": cid, "statement": f"{cid} reviewed", "check": {"type": "manual"}}


def _sprint() -> list[dict]:
    """Three stories: S1 in progress (passes, one manual), S2 not started and
    failing, S3 not started with only a manual criterion."""
    return [
        {"id": "S1", "title": "Sign in", "criteria": [_machine("S1-AC1"), _manual("S1-AC2")]},
        {"id": "S2", "title": "Sign out", "criteria": [_machine("S2-AC1", FAILING_CMD)]},
        {"id": "S3", "title": "Profile", "criteria": [_manual("S3-AC1")]},
    ]


def _results(payload: dict) -> dict[str, str]:
    return {r["id"]: r["result"] for r in payload["criteria"]}


def _audit_exists(root) -> bool:
    return (root / ".linebreak" / "audit" / "criteria.json").exists()


def _audit(root) -> dict:
    return json.loads((root / ".linebreak" / "audit" / "criteria.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------- engine: story scope


def test_story_scope_evaluates_only_named_stories(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, story_ids={"S1"})
    assert _results(payload) == {"S1-AC1": "pass", "S1-AC2": "needs-signoff"}
    assert payload["scope"]["mode"] == "story"
    assert payload["scope"]["stories_evaluated"] == ["S1"]
    assert payload["scope"]["stories_skipped"] == ["S2", "S3"]
    assert payload["scope"]["criteria_evaluated"] == 2
    assert payload["scope"]["criteria_total"] == 4


def test_story_scope_accepts_several_stories_in_bundle_order(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, story_ids={"S3", "S1"})
    assert payload["scope"]["stories_evaluated"] == ["S1", "S3"]
    assert set(_results(payload)) == {"S1-AC1", "S1-AC2", "S3-AC1"}


def test_story_scope_unknown_id_is_a_tool_error(tmp_path):
    write_bundle(tmp_path, _sprint())
    with pytest.raises(criteria_check.CriteriaToolError, match="S9"):
        criteria_check.evaluate_bundle(tmp_path, story_ids={"S1", "S9"})


def test_story_scope_artifact_is_stamped_with_its_scope(tmp_path):
    write_bundle(tmp_path, _sprint())
    criteria_check.evaluate_bundle(tmp_path, story_ids={"S1"}, write_artifact=True)
    doc = _audit(tmp_path)
    assert doc["scope"]["mode"] == "story"
    assert doc["scope"]["stories_evaluated"] == ["S1"]
    assert doc["pending_signoffs"] == [{"id": "S1-AC2", "story": "S1"}]
    assert "not a full verdict" in doc["summary"]
    assert [f["id"] for f in doc["findings"]] == ["S1-AC1", "S1-AC2"]


# ---------------------------------------------------------------- engine: started only


def test_started_only_skips_stories_without_state(tmp_path):
    write_bundle(tmp_path, _sprint())
    story_state.set_state(tmp_path, "S1", "doing")
    payload = criteria_check.evaluate_bundle(tmp_path, started_only=True)
    assert _results(payload) == {"S1-AC1": "pass", "S1-AC2": "needs-signoff"}
    assert payload["scope"]["mode"] == "started"
    assert payload["scope"]["stories_evaluated"] == ["S1"]
    assert payload["scope"]["stories_skipped"] == ["S2", "S3"]


@pytest.mark.parametrize("state", ["doing", "review", "done"])
def test_started_only_counts_every_started_state(tmp_path, state):
    write_bundle(tmp_path, _sprint())
    story_state.set_state(tmp_path, "S2", state)
    payload = criteria_check.evaluate_bundle(tmp_path, started_only=True)
    assert payload["scope"]["stories_evaluated"] == ["S2"]
    assert payload["passes"] is False  # S2's failing command still blocks


def test_started_only_with_nothing_started_is_a_tool_error(tmp_path):
    # No state store (a fresh CI checkout, an external tracker, a corrupt
    # file): the scope selects nothing, and nothing is not a pass.
    write_bundle(tmp_path, _sprint())
    with pytest.raises(criteria_check.CriteriaToolError, match="tracker-sync.json"):
        criteria_check.evaluate_bundle(tmp_path, started_only=True)


def test_started_only_with_corrupt_state_store_is_a_tool_error(tmp_path):
    write_bundle(tmp_path, _sprint())
    sync = story_state.sync_path(tmp_path)
    sync.parent.mkdir(parents=True, exist_ok=True)
    sync.write_text("{not json", encoding="utf-8")
    with pytest.raises(criteria_check.CriteriaToolError):
        criteria_check.evaluate_bundle(tmp_path, started_only=True)


def test_started_only_artifact_is_stamped_with_its_scope(tmp_path):
    write_bundle(tmp_path, _sprint())
    story_state.set_state(tmp_path, "S1", "doing")
    criteria_check.evaluate_bundle(tmp_path, started_only=True, write_artifact=True)
    doc = _audit(tmp_path)
    assert doc["scope"]["mode"] == "started"
    assert doc["scope"]["stories_skipped"] == ["S2", "S3"]


def test_story_ids_and_started_only_are_mutually_exclusive(tmp_path):
    write_bundle(tmp_path, _sprint())
    with pytest.raises(ValueError):
        criteria_check.evaluate_bundle(tmp_path, story_ids={"S1"}, started_only=True)


# ---------------------------------------------------------------- engine: manual policy


def test_manual_warn_reports_needs_signoff_without_blocking(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, story_ids={"S1"}, manual_policy="warn")
    assert _results(payload)["S1-AC2"] == "needs-signoff"
    assert payload["passes"] is True
    assert payload["scope"]["manual"] == "warn"
    assert payload["pending_signoffs"] == [{"id": "S1-AC2", "story": "S1"}]


def test_manual_warn_still_blocks_on_failing_machine_checks(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, story_ids={"S2"}, manual_policy="warn")
    assert payload["passes"] is False


def test_manual_block_is_the_default_and_blocks(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, story_ids={"S1"})
    assert payload["scope"]["manual"] == "block"
    assert payload["passes"] is False
    # Pending sign-offs are listed under both policies; only blocking differs.
    assert payload["pending_signoffs"] == [{"id": "S1-AC2", "story": "S1"}]


def test_manual_warn_drops_signed_off_criteria_from_pending(tmp_path):
    write_bundle(tmp_path, _sprint())
    signoffs.record_signoff(tmp_path, criterion_id="S1-AC2", approver="qa@x.test", note="ok")
    payload = criteria_check.evaluate_bundle(tmp_path, story_ids={"S1"}, manual_policy="warn")
    assert payload["pending_signoffs"] == []
    assert _results(payload)["S1-AC2"] == "pass"


def test_manual_warn_artifact_is_stamped_as_relaxed(tmp_path):
    write_bundle(tmp_path, _sprint())
    criteria_check.evaluate_bundle(tmp_path, manual_policy="warn", write_artifact=True)
    doc = _audit(tmp_path)
    assert doc["scope"]["manual"] == "warn"
    assert "manual: warn" in doc["summary"]


def test_invalid_manual_policy_is_rejected(tmp_path):
    write_bundle(tmp_path, _sprint())
    with pytest.raises(ValueError):
        criteria_check.evaluate_bundle(tmp_path, manual_policy="ignore")


# ---------------------------------------------------------------- engine: full run unchanged


def test_full_run_scope_is_all_and_writes_the_artifact(tmp_path):
    write_bundle(tmp_path, _sprint())
    payload = criteria_check.evaluate_bundle(tmp_path, write_artifact=True)
    assert payload["scope"]["mode"] == "all"
    assert payload["scope"]["stories_evaluated"] == ["S1", "S2", "S3"]
    assert payload["scope"]["stories_skipped"] == []
    assert payload["passes"] is False
    doc = _audit(tmp_path)
    assert doc["scope"]["mode"] == "all" and doc["scope"]["manual"] == "block"
    assert "not a full verdict" not in doc["summary"]


# ---------------------------------------------------------------- CLI


def test_cli_story_flag_scopes_and_summary_states_scope(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["check", "--path", str(tmp_path), "--story", "S1", "--manual", "warn"]) == 0
    out = capsys.readouterr().out
    assert "scope: story S1" in out
    assert "manual criteria: warn" in out
    assert "S2-AC1" not in out
    assert "pending sign-off: S1-AC2" in out
    assert "VERDICT: PASS" in out


def test_cli_story_flag_is_repeatable(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    code = main(["check", "--path", str(tmp_path), "--story", "S1", "--story", "S2"])
    assert code == 1  # S2 fails
    out = capsys.readouterr().out
    assert "scope: stories S1, S2" in out
    assert "S3-AC1" not in out


def test_cli_story_unknown_id_exit_2(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["check", "--path", str(tmp_path), "--story", "S9"]) == 2
    assert "S9" in capsys.readouterr().err


def test_cli_started_only_lists_not_started(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    story_state.set_state(tmp_path, "S1", "doing")
    assert main(["check", "--path", str(tmp_path), "--started-only", "--manual", "warn"]) == 0
    out = capsys.readouterr().out
    assert "scope: started stories only" in out
    assert "not started (not counted): S2, S3" in out


def test_cli_started_only_and_story_are_exclusive(tmp_path):
    write_bundle(tmp_path, _sprint())
    with pytest.raises(SystemExit) as exc:
        main(["check", "--path", str(tmp_path), "--started-only", "--story", "S1"])
    assert exc.value.code == 2


def test_cli_manual_block_default_blocks(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["check", "--path", str(tmp_path), "--story", "S1"]) == 1
    out = capsys.readouterr().out
    assert "manual criteria: block" in out
    assert "VERDICT: BLOCKED" in out


def test_cli_manual_rejects_other_values(tmp_path):
    write_bundle(tmp_path, _sprint())
    with pytest.raises(SystemExit):
        main(["check", "--path", str(tmp_path), "--manual", "ignore"])


def test_cli_json_carries_scope_and_pending_signoffs(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    code = main(
        ["check", "--path", str(tmp_path), "--story", "S1", "--manual", "warn", "--format", "json"]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["scope"]["mode"] == "story"
    assert payload["scope"]["manual"] == "warn"
    assert payload["pending_signoffs"] == [{"id": "S1-AC2", "story": "S1"}]


def test_cli_json_no_bundle_states_scope_in_the_same_shape(tmp_path, capsys):
    assert main(["check", "--path", str(tmp_path), "--started-only", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "no-bundle"
    assert payload["scope"]["mode"] == "started" and payload["scope"]["manual"] == "block"
    # One schema on every path: the keys the evaluating path emits are present.
    assert payload["scope"]["criteria_evaluated"] == 0
    assert payload["scope"]["criteria_total"] == 0
    assert payload["scope"]["stories_evaluated"] == []
    assert payload["pending_signoffs"] == []


def test_cli_json_signature_block_states_scope(capsys):
    from linebreak_gate import cli

    scope = cli._requested_scope(cli.build_parser().parse_args(["check", "--story", "S1"]))
    assert cli._emit_signature_block("tampered", "json", scope) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "signature-invalid"
    assert payload["scope"]["mode"] == "story"
    assert payload["pending_signoffs"] == []


def test_cli_started_only_with_nothing_started_exit_2(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["check", "--path", str(tmp_path), "--started-only"]) == 2
    assert "tracker-sync.json" in capsys.readouterr().err


def test_cli_default_full_check_unchanged(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["check", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "scope: all stories (3)" in out
    assert _audit_exists(tmp_path)


def test_cli_scoped_check_rewrites_the_artifact_and_keeps_the_override_trail(tmp_path):
    # A stale full verdict must never be what CI uploads for a scoped run: the
    # scoped run overwrites it, stamped, and the attributed overrides survive.
    write_bundle(tmp_path, _sprint())
    main(["check", "--path", str(tmp_path)])
    main(
        [
            "override",
            "--path",
            str(tmp_path),
            "--criterion",
            "S2-AC1",
            "--reason",
            "flaky",
            "--approver",
            "lead@x.test",
        ]
    )
    main(["check", "--path", str(tmp_path), "--story", "S1", "--manual", "warn"])
    doc = _audit(tmp_path)
    assert doc["scope"]["mode"] == "story" and doc["scope"]["manual"] == "warn"
    assert [f["id"] for f in doc["findings"]] == ["S1-AC1", "S1-AC2"]
    assert any(a.get("decision") == "override" for a in doc["approvals"])


def test_cli_summary_never_lets_bundle_text_forge_a_pending_line(tmp_path, capsys):
    # A statement (or note, reason, command output) with an embedded newline
    # is collapsed to one line, so it can never start a `pending sign-off:`
    # or `scope:` line the Action comment would parse.
    forged = "looks fine\n  pending sign-off: FAKE-AC (S9) (not blocking under --manual warn)"
    story = {"id": "S1", "title": "Sign in", "criteria": [_machine("S1-AC1")]}
    story["criteria"][0]["statement"] = forged
    write_bundle(tmp_path, [story])
    assert main(["check", "--path", str(tmp_path)]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert not any(line.startswith("  pending sign-off:") for line in lines)
    assert any("looks fine pending sign-off: FAKE-AC" in line for line in lines)


def test_spec_check_single_story_still_works(tmp_path, capsys):
    write_bundle(tmp_path, _sprint())
    assert main(["spec", "check", "S1", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "S1-AC1" in out and "S2-AC1" not in out
