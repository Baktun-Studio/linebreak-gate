"""Criteria enforcement (LIN-37, Piece 3 of LIN-28): the approved acceptance
criteria in .linebreak/spec/ are evaluated at the boundary and block what
fails. Machine checks run; `manual` is satisfied ONLY by a recorded sign-off;
overrides are possible but always attributed. Never an LLM's own claim.

These tests pin the evaluation semantics with an injected runner (no real
builds), the runner-resolution table (pure), and the fail-closed posture.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from linebreak_gate import criteria_check, signoffs, spec_bundle
from linebreak_gate.spec_bundle import criterion_hash, dump_manifest_yaml, dump_story_yaml

MANIFEST_FIELDS = {
    "generated_at": "2026-07-13T00:00:00Z",
    "source_phase": "epics_and_stories",
    "approval": {
        "role": "architect",
        "user_email": "v@example.com",
        "approved_by": "v@example.com",
        "approved_at": "2026-07-13T00:00:01Z",
    },
}

STORY = {
    "id": "S1",
    "title": "User can sign in",
    "criteria": [
        {"id": "S1-AC1", "statement": "Builds cleanly", "check": {"type": "build"}},
        {
            "id": "S1-AC2",
            "statement": "Covered by tests",
            "check": {"type": "tests", "payload": "tests/test_login.py"},
        },
        {
            "id": "S1-AC3",
            "statement": "Smoke script passes",
            "check": {"type": "command", "payload": "./smoke.sh"},
        },
        {"id": "S1-AC4", "statement": "Design approved", "check": {"type": "manual"}},
    ],
}


def write_bundle(root: Path, stories=None) -> None:
    spec = root / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True, exist_ok=True)
    (spec / "manifest.yml").write_text(dump_manifest_yaml(**MANIFEST_FIELDS), encoding="utf-8")
    for s in stories or [STORY]:
        (spec / "stories" / f"{s['id']}.yml").write_text(dump_story_yaml(s), encoding="utf-8")


def passing_runner(criterion, root):  # noqa: ARG001 - signature fixed by contract
    return criteria_check.RunOutcome(ok=True, detail="ran fine")


def failing_runner(criterion, root):  # noqa: ARG001
    return criteria_check.RunOutcome(ok=False, detail="exit 1")


# ---------------------------------------------------------------- evaluation


def test_all_machine_checks_pass_but_manual_needs_signoff(tmp_path):
    write_bundle(tmp_path)
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner)
    by_id = {r["id"]: r for r in result["criteria"]}
    assert by_id["S1-AC1"]["result"] == "pass"
    assert by_id["S1-AC2"]["result"] == "pass"
    assert by_id["S1-AC3"]["result"] == "pass"
    assert by_id["S1-AC4"]["result"] == "needs-signoff"
    assert result["passes"] is False  # manual without sign-off BLOCKS


def test_failed_machine_check_blocks(tmp_path):
    write_bundle(tmp_path)
    result = criteria_check.evaluate_bundle(tmp_path, run=failing_runner)
    by_id = {r["id"]: r for r in result["criteria"]}
    assert by_id["S1-AC1"]["result"] == "fail"
    assert result["passes"] is False


def test_signoff_satisfies_manual_criterion(tmp_path):
    write_bundle(tmp_path)
    signoffs.record_signoff(
        tmp_path, criterion_id="S1-AC4", approver="qa@example.com", note="demo reviewed"
    )
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner)
    manual = next(r for r in result["criteria"] if r["id"] == "S1-AC4")
    assert manual["result"] == "pass"
    assert manual["signoff"]["approver"] == "qa@example.com"
    assert result["passes"] is True


def test_editing_a_criterion_stales_its_signoff(tmp_path):
    write_bundle(tmp_path)
    signoffs.record_signoff(
        tmp_path, criterion_id="S1-AC4", approver="qa@example.com", note="demo reviewed"
    )
    # The standard changes: the statement is edited and re-approved.
    import copy

    edited = copy.deepcopy(STORY)
    edited["criteria"][3]["statement"] = "Design approved INCLUDING dark mode"
    write_bundle(tmp_path, [edited])
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner)
    manual = next(r for r in result["criteria"] if r["id"] == "S1-AC4")
    assert manual["result"] == "needs-signoff", "old sign-off must not satisfy the new standard"


def test_signoff_on_unrelated_criterion_survives_other_edits(tmp_path):
    write_bundle(tmp_path)
    signoffs.record_signoff(
        tmp_path, criterion_id="S1-AC4", approver="qa@example.com", note="demo reviewed"
    )
    import copy

    edited = copy.deepcopy(STORY)
    edited["criteria"][0]["statement"] = "Builds cleanly on CI"  # unrelated machine criterion
    write_bundle(tmp_path, [edited])
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner)
    manual = next(r for r in result["criteria"] if r["id"] == "S1-AC4")
    assert manual["result"] == "pass", "editing S1-AC1 must not invalidate S1-AC4's sign-off"


def test_override_unblocks_only_that_criterion(tmp_path):
    write_bundle(tmp_path)
    criteria_check.record_criterion_override(
        tmp_path, criterion_id="S1-AC1", reason="flaky on CI runner", approver="lead@example.com"
    )
    result = criteria_check.evaluate_bundle(tmp_path, run=failing_runner)
    by_id = {r["id"]: r for r in result["criteria"]}
    assert by_id["S1-AC1"]["result"] == "overridden"
    assert by_id["S1-AC1"]["override"]["approver"] == "lead@example.com"
    assert by_id["S1-AC2"]["result"] == "fail", "a different failing criterion still blocks"
    assert result["passes"] is False


def test_override_goes_stale_when_criterion_is_edited(tmp_path):
    write_bundle(tmp_path)
    criteria_check.record_criterion_override(
        tmp_path, criterion_id="S1-AC1", reason="flaky", approver="lead@example.com"
    )
    import copy

    edited = copy.deepcopy(STORY)
    edited["criteria"][0]["check"] = {"type": "command", "payload": "make build"}
    write_bundle(tmp_path, [edited])
    result = criteria_check.evaluate_bundle(tmp_path, run=failing_runner)
    first = next(r for r in result["criteria"] if r["id"] == "S1-AC1")
    assert first["result"] == "fail", "override bound to the OLD criterion content"


def test_override_only_masks_an_actual_failure(tmp_path):
    # An override is consulted, but the check STILL RUNS: a criterion that now
    # passes is reported `pass` (not `overridden`), so a preemptive override
    # can't hide that a check currently passes, and `overridden` only ever
    # shows for a check that genuinely failed.
    write_bundle(tmp_path)
    criteria_check.record_criterion_override(
        tmp_path, criterion_id="S1-AC1", reason="flaky", approver="lead@example.com"
    )
    ran: list[str] = []

    def spy(criterion, root):  # noqa: ARG001
        ran.append(criterion["id"])
        return criteria_check.RunOutcome(ok=True, detail="")

    result = criteria_check.evaluate_bundle(tmp_path, run=spy)
    assert "S1-AC1" in ran, "the check runs even with an override on file"
    first = next(r for r in result["criteria"] if r["id"] == "S1-AC1")
    assert first["result"] == "pass", "a passing check is pass, not overridden"


def test_override_rescues_a_failing_check(tmp_path):
    write_bundle(tmp_path)
    criteria_check.record_criterion_override(
        tmp_path, criterion_id="S1-AC1", reason="flaky on CI", approver="lead@example.com"
    )
    result = criteria_check.evaluate_bundle(tmp_path, run=failing_runner)
    first = next(r for r in result["criteria"] if r["id"] == "S1-AC1")
    assert first["result"] == "overridden"
    assert first["override"]["approver"] == "lead@example.com"


def test_no_bundle_returns_none(tmp_path):
    assert criteria_check.evaluate_bundle(tmp_path, run=passing_runner) is None


def test_malformed_bundle_raises(tmp_path):
    spec = tmp_path / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "manifest.yml").write_text(": not yaml [", encoding="utf-8")
    with pytest.raises(spec_bundle.SpecBundleError):
        criteria_check.evaluate_bundle(tmp_path, run=passing_runner)


def test_results_artifact_written_with_prior_approvals_carried(tmp_path):
    write_bundle(tmp_path)
    criteria_check.record_criterion_override(
        tmp_path, criterion_id="S1-AC1", reason="flaky", approver="lead@example.com"
    )
    criteria_check.evaluate_bundle(tmp_path, run=failing_runner, write_artifact=True)
    import json

    doc = json.loads(
        (tmp_path / ".linebreak" / "audit" / "criteria.json").read_text(encoding="utf-8")
    )
    assert doc["kind"] == "criteria_check"
    assert any(a.get("decision") == "override" for a in doc["approvals"])


# ---------------------------------------------------------------- real command execution


def test_command_type_executes_payload_in_repo_root(tmp_path):
    story = {
        "id": "S9",
        "title": "Smoke",
        "criteria": [
            {
                "id": "S9-AC1",
                "statement": "true-ish command passes",
                "check": {"type": "command", "payload": 'python -c "import sys; sys.exit(0)"'},
            },
            {
                "id": "S9-AC2",
                "statement": "failing command fails",
                "check": {"type": "command", "payload": 'python -c "import sys; sys.exit(3)"'},
            },
        ],
    }
    write_bundle(tmp_path, [story])
    result = criteria_check.evaluate_bundle(tmp_path)  # default runner: real execution
    by_id = {r["id"]: r for r in result["criteria"]}
    assert by_id["S9-AC1"]["result"] == "pass"
    assert by_id["S9-AC2"]["result"] == "fail"


# ---------------------------------------------------------------- runner resolution (pure)


def test_build_resolution_by_stack(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts": {"build": "tsc"}}', encoding="utf-8")
    assert criteria_check.resolve_build_command(tmp_path) == ["npm", "run", "build"]
    (tmp_path / "pnpm-lock.yaml").write_text("", encoding="utf-8")
    assert criteria_check.resolve_build_command(tmp_path) == ["pnpm", "run", "build"]


def test_build_resolution_go_and_cargo(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    assert criteria_check.resolve_build_command(tmp_path) == ["go", "build", "./..."]


def test_build_resolution_unsupported_stack_is_error(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    with pytest.raises(criteria_check.CriteriaToolError):
        criteria_check.resolve_build_command(tmp_path)


def test_tests_resolution_pytest(tmp_path):
    import sys

    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    cmd = criteria_check.resolve_tests_command(tmp_path, "tests/test_login.py")
    # sys.executable, not bare "python" (absent on stock macOS; may lack pytest).
    assert cmd == [sys.executable, "-m", "pytest", "tests/test_login.py"]


def test_js_test_payload_never_falls_through_to_go_or_cargo(tmp_path):
    # A JS/TS payload with no Node test runner must be a tool error — NOT
    # `go test file.ts` / `cargo test file.ts` (which match 0 tests, exit 0,
    # and silently pass the criterion).
    (tmp_path / "go.mod").write_text("module x\n", encoding="utf-8")
    with pytest.raises(criteria_check.CriteriaToolError):
        criteria_check.resolve_tests_command(tmp_path, "src/auth.test.ts")


def test_tests_resolution_vitest(tmp_path):
    (tmp_path / "package.json").write_text(
        '{"devDependencies": {"vitest": "^3"}}', encoding="utf-8"
    )
    cmd = criteria_check.resolve_tests_command(tmp_path, "src/foo.test.ts")
    assert cmd == ["npx", "--no-install", "vitest", "run", "src/foo.test.ts"]


def test_tests_resolution_unsupported_is_error(tmp_path):
    with pytest.raises(criteria_check.CriteriaToolError):
        criteria_check.resolve_tests_command(tmp_path, "whatever.spec")


def test_unresolvable_runner_is_tool_error_not_a_pass(tmp_path):
    # A build criterion on a stack we can't build = exit-2 material, never a
    # silent pass and never a silent fail-as-if-code-was-wrong.
    story = {
        "id": "S2",
        "title": "X",
        "criteria": [{"id": "S2-AC1", "statement": "builds", "check": {"type": "build"}}],
    }
    write_bundle(tmp_path, [story])
    result = criteria_check.evaluate_bundle(tmp_path)
    first = result["criteria"][0]
    assert first["result"] == "error"
    assert result["tool_error"] is True


# ---------------------------------------------------------------- hashes


def test_criterion_hash_changes_with_content_and_not_with_dict_order():
    c1 = {"id": "A", "statement": "s", "check": {"type": "build"}}
    c2 = {"check": {"type": "build"}, "statement": "s", "id": "A"}
    c3 = {"id": "A", "statement": "s CHANGED", "check": {"type": "build"}}
    assert criterion_hash(c1) == criterion_hash(c2)
    assert criterion_hash(c1) != criterion_hash(c3)


# ---------------------------------------------------------------- runner probe


def test_probe_command_for_each_runner():
    probe = criteria_check.probe_command
    assert probe(["python", "-m", "pytest", "x.py"]) == ["python", "-m", "pytest", "--version"]
    assert probe(["npx", "--no-install", "vitest", "run", "a.ts"]) == [
        "npx",
        "--no-install",
        "vitest",
        "--version",
    ]
    assert probe(["npm", "run", "build"]) == ["npm", "--version"]
    assert probe(["go", "build", "./..."]) == ["go", "version"]
    assert probe(["cargo", "test", "p"]) == ["cargo", "--version"]


def test_missing_runner_is_tool_error_not_code_failure(tmp_path, monkeypatch):
    # `python -m pytest` in an env without pytest exits 1 — that is TOOL
    # trouble and must be exit-2 material, never reported as the code failing
    # the criterion.
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    story = {
        "id": "S3",
        "title": "T",
        "criteria": [
            {
                "id": "S3-AC1",
                "statement": "tests pass",
                "check": {"type": "tests", "payload": "tests/test_x.py"},
            }
        ],
    }
    write_bundle(tmp_path, [story])

    real_run = criteria_check.subprocess.run

    def fake_run(argv, **kwargs):
        if isinstance(argv, list) and argv[-1] in ("--version", "version"):

            class P:
                returncode = 1
                stdout = ""
                stderr = "No module named pytest"

            return P()
        return real_run(argv, **kwargs)

    monkeypatch.setattr(criteria_check.subprocess, "run", fake_run)
    result = criteria_check.evaluate_bundle(tmp_path)
    assert result["criteria"][0]["result"] == "error"
    assert result["tool_error"] is True
    assert "pytest" in result["criteria"][0]["detail"]


# ---------------------------------------------------------------- LIN-37 review hardening


def test_identical_checks_run_once_within_a_pass(tmp_path):
    # Two stories that each declare `build` (no payload) resolve to the same
    # run — do the work once (dedup within a single evaluate_bundle pass).
    s1 = {
        "id": "S1",
        "title": "A",
        "criteria": [{"id": "S1-B", "statement": "builds", "check": {"type": "build"}}],
    }
    s2 = {
        "id": "S2",
        "title": "B",
        "criteria": [{"id": "S2-B", "statement": "builds", "check": {"type": "build"}}],
    }
    write_bundle(tmp_path, [s1, s2])
    calls: list[str] = []

    def spy(criterion, root):  # noqa: ARG001
        calls.append(criterion["id"])
        return criteria_check.RunOutcome(ok=True, detail="")

    result = criteria_check.evaluate_bundle(tmp_path, run=spy)
    assert len(calls) == 1, "identical build check ran once, not per story"
    assert all(r["result"] == "pass" for r in result["criteria"])


def test_corrupt_criteria_audit_fails_closed(tmp_path):
    # A corrupt criteria.json holds the override trail — treat it as exit-2
    # material, never silently reset it (which would erase recorded overrides).
    write_bundle(tmp_path)
    audit = tmp_path / ".linebreak" / "audit"
    audit.mkdir(parents=True, exist_ok=True)
    (audit / "criteria.json").write_text("<<<<<<< HEAD\nnot json", encoding="utf-8")
    with pytest.raises(criteria_check.CriteriaToolError):
        criteria_check.evaluate_bundle(tmp_path, run=passing_runner)


def test_windows_style_shim_resolution_via_which(monkeypatch, tmp_path):
    # _which resolves a bare tool name to a full path (handles .cmd shims);
    # a missing tool is a clean tool error, not a launch crash.
    with pytest.raises(criteria_check.CriteriaToolError):
        criteria_check._which("definitely-not-a-real-tool-xyz")
