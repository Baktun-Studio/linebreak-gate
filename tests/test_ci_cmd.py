"""`linebreak-gate ci`: scan + scoped check + evidence + PR comment/status +
the worse exit code, for Bitbucket Pipelines and Azure DevOps."""

import json
from pathlib import Path

import pytest

from linebreak_gate import ci_cmd, ci_env, spec_bundle
from linebreak_gate.cli import main
from linebreak_gate.gate_config import GateConfigError

BITBUCKET_PR = {
    "BITBUCKET_BUILD_NUMBER": "12",
    "BITBUCKET_REPO_FULL_NAME": "acme-ws/backend",
    "BITBUCKET_COMMIT": "0123456789abcdef",
    "BITBUCKET_BRANCH": "feat/S1",
    "BITBUCKET_PR_ID": "5",
}


class FakeCli:
    """Stands in for cli.main: records argv, prints a canned report, returns
    a canned code per command."""

    def __init__(self, codes=None, texts=None, boom=False):
        self.calls = []
        self.codes = {"scan": 0, "check": 0, "report": 0, **(codes or {})}
        self.texts = {
            "scan": "LineBreak security gate\nVERDICT: PASS\n",
            "check": "VERDICT: PASS.\n",
            "report": json.dumps({"passes": True}),
            **(texts or {}),
        }
        self.boom = boom

    def __call__(self, argv):
        self.calls.append(list(argv))
        if self.boom and argv[0] == "scan":
            raise RuntimeError("scanner exploded")
        print(self.texts[argv[0]], end="")
        return self.codes[argv[0]]

    def argv(self, command):
        return next(c for c in self.calls if c[0] == command)


class FakeTransport:
    def __init__(self):
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, json.loads(body) if body else None))
        if method == "GET":
            return 200, {"values": [], "value": []}
        return 201, {}


def _write_bundle(root: Path, story_ids=("S1",)) -> None:
    spec_dir = root / ".linebreak" / "spec"
    (spec_dir / "stories").mkdir(parents=True)
    for sid in story_ids:
        story = {
            "id": sid,
            "title": f"Story {sid}",
            "epic": "E1",
            "criteria": [
                {
                    "id": f"{sid}-AC1",
                    "statement": "exits zero",
                    "check": {"type": "command", "payload": "true"},
                }
            ],
        }
        (spec_dir / "stories" / f"{sid}.yml").write_text(
            spec_bundle.dump_story_yaml(story), encoding="utf-8"
        )
    (spec_dir / "manifest.yml").write_text(
        spec_bundle.dump_manifest_yaml(
            generated_at="2026-09-01T00:00:00Z",
            source_phase="epics_and_stories",
            approval={"approved_by": "someone@x.test"},
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------- exit code + evidence


def test_worse_code_wins_and_evidence_is_written(tmp_path, capsys):
    (tmp_path / ".linebreak" / "audit").mkdir(parents=True)
    (tmp_path / ".linebreak" / "audit" / "security.json").write_text("{}")
    cli = FakeCli(codes={"scan": 1, "check": 0})
    rc = ci_cmd.run_ci(path=tmp_path, environ=BITBUCKET_PR, run_cli=cli)
    assert rc == 1
    out_dir = tmp_path / ".linebreak" / "ci-out"
    assert (out_dir / "report.txt").read_text(encoding="utf-8") == cli.texts["scan"]
    criteria = (out_dir / "criteria.txt").read_text(encoding="utf-8")
    assert criteria.startswith(
        "linebreak-gate ci: scope: all stories (story: all); manual criteria: warn; stage: pr\n"
    )
    assert json.loads((out_dir / "report.json").read_text(encoding="utf-8")) == {"passes": True}
    assert (
        (out_dir / "comment.md")
        .read_text(encoding="utf-8")
        .startswith("<!-- linebreak-gate-summary -->")
    )
    assert (out_dir / "security.json").exists()
    out = capsys.readouterr().out
    assert (
        "Bitbucket Pipelines; repo acme-ws/backend; commit 0123456789ab; branch feat/S1; PR #5"
        in out
    )
    assert "scan exited 1, check exited 0" in out
    assert "no credentials" in out  # comment skipped, said out loud


@pytest.mark.parametrize(
    "codes, expected", [({"scan": 0, "check": 2}, 2), ({"scan": 2, "check": 1}, 2), ({}, 0)]
)
def test_tool_error_is_never_downgraded(tmp_path, codes, expected):
    assert ci_cmd.run_ci(path=tmp_path, environ={}, run_cli=FakeCli(codes=codes)) == expected


def test_a_crash_in_the_cli_is_a_tool_error_with_the_trace_as_evidence(tmp_path):
    rc = ci_cmd.run_ci(path=tmp_path, environ={}, run_cli=FakeCli(boom=True))
    assert rc == 2
    report = (tmp_path / ".linebreak" / "ci-out" / "report.txt").read_text(encoding="utf-8")
    assert "scanner exploded" in report and "gate stays closed" in report


def test_fail_on_and_out_dir_are_forwarded(tmp_path):
    cli = FakeCli()
    out = tmp_path / "evidence"
    ci_cmd.run_ci(path=tmp_path, fail_on="high", out_dir=out, environ={}, run_cli=cli)
    assert cli.argv("scan") == ["scan", "--path", str(tmp_path.resolve()), "--fail-on", "high"]
    assert "--fail-on" in cli.argv("report")
    assert (out / "report.txt").exists()


# ---------------------------------------------------------------- scope (check-scope.sh parity)


def test_scope_all_on_a_pull_request_defaults_to_warn_and_pr(tmp_path):
    cli = FakeCli()
    ci_cmd.run_ci(path=tmp_path, environ=BITBUCKET_PR, run_cli=cli)
    assert cli.argv("check")[3:] == ["--manual", "warn", "--stage", "pr"]


def test_scope_all_on_a_branch_build_defaults_to_block_and_release(tmp_path):
    cli = FakeCli()
    env = {k: v for k, v in BITBUCKET_PR.items() if k != "BITBUCKET_PR_ID"}
    ci_cmd.run_ci(path=tmp_path, environ=env, run_cli=cli)
    assert cli.argv("check")[3:] == ["--manual", "block", "--stage", "release"]


def test_explicit_manual_and_stage_win_over_auto(tmp_path):
    cli = FakeCli()
    ci_cmd.run_ci(path=tmp_path, environ=BITBUCKET_PR, run_cli=cli, manual="block", stage="release")
    assert cli.argv("check")[3:] == ["--manual", "block", "--stage", "release"]


def test_story_auto_infers_the_approved_story_from_the_branch(tmp_path):
    _write_bundle(tmp_path, ("S1", "S2"))
    cli = FakeCli()
    env = {**BITBUCKET_PR, "BITBUCKET_BRANCH": "feat/S1-add-login"}
    ci_cmd.run_ci(path=tmp_path, environ=env, run_cli=cli, story="auto")
    assert cli.argv("check")[-2:] == ["--story", "S1"]
    criteria = (tmp_path / ".linebreak" / "ci-out" / "criteria.txt").read_text(encoding="utf-8")
    assert "scope: story S1 inferred from branch feat/S1-add-login (story: auto)" in criteria


def test_story_auto_falls_back_to_started_only(tmp_path):
    _write_bundle(tmp_path, ("S1",))
    cli = FakeCli()
    env = {**BITBUCKET_PR, "BITBUCKET_BRANCH": "feat/S9-unknown"}
    ci_cmd.run_ci(path=tmp_path, environ=env, run_cli=cli, story="auto")
    assert cli.argv("check")[-1] == "--started-only"
    criteria = (tmp_path / ".linebreak" / "ci-out" / "criteria.txt").read_text(encoding="utf-8")
    assert "started stories only; no approved story id in branch 'feat/S9-unknown'" in criteria


def test_story_auto_on_main_uses_started_only(tmp_path):
    cli = FakeCli()
    env = {**BITBUCKET_PR, "BITBUCKET_BRANCH": "main"}
    ci_cmd.run_ci(path=tmp_path, environ=env, run_cli=cli, story="auto")
    assert cli.argv("check")[-1] == "--started-only"


def test_explicit_story_id(tmp_path):
    cli = FakeCli()
    ci_cmd.run_ci(path=tmp_path, environ={}, run_cli=cli, story="S7")
    assert cli.argv("check")[-2:] == ["--story", "S7"]


@pytest.mark.parametrize("kw", [{"manual": "maybe"}, {"stage": "later"}, {"story": "  "}])
def test_invalid_scope_input_fails_closed_without_running_check(tmp_path, kw):
    cli = FakeCli()
    rc = ci_cmd.run_ci(path=tmp_path, environ={}, run_cli=cli, **kw)
    assert rc == 2
    assert not [c for c in cli.calls if c[0] == "check"]
    criteria = (tmp_path / ".linebreak" / "ci-out" / "criteria.txt").read_text(encoding="utf-8")
    assert "gate stays closed" in criteria


def test_infer_story_without_a_spec_trusts_the_branch():
    # Same as check-scope.sh: `spec show` exits 0 when no spec exists, and the
    # check is a no-op then anyway.
    assert ci_cmd.infer_story(Path("/nonexistent-root"), "feat/S1") == "S1"
    assert ci_cmd.infer_story(Path("/nonexistent-root"), "hotfix/x") is None
    assert ci_cmd.infer_story(Path("/nonexistent-root"), None) is None


# ---------------------------------------------------------------- PR comment + status


def test_comment_and_status_posted_on_bitbucket_with_a_token(tmp_path, capsys):
    t = FakeTransport()
    cli = FakeCli(codes={"scan": 1})
    rc = ci_cmd.run_ci(
        path=tmp_path,
        environ={**BITBUCKET_PR, "BITBUCKET_ACCESS_TOKEN": "tok"},
        run_cli=cli,
        transport=t,
    )
    assert rc == 1
    posts = [(m, u, b) for m, u, b in t.calls if m == "POST"]
    assert posts[0][1].endswith("/pullrequests/5/comments")
    assert "known vulnerabilities" in posts[0][2]["content"]["raw"]
    assert posts[1][1].endswith("/commit/0123456789abcdef/statuses/build")
    assert posts[1][2]["state"] == "FAILED"
    out = capsys.readouterr().out
    assert "PR comment created on Bitbucket Pipelines pull request #5" in out


def test_no_comment_and_no_status_flags(tmp_path):
    t = FakeTransport()
    ci_cmd.run_ci(
        path=tmp_path,
        environ={**BITBUCKET_PR, "BITBUCKET_ACCESS_TOKEN": "tok"},
        run_cli=FakeCli(),
        transport=t,
        comment=False,
        status=False,
    )
    assert not t.calls


def test_azure_end_to_end_with_job_token(tmp_path):
    t = FakeTransport()
    env = {
        "TF_BUILD": "True",
        "SYSTEM_PULLREQUEST_PULLREQUESTID": "31",
        "SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/feat/S1",
        "BUILD_SOURCEVERSION": "mergesha",
        "BUILD_REPOSITORY_NAME": "backend",
        "BUILD_REPOSITORY_PROVIDER": "TfsGit",
        "SYSTEM_TEAMPROJECT": "Core",
        "SYSTEM_COLLECTIONURI": "https://dev.azure.com/acme/",
        "SYSTEM_ACCESSTOKEN": "sys",
    }
    rc = ci_cmd.run_ci(path=tmp_path, environ=env, run_cli=FakeCli(), transport=t)
    assert rc == 0
    urls = [u for _, u, _ in t.calls]
    assert any(u.endswith("/pullRequests/31/threads?api-version=7.1") for u in urls)
    assert any(u.endswith("/pullRequests/31/statuses?api-version=7.1") for u in urls)


# ---------------------------------------------------------------- Azure macro scrub


def test_unexpanded_azure_macros_are_treated_as_unset(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "$(ANTHROPIC_API_KEY)")
    monkeypatch.setenv("LINEBREAK_LICENSE_KEY", "real-key")
    monkeypatch.setenv("SYSTEM_ACCESSTOKEN", "$(System.AccessToken)")
    for name in BITBUCKET_PR:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("TF_BUILD", raising=False)
    ci_cmd.run_ci(path=tmp_path, run_cli=FakeCli())
    import os

    assert "ANTHROPIC_API_KEY" not in os.environ
    assert "SYSTEM_ACCESSTOKEN" not in os.environ
    assert os.environ["LINEBREAK_LICENSE_KEY"] == "real-key"
    out = capsys.readouterr().out
    assert "ANTHROPIC_API_KEY holds an unexpanded $(...) pipeline macro" in out


def test_scrub_only_touches_credential_names():
    environ = {"ANTHROPIC_API_KEY": "$(X)", "OTHER": "$(Y)", "BITBUCKET_ACCESS_TOKEN": "tok"}
    assert ci_cmd.scrub_unexpanded_macros(environ) == ["ANTHROPIC_API_KEY"]
    assert environ == {"OTHER": "$(Y)", "BITBUCKET_ACCESS_TOKEN": "tok"}


# ---------------------------------------------------------------- CLI routing


def test_cli_routes_ci_with_every_flag(tmp_path, monkeypatch):
    called = {}
    monkeypatch.setattr(ci_cmd, "run_ci", lambda **kw: called.update(kw) or 1)
    rc = main(
        [
            "ci",
            "--path",
            str(tmp_path),
            "--fail-on",
            "high",
            "--story",
            "auto",
            "--manual",
            "block",
            "--stage",
            "pr",
            "--out-dir",
            "ev",
            "--no-comment",
            "--no-status",
        ]
    )
    assert rc == 1
    assert called == {
        "path": str(tmp_path),
        "fail_on": "high",
        "story": "auto",
        "manual": "block",
        "stage": "pr",
        "comment": False,
        "status": False,
        "out_dir": "ev",
    }


def test_cli_ci_defaults(tmp_path, monkeypatch):
    called = {}
    monkeypatch.setattr(ci_cmd, "run_ci", lambda **kw: called.update(kw) or 0)
    assert main(["ci", "--path", str(tmp_path)]) == 0
    assert (called["story"], called["manual"], called["stage"]) == ("all", "auto", "auto")
    assert called["comment"] is True and called["status"] is True


def test_ci_real_cli_end_to_end_without_a_scanner(tmp_path, monkeypatch, capsys):
    """The real CLI under `ci`: a scan that cannot run fails closed (2), the
    check with no bundle is a no-op (0), the verdict is 2, and the evidence
    files exist. No network, no scanner binary."""
    from linebreak_gate import llm, security_scan

    monkeypatch.setattr(llm, "build_ask", lambda: None)
    monkeypatch.setattr(
        security_scan,
        "scan_project",
        lambda root, **kw: {
            "findings": [],
            "scanner": None,
            "error": "no scanner",
            "risk_score": None,
        },
    )
    monkeypatch.delenv("LINEBREAK_LICENSE_KEY", raising=False)
    monkeypatch.delenv("LINEBREAK_ENTITLEMENTS_PROVIDER", raising=False)
    rc = ci_cmd.run_ci(path=tmp_path, environ=BITBUCKET_PR)
    assert rc == 2
    report = (tmp_path / ".linebreak" / "ci-out" / "report.txt").read_text(encoding="utf-8")
    assert "gate stays closed" in report
    criteria = (tmp_path / ".linebreak" / "ci-out" / "criteria.txt").read_text(encoding="utf-8")
    assert "no approved criteria found" in criteria
    assert "SCAN ERROR" in (tmp_path / ".linebreak" / "ci-out" / "comment.md").read_text(
        encoding="utf-8"
    )


def test_env_detection_is_the_only_source_of_provider_facts(tmp_path, capsys):
    ci_cmd.run_ci(path=tmp_path, environ={"USER": "vlad"}, run_cli=FakeCli())
    out = capsys.readouterr().out
    assert ci_env.PROVIDER_LABELS["local"] in out
    assert "not a pull request" in out


def test_gate_config_error_from_init_provider_is_reported():
    from linebreak_gate import init_cmd

    with pytest.raises(GateConfigError):
        init_cmd.run_init(path=".", provider="svn", interactive=False, run=lambda *a, **k: None)


# ---------------------------------------------------------------- block reasons in the PR (1.13.4)


def test_block_reasons_from_report_json_reach_comment_and_status(tmp_path):
    t = FakeTransport()
    cli = FakeCli(
        codes={"scan": 1},
        texts={
            "scan": "VERDICT: BLOCKED — 1 blocking finding(s) (1 vulnerability; floor 'critical').\n",
            "report": json.dumps({"passes": False, "block_reasons": ["kev", "expired_risk"]}),
        },
    )
    ci_cmd.run_ci(
        path=tmp_path,
        environ={**BITBUCKET_PR, "BITBUCKET_ACCESS_TOKEN": "tok"},
        run_cli=cli,
        transport=t,
    )
    posts = [(u, b) for m, u, b in t.calls if m == "POST"]
    comment = posts[0][1]["content"]["raw"]
    # The JSON report is authoritative over the summary text.
    assert "**Block reasons:** kev, expired_risk" in comment
    assert posts[1][1]["description"] == "BLOCKED: known vulnerabilities (kev, expired_risk)"
    assert "Block reasons" in (tmp_path / ".linebreak" / "ci-out" / "comment.md").read_text(
        encoding="utf-8"
    )


def test_role_denials_in_the_check_reach_the_status(tmp_path):
    t = FakeTransport()
    cli = FakeCli(
        codes={"check": 1},
        texts={
            "check": "  role denied: S1-AC2 (S1): sign-off by dev does not count\n"
            "VERDICT: BLOCKED — 1 role-denied (reasons: role_denied). Fix.\n",
            "report": "not json",
        },
    )
    ci_cmd.run_ci(
        path=tmp_path,
        environ={**BITBUCKET_PR, "BITBUCKET_ACCESS_TOKEN": "tok"},
        run_cli=cli,
        transport=t,
    )
    posts = [(u, b) for m, u, b in t.calls if m == "POST"]
    assert posts[1][1]["description"] == "BLOCKED: acceptance criteria unmet (role_denied)"
    assert "**Role denied:** `S1-AC2` (S1)" in posts[0][1]["content"]["raw"]


def test_json_block_reasons_guards():
    assert ci_cmd._json_block_reasons("nope") is None
    assert ci_cmd._json_block_reasons(json.dumps({"passes": None})) is None
    assert ci_cmd._json_block_reasons(json.dumps({"block_reasons": "kev"})) is None
    assert ci_cmd._json_block_reasons(json.dumps({"block_reasons": ["kev"]})) == ["kev"]
