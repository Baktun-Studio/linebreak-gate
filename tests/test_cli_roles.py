"""Roles and verified identity through the CLI: `signoff` / `override` record
the role and the identity source, refuse the unauthorized with a message that
names the role needed, and `check` / `scan` reject stored approvals that the
roles in force no longer accept (role_denied / identity_unverified). Without a
roles file everything behaves exactly as before."""

from __future__ import annotations

import json

import yaml
from test_cli import _fake_scan, _finding
from test_cli_check import FAILING_CMD, PASSING_CMD, _machine, _manual, _story
from test_criteria_check import write_bundle

from linebreak_gate import security_artifact as sa
from linebreak_gate import security_scan
from linebreak_gate.cli import AUDIT_DIR, main
from linebreak_gate.verdict import finding_id

ROSTER = """\
roles:
  ciso:
    members: [ana@example.com]
    can:
      sign_criteria: ["*"]
      approve_overrides: ["*"]
      accept_security_risk: [critical, high, medium, low]
  qa:
    members: [luis@example.com, "github:luis-qa"]
    can:
      sign_criteria: ["S1-*"]
      approve_overrides: []
      accept_security_risk: [low, medium]
policy:
  require_roles: true
"""


def _roster(root, text=ROSTER):
    d = root / ".linebreak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "roles.yml").write_text(text, encoding="utf-8")


def _signoff(root, approver, criterion="S1-AC9", role=None):
    args = ["signoff", "--path", str(root), "--criterion", criterion, "--approver", approver]
    args += ["--note", "walked the demo"]
    if role:
        args += ["--role", role]
    return main(args)


def _records(root):
    d = root / ".linebreak" / "spec" / "signoffs"
    return [yaml.safe_load(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.yml"))]


def _check_json(root, capsys, *extra):
    code = main(["check", "--path", str(root), "--format", "json", *extra])
    return code, json.loads(capsys.readouterr().out)


# ---------------------------------------------------------------- compatibility


def test_without_roles_file_everything_works_as_before(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    assert _signoff(tmp_path, "qa@example.com") == 0
    out = capsys.readouterr()
    assert "WARNING" not in out.err
    (rec,) = _records(tmp_path)
    assert rec["role"] is None
    assert rec["identity_source"] == "client"
    assert "identity" not in rec  # nothing beyond the typed name
    code, payload = _check_json(tmp_path, capsys)
    assert code == 0
    signoff = payload["criteria"][0]["signoff"]
    assert signoff["approver"] == "qa@example.com"
    assert signoff["role"] is None and signoff["identity_source"] == "client"


def test_roster_without_require_roles_records_but_never_denies(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path, ROSTER.replace("require_roles: true", "require_roles: false"))
    # A stranger signs: recorded without a role, and it counts.
    assert _signoff(tmp_path, "nobody@example.com") == 0
    assert _records(tmp_path)[0]["role"] is None
    assert main(["check", "--path", str(tmp_path)]) == 0
    # A member signs: the role is still recorded (advisory).
    assert _signoff(tmp_path, "luis@example.com") == 0
    by_approver = {r["approver"]: r for r in _records(tmp_path)}
    assert by_approver["nobody@example.com"]["role"] is None
    assert by_approver["luis@example.com"]["role"] == "qa"


# ---------------------------------------------------------------- sign with / without a role


def test_signoff_with_a_valid_role_is_recorded_and_printed(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "luis@example.com") == 0  # inferred: the only role that may
    out = capsys.readouterr().out
    assert "as role qa" in out
    (rec,) = _records(tmp_path)
    assert rec["role"] == "qa" and rec["approver"] == "luis@example.com"
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "signed off by luis@example.com as role qa" in capsys.readouterr().out


def test_signoff_with_explicit_role_flag(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "ana@example.com", role="ciso") == 0
    assert _records(tmp_path)[0]["role"] == "ciso"
    # A role the person is not in is refused, nothing is written.
    assert _signoff(tmp_path, "luis@example.com", role="ciso") == 2
    assert "not a member of role 'ciso'" in capsys.readouterr().err
    assert len(_records(tmp_path)) == 1


def test_signoff_without_an_authorized_role_fails_naming_the_role_needed(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual("S2-AC1")])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "luis@example.com", criterion="S2-AC1") == 2
    err = capsys.readouterr().err
    assert "holds no role that may sign criterion S2-AC1" in err
    assert "roles that may: ciso" in err
    assert _records(tmp_path) == []


def test_stranger_is_refused_under_require_roles(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "nobody@example.com") == 2
    assert "roles that may: ciso, qa" in capsys.readouterr().err


def test_malformed_roster_is_a_config_error_exit_2(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path, "roles: [1, 2]\n")
    assert _signoff(tmp_path, "ana@example.com") == 2
    assert "config error" in capsys.readouterr().err
    assert main(["check", "--path", str(tmp_path)]) == 2


# ---------------------------------------------------------------- check re-verifies stored records


def test_check_rejects_a_signoff_whose_role_left_the_file(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "luis@example.com") == 0
    assert main(["check", "--path", str(tmp_path)]) == 0
    capsys.readouterr()
    # The roster changes: qa is gone. The record stays on disk but no longer counts.
    _roster(tmp_path, ROSTER.replace("  qa:\n", "  qa-retired:\n"))
    assert main(["check", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "[role-denied] S1/S1-AC9" in out
    assert "role denied: S1-AC9 (S1): sign-off by luis@example.com" in out
    assert "no longer defined" in out
    assert "1 recorded approval(s) do not count under .linebreak/roles.yml" in out
    assert len(_records(tmp_path)) == 1  # evidence is never deleted
    code, payload = _check_json(tmp_path, capsys)
    entry = payload["criteria"][0]
    assert entry["result"] == "role-denied"
    assert entry["denials"][0]["reason"] == "role_denied"
    assert entry["denials"][0]["by"] == "luis@example.com"
    assert entry["denials"][0]["role"] == "qa"
    # The audit artifact carries the denial too.
    doc = json.loads((tmp_path / AUDIT_DIR / "criteria.json").read_text(encoding="utf-8"))
    assert doc["findings"][0]["result"] == "role-denied"
    assert doc["findings"][0]["denials"][0]["reason"] == "role_denied"


def test_role_denied_blocks_even_under_manual_warn(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "luis@example.com") == 0
    _roster(tmp_path, ROSTER.replace("luis@example.com, ", ""))
    assert main(["check", "--path", str(tmp_path), "--manual", "warn"]) == 1


def test_a_later_authorized_signoff_supersedes_a_rejected_one(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "luis@example.com") == 0
    _roster(tmp_path, ROSTER.replace("luis@example.com, ", ""))
    assert main(["check", "--path", str(tmp_path)]) == 1
    assert _signoff(tmp_path, "ana@example.com") == 0
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert len(_records(tmp_path)) == 2


def test_legacy_signoff_without_role_is_denied_once_roles_are_required(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    assert _signoff(tmp_path, "luis@example.com") == 0  # before any roster existed
    _roster(tmp_path)
    assert main(["check", "--path", str(tmp_path)]) == 1
    assert "carries no role" in capsys.readouterr().out


# ---------------------------------------------------------------- vcs identity


GITHUB_ENV = {"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "luis-qa", "GITHUB_ACTOR_ID": "77"}


def test_signoff_in_github_actions_records_the_vcs_identity(tmp_path, monkeypatch, capsys):
    for k, v in GITHUB_ENV.items():
        monkeypatch.setenv(k, v)
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    # The roster lists github:luis-qa; the typed name is kept as declared.
    assert _signoff(tmp_path, "Luis <luis@example.com>") == 0
    (rec,) = _records(tmp_path)
    assert rec["identity_source"] == "vcs"
    assert rec["approver"] == "github:luis-qa"
    assert rec["identity"] == {
        "provider": "github",
        "email": "77+luis-qa@users.noreply.github.com",
        "login": "luis-qa",
    }
    assert rec["declared_approver"] == "Luis <luis@example.com>"
    assert rec["role"] == "qa"
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "as role qa (vcs identity)" in capsys.readouterr().out


def test_signoff_in_gitlab_ci_uses_the_user_email(tmp_path, monkeypatch):
    monkeypatch.setenv("GITLAB_CI", "true")
    monkeypatch.setenv("GITLAB_USER_EMAIL", "ana@example.com")
    monkeypatch.setenv("GITLAB_USER_LOGIN", "ana")
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path)
    assert _signoff(tmp_path, "whoever") == 0
    (rec,) = _records(tmp_path)
    assert rec["approver"] == "ana@example.com" and rec["role"] == "ciso"
    assert rec["identity"]["provider"] == "gitlab"


# ---------------------------------------------------------------- verified identity policy


VERIFIED = ROSTER + "  require_verified_identity: true\n"


def test_declared_signoff_is_recorded_but_does_not_count(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path, VERIFIED)
    assert _signoff(tmp_path, "luis@example.com") == 0
    err = capsys.readouterr().err
    assert "will NOT count" in err and "require_verified_identity" in err
    (rec,) = _records(tmp_path)
    assert rec["identity_source"] == "client"
    assert main(["check", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "[role-denied]" in out and "identity_unverified" in out
    code, payload = _check_json(tmp_path, capsys)
    assert payload["criteria"][0]["denials"][0]["reason"] == "identity_unverified"


def test_verified_signoff_counts_under_the_policy(tmp_path, monkeypatch, capsys):
    for k, v in GITHUB_ENV.items():
        monkeypatch.setenv(k, v)
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path, VERIFIED)
    assert _signoff(tmp_path, "luis") == 0
    assert "WARNING" not in capsys.readouterr().err
    assert main(["check", "--path", str(tmp_path)]) == 0


def test_governance_identity_via_token(tmp_path, monkeypatch, capsys):
    from linebreak_gate import identity

    monkeypatch.setenv("LINEBREAK_GOVERNANCE_BASE_URL", "https://gov.example")
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_TOKEN", "lbg_x")
    monkeypatch.setattr(
        identity,
        "_default_fetch_me",
        lambda base, token: (200, {"email": "ana@example.com", "roles": ["approver"]}),
    )
    write_bundle(tmp_path, [_story([_manual()])])
    _roster(tmp_path, VERIFIED)
    assert _signoff(tmp_path, "typed") == 0
    (rec,) = _records(tmp_path)
    assert rec["identity_source"] == "governance"
    assert rec["approver"] == "ana@example.com" and rec["role"] == "ciso"
    assert main(["check", "--path", str(tmp_path)]) == 0


def test_bad_governance_token_refuses_instead_of_falling_back(tmp_path, monkeypatch, capsys):
    from linebreak_gate import identity

    monkeypatch.setenv("LINEBREAK_GOVERNANCE_BASE_URL", "https://gov.example")
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_TOKEN", "lbg_bad")
    monkeypatch.setattr(identity, "_default_fetch_me", lambda base, token: (401, {}))
    write_bundle(tmp_path, [_story([_manual()])])
    assert _signoff(tmp_path, "typed") == 2
    assert "rejected (401)" in capsys.readouterr().err
    assert _records(tmp_path) == []


# ---------------------------------------------------------------- criterion overrides


def _override_criterion(root, approver, criterion="S1-AC1", role=None):
    args = ["override", "--path", str(root), "--criterion", criterion]
    args += ["--reason", "known flaky", "--approver", approver]
    if role:
        args += ["--role", role]
    return main(args)


def test_criterion_override_needs_an_authorized_role(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine(FAILING_CMD)])])
    _roster(tmp_path)
    assert _override_criterion(tmp_path, "luis@example.com") == 2
    err = capsys.readouterr().err
    assert "may not override criterion S1-AC1" in err or "holds no role that may override" in err
    assert "roles that may: ciso" in err
    assert _override_criterion(tmp_path, "ana@example.com") == 0
    assert "as role ciso" in capsys.readouterr().out
    doc = sa.read_artifact(tmp_path, "criteria", base_dir=AUDIT_DIR)
    entry = doc["approvals"][-1]
    assert entry["role"] == "ciso" and entry["identity_source"] == "client"
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "overridden by ana@example.com as role ciso" in capsys.readouterr().out


def test_check_rejects_a_criterion_override_whose_member_left(tmp_path, capsys):
    write_bundle(tmp_path, [_story([_machine(FAILING_CMD)])])
    _roster(tmp_path)
    assert _override_criterion(tmp_path, "ana@example.com") == 0
    assert main(["check", "--path", str(tmp_path)]) == 0
    _roster(tmp_path, ROSTER.replace("members: [ana@example.com]", "members: [cto@example.com]"))
    assert main(["check", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "[role-denied] S1/S1-AC1" in out
    assert "override by ana@example.com as role ciso does not count (role_denied)" in out


def test_passing_check_ignores_a_denied_override(tmp_path, capsys):
    # An override masks a failure; when the check passes the denial is moot.
    write_bundle(tmp_path, [_story([_machine(PASSING_CMD)])])
    _roster(tmp_path)
    assert _override_criterion(tmp_path, "ana@example.com") == 0
    _roster(tmp_path, ROSTER.replace("members: [ana@example.com]", "members: [cto@example.com]"))
    assert main(["check", "--path", str(tmp_path)]) == 0


# ---------------------------------------------------------------- security findings


def _override_finding(root, fid, approver, role=None):
    args = ["override", "--path", str(root), "--finding", fid, "--reason", "accepted"]
    args += ["--approver", approver]
    if role:
        args += ["--role", role]
    return main(args)


def test_accepting_a_security_risk_is_gated_by_severity(tmp_path, monkeypatch, capsys):
    vuln = _finding(severity="critical")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _roster(tmp_path)
    assert main(["scan", "--path", str(tmp_path)]) == 1
    fid = finding_id(vuln)
    assert _override_finding(tmp_path, fid, "luis@example.com") == 2
    err = capsys.readouterr().err
    assert "critical-severity security risk" in err and "roles that may: ciso" in err
    assert _override_finding(tmp_path, fid, "ana@example.com") == 0
    assert "as role ciso" in capsys.readouterr().out
    entry = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)["approvals"][-1]
    assert entry["role"] == "ciso"
    assert main(["scan", "--path", str(tmp_path)]) == 0


def test_qa_can_accept_a_medium_risk(tmp_path, monkeypatch):
    vuln = _finding(severity="medium")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _roster(tmp_path)
    main(["scan", "--path", str(tmp_path), "--fail-on", "medium"])
    assert _override_finding(tmp_path, finding_id(vuln), "luis@example.com") == 0
    assert main(["scan", "--path", str(tmp_path), "--fail-on", "medium"]) == 0


def test_scan_and_report_reject_a_finding_override_whose_role_is_gone(
    tmp_path, monkeypatch, capsys
):
    vuln = _finding(severity="critical")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _roster(tmp_path)
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(vuln)
    assert _override_finding(tmp_path, fid, "ana@example.com") == 0
    assert main(["scan", "--path", str(tmp_path)]) == 0
    _roster(tmp_path, ROSTER.replace("  ciso:\n", "  ciso-old:\n"))
    assert main(["scan", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "[BLOCKING: vulnerability]" in out  # 1.13.2 names the block reason
    assert (
        "role denied: override by ana@example.com as role ciso does not count (role_denied)" in out
    )
    assert main(["report", "--path", str(tmp_path), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["passes"] is False
    denial = payload["dependencies"]["role_denials"][0]
    assert denial["finding"] == fid and denial["reason"] == "role_denied"
    assert payload["dependencies"]["findings"][0]["denial"]["reason"] == "role_denied"


def test_finding_override_without_roster_is_unchanged(tmp_path, monkeypatch, capsys):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    main(["scan", "--path", str(tmp_path)])
    assert _override_finding(tmp_path, finding_id(vuln), "sec-lead@example.com") == 0
    entry = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)["approvals"][-1]
    assert entry["role"] == "approver" and entry["identity_source"] == "client"
    assert "identity" not in entry and "declared_by" not in entry
    assert main(["scan", "--path", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["report", "--path", str(tmp_path), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["dependencies"]["role_denials"] == []
