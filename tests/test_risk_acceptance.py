"""Accepted risks expire: policy (`risk_acceptance` in gate.yml), the
`expired_risk` block, the 14-day warning, and renewals that keep history."""

from __future__ import annotations

import datetime as dt
import json

import pytest
from test_criteria_check import write_bundle

from linebreak_gate import llm, risk_acceptance, security_scan
from linebreak_gate import security_artifact as sa
from linebreak_gate.cli import AUDIT_DIR, main
from linebreak_gate.verdict import finding_id

TODAY = dt.date(2026, 9, 21)
FAILING_CMD = 'python -c "import sys; sys.exit(1)"'
PASSING_CMD = 'python -c "import sys; sys.exit(0)"'


def _finding(severity="critical", cve="CVE-2024-0001", package="lodash", version="4.17.20"):
    return {
        "cve_id": cve,
        "severity": severity,
        "cvss": 9.8,
        "package": package,
        "ecosystem": "npm",
        "installed_version": version,
        "fixed_version": "9.9.9",
        "advisory_url": f"https://osv.dev/vulnerability/{cve}",
        "title": f"test advisory for {package}",
    }


def _fake_scan(findings):
    def scan(root, **kwargs):
        return {"findings": findings, "risk_score": 100, "scanner": "osv-scanner", "error": None}

    return scan


def _gate_yml(root, text):
    d = root / ".linebreak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "gate.yml").write_text(text, encoding="utf-8")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("LINEBREAK_LICENSE_KEY", raising=False)
    monkeypatch.delenv("LINEBREAK_ENTITLEMENTS_PROVIDER", raising=False)
    monkeypatch.setattr(llm, "build_ask", lambda: None)
    monkeypatch.setattr(risk_acceptance, "today", lambda: TODAY)


def _set_today(monkeypatch, date):
    monkeypatch.setattr(risk_acceptance, "today", lambda: date)


def _override(root, fid, *extra):
    return main(
        [
            "override",
            "--path",
            str(root),
            "--finding",
            fid,
            "--reason",
            "fix blocked upstream",
            "--approver",
            "sec-lead@example.com",
            *extra,
        ]
    )


# ---------------------------------------------------------------- policy (pure)


def test_resolve_expiry_days_and_date():
    assert (
        risk_acceptance.resolve_expiry(
            expires=None, days=30, max_days=None, required=False, now=TODAY
        )
        == "2026-10-21"
    )
    assert (
        risk_acceptance.resolve_expiry(
            expires="2026-12-01", days=None, max_days=None, required=False, now=TODAY
        )
        == "2026-12-01"
    )
    assert (
        risk_acceptance.resolve_expiry(
            expires=None, days=None, max_days=None, required=False, now=TODAY
        )
        is None
    )


@pytest.mark.parametrize(
    "kwargs, fragment",
    [
        (dict(expires=None, days=None, required=True, max_days=None), "requires an expiry"),
        (dict(expires="2027-01-01", days=None, required=True, max_days=90), "more than 90"),
        (dict(expires="2026-09-21", days=None, required=False, max_days=None), "not in the future"),
        (dict(expires="21/09/2026", days=None, required=False, max_days=None), "YYYY-MM-DD"),
        (dict(expires=None, days=0, required=False, max_days=None), "positive"),
        (dict(expires="2026-10-01", days=3, required=False, max_days=None), "not both"),
    ],
)
def test_resolve_expiry_refusals(kwargs, fragment):
    with pytest.raises(risk_acceptance.RiskAcceptanceError) as exc:
        risk_acceptance.resolve_expiry(now=TODAY, **kwargs)
    assert fragment in str(exc.value)


def test_acceptance_state_classification():
    assert risk_acceptance.acceptance_state({}, TODAY)["state"] == "open"
    assert risk_acceptance.acceptance_state({"expires": "2026-12-01"}, TODAY)["state"] == "active"
    soon = risk_acceptance.acceptance_state({"expires": "2026-10-01"}, TODAY)
    assert soon["state"] == "expiring" and soon["days_left"] == 10
    # Valid THROUGH the expiry date, expired the day after.
    assert risk_acceptance.acceptance_state({"expires": "2026-09-21"}, TODAY)["state"] == "expiring"
    assert risk_acceptance.acceptance_state({"expires": "2026-09-20"}, TODAY)["state"] == "expired"
    # An unreadable bound is not a bound (fail closed).
    assert risk_acceptance.acceptance_state({"expires": "soon"}, TODAY)["state"] == "expired"


def test_latest_by_target_keeps_the_newest_record():
    entries = [
        {"decision": "override", "finding": {"id": "x"}, "at": "2026-01-01T00:00:00+00:00"},
        {"decision": "override", "finding": {"id": "x"}, "at": "2026-03-01T00:00:00+00:00"},
        {"decision": "approved", "finding": {"id": "x"}, "at": "2026-05-01T00:00:00+00:00"},
    ]
    latest = risk_acceptance.latest_by_target(entries, lambda e: e["finding"]["id"])
    assert latest["x"]["at"].startswith("2026-03")


# ---------------------------------------------------------------- security findings


def test_override_records_expiry_and_required_policy_refuses_without_it(
    tmp_path, monkeypatch, capsys
):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, "risk_acceptance:\n  max_days: 90\n  required: true\n")
    assert main(["scan", "--path", str(tmp_path)]) == 1
    fid = finding_id(vuln)

    # No expiry under `required: true`: refused, nothing recorded, and it says why.
    assert _override(tmp_path, fid) == 2
    assert "requires an expiry" in capsys.readouterr().err
    assert sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)["approvals"] == []

    # Past the cap: refused too.
    assert _override(tmp_path, fid, "--days", "120") == 2
    assert "more than 90" in capsys.readouterr().err

    assert _override(tmp_path, fid, "--days", "30") == 0
    out = capsys.readouterr().out
    assert "expires on 2026-10-21" in out
    entry = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)["approvals"][-1]
    assert entry["expires"] == "2026-10-21"
    assert entry["decision"] == "override"
    assert main(["scan", "--path", str(tmp_path)]) == 0


def test_expired_acceptance_blocks_again_with_expired_risk(tmp_path, monkeypatch, capsys):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(vuln)
    assert _override(tmp_path, fid, "--expires", "2026-10-15") == 0
    assert main(["scan", "--path", str(tmp_path)]) == 0

    # The calendar moves past the expiry: the same finding blocks again.
    _set_today(monkeypatch, dt.date(2026, 10, 16))
    capsys.readouterr()
    assert main(["scan", "--path", str(tmp_path), "--format", "json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["block_reasons"] == ["expired_risk"]
    blocked = data["dependencies"]["blocking"][0]
    assert blocked["status"] == "expired_risk"
    assert blocked["acceptance"]["by"] == "sec-lead@example.com"
    assert blocked["acceptance"]["expires"] == "2026-10-15"

    # The human summary names the finding, who accepted it, when it expired, and the way out.
    assert main(["report", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "EXPIRED RISK" in out
    assert "sec-lead@example.com" in out and "expired 2026-10-15" in out
    assert "renew it" in out and "--expires" in out and "expired_risk" in out


def test_expiring_within_14_days_warns_without_blocking(tmp_path, monkeypatch, capsys):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    main(["scan", "--path", str(tmp_path)])
    assert _override(tmp_path, finding_id(vuln), "--expires", "2026-12-01") == 0
    capsys.readouterr()
    assert main(["scan", "--path", str(tmp_path)]) == 0
    assert "expiring risk" not in capsys.readouterr().out

    _set_today(monkeypatch, dt.date(2026, 11, 20))  # 11 days left
    assert main(["scan", "--path", str(tmp_path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["passes"] is True and data["block_reasons"] == []
    assert data["dependencies"]["expiring"][0]["acceptance"]["days_left"] == 11
    assert main(["scan", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "expiring risk" in out and "11 day(s) left" in out and "not blocking" in out


def test_renewal_keeps_the_earlier_acceptance_in_history(tmp_path, monkeypatch):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(vuln)
    assert _override(tmp_path, fid, "--expires", "2026-10-01") == 0
    _set_today(monkeypatch, dt.date(2026, 10, 5))
    assert main(["scan", "--path", str(tmp_path)]) == 1  # expired

    # Renew: a NEW record; the old one stays.
    assert _override(tmp_path, fid, "--days", "60") == 0
    assert main(["scan", "--path", str(tmp_path)]) == 0
    trail = [
        a
        for a in sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)["approvals"]
        if a["decision"] == "override" and a["finding"]["id"] == fid
    ]
    assert [a["expires"] for a in trail] == ["2026-10-01", "2026-12-04"]


def test_open_ended_acceptance_still_allowed_without_policy(tmp_path, monkeypatch, capsys):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    main(["scan", "--path", str(tmp_path)])
    assert _override(tmp_path, finding_id(vuln)) == 0
    assert "NO expiry" in capsys.readouterr().out
    _set_today(monkeypatch, dt.date(2030, 1, 1))
    assert main(["scan", "--path", str(tmp_path)]) == 0


def test_invalid_risk_acceptance_config_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    _gate_yml(tmp_path, "risk_acceptance:\n  max_days: ninety\n")
    assert main(["scan", "--path", str(tmp_path)]) == 2
    assert "max_days" in capsys.readouterr().err


# ---------------------------------------------------------------- criteria exceptions


def _story(cmd=FAILING_CMD):
    return {
        "id": "S1",
        "title": "Story",
        "criteria": [
            {
                "id": "S1-AC1",
                "statement": "cmd passes",
                "check": {"type": "command", "payload": cmd},
            }
        ],
    }


def _override_criterion(root, *extra):
    return main(
        [
            "override",
            "--path",
            str(root),
            "--criterion",
            "S1-AC1",
            "--reason",
            "known-flaky on CI",
            "--approver",
            "lead@example.com",
            *extra,
        ]
    )


def test_criterion_exception_expires_and_blocks_again(tmp_path, monkeypatch, capsys):
    write_bundle(tmp_path, [_story()])
    _gate_yml(tmp_path, "risk_acceptance:\n  required: true\n")
    assert _override_criterion(tmp_path) == 2  # required expiry
    assert _override_criterion(tmp_path, "--expires", "2026-10-10") == 0
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "expires 2026-10-10" in capsys.readouterr().out

    _set_today(monkeypatch, dt.date(2026, 10, 5))  # 5 days left: warning only
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert "expiring exception" in capsys.readouterr().out

    _set_today(monkeypatch, dt.date(2026, 10, 11))
    assert main(["check", "--path", str(tmp_path), "--format", "json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["block_reasons"] == ["expired_risk"]
    assert payload["criteria"][0]["result"] == "fail"
    assert payload["expired_overrides"][0]["approver"] == "lead@example.com"
    assert main(["check", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "expired risk" in out and "lead@example.com" in out and "expired_risk" in out

    # Renewal: new record, old kept, check passes again.
    assert _override_criterion(tmp_path, "--days", "30") == 0
    assert main(["check", "--path", str(tmp_path)]) == 0
    trail = sa.read_artifact(tmp_path, "criteria", base_dir=AUDIT_DIR)["approvals"]
    assert [a["expires"] for a in trail] == ["2026-10-10", "2026-11-10"]
