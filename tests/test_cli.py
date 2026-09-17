"""End-to-end CLI contract: exit codes (0 pass / 1 blocking / 2 tool error,
fail closed), config precedence, override lifecycle, audit records."""

import json

import pytest

from linebreak_gate import code_scan, llm, security_scan
from linebreak_gate import security_artifact as sa
from linebreak_gate.cli import AUDIT_DIR, main
from linebreak_gate.verdict import finding_id


def _finding(severity="critical", cve="CVE-2024-0001", package="lodash", version="4.17.20"):
    return {
        "cve_id": cve,
        "severity": severity,
        "cvss": 9.8 if severity == "critical" else 7.5,
        "package": package,
        "ecosystem": "npm",
        "installed_version": version,
        "fixed_version": "9.9.9",
        "advisory_url": f"https://osv.dev/vulnerability/{cve}",
        "title": f"test advisory for {package}",
    }


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("LINEBREAK_LICENSE_KEY", raising=False)
    monkeypatch.delenv("LINEBREAK_ENTITLEMENTS_PROVIDER", raising=False)
    # Deterministic: no SAST unless a test opts in.
    monkeypatch.setattr(llm, "build_ask", lambda: None)


def _fake_scan(findings, error=None):
    def scan(root, **kwargs):
        if error:
            return {"findings": [], "risk_score": None, "scanner": None, "error": error}
        return {"findings": findings, "risk_score": 100, "scanner": "osv-scanner", "error": None}

    return scan


def _gate_yml(root, text):
    d = root / ".linebreak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "gate.yml").write_text(text, encoding="utf-8")


# ---------------------------------------------------------------- scan


def test_scan_blocks_on_critical_and_writes_artifact(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([_finding()]))
    rc = main(["scan", "--path", str(tmp_path)])
    assert rc == 1
    out = capsys.readouterr().out
    assert "CVE-2024-0001" in out
    doc = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)
    assert doc["kind"] == "cve_scan"
    assert doc["scanner"] == "osv-scanner"
    assert doc["actor"]  # scans are attributed


def test_scan_clean_exits_zero(tmp_path, monkeypatch):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    assert main(["scan", "--path", str(tmp_path)]) == 0


def test_scanner_failure_fails_closed_exit_2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([], error="no scanner found"))
    rc = main(["scan", "--path", str(tmp_path)])
    assert rc == 2
    assert "no scanner found" in capsys.readouterr().err
    # A failed scan writes NOTHING — it must never look like a clean pass.
    assert sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)["kind"] is None


def test_high_blocks_only_when_floor_lowered(tmp_path, monkeypatch):
    high = _finding(severity="high", cve="CVE-2024-0002")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([high]))
    # Default floor (critical): a high finding does not block.
    assert main(["scan", "--path", str(tmp_path)]) == 0
    # gate.yml lowers the floor to high: now it blocks.
    _gate_yml(tmp_path, "fail_on: high\n")
    assert main(["scan", "--path", str(tmp_path)]) == 1
    # An explicit CLI flag overrides the file.
    assert main(["scan", "--path", str(tmp_path), "--fail-on", "critical"]) == 0


def test_invalid_gate_yml_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    _gate_yml(tmp_path, "fail_on: severe\n")
    assert main(["scan", "--path", str(tmp_path)]) == 2
    assert "fail_on" in capsys.readouterr().err


def test_scan_json_format(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([_finding()]))
    rc = main(["scan", "--path", str(tmp_path), "--format", "json"])
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert data["passes"] is False
    assert data["fail_on"] == "critical"
    assert data["dependencies"]["blocking"][0]["cve_id"] == "CVE-2024-0001"


# ---------------------------------------------------------------- overrides


def test_override_lifecycle(tmp_path, monkeypatch):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    assert main(["scan", "--path", str(tmp_path)]) == 1

    fid = finding_id(vuln)
    rc = main(
        [
            "override",
            "--path",
            str(tmp_path),
            "--finding",
            fid,
            "--reason",
            "accepted risk; fix blocked upstream, tracking #123",
            "--approver",
            "sec-lead@example.com",
        ]
    )
    assert rc == 0

    # Recorded in the git-native audit format.
    doc = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)
    entry = doc["approvals"][-1]
    assert entry["decision"] == "override"
    assert entry["user_email"] == "sec-lead@example.com"
    assert entry["finding"]["id"] == fid

    # The same finding no longer blocks…
    assert main(["scan", "--path", str(tmp_path)]) == 0
    # …and the override survived the rescan (approvals carried forward).
    doc = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)
    assert any(a.get("decision") == "override" for a in doc["approvals"])

    # A DIFFERENT CVE still blocks.
    other = _finding(cve="CVE-2024-0002")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln, other]))
    assert main(["scan", "--path", str(tmp_path)]) == 1


def test_override_requires_reason_and_approver(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([_finding()]))
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(_finding())
    # argparse enforces presence (SystemExit(2))…
    with pytest.raises(SystemExit) as exc:
        main(["override", "--path", str(tmp_path), "--finding", fid, "--approver", "a@b.c"])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main(["override", "--path", str(tmp_path), "--finding", fid, "--reason", "because"])
    assert exc.value.code == 2
    # …and blank values are refused too.
    rc = main(
        [
            "override",
            "--path",
            str(tmp_path),
            "--finding",
            fid,
            "--reason",
            "  ",
            "--approver",
            "a@b.c",
        ]
    )
    assert rc == 2
    assert "reason" in capsys.readouterr().err


def test_override_unknown_finding_refused(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([_finding()]))
    main(["scan", "--path", str(tmp_path)])
    rc = main(
        [
            "override",
            "--path",
            str(tmp_path),
            "--finding",
            "dep:nope@0.0.0:CVE-1999-0000",
            "--reason",
            "r",
            "--approver",
            "a@b.c",
        ]
    )
    assert rc == 2
    assert "not" in capsys.readouterr().err.lower()


# ---------------------------------------------------------------- report


def test_report_lists_cve_cvss_advisory(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([_finding()]))
    main(["scan", "--path", str(tmp_path)])
    capsys.readouterr()
    assert main(["report", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "CVE-2024-0001" in out
    assert "9.8" in out
    assert "https://osv.dev/vulnerability/CVE-2024-0001" in out
    assert "critical" in out.lower()


def test_report_json(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([_finding()]))
    main(["scan", "--path", str(tmp_path)])
    capsys.readouterr()
    assert main(["report", "--path", str(tmp_path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dependencies"]["findings"][0]["cve_id"] == "CVE-2024-0001"


def test_report_without_scan_says_so(tmp_path, capsys):
    assert main(["report", "--path", str(tmp_path)]) == 0
    assert "no scan" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------- licensing


def test_license_notice_without_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    assert "license" in capsys.readouterr().err.lower()


def test_no_notice_with_key(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LINEBREAK_LICENSE_KEY", "lk_test")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    # The upsell notice must not fire when a key is set. (Match its wording,
    # not the substring "license" — the code-scan skip hint legitimately names
    # LINEBREAK_LICENSE_KEY as a credential.)
    assert "AI code review is a LineBreak Pro feature" not in capsys.readouterr().err


def test_no_upsell_notice_for_byok(tmp_path, monkeypatch, capsys):
    # A BYOK user (own Anthropic key, no license key) already has the AI review —
    # don't nag them to buy a license.
    monkeypatch.delenv("LINEBREAK_LICENSE_KEY", raising=False)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-byok")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    assert "AI code review is a LineBreak Pro feature" not in capsys.readouterr().err


def test_remote_entitlements_fail_closed_in_ci(tmp_path, monkeypatch, capsys):
    # Once the operator flips to remote, a standalone runner (no registered
    # remote provider) must not pass the gate check.
    monkeypatch.setenv("LINEBREAK_ENTITLEMENTS_PROVIDER", "remote")
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    assert main(["scan", "--path", str(tmp_path)]) == 2
    assert "license" in capsys.readouterr().err.lower()


# ---------------------------------------------------------------- code scan


def test_code_scan_on_without_llm_fails_closed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    _gate_yml(tmp_path, "code_scan: on\n")
    assert main(["scan", "--path", str(tmp_path)]) == 2
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().err


def test_code_scan_auto_skips_without_llm(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    assert main(["scan", "--path", str(tmp_path)]) == 0
    assert "code scan" in capsys.readouterr().err.lower()
    # No code artifact when the detector didn't run.
    assert sa.read_artifact(tmp_path, "code", base_dir=AUDIT_DIR)["kind"] is None


def test_code_scan_blocks_and_is_overridable(tmp_path, monkeypatch):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    monkeypatch.setattr(llm, "build_ask", lambda: lambda system, user: "[]")
    code_finding = {
        "category": "injection",
        "severity": "critical",
        "file": "app.py",
        "line": 10,
        "title": "SQL injection in login",
        "description": "d",
        "remediation": "r",
        "confidence": 0.9,
    }

    def fake_scan_code(root, *, discover, verify, **kwargs):
        return {
            "findings": [code_finding],
            "risk_score": 100,
            "scanner": "claude-code-scan",
            "error": None,
        }

    monkeypatch.setattr(code_scan, "scan_code", fake_scan_code)
    assert main(["scan", "--path", str(tmp_path)]) == 1
    doc = sa.read_artifact(tmp_path, "code", base_dir=AUDIT_DIR)
    assert doc["kind"] == "code_scan"

    fid = finding_id(code_finding, detector="code")
    rc = main(
        [
            "override",
            "--path",
            str(tmp_path),
            "--finding",
            fid,
            "--reason",
            "false positive confirmed by manual review",
            "--approver",
            "sec-lead@example.com",
        ]
    )
    assert rc == 0
    assert main(["scan", "--path", str(tmp_path)]) == 0


def test_code_scan_error_fails_closed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    monkeypatch.setattr(llm, "build_ask", lambda: lambda system, user: "[]")

    def broken_scan_code(root, *, discover, verify, **kwargs):
        return {"findings": [], "risk_score": None, "scanner": None, "error": "model unreachable"}

    monkeypatch.setattr(code_scan, "scan_code", broken_scan_code)
    assert main(["scan", "--path", str(tmp_path)]) == 2
    assert "model unreachable" in capsys.readouterr().err


def test_committed_code_artifact_still_gates_when_scan_is_skipped(tmp_path, monkeypatch):
    """A committed code.json is evidence on the record: skipping the detector
    for lack of credentials must not silently stop gating on it — and `scan`
    and `report` must agree."""
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    monkeypatch.setattr(llm, "build_ask", lambda: lambda system, user: "[]")
    code_finding = {
        "category": "injection",
        "severity": "critical",
        "file": "app.py",
        "line": 10,
        "title": "SQL injection in login",
        "description": "d",
        "remediation": "r",
        "confidence": 0.9,
    }

    def fake_scan_code(root, *, discover, verify, **kwargs):
        return {
            "findings": [code_finding],
            "risk_score": 100,
            "scanner": "claude-code-scan",
            "error": None,
        }

    monkeypatch.setattr(code_scan, "scan_code", fake_scan_code)
    assert main(["scan", "--path", str(tmp_path)]) == 1  # writes code.json

    # Credentials disappear: the committed record still gates (fail closed).
    monkeypatch.setattr(llm, "build_ask", lambda: None)
    assert main(["scan", "--path", str(tmp_path)]) == 1
    # And report tells the same story.
    assert main(["report", "--path", str(tmp_path)]) == 0

    # Explicit opt-out ignores it on BOTH commands.
    _gate_yml(tmp_path, "code_scan: off\n")
    assert main(["scan", "--path", str(tmp_path)]) == 0


def test_report_honors_code_scan_off(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    monkeypatch.setattr(llm, "build_ask", lambda: lambda system, user: "[]")
    monkeypatch.setattr(
        code_scan,
        "scan_code",
        lambda root, *, discover, verify, **kw: {
            "findings": [
                {
                    "category": "injection",
                    "severity": "critical",
                    "file": "a.py",
                    "line": 1,
                    "title": "x",
                }
            ],
            "risk_score": 100,
            "scanner": "claude-code-scan",
            "error": None,
        },
    )
    main(["scan", "--path", str(tmp_path)])
    _gate_yml(tmp_path, "code_scan: off\n")
    capsys.readouterr()
    assert main(["report", "--path", str(tmp_path), "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["code"] is None
    assert data["passes"] is True
