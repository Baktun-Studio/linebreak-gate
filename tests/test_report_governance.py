"""``report --from-governance``: the security summary of the last run CI
published, readable outside CI with the governance token (read only).

The service side is ``GET /v1/reports/projects/{id}?format=json`` (the runs,
newest first) and ``GET /v1/projects/{id}/gate-runs/{run_id}`` (the run as
ingested); the fake below answers both the way ``services/governance`` does.
"""

from __future__ import annotations

import json

import pytest

from linebreak_gate import governance_env, governance_report
from linebreak_gate.cli import main

BASE = "https://gov.example"
PROJECT = "prj_990525828d34eec7"

RUNS = [
    {"run_id": "r-new-pr", "at": "2026-09-23T16:23:43+00:00", "stage": "pr", "verdict": "pass"},
    {"run_id": "r-release", "at": "2026-09-22T10:00:00+00:00", "stage": "release"},
]

RUN = {
    "run_id": "r-new-pr",
    "project": "linebreak",
    "at": "2026-09-23T16:23:43+00:00",
    "repo": "Baktun-Studio/linebreak",
    "commit": "0749009313f2abcdef",
    "stage": "pr",
    "verdict": "blocked",
    "block_reasons": ["vulnerability"],
    "findings": [
        {"id": "CVE-1", "severity": "medium", "package": "a", "version": "1"},
        {
            "id": "CVE-2",
            "severity": "high",
            "package": "langgraph",
            "version": "0.6.11",
            "fixed_in": "0.6.12",
            "accepted": {"by": "ana@example.com", "expires": "2026-11-21T00:00:00+00:00"},
        },
        {"id": "CVE-3", "severity": "critical", "package": "b", "version": "2", "kev": True},
    ],
    "criteria": [{"id": "c1", "result": "pass"}, {"id": "c2", "result": "pending"}],
}


class FakeService:
    def __init__(self, runs=RUNS, run=RUN, status=200):
        self.runs, self.run, self.status = runs, run, status
        self.calls: list[tuple[str, str]] = []

    def __call__(self, url, token):
        self.calls.append((url, token))
        if self.status != 200:
            return self.status, {"detail": "no"}
        if "/v1/reports/projects/" in url:
            return 200, {"runs": self.runs}
        run_id = url.rsplit("/", 1)[1]
        return (200, dict(self.run, run_id=run_id)) if self.run else (404, None)


CREDS = governance_env.Credentials(
    base_url=BASE, token="lbg_t", project=PROJECT, source="environment"
)


def test_reads_the_last_published_run():
    fake = FakeService()
    report = governance_report.fetch_report(CREDS, fetch=fake)
    assert [u for u, _ in fake.calls] == [
        f"{BASE}/v1/reports/projects/{PROJECT}?format=json",
        f"{BASE}/v1/projects/{PROJECT}/gate-runs/r-new-pr",
    ]
    assert all(t == "lbg_t" for _, t in fake.calls)
    s = report["summary"]
    assert s["findings"] == {
        "total": 3,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "unknown": 0,
        "accepted": 1,
        "kev": 1,
    }
    assert s["verdict"] == "blocked" and s["criteria"] == {"pass": 1, "pending": 1}


def test_stage_and_run_id_select_the_run():
    fake = FakeService()
    report = governance_report.fetch_report(CREDS, stage="release", fetch=fake)
    assert report["run"]["run_id"] == "r-release"
    fake = FakeService()
    governance_report.fetch_report(CREDS, run_id="r-x", fetch=fake)
    assert len(fake.calls) == 1 and fake.calls[0][0].endswith("/gate-runs/r-x")


def test_nothing_published_is_none_and_errors_are_said():
    assert governance_report.fetch_report(CREDS, fetch=FakeService(runs=[])) is None
    with pytest.raises(governance_report.GovernanceReportError, match="401"):
        governance_report.fetch_report(CREDS, fetch=FakeService(status=401))
    no_project = governance_env.Credentials(BASE, "t", None, "environment")
    with pytest.raises(governance_report.GovernanceReportError, match="no project id"):
        governance_report.fetch_report(no_project, fetch=FakeService())
    none = governance_env.Credentials(None, None, None, None)
    with pytest.raises(governance_report.GovernanceReportError, match="no governance credentials"):
        governance_report.fetch_report(none, fetch=FakeService())


def test_render_orders_by_severity_and_marks_acceptances():
    lines = governance_report.render(governance_report.fetch_report(CREDS, fetch=FakeService()))
    text = "\n".join(lines)
    assert "run r-new-pr · stage pr" in text and "commit 0749009313f2 " in text
    findings = [line for line in lines if line.startswith("  [")]
    assert findings[0].startswith("  [critical KEV] CVE-3")
    assert "accepted by ana@example.com until 2026-11-21" in findings[1]
    assert lines[-1] == "VERDICT (as published by that run): BLOCKED (reasons: vulnerability)"


@pytest.fixture
def service(monkeypatch):
    fake = FakeService()
    monkeypatch.setattr(governance_report, "_default_fetch", fake)
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_BASE_URL", BASE)
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_TOKEN", "lbg_t")
    return fake


def test_cli_summary_and_json(service, tmp_path, capsys):
    assert main(["report", "--path", str(tmp_path), "--from-governance", "--project", PROJECT]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"LineBreak security summary from the governance service ({BASE})")
    assert "read with credentials from environment variables (read only)" in out
    assert main(["report", "--from-governance", "--project", PROJECT, "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["source"] == "governance" and data["run"]["run_id"] == "r-new-pr"


def test_cli_reads_the_credential_file(tmp_path, monkeypatch, capsys):
    fake = FakeService()
    monkeypatch.setattr(governance_report, "_default_fetch", fake)
    home = tmp_path / "home"
    (home / ".config/linebreak").mkdir(parents=True)
    (home / ".config/linebreak/governance-local.env").write_text(
        f"LINEBREAK_GOVERNANCE_BASE_URL={BASE}\nLINEBREAK_GOVERNANCE_TOKEN=lbg_file\n"
        f"LINEBREAK_GOV_PROJECT={PROJECT}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(governance_env, "_home", lambda: home)
    assert main(["report", "--from-governance"]) == 0
    assert "credentials from ~/.config/linebreak/governance-local.env" in capsys.readouterr().out
    assert fake.calls[0][1] == "lbg_file"


def test_cli_errors_are_exit_2_and_flags_need_the_switch(service, tmp_path, capsys):
    service.status = 503
    assert main(["report", "--from-governance", "--project", PROJECT]) == 2
    assert "answered 503" in capsys.readouterr().err
    assert main(["report", "--path", str(tmp_path), "--project", PROJECT]) == 2
    assert "only with --from-governance" in capsys.readouterr().err
