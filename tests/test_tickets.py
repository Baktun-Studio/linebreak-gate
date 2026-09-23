"""Ticket mirroring against a simulated tracker (Jira REST v2 and GitHub
Issues over a fake HTTP transport): creation, renewal, reopen on expiry,
close on fix, attention ticket for a new vulnerability on main, and the
rule that a tracker failure never touches the verdict (plus `tickets sync`)."""

from __future__ import annotations

import datetime as dt
import json
import re
import urllib.parse

import pytest
from test_criteria_check import write_bundle

from linebreak_gate import llm, risk_acceptance, security_scan, tickets
from linebreak_gate import security_artifact as sa
from linebreak_gate.cli import AUDIT_DIR, main
from linebreak_gate.verdict import finding_id

TODAY = dt.date(2026, 9, 21)
JIRA_YML = "tickets:\n  provider: jira\n  project: SEC\n  labels: [linebreak, security]\n"
GITHUB_YML = "tickets:\n  provider: github\n  project: acme/app\n"
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


class FakeJira:
    """Just enough of Jira REST v2 for the gate: issues, comments, status,
    transitions and the label search. ``down`` simulates no network."""

    def __init__(self):
        self.issues: dict[str, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.down = False
        self.n = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        if self.down:
            raise tickets.TicketError("network error reaching jira: connection refused")
        assert headers["Authorization"].startswith("Basic ")
        payload = json.loads(body) if body else None
        path = url.split("/rest/api/2", 1)[1]
        if method == "POST" and path == "/issue":
            self.n += 1
            key = f"SEC-{self.n}"
            f = payload["fields"]
            assert f["project"] == {"key": "SEC"} and f["issuetype"] == {"name": "Task"}
            self.issues[key] = {
                "summary": f["summary"],
                "description": f["description"],
                "labels": list(f["labels"]),
                "closed": False,
                "comments": [],
            }
            return 201, json.dumps({"key": key}).encode()
        if path.startswith("/search/jql"):
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            label = re.search(r'labels = "([^"]+)"', qs["jql"][0]).group(1)
            issues = [
                {"key": k, "fields": {"status": self._status(v), "labels": v["labels"]}}
                for k, v in self.issues.items()
                if label in v["labels"]
            ]
            return 200, json.dumps({"issues": issues}).encode()
        m = re.match(r"/issue/([^/?]+)(/comment|/transitions)?(\?.*)?$", path)
        key, sub = m.group(1), m.group(2)
        issue = self.issues.get(key)
        if issue is None:
            return 404, json.dumps({"errorMessages": ["Issue does not exist"]}).encode()
        if sub == "/comment":
            if method == "POST":
                issue["comments"].append(payload["body"])
                return 201, b"{}"
            return 200, json.dumps({"comments": [{"body": c} for c in issue["comments"]]}).encode()
        if sub == "/transitions":
            if method == "GET":
                return 200, json.dumps(
                    {
                        "transitions": [
                            {"id": "31", "to": {"statusCategory": {"key": "done"}}},
                            {"id": "11", "to": {"statusCategory": {"key": "new"}}},
                        ]
                    }
                ).encode()
            issue["closed"] = payload["transition"]["id"] == "31"
            return 204, b""
        return 200, json.dumps({"fields": {"status": self._status(issue)}}).encode()

    @staticmethod
    def _status(issue):
        return {"statusCategory": {"key": "done" if issue["closed"] else "new"}}


class FakeGitHub:
    def __init__(self):
        self.issues: dict[int, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.n = 0

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url))
        assert headers["Authorization"] == "Bearer ghp_test"
        payload = json.loads(body) if body else None
        path = url.split("https://api.github.com", 1)[1]
        if method == "POST" and path == "/repos/acme/app/issues":
            self.n += 1
            self.issues[self.n] = {
                "title": payload["title"],
                "body": payload["body"],
                "labels": list(payload["labels"]),
                "state": "open",
                "comments": [],
            }
            return 201, json.dumps({"number": self.n}).encode()
        if path.startswith("/repos/acme/app/issues?"):
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            label = qs["labels"][0]
            found = [
                {"number": n, "state": v["state"], "labels": [{"name": lb} for lb in v["labels"]]}
                for n, v in self.issues.items()
                if label in v["labels"]
            ]
            return 200, json.dumps(found).encode()
        m = re.match(r"/repos/acme/app/issues/(\d+)(/comments)?(\?.*)?$", path)
        issue = self.issues[int(m.group(1))]
        if m.group(2):
            if method == "POST":
                issue["comments"].append(payload["body"])
                return 201, b"{}"
            return 200, json.dumps([{"body": c} for c in issue["comments"]]).encode()
        if method == "PATCH":
            issue["state"] = payload["state"]
        return 200, json.dumps({"state": issue["state"]}).encode()


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("LINEBREAK_LICENSE_KEY", raising=False)
    monkeypatch.delenv("LINEBREAK_ENTITLEMENTS_PROVIDER", raising=False)
    monkeypatch.setattr(llm, "build_ask", lambda: None)
    monkeypatch.setattr(risk_acceptance, "today", lambda: TODAY)
    monkeypatch.setenv("JIRA_BASE_URL", "https://jira.example.com")
    monkeypatch.setenv("JIRA_EMAIL", "bot@example.com")
    monkeypatch.setenv("JIRA_API_TOKEN", "secret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_test")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_SHA", "abc123def456")
    monkeypatch.setenv("GITHUB_REF_NAME", "feature/x")
    monkeypatch.delenv("GITHUB_HEAD_REF", raising=False)
    monkeypatch.delenv("GITHUB_SERVER_URL", raising=False)
    monkeypatch.delenv("GITHUB_API_URL", raising=False)


@pytest.fixture
def jira(monkeypatch):
    fake = FakeJira()
    monkeypatch.setattr(tickets, "_send", fake)
    return fake


@pytest.fixture
def github(monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(tickets, "_send", fake)
    return fake


def _override(root, fid, *extra, approver="sec-lead@example.com"):
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
            approver,
            *extra,
        ]
    )


def _entry(root, artifact="security"):
    return sa.read_artifact(root, artifact, base_dir=AUDIT_DIR)["approvals"][-1]


def _ledger(root):
    return tickets.read_ledger(root)


# ---------------------------------------------------------------- creation


def test_override_creates_jira_ticket_and_records_key(tmp_path, monkeypatch, jira, capsys):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, JIRA_YML)
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(vuln)
    assert _override(tmp_path, fid, "--expires", "2026-12-01") == 0
    assert "Ticket: SEC-1 (https://jira.example.com/browse/SEC-1)" in capsys.readouterr().out

    entry = _entry(tmp_path)
    assert entry["ticket"] == "SEC-1"
    assert "ticket_error" not in entry
    issue = jira.issues["SEC-1"]
    assert issue["summary"] == "[LineBreak] Accepted risk: CVE-2024-0001 in lodash@4.17.20"
    body = issue["description"]
    for needle in (
        f"Target: {fid}",
        "Accepted by: sec-lead@example.com",
        "Reason: fix blocked upstream",
        "Expires: 2026-12-01",
        "Repository: acme/app",
        "Commit: abc123def456",
        "Evidence: https://github.com/acme/app/blob/abc123def456/.linebreak/audit/security.json",
    ):
        assert needle in body
    assert set(issue["labels"]) >= {
        "linebreak",
        "security",
        f"linebreak-target-{tickets.target_hash(fid)}",
        "linebreak-artifact-security",
    }
    item = _ledger(tmp_path)["tickets"][0]
    assert item["key"] == "SEC-1" and item["pending"] == [] and item["error"] is None


def test_renewal_updates_the_same_ticket_and_reopens_it(tmp_path, monkeypatch, jira):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, JIRA_YML)
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(vuln)
    assert _override(tmp_path, fid, "--expires", "2026-10-01") == 0
    jira.issues["SEC-1"]["closed"] = True  # someone closed it in Jira

    assert _override(tmp_path, fid, "--expires", "2026-12-01", approver="cto@example.com") == 0
    assert len(jira.issues) == 1  # no second ticket
    issue = jira.issues["SEC-1"]
    assert issue["closed"] is False
    assert any("renewed by cto@example.com" in c and "2026-12-01" in c for c in issue["comments"])
    assert _entry(tmp_path)["ticket"] == "SEC-1"


# ---------------------------------------------------------------- lifecycle on scan


def test_expired_acceptance_comments_and_reopens_once(tmp_path, monkeypatch, jira):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, JIRA_YML)
    main(["scan", "--path", str(tmp_path)])
    assert _override(tmp_path, finding_id(vuln), "--expires", "2026-10-01") == 0
    jira.issues["SEC-1"]["closed"] = True

    monkeypatch.setattr(risk_acceptance, "today", lambda: dt.date(2026, 10, 2))
    assert main(["scan", "--path", str(tmp_path)]) == 1  # expired_risk blocks
    issue = jira.issues["SEC-1"]
    assert issue["closed"] is False
    expired = [c for c in issue["comments"] if "expired on 2026-10-01" in c]
    assert len(expired) == 1 and "[linebreak expired 2026-10-01]" in expired[0]

    # A rerun (CI runs the gate on every push) does not repeat the comment.
    assert main(["scan", "--path", str(tmp_path)]) == 1
    assert len([c for c in jira.issues["SEC-1"]["comments"] if "expired on" in c]) == 1


def test_fixed_finding_comments_and_closes(tmp_path, monkeypatch, jira):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, JIRA_YML)
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(vuln)
    assert _override(tmp_path, fid, "--expires", "2026-12-01") == 0

    # The dependency is upgraded: the finding is gone from the scan.
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    assert main(["scan", "--path", str(tmp_path)]) == 0
    issue = jira.issues["SEC-1"]
    assert issue["closed"] is True
    assert any("Resolved" in c and fid in c for c in issue["comments"])
    assert _ledger(tmp_path)["tickets"][0]["state"] == "closed"
    # Closing is not repeated on the next scan.
    calls = len(jira.calls)
    assert main(["scan", "--path", str(tmp_path)]) == 0
    assert not any(m == "POST" and "/transitions" in u for m, u in jira.calls[calls:])


def test_new_vulnerability_on_main_opens_attention_ticket(tmp_path, monkeypatch, jira):
    old = _finding()
    new = _finding(cve="CVE-2024-0002", package="minimist", version="1.2.5")
    _gate_yml(tmp_path, JIRA_YML)
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([old]))
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    # First scan ever: no baseline, nothing is "new" yet.
    assert main(["scan", "--path", str(tmp_path)]) == 1
    assert jira.issues == {}

    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([old, new]))
    assert main(["scan", "--path", str(tmp_path)]) == 1
    assert len(jira.issues) == 1
    issue = jira.issues["SEC-1"]
    assert (
        issue["summary"] == "[LineBreak] New vulnerability on main: CVE-2024-0002 in minimist@1.2.5"
    )
    assert "Branch: main" in issue["description"] and "Fixed in: 9.9.9" in issue["description"]
    assert f"linebreak-target-{tickets.target_hash(finding_id(new))}" in issue["labels"]

    # Same finding on the next run, even without the local ledger: no duplicate
    # (the tracker is searched by label before creating).
    tickets.ledger_path(tmp_path).unlink()
    assert main(["scan", "--path", str(tmp_path)]) == 1
    assert len(jira.issues) == 1


def test_new_finding_on_a_branch_does_not_open_a_ticket(tmp_path, monkeypatch, jira):
    _gate_yml(tmp_path, JIRA_YML)
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([_finding()]))
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/y")  # a pull request
    assert main(["scan", "--path", str(tmp_path)]) == 1
    assert jira.issues == {}


# ---------------------------------------------------------------- failure never blocks


def test_tracker_failure_never_blocks_and_sync_retries(tmp_path, monkeypatch, jira, capsys):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, JIRA_YML)
    main(["scan", "--path", str(tmp_path)])
    fid = finding_id(vuln)

    jira.down = True
    assert _override(tmp_path, fid, "--expires", "2026-12-01") == 0  # recorded anyway
    captured = capsys.readouterr()
    assert "Ticket: pending" in captured.out
    assert "tickets sync" in captured.err
    entry = _entry(tmp_path)
    assert "ticket" not in entry and "connection refused" in entry["ticket_error"]
    item = _ledger(tmp_path)["tickets"][0]
    assert item["pending"][0]["action"] == "create" and "connection refused" in item["error"]

    # The verdict is what the evidence says, tracker or no tracker.
    assert main(["scan", "--path", str(tmp_path)]) == 0
    assert main(["tickets", "sync", "--path", str(tmp_path)]) == 1
    assert "still pending" in capsys.readouterr().out

    jira.down = False
    assert main(["tickets", "sync", "--path", str(tmp_path)]) == 0
    assert "synced to SEC-1" in capsys.readouterr().out
    assert jira.issues["SEC-1"]["summary"].startswith("[LineBreak] Accepted risk")
    entry = _entry(tmp_path)
    assert entry["ticket"] == "SEC-1" and "ticket_error" not in entry
    assert _ledger(tmp_path)["tickets"][0]["pending"] == []


def test_missing_credentials_are_a_warning_not_a_block(tmp_path, monkeypatch, jira, capsys):
    monkeypatch.delenv("JIRA_API_TOKEN")
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, JIRA_YML)
    main(["scan", "--path", str(tmp_path)])
    assert _override(tmp_path, finding_id(vuln), "--expires", "2026-12-01") == 0
    assert "JIRA_API_TOKEN" in capsys.readouterr().err
    assert "JIRA_API_TOKEN" in _entry(tmp_path)["ticket_error"]
    assert main(["scan", "--path", str(tmp_path)]) == 0
    assert jira.calls == []


def test_http_error_from_tracker_is_recorded(tmp_path, monkeypatch, jira):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, "tickets:\n  provider: jira\n  project: SEC\n  issue_type: Nope\n")
    main(["scan", "--path", str(tmp_path)])

    def refuse(method, url, headers, body):
        if method == "POST" and url.endswith("/issue"):
            return 400, json.dumps({"errors": {"issuetype": "issue type is not valid"}}).encode()
        return jira(method, url, headers, body)

    monkeypatch.setattr(tickets, "_send", refuse)
    assert _override(tmp_path, finding_id(vuln), "--expires", "2026-12-01") == 0
    assert "HTTP 400" in _entry(tmp_path)["ticket_error"]
    assert "issue type is not valid" in _entry(tmp_path)["ticket_error"]


def test_no_tickets_config_means_no_network(tmp_path, monkeypatch, jira):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    main(["scan", "--path", str(tmp_path)])
    assert _override(tmp_path, finding_id(vuln)) == 0
    assert jira.calls == []
    assert "ticket" not in _entry(tmp_path)
    assert not tickets.ledger_path(tmp_path).exists()


def test_invalid_tickets_config_exits_2(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    _gate_yml(tmp_path, "tickets:\n  provider: trello\n  project: X\n")
    assert main(["scan", "--path", str(tmp_path)]) == 2
    assert "tickets.provider" in capsys.readouterr().err
    _gate_yml(tmp_path, "tickets:\n  provider: github\n  project: nope\n")
    assert main(["scan", "--path", str(tmp_path)]) == 2
    assert "owner/repo" in capsys.readouterr().err


# ---------------------------------------------------------------- GitHub provider


def test_github_issues_provider_creates_and_closes(tmp_path, monkeypatch, github):
    vuln = _finding()
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([vuln]))
    _gate_yml(tmp_path, GITHUB_YML)
    main(["scan", "--path", str(tmp_path)])
    assert _override(tmp_path, finding_id(vuln), "--expires", "2026-12-01") == 0
    entry = _entry(tmp_path)
    assert entry["ticket"] == "acme/app#1"
    assert entry["ticket_url"] == "https://github.com/acme/app/issues/1"
    assert github.issues[1]["title"].startswith("[LineBreak] Accepted risk")
    assert "linebreak" in github.issues[1]["labels"]

    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    assert main(["scan", "--path", str(tmp_path)]) == 0
    assert github.issues[1]["state"] == "closed"
    assert any("Resolved" in c for c in github.issues[1]["comments"])


# ---------------------------------------------------------------- criteria exceptions


def _story(cmd):
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


def test_criterion_exception_ticket_lifecycle(tmp_path, monkeypatch, jira):
    write_bundle(tmp_path, [_story(FAILING_CMD)])
    _gate_yml(tmp_path, JIRA_YML)
    assert _override_criterion(tmp_path, "--expires", "2026-10-01") == 0
    entry = _entry(tmp_path, "criteria")
    assert entry["ticket"] == "SEC-1"
    issue = jira.issues["SEC-1"]
    assert issue["summary"] == "[LineBreak] Criterion exception: criterion S1-AC1 (story S1)"
    assert "Statement: cmd passes" in issue["description"]
    assert "linebreak-artifact-criteria" in issue["labels"]

    # Expired: the check blocks and the ticket gets the comment (reopened).
    jira.issues["SEC-1"]["closed"] = True
    monkeypatch.setattr(risk_acceptance, "today", lambda: dt.date(2026, 10, 2))
    assert main(["check", "--path", str(tmp_path)]) == 1
    assert issue["closed"] is False
    assert any("expired on 2026-10-01" in c for c in issue["comments"])

    # Fixed: the criterion passes on its own; a full check closes the ticket.
    write_bundle(tmp_path, [_story(PASSING_CMD)])
    assert main(["check", "--path", str(tmp_path)]) == 0
    assert issue["closed"] is True
    assert any("criterion passes on its own" in c for c in issue["comments"])


def test_scoped_check_never_closes_criteria_tickets(tmp_path, monkeypatch, jira):
    write_bundle(tmp_path, [_story(FAILING_CMD)])
    _gate_yml(tmp_path, JIRA_YML)
    assert _override_criterion(tmp_path, "--expires", "2026-12-01") == 0
    write_bundle(tmp_path, [_story(PASSING_CMD)])
    assert main(["check", "--path", str(tmp_path), "--story", "S1"]) == 0
    assert jira.issues["SEC-1"]["closed"] is False


# ---------------------------------------------------------------- Jira client details


def test_jira_search_falls_back_to_legacy_endpoint(monkeypatch):
    seen = []

    def send(method, url, headers, body):
        seen.append(url)
        if "/search/jql" in url:
            return 410, b'{"errorMessages":["gone"]}'
        return 200, json.dumps(
            {
                "issues": [
                    {
                        "key": "SEC-9",
                        "fields": {"status": {"statusCategory": {"key": "done"}}, "labels": ["x"]},
                    }
                ]
            }
        ).encode()

    monkeypatch.setattr(tickets, "_send", send)
    client = tickets.JiraClient("https://jira.example.com/", "e", "t")
    found = client.find_by_label("SEC", "x")
    assert found == [{"key": "SEC-9", "state": "closed", "labels": ["x"]}]
    assert "/rest/api/2/search?" in seen[1]


def test_jira_reopen_without_transition_is_a_ticket_error(monkeypatch):
    def send(method, url, headers, body):
        return 200, json.dumps(
            {"transitions": [{"id": "31", "to": {"statusCategory": {"key": "done"}}}]}
        ).encode()

    monkeypatch.setattr(tickets, "_send", send)
    client = tickets.JiraClient("https://jira.example.com", "e", "t")
    with pytest.raises(tickets.TicketError) as exc:
        client.reopen("SEC-1")
    assert "no transition" in str(exc.value)
