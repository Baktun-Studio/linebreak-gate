"""The PR comment (same content as the GitHub Action's) and the build status
for Bitbucket Pipelines and Azure DevOps, over a recorded fake transport."""

import base64
import json

import pytest

from linebreak_gate import ci_env, ci_report
from linebreak_gate.ci_report import (
    MARKER,
    AzureDevOpsReporter,
    BitbucketReporter,
    ReportError,
    render_comment,
    report_to_pr,
    verdict,
)

BITBUCKET_ENV = ci_env.detect(
    {
        "BITBUCKET_BUILD_NUMBER": "12",
        "BITBUCKET_REPO_FULL_NAME": "acme-ws/backend",
        "BITBUCKET_COMMIT": "0123456789abcdef",
        "BITBUCKET_BRANCH": "feat/S1",
        "BITBUCKET_PR_ID": "5",
    }
)
AZURE_ENV = ci_env.detect(
    {
        "TF_BUILD": "True",
        "SYSTEM_PULLREQUEST_PULLREQUESTID": "31",
        "BUILD_SOURCEVERSION": "mergesha",
        "BUILD_REPOSITORY_NAME": "backend",
        "BUILD_REPOSITORY_ID": "repo-guid",
        "BUILD_REPOSITORY_PROVIDER": "TfsGit",
        "SYSTEM_TEAMPROJECT": "Core Banking",
        "SYSTEM_COLLECTIONURI": "https://dev.azure.com/acme/",
        "BUILD_BUILDID": "900",
    }
)


class FakeTransport:
    """Records every request; answers from a (method, url-substring) table."""

    def __init__(self, responses=None, raise_with=None):
        self.calls = []
        self._responses = responses or {}
        self._raise = raise_with

    def __call__(self, method, url, headers, body):
        payload = json.loads(body) if body else None
        self.calls.append({"method": method, "url": url, "headers": headers, "json": payload})
        if self._raise:
            raise self._raise
        for (m, fragment), (status, data) in self._responses.items():
            if m == method and fragment in url:
                return status, data
        return 200, {}

    def of(self, method):
        return [c for c in self.calls if c["method"] == method]


# ---------------------------------------------------------------- the comment


SCOPE_LINE = "linebreak-gate ci: scope: story S1 (story input); manual criteria: warn; stage: pr"


def test_comment_both_clear():
    body = render_comment("Scan clean.", 0, "VERDICT: PASS.", 0)
    assert body.startswith(MARKER)
    assert "## LineBreak gate" in body
    assert "PASS: security and acceptance criteria both clear" in body
    assert "### Security" in body and "### Acceptance criteria" in body
    assert "Scan clean." in body and "VERDICT: PASS." in body
    assert "Humans stay on the record" in body


def test_comment_blocked_scan_names_the_failing_section():
    body = render_comment("VERDICT: BLOCKED", 1, "VERDICT: PASS.", 0)
    assert "BLOCKED: see the failing section below" in body
    assert "known vulnerabilities at/above the configured floor" in body


def test_comment_tool_error_is_not_a_block():
    body = render_comment("scan failed", 2, "VERDICT: PASS.", 0)
    assert "SCAN ERROR: gate failed closed" in body


def test_comment_not_enforced_is_not_a_pass():
    text = "Acceptance criteria: no approved criteria found (.linebreak/spec/ absent)"
    body = render_comment("Scan clean.", 0, text, 0)
    assert "NOT ENFORCED" in body
    assert "Security clear; acceptance criteria not enforced" in body
    assert "**Scope:**" not in body


def test_comment_scope_pending_signoffs_and_release_only():
    text = "\n".join(
        [
            SCOPE_LINE,
            "  scope: story S1 (1 of 3 stories), 2 of 5 criteria, manual criteria: warn, stage: pr",
            "  release-only (not evaluated at stage pr): S1-AC9 (S1), S1-AC10 (S1)",
            "  pending sign-off: S1-AC3 (S1) (not blocking under --manual warn)",
            "VERDICT: PASS.",
        ]
    )
    body = render_comment("Scan clean.", 0, text, 0)
    assert "**Scope:** story S1 (story input); manual criteria: warn; stage: pr" in body
    assert "**Pending sign-offs:** `S1-AC3` (S1). 1 manual criterion(s) still need" in body
    assert "**Release-only (not evaluated at stage pr" in body
    assert (
        "PASS: security clear; 1 sign-off(s) pending before release; 2 criterion(s) deferred"
        in body
    )
    assert "PASS** (1 sign-off(s) pending before release; 2 release-only criterion(s)" in body


def test_comment_accepts_the_github_action_scope_prefix_too():
    text = "linebreak-gate action: scope: all stories (story: all); manual criteria: block; stage: release\n  not started (not counted): S2, S3\nVERDICT: PASS."
    body = render_comment("Scan clean.", 0, text, 0)
    assert "**Scope:** all stories (story: all); manual criteria: block; stage: release" in body
    assert "**Not started (not counted):** S2, S3" in body


def test_comment_blocked_check_with_blocking_signoff():
    text = (
        f"{SCOPE_LINE.replace('warn', 'block')}\n  pending sign-off: S1-AC3 (S1)\nVERDICT: BLOCKED"
    )
    body = render_comment("Scan clean.", 0, text, 1)
    assert "acceptance criteria unmet" in body
    assert "1 manual criterion(s) need a sign-off (blocking)" in body


def test_comment_clips_long_reports():
    body = render_comment("x" * 40000, 0, "VERDICT: PASS.", 0)
    assert "truncated; full report in the pipeline artifact" in body
    assert len(body) < 40000


@pytest.mark.parametrize(
    "scan, check, state",
    [(0, 0, "success"), (1, 0, "failure"), (0, 1, "failure"), (2, 1, "error"), (0, 2, "error")],
)
def test_verdict_worse_code_wins(scan, check, state):
    got, description = verdict(scan, check)
    assert got == state
    assert description.split(":")[0] in ("PASS", "BLOCKED", "ERROR")


def test_verdict_names_both_blocking_reasons():
    assert verdict(1, 1)[1] == "BLOCKED: known vulnerabilities; acceptance criteria unmet"


# ---------------------------------------------------------------- Bitbucket


def test_bitbucket_creates_comment_when_none_exists():
    t = FakeTransport({("GET", "/comments"): (200, {"values": []})})
    r = BitbucketReporter(BITBUCKET_ENV, auth_header="Bearer tok", transport=t)
    assert r.upsert_comment(f"{MARKER}\nhello") == "created"
    post = t.of("POST")[0]
    assert post["url"] == (
        "https://api.bitbucket.org/2.0/repositories/acme-ws/backend/pullrequests/5/comments"
    )
    assert post["headers"]["Authorization"] == "Bearer tok"
    assert post["headers"]["Content-Type"] == "application/json"
    assert post["headers"]["User-Agent"].startswith("linebreak-gate/")
    assert post["json"] == {"content": {"raw": f"{MARKER}\nhello"}}


def test_bitbucket_updates_the_existing_marked_comment_in_place():
    listing = {
        "values": [
            {"id": 1, "content": {"raw": "unrelated"}},
            {"id": 2, "content": {"raw": f"{MARKER}\nold"}, "deleted": True},
            {"id": 3, "content": {"raw": f"{MARKER}\nold"}},
        ]
    }
    t = FakeTransport({("GET", "/comments"): (200, listing)})
    r = BitbucketReporter(BITBUCKET_ENV, auth_header="Bearer tok", transport=t)
    assert r.upsert_comment(f"{MARKER}\nnew") == "updated"
    assert not t.of("POST")
    put = t.of("PUT")[0]
    assert put["url"].endswith("/pullrequests/5/comments/3")
    assert put["json"]["content"]["raw"] == f"{MARKER}\nnew"


def test_bitbucket_follows_pagination():
    page1 = {"values": [{"id": 1, "content": {"raw": "x"}}], "next": "https://api/next?page=2"}
    page2 = {"values": [{"id": 9, "content": {"raw": f"{MARKER} z"}}]}
    t = FakeTransport({("GET", "page=2"): (200, page2), ("GET", "/comments"): (200, page1)})
    r = BitbucketReporter(BITBUCKET_ENV, auth_header="Bearer tok", transport=t)
    assert r.upsert_comment(f"{MARKER} new") == "updated"
    assert t.of("PUT")[0]["url"].endswith("/comments/9")


@pytest.mark.parametrize(
    "state, expected", [("success", "SUCCESSFUL"), ("failure", "FAILED"), ("error", "FAILED")]
)
def test_bitbucket_build_status_on_the_commit(state, expected):
    t = FakeTransport()
    r = BitbucketReporter(BITBUCKET_ENV, auth_header="Bearer tok", transport=t)
    r.set_status(state, "PASS: all clear")
    post = t.of("POST")[0]
    assert post["url"] == (
        "https://api.bitbucket.org/2.0/repositories/acme-ws/backend/commit/"
        "0123456789abcdef/statuses/build"
    )
    assert post["json"]["key"] == "linebreak-gate"
    assert post["json"]["state"] == expected
    assert post["json"]["name"] == "LineBreak gate"
    assert post["json"]["url"] == "https://bitbucket.org/acme-ws/backend/pipelines/results/12"


def test_bitbucket_credentials_token_or_app_password():
    assert BitbucketReporter.from_environ(BITBUCKET_ENV, {}) is None
    bearer = BitbucketReporter.from_environ(BITBUCKET_ENV, {"BITBUCKET_ACCESS_TOKEN": "tok"})
    assert bearer._auth == "Bearer tok"
    basic = BitbucketReporter.from_environ(
        BITBUCKET_ENV, {"BITBUCKET_USERNAME": "ana", "BITBUCKET_APP_PASSWORD": "pw"}
    )
    assert basic._auth == "Basic " + base64.b64encode(b"ana:pw").decode()


def test_bitbucket_api_refusal_is_a_report_error():
    t = FakeTransport({("GET", "/comments"): (401, {"error": {"message": "Access token expired"}})})
    r = BitbucketReporter(BITBUCKET_ENV, auth_header="Bearer tok", transport=t)
    with pytest.raises(ReportError, match="HTTP 401.*Access token expired"):
        r.upsert_comment("x")


# ---------------------------------------------------------------- Azure DevOps

AZ_BASE = (
    "https://dev.azure.com/acme/Core%20Banking/_apis/git/repositories/repo-guid/pullRequests/31"
)


def test_azure_creates_a_thread_when_none_exists():
    t = FakeTransport({("GET", "/threads"): (200, {"value": []})})
    r = AzureDevOpsReporter(AZURE_ENV, auth_header="Bearer sys", transport=t)
    assert r.upsert_comment(f"{MARKER}\nhello", state="failure") == "created"
    post = t.of("POST")[0]
    assert post["url"] == f"{AZ_BASE}/threads?api-version=7.1"
    assert post["headers"]["Authorization"] == "Bearer sys"
    assert post["json"]["status"] == 1  # active while blocked
    assert post["json"]["comments"][0]["content"].startswith(MARKER)
    assert post["json"]["comments"][0]["parentCommentId"] == 0


def test_azure_updates_the_marked_thread_and_closes_it_on_pass():
    threads = {
        "value": [
            {"id": 4, "comments": [{"id": 1, "content": "unrelated"}]},
            {"id": 8, "comments": [{"id": 2, "content": f"{MARKER}\nold"}]},
        ]
    }
    t = FakeTransport({("GET", "/threads"): (200, threads)})
    r = AzureDevOpsReporter(AZURE_ENV, auth_header="Bearer sys", transport=t)
    assert r.upsert_comment(f"{MARKER}\nnew", state="success") == "updated"
    patches = t.of("PATCH")
    assert patches[0]["url"] == f"{AZ_BASE}/threads/8/comments/2?api-version=7.1"
    assert patches[0]["json"] == {"content": f"{MARKER}\nnew"}
    assert patches[1]["url"] == f"{AZ_BASE}/threads/8?api-version=7.1"
    assert patches[1]["json"] == {"status": 4}
    assert not t.of("POST")


@pytest.mark.parametrize(
    "state, expected", [("success", "succeeded"), ("failure", "failed"), ("error", "error")]
)
def test_azure_pull_request_status(state, expected):
    t = FakeTransport()
    r = AzureDevOpsReporter(AZURE_ENV, auth_header="Bearer sys", transport=t)
    r.set_status(state, "BLOCKED: known vulnerabilities")
    post = t.of("POST")[0]
    assert post["url"] == f"{AZ_BASE}/statuses?api-version=7.1"
    assert post["json"]["state"] == expected
    assert post["json"]["context"] == {"name": "gate", "genre": "linebreak"}
    assert post["json"]["targetUrl"].startswith("https://dev.azure.com/acme/Core%20Banking/_build")


def test_azure_credentials_job_token_or_pat():
    assert AzureDevOpsReporter.from_environ(AZURE_ENV, {}) is None
    assert AzureDevOpsReporter.from_environ(AZURE_ENV, {"SYSTEM_ACCESSTOKEN": "s"})._auth == (
        "Bearer s"
    )
    pat = AzureDevOpsReporter.from_environ(AZURE_ENV, {"AZURE_DEVOPS_PAT": "p"})
    assert pat._auth == "Basic " + base64.b64encode(b":p").decode()


def test_azure_refuses_non_azure_repos_sources():
    env = ci_env.detect(
        {
            "TF_BUILD": "True",
            "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER": "3",
            "BUILD_REPOSITORY_NAME": "acme/backend",
            "BUILD_REPOSITORY_PROVIDER": "GitHub",
            "SYSTEM_TEAMPROJECT": "p",
            "SYSTEM_COLLECTIONURI": "https://dev.azure.com/acme/",
        }
    )
    r = AzureDevOpsReporter(env, auth_header="Bearer s", transport=FakeTransport())
    with pytest.raises(ReportError, match="hosted on GitHub"):
        r.set_status("success", "x")


# ---------------------------------------------------------------- report_to_pr


def test_report_posts_comment_and_status_on_bitbucket():
    t = FakeTransport({("GET", "/comments"): (200, {"values": []})})
    notes = report_to_pr(
        BITBUCKET_ENV,
        f"{MARKER} body",
        "failure",
        "BLOCKED",
        environ={"BITBUCKET_ACCESS_TOKEN": "tok"},
        transport=t,
    )
    assert any("PR comment created on Bitbucket Pipelines pull request #5" in n for n in notes)
    assert any("build status 'LineBreak gate' set to failure" in n for n in notes)
    assert len(t.of("POST")) == 2


def test_report_without_credentials_is_a_note_never_an_error():
    t = FakeTransport()
    notes = report_to_pr(BITBUCKET_ENV, "b", "failure", "d", environ={}, transport=t)
    assert not t.calls
    assert len(notes) == 1
    assert "no credentials" in notes[0] and "BITBUCKET_ACCESS_TOKEN" in notes[0]
    assert "exit code still enforces" in notes[0]


def test_report_outside_a_pull_request_is_a_note():
    env = ci_env.detect({"BITBUCKET_COMMIT": "abc", "BITBUCKET_REPO_FULL_NAME": "ws/r"})
    notes = report_to_pr(env, "b", "success", "d", environ={"BITBUCKET_ACCESS_TOKEN": "t"})
    assert "not a pull request build" in notes[0]


def test_report_transport_failure_never_raises():
    t = FakeTransport(raise_with=OSError("connection refused"))
    notes = report_to_pr(
        AZURE_ENV, "b", "failure", "d", environ={"SYSTEM_ACCESSTOKEN": "s"}, transport=t
    )
    assert any("could not post" in n and "connection refused" in n for n in notes)
    assert any("could not set" in n for n in notes)


def test_report_on_github_defers_to_the_action():
    env = ci_env.detect({"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/pull/1/merge"})
    t = FakeTransport()
    notes = report_to_pr(env, "b", "success", "d", environ={"GITHUB_TOKEN": "x"}, transport=t)
    assert "linebreak-gate@v1 Action" in notes[0]
    assert not t.calls


def test_report_flags_disable_each_half():
    t = FakeTransport({("GET", "/comments"): (200, {"values": []})})
    notes = report_to_pr(
        BITBUCKET_ENV,
        "b",
        "success",
        "d",
        environ={"BITBUCKET_ACCESS_TOKEN": "tok"},
        transport=t,
        comment=False,
    )
    assert len(t.of("POST")) == 1 and "/statuses/build" in t.of("POST")[0]["url"]
    assert len(notes) == 1


def test_default_transport_parses_http_errors(monkeypatch):
    import io
    import urllib.error

    def fake_urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 403, "forbidden", {}, io.BytesIO(b'{"message": "nope"}')
        )

    monkeypatch.setattr(ci_report.urllib.request, "urlopen", fake_urlopen)
    status, body = ci_report._default_transport("GET", "https://x.test/", {}, None)
    assert (status, body) == (403, {"message": "nope"})


# ---------------------------------------------------------------- block reasons + role denials (1.13.4)

SCAN_BLOCKED = "\n".join(
    [
        "LineBreak security gate — fail on: critical (default), block KEV: yes, EPSS threshold: off",
        "Dependencies (osv-scanner): 3 finding(s) — 1 critical, 2 high, 0 medium, 0 low, 0 unknown",
        "  [BLOCKING: kev] CVE-2024-0001  critical cvss 9.8  lodash@4.17.20",
        "      id: dep:lodash@4.17.20:CVE-2024-0001",
        "  [BLOCKING: vulnerability] CVE-2024-0002  critical cvss 9.1  yaml@1.0.0",
        "      id: dep:yaml@1.0.0:CVE-2024-0002",
        "      role denied: override by dev@example.com as role developer does not count (role not allowed): developers cannot accept risk",
        "  [EXPIRED RISK (acceptance ran out): expired_risk] CVE-2023-0009  high cvss 7.5  x@1",
        "      id: dep:x@1:CVE-2023-0009",
        "VERDICT: BLOCKED — 3 blocking finding(s) (1 kev, 1 vulnerability, 1 expired_risk; floor 'critical'). Fix them or record a human-approved override (linebreak-gate override --finding <id> --reason ... --approver ...). 1 of them had a risk acceptance that EXPIRED (expired_risk): renew it with --expires or fix the finding.",
    ]
)
CHECK_BLOCKED = "\n".join(
    [
        SCOPE_LINE.replace("warn", "block"),
        "  [x] [fail] S2/S2-AC1  (command: false)  S2-AC1 passes",
        "  [!] [role-denied] S1/S1-AC2  (manual)  S1-AC2 reviewed",
        "  role denied: S1-AC2 (S1): sign-off by dev@example.com as role developer does not count",
        "VERDICT: BLOCKED — 1 fail, 1 role-denied (reasons: tests_failed, role_denied). Fix the code.",
    ]
)


def test_parse_block_reasons_from_both_summaries():
    r = ci_report.parse_block_reasons(SCAN_BLOCKED, CHECK_BLOCKED)
    assert r["scan_reasons"] == ["kev", "vulnerability", "expired_risk"]
    assert r["scan_role_denied"] == 1
    assert r["check_reasons"] == ["tests_failed", "role_denied"]
    assert r["check_role_denied"] == [{"id": "S1-AC2", "story": "S1"}]


def test_parse_block_reasons_is_empty_on_pass():
    r = ci_report.parse_block_reasons("VERDICT: PASS — no blocking findings.", "VERDICT: PASS.")
    assert r == {
        "scan_reasons": [],
        "scan_role_denied": 0,
        "check_reasons": [],
        "check_role_denied": [],
    }


def test_comment_names_block_reasons_and_role_denials():
    body = render_comment(SCAN_BLOCKED, 1, CHECK_BLOCKED, 1)
    assert (
        "BLOCKED (kev, vulnerability, expired_risk; criteria: tests_failed, role_denied): see"
        in body
    )
    assert "configured floor (kev, vulnerability, expired_risk)**" in body
    assert "**Block reasons:** kev, vulnerability, expired_risk" in body
    assert "**Role denied:** 1 recorded override(s) do not count" in body
    assert "acceptance criteria unmet (tests_failed, role_denied)**" in body
    assert "**Role denied:** `S1-AC2` (S1). These approvals do not count" in body


def test_comment_scan_reasons_from_json_override_the_text():
    body = render_comment(SCAN_BLOCKED, 1, "VERDICT: PASS.", 0, scan_reasons=["kev"])
    assert "**Block reasons:** kev\n" in body
    assert "BLOCKED (kev): see the failing section below" in body


def test_comment_without_reasons_keeps_the_generic_wording():
    body = render_comment("VERDICT: BLOCKED", 1, "VERDICT: BLOCKED", 1)
    assert "BLOCKED: see the failing section below" in body
    assert "unmet (failing check or missing sign-off)" in body
    assert "**Block reasons:**" not in body


def test_verdict_description_names_the_reasons():
    _, d = verdict(1, 1, scan_reasons=["kev", "expired_risk"], check_reasons=["role_denied"])
    assert (
        d
        == "BLOCKED: known vulnerabilities (kev, expired_risk); acceptance criteria unmet (role_denied)"
    )
    assert verdict(1, 0)[1] == "BLOCKED: known vulnerabilities"
    assert verdict(0, 0, scan_reasons=["kev"])[0] == "success"
