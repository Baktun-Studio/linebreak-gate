"""The PR summary comment and build status, for CI providers without a
native Action: Bitbucket Pipelines (API 2.0) and Azure DevOps (REST 7.1).

The comment carries the SAME content the GitHub Action posts (security
section, acceptance-criteria section, scope, pending sign-offs), rendered by
:func:`render_comment` from the two report texts and exit codes. One comment
per pull request, updated in place on every run (found by a hidden marker),
never spammed.

Reporting is best effort by construction: without credentials, or when the
provider's API refuses, :func:`report_to_pr` returns a note and the caller
prints the verdict anyway. Nothing here can change the exit code: the gate
blocks through the pipeline's exit status, the comment is the evidence.

Stdlib-only transport (urllib), injectable for tests.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import quote

from .ci_env import CiEnv

MARKER = "<!-- linebreak-gate-summary -->"
STATUS_KEY = "linebreak-gate"
STATUS_NAME = "LineBreak gate"
_CAP = 30000
_TIMEOUT_SECONDS = 15
_MAX_PAGES = 10

#: (method, url, headers, body) -> (status, parsed json or {}).
Transport = Callable[[str, str, dict[str, str], bytes | None], tuple[int, Any]]


class ReportError(Exception):
    """The provider's API answered outside 2xx."""


def _user_agent() -> str:
    from linebreak_gate import __version__

    return f"linebreak-gate/{__version__}"


def _default_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, Any]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8", "replace")
            return response.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(raw) if raw.strip() else {}
        except ValueError:
            parsed = {"raw": raw[:500]}
        return e.code, parsed


# ---------------------------------------------------------------- the comment


def _clip(text: str) -> str:
    if len(text) <= _CAP:
        return text
    return text[:_CAP] + "\n… (truncated; full report in the pipeline artifact)"


def parse_block_reasons(scan_text: str, criteria_text: str) -> dict[str, Any]:
    """Lift the block reasons and the role denials out of the two summaries,
    from the fixed-shape lines the CLI prints: the scan verdict names its
    reasons as ``(1 kev, 2 vulnerability; floor ...)`` and prints one
    ``role denied:`` line under each override that does not count; the check
    verdict names ``(reasons: tests_failed, role_denied)`` and prints one
    ``role denied: <id> (<story>)`` line per rejected approval."""
    scan_reasons: list[str] = []
    m = re.search(r"^VERDICT: BLOCKED.*?blocking finding\(s\) \((.*?); floor", scan_text, re.M)
    if m:
        scan_reasons = [r for _, r in re.findall(r"(\d+) ([a-z_]+)", m.group(1))]
    scan_role_denied = len(re.findall(r"^\s+role denied: override by ", scan_text, re.M))
    check_reasons: list[str] = []
    m = re.search(r"^VERDICT: BLOCKED.*?\(reasons: ([a-z_, ]+)\)", criteria_text, re.M)
    if m:
        check_reasons = [r.strip() for r in m.group(1).split(",") if r.strip()]
    check_role_denied = [
        {"id": i, "story": s}
        for i, s in re.findall(r"^  role denied: (\S+) \((\S+)\)", criteria_text, re.M)
    ]
    return {
        "scan_reasons": scan_reasons,
        "scan_role_denied": scan_role_denied,
        "check_reasons": check_reasons,
        "check_role_denied": check_role_denied,
    }


def verdict(
    scan_code: int,
    check_code: int,
    *,
    scan_reasons: list[str] | None = None,
    check_reasons: list[str] | None = None,
) -> tuple[str, str]:
    """(state, description) for the build status: ``success`` | ``failure``
    | ``error``. The worse code wins, so a tool error (2) is never reported
    as a plain block. The block reasons (``kev``, ``vulnerability``,
    ``expired_risk``; ``tests_failed``, ``role_denied``, ...) are named when
    known, so the status line says why without opening the log."""
    worst = max(scan_code, check_code)
    if worst == 0:
        return "success", "PASS: security and acceptance criteria clear"
    if worst == 1:
        parts = []
        if scan_code == 1:
            why = f" ({', '.join(scan_reasons)})" if scan_reasons else ""
            parts.append(f"known vulnerabilities{why}")
        if check_code == 1:
            why = f" ({', '.join(check_reasons)})" if check_reasons else ""
            parts.append(f"acceptance criteria unmet{why}")
        return "failure", "BLOCKED: " + "; ".join(parts)
    return "error", "ERROR: the gate failed closed (scan or check could not run)"


def _parse_criteria(criteria_text: str, check_code: int) -> dict[str, Any]:
    """Lift the fixed-shape lines the CLI prints out of the criteria report:
    the same anchored patterns the GitHub Action's comment uses."""
    not_enforced = check_code == 0 and bool(
        re.search(
            r"^Acceptance criteria: (no approved criteria found|enforcement DISABLED)",
            criteria_text,
            re.M,
        )
    )
    scope_match = re.search(
        r"^linebreak-gate (?:action|ci): scope: (.+); manual criteria: (warn|block); "
        r"stage: (release|pr)$",
        criteria_text,
        re.M,
    )
    not_started = re.search(r"^  not started \(not counted\): (.+)$", criteria_text, re.M)
    release_only = re.search(
        r"^  release-only \(not evaluated at stage pr\): (.+)$", criteria_text, re.M
    )
    pending = re.findall(r"^  pending sign-off: (\S+) \((\S+)\)", criteria_text, re.M)
    return {
        "not_enforced": not_enforced,
        "scope": scope_match.group(1) if scope_match else None,
        "manual_warn": scope_match.group(2) == "warn" if scope_match else False,
        "stage": scope_match.group(3) if scope_match else "release",
        "not_started": not_started.group(1) if not_started else None,
        "release_only": release_only.group(1) if release_only else None,
        "release_only_count": len(release_only.group(1).split(", ")) if release_only else 0,
        "pending": [{"id": i, "story": s} for i, s in pending],
    }


def render_comment(
    scan_text: str,
    scan_code: int,
    criteria_text: str,
    check_code: int,
    *,
    scan_reasons: list[str] | None = None,
) -> str:
    """The PR summary comment body (Markdown), content-identical to the
    GitHub Action's comment: overall verdict, the security section with the
    scan report, the acceptance-criteria section with scope, pending
    sign-offs and the check report, and the reminder that humans stay on the
    record. Block reasons and role denials are named in the status lines;
    ``scan_reasons`` (from the JSON report) overrides what the text says."""
    reasons = parse_block_reasons(scan_text, criteria_text)
    if scan_reasons is not None:
        reasons["scan_reasons"] = list(scan_reasons)
    scan_why = f" ({', '.join(reasons['scan_reasons'])})" if reasons["scan_reasons"] else ""
    check_why = f" ({', '.join(reasons['check_reasons'])})" if reasons["check_reasons"] else ""
    scan_status = (
        "✅ **PASS**"
        if scan_code == 0
        else f"⛔ **BLOCKED: known vulnerabilities at/above the configured floor{scan_why}**"
        if scan_code == 1
        else "⚠️ **SCAN ERROR: gate failed closed**"
    )
    scan_lines: list[str] = []
    if scan_code == 1 and reasons["scan_reasons"]:
        scan_lines.append(f"**Block reasons:** {', '.join(reasons['scan_reasons'])}")
    if reasons["scan_role_denied"]:
        scan_lines.append(
            f"**Role denied:** {reasons['scan_role_denied']} recorded override(s) do not count "
            "under the roles policy (see the `role denied` lines); record them again with an "
            "authorized role"
        )
    if scan_lines:
        scan_lines.append("")
    c = _parse_criteria(criteria_text, check_code)
    pending, release_only_count = c["pending"], c["release_only_count"]
    pending_note = None
    if pending:
        pending_note = (
            f"{len(pending)} manual criterion(s) still need a sign-off before release "
            "(not blocking in this check; the release check with manual: block requires them)"
            if c["manual_warn"]
            else f"{len(pending)} manual criterion(s) need a sign-off (blocking)"
        )
    pass_tail = [
        f"{len(pending)} sign-off(s) pending before release" if pending else None,
        (
            f"{release_only_count} release-only criterion(s) not evaluated at stage pr"
            if release_only_count
            else None
        ),
    ]
    pass_tail = [p for p in pass_tail if p]
    if c["not_enforced"]:
        check_status = "ℹ️ **NOT ENFORCED: no approved spec bundle, or criteria.enforce: false**"
    elif check_code == 0:
        check_status = f"✅ **PASS** ({'; '.join(pass_tail)})" if pass_tail else "✅ **PASS**"
    elif check_code == 1:
        check_status = f"⛔ **BLOCKED: acceptance criteria unmet{check_why or ' (failing check or missing sign-off)'}**"
    else:
        check_status = "⚠️ **CHECK ERROR: gate failed closed**"

    blocked_why = "; ".join(
        p
        for p in (
            ", ".join(reasons["scan_reasons"]) if scan_code == 1 else "",
            f"criteria: {', '.join(reasons['check_reasons'])}"
            if check_code == 1 and reasons["check_reasons"]
            else "",
        )
        if p
    )
    if scan_code == 0 and check_code == 0:
        if c["not_enforced"]:
            status = "✅ **Security clear; acceptance criteria not enforced**"
        elif pass_tail:
            deferred = [
                f"{len(pending)} sign-off(s) pending before release" if pending else None,
                (
                    f"{release_only_count} criterion(s) deferred to the release check"
                    if release_only_count
                    else None
                ),
            ]
            status = f"✅ **PASS: security clear; {'; '.join(d for d in deferred if d)}**"
        else:
            status = "✅ **PASS: security and acceptance criteria both clear**"
    else:
        status = (
            f"⛔ **BLOCKED ({blocked_why}): see the failing section below**"
            if blocked_why
            else "⛔ **BLOCKED: see the failing section below**"
        )

    scope_lines: list[str] = []
    if c["scope"] and not c["not_enforced"]:
        manual = "warn" if c["manual_warn"] else "block"
        scope_lines.append(
            f"**Scope:** {c['scope']}; manual criteria: {manual}; stage: {c['stage']}"
        )
        if c["not_started"]:
            scope_lines.append(f"**Not started (not counted):** {c['not_started']}")
        if c["release_only"]:
            scope_lines.append(
                f"**Release-only (not evaluated at stage {c['stage']}; the release check "
                f"owns them):** {c['release_only']}"
            )
        if pending:
            ids = ", ".join(f"`{p['id']}` ({p['story']})" for p in pending)
            scope_lines.append(f"**Pending sign-offs:** {ids}. {pending_note}.")
        if reasons["check_role_denied"]:
            ids = ", ".join(f"`{d['id']}` ({d['story']})" for d in reasons["check_role_denied"])
            scope_lines.append(
                f"**Role denied:** {ids}. These approvals do not count under the roles policy; "
                "record them again with an authorized role."
            )
        scope_lines.append("")

    return "\n".join(
        [
            MARKER,
            "## LineBreak gate",
            "",
            status,
            "",
            "### Security",
            "",
            scan_status,
            "",
            *scan_lines,
            "```text",
            _clip(scan_text).rstrip(),
            "```",
            "",
            "### Acceptance criteria",
            "",
            check_status,
            "",
            *scope_lines,
            "```text",
            _clip(criteria_text).rstrip(),
            "```",
            "",
            "_Humans stay on the record: security overrides via `linebreak-gate override "
            '--finding <id> --reason "…" --approver <…>`; criteria via `--criterion <id>`; '
            "`manual` criteria via `linebreak-gate signoff --criterion <id> --approver <…> "
            '--note "…"`. Commit the updated `.linebreak/` files._',
        ]
    )


# ---------------------------------------------------------------- reporters


class _Reporter:
    name = ""

    def __init__(self, env: CiEnv, *, auth_header: str, transport: Transport | None = None):
        self.env = env
        self._auth = auth_header
        self._transport = transport or _default_transport

    def _call(self, method: str, url: str, payload: Any = None) -> Any:
        headers = {
            "Authorization": self._auth,
            "Accept": "application/json",
            "User-Agent": _user_agent(),
        }
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, parsed = self._transport(method, url, headers, body)
        if not 200 <= status < 300:
            detail = ""
            if isinstance(parsed, dict):
                err = parsed.get("error") or parsed.get("message") or parsed.get("raw")
                if isinstance(err, dict):
                    err = err.get("message") or err
                if err:
                    detail = f": {str(err)[:200]}"
            raise ReportError(f"{self.name} API answered HTTP {status} on {method} {url}{detail}")
        return parsed


class BitbucketReporter(_Reporter):
    """Bitbucket Cloud API 2.0: pull request comments and commit build
    statuses. Auth: a repository/workspace access token (``Bearer``) or an
    app password / API token with the account name (``Basic``)."""

    name = "bitbucket"

    @classmethod
    def from_environ(
        cls, env: CiEnv, environ: Mapping[str, str], transport: Transport | None = None
    ) -> BitbucketReporter | None:
        token = (environ.get("BITBUCKET_ACCESS_TOKEN") or "").strip()
        if token:
            return cls(env, auth_header=f"Bearer {token}", transport=transport)
        user = (environ.get("BITBUCKET_USERNAME") or "").strip()
        secret = (
            environ.get("BITBUCKET_APP_PASSWORD") or environ.get("BITBUCKET_API_TOKEN") or ""
        ).strip()
        if user and secret:
            raw = base64.b64encode(f"{user}:{secret}".encode()).decode("ascii")
            return cls(env, auth_header=f"Basic {raw}", transport=transport)
        return None

    @staticmethod
    def credentials_hint() -> str:
        return (
            "set BITBUCKET_ACCESS_TOKEN (repository access token with pullrequest:write and "
            "repository:write) or BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD as repository "
            "variables"
        )

    def _repo_url(self) -> str:
        workspace = self.env.details.get("workspace")
        slug = self.env.details.get("repo_slug")
        if not workspace or not slug:
            raise ReportError("Bitbucket workspace/repo slug not set (BITBUCKET_REPO_FULL_NAME)")
        return f"{self.env.server_url}/repositories/{quote(workspace)}/{quote(slug)}"

    def _find_comment(self, base: str) -> int | None:
        url: str | None = f"{base}/comments?pagelen=100"
        pages = 0
        while url and pages < _MAX_PAGES:
            page = self._call("GET", url)
            for c in (page or {}).get("values") or []:
                if c.get("deleted"):
                    continue
                raw = ((c.get("content") or {}).get("raw")) or ""
                if raw.startswith(MARKER) and c.get("id") is not None:
                    return int(c["id"])
            url = (page or {}).get("next")
            pages += 1
        return None

    def upsert_comment(self, body: str) -> str:
        if self.env.pr_number is None:
            raise ReportError("not a pull request build")
        base = f"{self._repo_url()}/pullrequests/{self.env.pr_number}"
        payload = {"content": {"raw": body}}
        existing = self._find_comment(base)
        if existing is not None:
            self._call("PUT", f"{base}/comments/{existing}", payload)
            return "updated"
        self._call("POST", f"{base}/comments", payload)
        return "created"

    def set_status(self, state: str, description: str) -> None:
        if not self.env.commit:
            raise ReportError("no commit to attach the build status to (BITBUCKET_COMMIT)")
        bb_state = "SUCCESSFUL" if state == "success" else "FAILED"
        url = self.env.build_url or f"https://bitbucket.org/{self.env.repo}"
        self._call(
            "POST",
            f"{self._repo_url()}/commit/{self.env.commit}/statuses/build",
            {
                "key": STATUS_KEY,
                "name": STATUS_NAME,
                "state": bb_state,
                "description": description[:255],
                "url": url,
            },
        )


class AzureDevOpsReporter(_Reporter):
    """Azure DevOps Services / Server REST 7.1 on Azure Repos: pull request
    comment threads and pull request statuses. Auth: the job's
    ``System.AccessToken`` (mapped into ``SYSTEM_ACCESSTOKEN``) or a PAT."""

    name = "azure"
    _API = "api-version=7.1"

    @classmethod
    def from_environ(
        cls, env: CiEnv, environ: Mapping[str, str], transport: Transport | None = None
    ) -> AzureDevOpsReporter | None:
        token = (environ.get("SYSTEM_ACCESSTOKEN") or "").strip()
        if token:
            return cls(env, auth_header=f"Bearer {token}", transport=transport)
        pat = (environ.get("AZURE_DEVOPS_PAT") or "").strip()
        if pat:
            raw = base64.b64encode(f":{pat}".encode()).decode("ascii")
            return cls(env, auth_header=f"Basic {raw}", transport=transport)
        return None

    @staticmethod
    def credentials_hint() -> str:
        return (
            "map the job token in the step's env (SYSTEM_ACCESSTOKEN: $(System.AccessToken)) "
            "and grant the build service 'Contribute to pull requests' on the repository"
        )

    def _pr_url(self) -> str:
        collection = self.env.server_url
        project = self.env.details.get("project")
        repo = self.env.details.get("repository_id") or self.env.repo
        if not collection or not project or not repo:
            raise ReportError(
                "Azure DevOps collection/project/repository not set "
                "(SYSTEM_COLLECTIONURI, SYSTEM_TEAMPROJECT, BUILD_REPOSITORY_NAME)"
            )
        if self.env.pr_number is None:
            raise ReportError("not a pull request build")
        provider = self.env.details.get("repository_provider")
        if provider and provider.lower() != "tfsgit":
            raise ReportError(
                f"the repository is hosted on {provider}, not Azure Repos; the Azure DevOps "
                "PR API does not apply (use that provider's own comment path)"
            )
        return (
            f"{collection}/{quote(project, safe='')}/_apis/git/repositories/"
            f"{quote(repo, safe='')}/pullRequests/{self.env.pr_number}"
        )

    def _find_thread(self, base: str) -> tuple[int, int] | None:
        page = self._call("GET", f"{base}/threads?{self._API}")
        for thread in (page or {}).get("value") or []:
            if thread.get("isDeleted"):
                continue
            comments = thread.get("comments") or []
            if not comments:
                continue
            first = comments[0]
            if (first.get("content") or "").startswith(MARKER) and not first.get("isDeleted"):
                return int(thread["id"]), int(first["id"])
        return None

    def upsert_comment(self, body: str, *, state: str = "failure") -> str:
        base = self._pr_url()
        # Thread status: active while blocked (a "resolve all comments" policy
        # then holds the PR too), closed once the gate passes.
        thread_status = 4 if state == "success" else 1
        found = self._find_thread(base)
        if found is not None:
            thread_id, comment_id = found
            self._call(
                "PATCH",
                f"{base}/threads/{thread_id}/comments/{comment_id}?{self._API}",
                {"content": body},
            )
            self._call(
                "PATCH", f"{base}/threads/{thread_id}?{self._API}", {"status": thread_status}
            )
            return "updated"
        self._call(
            "POST",
            f"{base}/threads?{self._API}",
            {
                "comments": [{"parentCommentId": 0, "content": body, "commentType": 1}],
                "status": thread_status,
            },
        )
        return "created"

    def set_status(self, state: str, description: str) -> None:
        base = self._pr_url()
        az_state = {"success": "succeeded", "failure": "failed"}.get(state, "error")
        payload: dict[str, Any] = {
            "state": az_state,
            "description": description[:400],
            "context": {"name": "gate", "genre": "linebreak"},
        }
        if self.env.build_url:
            payload["targetUrl"] = self.env.build_url
        self._call("POST", f"{base}/statuses?{self._API}", payload)


_REPORTERS: dict[str, type[BitbucketReporter] | type[AzureDevOpsReporter]] = {
    "bitbucket": BitbucketReporter,
    "azure": AzureDevOpsReporter,
}

_TRANSPORT_ERRORS = (ReportError, OSError, ValueError, http.client.HTTPException)


def report_to_pr(
    env: CiEnv,
    body: str,
    state: str,
    description: str,
    *,
    environ: Mapping[str, str],
    transport: Transport | None = None,
    comment: bool = True,
    status: bool = True,
) -> list[str]:
    """Post the comment and the build status on the pull request when the
    provider, the build and the credentials allow it. Returns the notes to
    print (one per outcome). NEVER raises and never changes the verdict:
    the printed report is the evidence when the API path is unavailable."""
    notes: list[str] = []
    cls = _REPORTERS.get(env.provider)
    if cls is None:
        if env.provider == "github":
            notes.append(
                "PR comment: on GitHub Actions the Baktun-Studio/linebreak-gate@v1 Action posts it; "
                "nothing posted from here"
            )
        else:
            notes.append(
                f"PR comment: not posted ({env.label}); the verdict above and the exit code are "
                "the evidence"
            )
        return notes
    if env.pr_number is None:
        notes.append(f"PR comment: not a pull request build on {env.label}; nothing to post")
        return notes
    reporter = cls.from_environ(env, environ, transport)
    if reporter is None:
        notes.append(
            f"PR comment and status: no credentials for {env.label} ({cls.credentials_hint()}); "
            "the verdict above is the evidence, the exit code still enforces"
        )
        return notes
    if comment:
        try:
            if isinstance(reporter, AzureDevOpsReporter):
                outcome = reporter.upsert_comment(body, state=state)
            else:
                outcome = reporter.upsert_comment(body)
            notes.append(f"PR comment {outcome} on {env.label} pull request #{env.pr_number}")
        except _TRANSPORT_ERRORS as e:
            notes.append(
                f"PR comment: could not post on {env.label} ({e}); exit code still enforces"
            )
    if status:
        try:
            reporter.set_status(state, description)
            notes.append(f"build status '{STATUS_NAME}' set to {state} on {env.label}")
        except _TRANSPORT_ERRORS as e:
            notes.append(
                f"build status: could not set on {env.label} ({e}); exit code still enforces"
            )
    return notes
