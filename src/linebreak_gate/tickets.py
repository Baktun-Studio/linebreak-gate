"""Mirror accepted risks into the team's ticket tracker (Jira first, GitHub
Issues too), so traceability lives in THEIR tool and not only in LineBreak.

What gets a ticket:

* An accepted security finding or an excused criterion (``linebreak-gate
  override``): one ticket per target, carrying the finding/criterion, who
  accepted it, the reason, the expiry, the repo + commit and a link to the
  evidence record. The key lands in the approval entry (``ticket: "SEC-123"``).
  A renewal comments on the same ticket and reopens it if it was closed.
* An acceptance that expired (seen by ``scan`` / ``check``): a comment on the
  ticket, reopened if closed.
* A risk that was fixed (the finding is gone from the scan, the criterion
  passes on its own): a comment and the ticket is closed.
* A NEW vulnerability on released code: a ``scan`` on the main branch that
  finds something the previously recorded scan did not have opens an
  attention ticket.

Design points an auditor should know:

* The tracker NEVER blocks the verdict. Any failure (no network, bad
  credentials, a project that refuses the issue type) is recorded in the
  evidence (``ticket_error`` on the approval entry, the pending operation in
  ``.linebreak/audit/tickets.json``) and printed as a warning. ``linebreak-gate
  tickets sync`` replays the pending operations.
* Idempotency lives in the tracker, not in local state: every ticket carries a
  ``linebreak-target-<hash>`` label and the gate looks it up before creating
  one, so a CI runner without the local ledger never opens duplicates.
* Standard library only (``urllib``): the gate stays a light dependency.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import security_artifact as sa
from .gate_config import TicketsConfig

AUDIT_DIR = str(Path(".linebreak") / "audit")
LEDGER_NAME = "tickets.json"
LEDGER_VERSION = 1
TIMEOUT_S = 20

LABEL_PREFIX = "linebreak-target-"
ARTIFACT_LABEL_PREFIX = "linebreak-artifact-"
#: Marker embedded in the expiry comment so a rerun never comments twice for
#: the same expiry date (the tracker is the memory, not the local ledger).
EXPIRED_MARKER = "[linebreak expired {expires}]"

ARTIFACTS = ("security", "code", "criteria")
ACTIONS = ("create", "renew", "expired", "resolved")


class TicketError(Exception):
    """The tracker could not be reached or refused the request. Never fatal
    for the gate: callers record it and move on."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def target_hash(target: str) -> str:
    return hashlib.sha256(target.encode("utf-8")).hexdigest()[:12]


def _warn(message: str) -> None:
    print(f"linebreak-gate: tickets: {message}", file=sys.stderr)


# ---------------------------------------------------------------- transport


def _send(method: str, url: str, headers: dict[str, str], body: bytes | None) -> tuple[int, bytes]:
    """One HTTP exchange. Returns (status, raw body); HTTP errors are returned
    as their status (the client decides), transport errors raise TicketError.
    Tests replace this function to simulate the tracker."""
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:  # noqa: S310 (https API)
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise TicketError(f"network error reaching {url}: {e}") from e


def _short(data: Any) -> str:
    text = data if isinstance(data, str) else json.dumps(data)
    return " ".join(text.split())[:300]


class _Client:
    name = "tracker"

    def _headers(self) -> dict[str, str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def _call(
        self, method: str, url: str, payload: Any = None, *, ok: tuple[int, ...] = ()
    ) -> tuple[int, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        status, raw = _send(method, url, self._headers(), body)
        data: Any = None
        if raw:
            try:
                data = json.loads(raw.decode("utf-8"))
            except ValueError:
                data = raw.decode("utf-8", "replace")
        if status >= 400 and status not in ok:
            raise TicketError(f"{self.name}: HTTP {status} on {method} {url}: {_short(data)}")
        return status, data


class JiraClient(_Client):
    """Jira REST API v2 (Cloud and Data Center both serve it; v2 takes plain
    text bodies, v3 would need Atlassian Document Format)."""

    name = "jira"

    def __init__(self, base_url: str, email: str, token: str) -> None:
        self.base = base_url.rstrip("/")
        self._auth = base64.b64encode(f"{email}:{token}".encode()).decode("ascii")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Basic {self._auth}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "linebreak-gate",
        }

    def _api(self, path: str) -> str:
        return f"{self.base}/rest/api/2{path}"

    def url(self, key: str) -> str:
        return f"{self.base}/browse/{key}"

    def create(
        self, project: str, summary: str, body: str, labels: list[str], issue_type: str
    ) -> str:
        _, data = self._call(
            "POST",
            self._api("/issue"),
            {
                "fields": {
                    "project": {"key": project},
                    "summary": summary,
                    "description": body,
                    "issuetype": {"name": issue_type},
                    "labels": labels,
                }
            },
        )
        return str(data["key"])

    def comment(self, key: str, body: str) -> None:
        self._call("POST", self._api(f"/issue/{key}/comment"), {"body": body})

    def comments(self, key: str) -> list[str]:
        _, data = self._call("GET", self._api(f"/issue/{key}/comment?maxResults=100"))
        out: list[str] = []
        for c in (data or {}).get("comments") or []:
            body = c.get("body")
            out.append(body if isinstance(body, str) else json.dumps(body))
        return out

    def state(self, key: str) -> str:
        _, data = self._call("GET", self._api(f"/issue/{key}?fields=status"))
        return _jira_state(data)

    def _transition(self, key: str, *, to_done: bool) -> None:
        _, data = self._call("GET", self._api(f"/issue/{key}/transitions"))
        transitions = (data or {}).get("transitions") or []
        chosen = None
        for want in ("done",) if to_done else ("new", "indeterminate"):
            for t in transitions:
                cat = ((t.get("to") or {}).get("statusCategory") or {}).get("key")
                if cat == want:
                    chosen = t
                    break
            if chosen:
                break
        if chosen is None:
            raise TicketError(
                f"jira: no transition to {'a done' if to_done else 'an open'} status is "
                f"available on {key} from its current status"
            )
        self._call(
            "POST", self._api(f"/issue/{key}/transitions"), {"transition": {"id": chosen["id"]}}
        )

    def reopen(self, key: str) -> None:
        self._transition(key, to_done=False)

    def close(self, key: str) -> None:
        self._transition(key, to_done=True)

    def find_by_label(self, project: str, label: str) -> list[dict[str, Any]]:
        jql = f'project = "{project}" AND labels = "{label}" ORDER BY created DESC'
        query = urllib.parse.urlencode({"jql": jql, "fields": "status,labels", "maxResults": 50})
        # Jira Cloud replaced /search with /search/jql (2025); Data Center still
        # serves /search. Try the new one, fall back on 404/410.
        status, data = self._call("GET", self._api(f"/search/jql?{query}"), ok=(404, 410))
        if status in (404, 410):
            _, data = self._call("GET", self._api(f"/search?{query}"))
        out = []
        for issue in (data or {}).get("issues") or []:
            fields = issue.get("fields") or {}
            out.append(
                {
                    "key": issue.get("key"),
                    "state": _jira_state({"fields": fields}),
                    "labels": list(fields.get("labels") or []),
                }
            )
        return out


def _jira_state(data: Any) -> str:
    status = ((data or {}).get("fields") or {}).get("status") or {}
    category = (status.get("statusCategory") or {}).get("key")
    return "closed" if category == "done" else "open"


class GitHubClient(_Client):
    """GitHub Issues. Keys are ``owner/repo#123``."""

    name = "github"

    def __init__(
        self,
        token: str,
        api_base: str = "https://api.github.com",
        web_base: str = "https://github.com",
    ) -> None:
        self.api_base = api_base.rstrip("/")
        self.web_base = web_base.rstrip("/")
        self._token = token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "linebreak-gate",
        }

    @staticmethod
    def _split(key: str) -> tuple[str, str]:
        repo, _, number = key.partition("#")
        if not repo or not number.isdigit():
            raise TicketError(f"github: malformed ticket key {key!r} (expected owner/repo#N)")
        return repo, number

    def url(self, key: str) -> str:
        repo, number = self._split(key)
        return f"{self.web_base}/{repo}/issues/{number}"

    def create(
        self, project: str, summary: str, body: str, labels: list[str], issue_type: str
    ) -> str:
        _, data = self._call(
            "POST",
            f"{self.api_base}/repos/{project}/issues",
            {"title": summary, "body": body, "labels": labels},
        )
        return f"{project}#{data['number']}"

    def comment(self, key: str, body: str) -> None:
        repo, number = self._split(key)
        self._call("POST", f"{self.api_base}/repos/{repo}/issues/{number}/comments", {"body": body})

    def comments(self, key: str) -> list[str]:
        repo, number = self._split(key)
        _, data = self._call(
            "GET", f"{self.api_base}/repos/{repo}/issues/{number}/comments?per_page=100"
        )
        return [str(c.get("body") or "") for c in (data or [])]

    def state(self, key: str) -> str:
        repo, number = self._split(key)
        _, data = self._call("GET", f"{self.api_base}/repos/{repo}/issues/{number}")
        return "closed" if (data or {}).get("state") == "closed" else "open"

    def _set_state(self, key: str, state: str) -> None:
        repo, number = self._split(key)
        self._call("PATCH", f"{self.api_base}/repos/{repo}/issues/{number}", {"state": state})

    def reopen(self, key: str) -> None:
        self._set_state(key, "open")

    def close(self, key: str) -> None:
        self._set_state(key, "closed")

    def find_by_label(self, project: str, label: str) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"labels": label, "state": "all", "per_page": 50})
        _, data = self._call("GET", f"{self.api_base}/repos/{project}/issues?{query}")
        out = []
        for issue in data or []:
            if issue.get("pull_request"):
                continue
            out.append(
                {
                    "key": f"{project}#{issue.get('number')}",
                    "state": "closed" if issue.get("state") == "closed" else "open",
                    "labels": [
                        lb.get("name") if isinstance(lb, dict) else str(lb)
                        for lb in issue.get("labels") or []
                    ],
                }
            )
        return out


def _credential(cfg: TicketsConfig, name: str) -> str | None:
    """A credential by its environment name: the environment wins; what the
    governance service handed over (``cfg.credentials``) is the fallback."""
    return os.environ.get(name) or dict(cfg.credentials).get(name) or None


def client_from_env(cfg: TicketsConfig) -> _Client:
    """Build the provider client from environment credentials (or the ones
    the governance service handed over with the config). Missing credentials
    are a TicketError (recorded, never fatal)."""
    if cfg.provider == "jira":
        names = ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN")
        values = {n: _credential(cfg, n) for n in names}
        missing = [n for n in names if not values[n]]
        if missing:
            raise TicketError(f"jira credentials missing: set {', '.join(missing)}")
        return JiraClient(values["JIRA_BASE_URL"], values["JIRA_EMAIL"], values["JIRA_API_TOKEN"])  # type: ignore[arg-type]
    if cfg.provider == "github":
        token = _credential(cfg, "GITHUB_TOKEN")
        if not token:
            raise TicketError("github credentials missing: set GITHUB_TOKEN")
        return GitHubClient(
            token,
            api_base=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            web_base=os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
        )
    raise TicketError(f"unknown tickets.provider {cfg.provider!r}")  # pragma: no cover


# ---------------------------------------------------------------- governance config

GOVERNANCE_CONFIG_PATH = "/v1/gate/tickets-config"
#: (url, token) -> (status, parsed body)
GovernanceFetch = Callable[[str, str], tuple[int, Any]]


def _default_governance_fetch(url: str, token: str) -> tuple[int, Any]:
    status, raw = _send(
        "GET",
        url,
        {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "linebreak-gate",
        },
        None,
    )
    if not raw:
        return status, None
    try:
        return status, json.loads(raw.decode("utf-8"))
    except ValueError:
        return status, None


def from_governance(
    env: Mapping[str, str] | None = None, fetch: GovernanceFetch | None = None
) -> TicketsConfig | None:
    """The tracker configured on the governance service's Integrations screen,
    read with the pipeline token (``LINEBREAK_GOVERNANCE_BASE_URL`` and
    ``LINEBREAK_GOVERNANCE_TOKEN``). Used only when ``gate.yml`` fixes no
    ``tickets:`` block: what the repository says always wins.

    ``None`` when the variables are absent, the service has no tracker
    configured (404) or answers anything but 200. A malformed body is a
    :class:`TicketError` (the caller records it; never a verdict)."""
    from . import identity as _identity
    from .gate_config import GateConfigError, tickets_config_from_mapping

    env = os.environ if env is None else env
    base = (env.get(_identity.GOVERNANCE_BASE_ENV) or "").strip().rstrip("/")
    token = (env.get(_identity.GOVERNANCE_TOKEN_ENV) or "").strip()
    if not base or not token:
        return None
    status, body = (fetch or _default_governance_fetch)(f"{base}{GOVERNANCE_CONFIG_PATH}", token)
    if status == 404 or body is None:
        return None
    if status != 200:
        raise TicketError(f"governance service answered {status} to GET {GOVERNANCE_CONFIG_PATH}")
    if not isinstance(body, dict):
        raise TicketError("governance service returned an unexpected tickets configuration")
    creds = body.get("credentials") if isinstance(body.get("credentials"), dict) else {}
    block = {
        k: v
        for k, v in body.items()
        if k in ("provider", "project", "labels", "main_branch", "issue_type")
    }
    try:
        cfg = tickets_config_from_mapping(block, source="governance")
    except GateConfigError as e:
        raise TicketError(f"governance service tickets configuration is invalid: {e}") from e
    if cfg is None:
        return None
    return TicketsConfig(
        provider=cfg.provider,
        project=cfg.project,
        labels=cfg.labels,
        main_branch=cfg.main_branch,
        issue_type=cfg.issue_type,
        source="governance",
        credentials=tuple((str(k), str(v)) for k, v in creds.items() if isinstance(v, str) and v),
    )


# ---------------------------------------------------------------- repo context


@dataclass(frozen=True)
class RepoContext:
    repo: str | None
    commit: str | None
    branch: str | None
    server_url: str


def _git(root: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def _repo_from_remote(remote: str | None) -> str | None:
    if not remote:
        return None
    remote = remote.strip()
    if remote.endswith(".git"):
        remote = remote[:-4]
    for sep in ("github.com:", "github.com/"):
        if sep in remote:
            tail = remote.split(sep, 1)[1].strip("/")
            if tail.count("/") == 1:
                return tail
    return None


def repo_context(root: Path) -> RepoContext:
    """Repo, commit and branch: CI environment first (GitHub Actions
    variables), git as the fallback. A pull request is never "main":
    ``GITHUB_HEAD_REF`` (the PR source branch) wins over ``GITHUB_REF_NAME``."""
    env = os.environ
    repo = env.get("GITHUB_REPOSITORY") or _repo_from_remote(
        _git(root, "remote", "get-url", "origin")
    )
    commit = env.get("GITHUB_SHA") or _git(root, "rev-parse", "HEAD")
    branch = (
        env.get("GITHUB_HEAD_REF")
        or env.get("GITHUB_REF_NAME")
        or _git(root, "rev-parse", "--abbrev-ref", "HEAD")
    )
    return RepoContext(
        repo=repo,
        commit=commit,
        branch=branch,
        server_url=env.get("GITHUB_SERVER_URL", "https://github.com"),
    )


def evidence_link(ctx: RepoContext, artifact: str) -> str:
    rel = f"{AUDIT_DIR}/{artifact}.json".replace("\\", "/")
    if ctx.repo and ctx.commit:
        return f"{ctx.server_url}/{ctx.repo}/blob/{ctx.commit}/{rel}"
    return rel


# ---------------------------------------------------------------- ledger


def ledger_path(root: Path) -> Path:
    return root / AUDIT_DIR / LEDGER_NAME


def read_ledger(root: Path) -> dict[str, Any]:
    file = ledger_path(root)
    empty = {"version": LEDGER_VERSION, "tickets": []}
    if not file.exists():
        return empty
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict) or not isinstance(data.get("tickets"), list):
        return empty
    return data


def write_ledger(root: Path, doc: dict[str, Any]) -> None:
    file = ledger_path(root)
    file.parent.mkdir(parents=True, exist_ok=True)
    doc["version"] = LEDGER_VERSION
    doc["updated_at"] = _now()
    tmp = file.with_name(f"{file.name}.tmp.{os.getpid()}.{int(time.time() * 1000)}")
    try:
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, file)
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _find_item(ledger: dict[str, Any], artifact: str, thash: str) -> dict[str, Any] | None:
    for item in ledger["tickets"]:
        if item.get("artifact") == artifact and item.get("target_hash") == thash:
            return item
    return None


def _get_item(
    ledger: dict[str, Any],
    *,
    artifact: str,
    target: str | None,
    thash: str | None = None,
    kind: str = "acceptance",
    approval_id: str | None = None,
    provider: str,
) -> dict[str, Any]:
    thash = thash or target_hash(target or "")
    item = _find_item(ledger, artifact, thash)
    if item is None:
        item = {
            "id": uuid.uuid4().hex,
            "artifact": artifact,
            "target": target,
            "target_hash": thash,
            "kind": kind,
            "approval_id": approval_id,
            "provider": provider,
            "key": None,
            "url": None,
            "state": None,
            "pending": [],
            "error": None,
            "history": [],
            "created_at": _now(),
        }
        ledger["tickets"].append(item)
    else:
        if target and not item.get("target"):
            item["target"] = target
        if approval_id:
            item["approval_id"] = approval_id
    return item


# ---------------------------------------------------------------- rendering


def _lines(pairs: list[tuple[str, Any]]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in pairs if v not in (None, ""))


def _subject(artifact: str, finding: dict[str, Any]) -> str:
    if artifact == "criteria":
        return f"criterion {finding.get('criterion_id')} (story {finding.get('story_id')})"
    if artifact == "code":
        return f"{finding.get('title')} at {finding.get('file')}:{finding.get('line')}"
    label = finding.get("cve_id") or finding.get("title") or "finding"
    return f"{label} in {finding.get('package')}@{finding.get('installed_version')}"


def render_acceptance(artifact: str, entry: dict[str, Any], ctx: RepoContext) -> tuple[str, str]:
    """Summary + body of the ticket for a recorded acceptance."""
    finding = entry.get("finding") or {}
    kind = "Criterion exception" if artifact == "criteria" else "Accepted risk"
    summary = f"[LineBreak] {kind}: {_subject(artifact, finding)}"
    pairs: list[tuple[str, Any]] = [("Target", finding.get("id") or finding.get("criterion_id"))]
    if artifact == "criteria":
        pairs += [
            ("Story", finding.get("story_id")),
            ("Statement", finding.get("statement")),
            ("Check type", finding.get("check_type")),
        ]
    elif artifact == "code":
        pairs += [
            ("Title", finding.get("title")),
            ("Location", f"{finding.get('file')}:{finding.get('line')}"),
            ("Category", finding.get("category")),
            ("Severity", finding.get("severity")),
        ]
    else:
        pairs += [
            ("CVE", finding.get("cve_id")),
            ("Package", f"{finding.get('package')}@{finding.get('installed_version')}"),
            ("Severity", finding.get("severity")),
            ("Advisory", finding.get("advisory_url")),
        ]
    pairs += [
        ("Accepted by", entry.get("user_email")),
        ("Role", entry.get("role")),
        ("Accepted at", entry.get("at")),
        ("Expires", entry.get("expires") or "no expiry (open-ended)"),
        ("Reason", entry.get("notes")),
        ("Repository", ctx.repo),
        ("Commit", ctx.commit),
        ("Evidence", evidence_link(ctx, artifact)),
        ("Approval id", entry.get("id")),
    ]
    body = (
        "Recorded by linebreak-gate. The gate blocks again when this acceptance expires; "
        "renewing it is a new override on the record.\n\n" + _lines(pairs)
    )
    return summary, body


def render_attention(artifact: str, finding: dict[str, Any], ctx: RepoContext) -> tuple[str, str]:
    summary = (
        f"[LineBreak] New vulnerability on {ctx.branch or 'main'}: {_subject(artifact, finding)}"
    )
    pairs: list[tuple[str, Any]] = [
        ("Target", finding.get("id")),
        ("Severity", finding.get("severity")),
        ("CVSS", finding.get("cvss")),
        ("Package", f"{finding.get('package')}@{finding.get('installed_version')}")
        if artifact == "security"
        else ("Location", f"{finding.get('file')}:{finding.get('line')}"),
        ("Fixed in", finding.get("fixed_version")),
        ("Advisory", finding.get("advisory_url")),
        ("Repository", ctx.repo),
        ("Commit", ctx.commit),
        ("Branch", ctx.branch),
        ("Evidence", evidence_link(ctx, artifact)),
    ]
    body = (
        "linebreak-gate found this on released code: it was not in the previously "
        "recorded scan. Fix it, or accept the risk with an expiry "
        "(linebreak-gate override).\n\n" + _lines(pairs)
    )
    return summary, body


def render_renewal(entry: dict[str, Any], ctx: RepoContext) -> str:
    return (
        f"Acceptance renewed by {entry.get('user_email')} at {entry.get('at')}, "
        f"expires {entry.get('expires') or 'never (open-ended)'}.\n"
        f"Reason: {entry.get('notes')}\nCommit: {ctx.commit}\nApproval id: {entry.get('id')}"
    )


def render_expired(acceptance: dict[str, Any], target: str, ctx: RepoContext) -> str:
    expires = acceptance.get("expires")
    return (
        f"The risk acceptance for {target} expired on {expires} (accepted by "
        f"{acceptance.get('by') or acceptance.get('approver')}). The gate blocks again "
        "(expired_risk) until it is renewed with linebreak-gate override or the risk is "
        f"fixed.\nCommit: {ctx.commit}\n{EXPIRED_MARKER.format(expires=expires)}"
    )


def render_resolved(target: str, artifact: str, ctx: RepoContext) -> str:
    what = (
        "criterion passes on its own" if artifact == "criteria" else "finding is gone from the scan"
    )
    return (
        f"Resolved: the {what} ({target}). Closed by linebreak-gate.\n"
        f"Commit: {ctx.commit}\nEvidence: {evidence_link(ctx, artifact)}"
    )


# ---------------------------------------------------------------- operations


def _labels(cfg: TicketsConfig, artifact: str, thash: str) -> list[str]:
    return [*cfg.labels, f"{LABEL_PREFIX}{thash}", f"{ARTIFACT_LABEL_PREFIX}{artifact}"]


def _lookup(client: _Client, cfg: TicketsConfig, thash: str) -> dict[str, Any] | None:
    found = client.find_by_label(cfg.project, f"{LABEL_PREFIX}{thash}")
    return found[0] if found else None


def _ensure_key(client: _Client, cfg: TicketsConfig, item: dict[str, Any], hint: str | None) -> str:
    if not item.get("key") and hint:
        item["key"] = hint
        item["url"] = client.url(hint)
    if not item.get("key"):
        existing = _lookup(client, cfg, item["target_hash"])
        if existing is None:
            raise TicketError(
                f"no ticket exists yet for target {item.get('target') or item['target_hash']}"
            )
        item["key"] = existing["key"]
        item["state"] = existing["state"]
        item["url"] = client.url(existing["key"])
    return item["key"]


def _apply(client: _Client, cfg: TicketsConfig, item: dict[str, Any], op: dict[str, Any]) -> None:
    """Perform one operation against the tracker (raises TicketError)."""
    action = op["action"]
    if action == "create":
        existing = _lookup(client, cfg, item["target_hash"])
        if existing is not None:
            # Already mirrored (another runner, an earlier acceptance): reuse it
            # and treat this as a renewal so the new record is on the ticket.
            item["key"] = existing["key"]
            item["state"] = existing["state"]
            item["url"] = client.url(existing["key"])
            client.comment(item["key"], op.get("renewal") or op["body"])
            if item["state"] == "closed":
                client.reopen(item["key"])
                item["state"] = "open"
            return
        key = client.create(
            cfg.project,
            op["summary"],
            op["body"],
            _labels(cfg, item["artifact"], item["target_hash"]),
            cfg.issue_type,
        )
        item["key"] = key
        item["url"] = client.url(key)
        item["state"] = "open"
        return
    key = _ensure_key(client, cfg, item, op.get("key"))
    if action == "renew":
        client.comment(key, op["body"])
        if client.state(key) == "closed":
            client.reopen(key)
        item["state"] = "open"
        return
    if action == "expired":
        marker = EXPIRED_MARKER.format(expires=op["expires"])
        if any(marker in c for c in client.comments(key)):
            item["state"] = client.state(key)
            if item["state"] == "closed":
                client.reopen(key)
                item["state"] = "open"
            return
        client.comment(key, op["body"])
        if client.state(key) == "closed":
            client.reopen(key)
        item["state"] = "open"
        return
    if action == "resolved":
        if client.state(key) != "closed":
            client.comment(key, op["body"])
            client.close(key)
        item["state"] = "closed"
        return
    raise TicketError(f"unknown ticket operation {action!r}")  # pragma: no cover


def _flush(
    client: _Client | None, cfg: TicketsConfig, item: dict[str, Any], error: str | None
) -> bool:
    """Replay the item's pending operations in order. Returns True when none
    remain."""
    while item["pending"]:
        op = item["pending"][0]
        if client is None:
            item["error"] = error
            return False
        try:
            _apply(client, cfg, item, op)
        except TicketError as e:
            item["error"] = str(e)
            item["history"].append(
                {"at": _now(), "action": op["action"], "ok": False, "error": str(e)}
            )
            return False
        item["pending"].pop(0)
        item["error"] = None
        item["history"].append(
            {"at": _now(), "action": op["action"], "ok": True, "key": item["key"]}
        )
    return True


def _run(
    client: _Client | None,
    cfg: TicketsConfig,
    item: dict[str, Any],
    op: dict[str, Any],
    error: str | None,
) -> str | None:
    """Queue ``op`` behind whatever is pending for the item and try to run
    everything now. Returns the error message when the op is left pending."""
    op = {**op, "queued_at": _now()}
    item["pending"].append(op)
    _flush(client, cfg, item, error)
    item["updated_at"] = _now()
    return item["error"] if item["pending"] else None


def _connect(cfg: TicketsConfig) -> tuple[_Client | None, str | None]:
    try:
        return client_from_env(cfg), None
    except TicketError as e:
        return None, str(e)


# ---------------------------------------------------------------- hooks


def on_acceptance(
    root: Path,
    cfg: TicketsConfig | None,
    *,
    artifact: str,
    entry: dict[str, Any],
    ctx: RepoContext | None = None,
) -> dict[str, Any]:
    """After an override was recorded: create (or renew) its ticket and write
    the key back into the approval entry. Never raises."""
    if cfg is None:
        return {"ticket": None, "error": None}
    ctx = ctx or repo_context(root)
    target = (entry.get("finding") or {}).get("id") or (entry.get("finding") or {}).get(
        "criterion_id"
    )
    ledger = read_ledger(root)
    item = _get_item(
        ledger,
        artifact=artifact,
        target=str(target),
        kind="acceptance",
        approval_id=entry.get("id"),
        provider=cfg.provider,
    )
    client, error = _connect(cfg)
    summary, body = render_acceptance(artifact, entry, ctx)
    renewal = render_renewal(entry, ctx)
    if item.get("key") or entry.get("ticket"):
        op = {"action": "renew", "body": renewal, "key": entry.get("ticket")}
    else:
        op = {"action": "create", "summary": summary, "body": body, "renewal": renewal}
    left = _run(client, cfg, item, op, error)
    write_ledger(root, ledger)
    patch: dict[str, Any]
    if item.get("key"):
        patch = {"ticket": item["key"], "ticket_url": item.get("url")}
        if left:
            patch["ticket_error"] = left
        else:
            patch["ticket_error"] = None
    else:
        patch = {"ticket_error": left or "ticket not created"}
    sa.update_approval(root, artifact, entry["id"], patch, base_dir=AUDIT_DIR)
    if left:
        _warn(f"{left}; the record is saved, run `linebreak-gate tickets sync` to retry")
    return {"ticket": item.get("key"), "url": item.get("url"), "error": left}


def _open_tracked(
    client: _Client | None, cfg: TicketsConfig, ledger: dict[str, Any], artifact: str
) -> list[dict[str, Any]]:
    """Items with a ticket that is (as far as we know) open, for ``artifact``:
    the local ledger plus whatever the tracker lists under the artifact label
    (so a CI runner without the ledger still closes fixed risks)."""
    if client is not None:
        try:
            for found in client.find_by_label(cfg.project, f"{ARTIFACT_LABEL_PREFIX}{artifact}"):
                thash = next(
                    (
                        lb[len(LABEL_PREFIX) :]
                        for lb in found["labels"]
                        if lb.startswith(LABEL_PREFIX)
                    ),
                    None,
                )
                if not thash:
                    continue
                item = _get_item(
                    ledger,
                    artifact=artifact,
                    target=None,
                    thash=thash,
                    kind="tracked",
                    provider=cfg.provider,
                )
                item["key"] = found["key"]
                item["state"] = found["state"]
                item["url"] = client.url(found["key"])
        except TicketError as e:
            _warn(f"could not list open tickets for {artifact}: {e}")
    return [
        item
        for item in ledger["tickets"]
        if item.get("artifact") == artifact and item.get("key") and item.get("state") != "closed"
    ]


def on_scan(
    root: Path,
    cfg: TicketsConfig | None,
    *,
    current: dict[str, list[dict[str, Any]]],
    prior_ids: dict[str, set[str] | None],
    ctx: RepoContext | None = None,
) -> list[str]:
    """After a scan: close tickets of fixed findings, comment + reopen on
    expired acceptances, open attention tickets for findings that are new on
    the main branch. ``current`` maps artifact -> annotated findings (from the
    verdict) for the detectors that RAN this time; ``prior_ids`` maps artifact
    -> ids in the previously recorded artifact (None when there was none).
    Returns the messages printed. Never raises."""
    if cfg is None or not current:
        return []
    ctx = ctx or repo_context(root)
    ledger = read_ledger(root)
    client, error = _connect(cfg)
    messages: list[str] = []
    for artifact, findings in current.items():
        ids = {f["id"] for f in findings}
        hashes = {target_hash(i): i for i in ids}
        # Fixed: an open ticket whose target is no longer in the scan.
        for item in _open_tracked(client, cfg, ledger, artifact):
            if item["target_hash"] in hashes:
                continue
            target = item.get("target") or item["target_hash"]
            left = _run(
                client,
                cfg,
                item,
                {"action": "resolved", "body": render_resolved(target, artifact, ctx)},
                error,
            )
            messages.append(_report(left, f"closed {item['key']} (fixed: {target})"))
        # Expired acceptances: comment + reopen.
        for f in findings:
            acc = f.get("acceptance") or {}
            if f.get("status") != "expired_risk":
                continue
            item = _get_item(
                ledger,
                artifact=artifact,
                target=f["id"],
                kind="acceptance",
                approval_id=acc.get("approval_id"),
                provider=cfg.provider,
            )
            op = {
                "action": "expired",
                "expires": acc.get("expires"),
                "body": render_expired(acc, f["id"], ctx),
                "key": acc.get("ticket"),
            }
            left = _run(client, cfg, item, op, error)
            messages.append(
                _report(left, f"expired acceptance noted on {item.get('key')} ({f['id']})")
            )
        # New on main: findings at/above the floor that the previous record lacked.
        prior = prior_ids.get(artifact)
        if ctx.branch == cfg.main_branch and prior is not None:
            for f in findings:
                if f.get("status") not in ("blocking", "expired_risk") or f["id"] in prior:
                    continue
                if _find_item(ledger, artifact, target_hash(f["id"])) is not None:
                    continue
                item = _get_item(
                    ledger,
                    artifact=artifact,
                    target=f["id"],
                    kind="attention",
                    provider=cfg.provider,
                )
                summary, body = render_attention(artifact, f, ctx)
                left = _run(
                    client, cfg, item, {"action": "create", "summary": summary, "body": body}, error
                )
                messages.append(
                    _report(left, f"opened {item.get('key')} (new on {ctx.branch}: {f['id']})")
                )
    write_ledger(root, ledger)
    for m in messages:
        _warn(m)
    return messages


def on_check(
    root: Path,
    cfg: TicketsConfig | None,
    *,
    payload: dict[str, Any],
    overrides: list[dict[str, Any]],
    ctx: RepoContext | None = None,
) -> list[str]:
    """After a criteria check: comment + reopen on expired criterion
    exceptions; close the ticket of a criterion that passes on its own. The
    close only runs on a FULL check (scope ``all``): a scoped run has not
    evaluated the others. Never raises."""
    if cfg is None:
        return []
    ctx = ctx or repo_context(root)
    ledger = read_ledger(root)
    client, error = _connect(cfg)
    messages: list[str] = []
    for e in payload.get("expired_overrides") or []:
        item = _get_item(
            ledger, artifact="criteria", target=e["id"], kind="acceptance", provider=cfg.provider
        )
        op = {
            "action": "expired",
            "expires": e.get("expires"),
            "body": render_expired(e, e["id"], ctx),
            "key": e.get("ticket"),
        }
        left = _run(client, cfg, item, op, error)
        messages.append(_report(left, f"expired exception noted on {item.get('key')} ({e['id']})"))
    scope = payload.get("scope") or {}
    if scope.get("mode") == "all":
        passing = {r["id"] for r in payload.get("criteria") or [] if r.get("result") == "pass"}
        # Tickets we know about: the ledger, the tracker, and the committed
        # approval entries (their `ticket` key survives without a ledger).
        for entry in overrides:
            cid = (entry.get("finding") or {}).get("criterion_id")
            if cid and entry.get("ticket"):
                item = _get_item(
                    ledger,
                    artifact="criteria",
                    target=cid,
                    kind="acceptance",
                    provider=cfg.provider,
                )
                if not item.get("key"):
                    item["key"] = entry["ticket"]
                    item["state"] = "open"
        for item in _open_tracked(client, cfg, ledger, "criteria"):
            target = item.get("target")
            if target is None or target not in passing:
                continue
            left = _run(
                client,
                cfg,
                item,
                {"action": "resolved", "body": render_resolved(target, "criteria", ctx)},
                error,
            )
            messages.append(_report(left, f"closed {item['key']} (criterion passes: {target})"))
    write_ledger(root, ledger)
    for m in messages:
        _warn(m)
    return messages


def _report(left: str | None, done: str) -> str:
    return f"pending ({left}); run `linebreak-gate tickets sync` to retry" if left else done


def sync(root: Path, cfg: TicketsConfig | None) -> tuple[int, int, list[str]]:
    """Replay every pending ticket operation. Returns (completed, remaining,
    messages)."""
    if cfg is None:
        return 0, 0, ["tickets are not configured in .linebreak/gate.yml (no `tickets:` block)"]
    ledger = read_ledger(root)
    client, error = _connect(cfg)
    completed = remaining = 0
    messages: list[str] = []
    for item in ledger["tickets"]:
        before = len(item["pending"])
        if not before:
            continue
        _flush(client, cfg, item, error)
        after = len(item["pending"])
        completed += before - after
        remaining += after
        label = item.get("target") or item["target_hash"]
        if after:
            messages.append(f"{label}: {after} operation(s) still pending: {item.get('error')}")
        else:
            messages.append(f"{label}: synced to {item.get('key')}")
        if item.get("key") and item.get("approval_id") and item.get("artifact"):
            patch: dict[str, Any] = {"ticket": item["key"], "ticket_url": item.get("url")}
            patch["ticket_error"] = item.get("error") if after else None
            sa.update_approval(
                root, item["artifact"], item["approval_id"], patch, base_dir=AUDIT_DIR
            )
    write_ledger(root, ledger)
    return completed, remaining, messages
