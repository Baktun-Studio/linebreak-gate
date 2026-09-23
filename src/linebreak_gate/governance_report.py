"""``linebreak-gate report --from-governance``: the security summary of the
last run PUBLISHED to the governance service, readable outside CI.

The scan runs in CI and ``report`` alone only reads the scan recorded on this
machine (``.linebreak/audit/``). With ``--from-governance`` the report reads
what CI published instead, with the governance token (see
:mod:`governance_env` for where it comes from):

1. ``GET /v1/reports/projects/{id}?format=json`` lists the project's runs,
   newest first; the first one (of the requested ``--stage``, when given) is
   the last published run. ``--run-id`` skips this step.
2. ``GET /v1/projects/{id}/gate-runs/{run_id}`` returns that run as it was
   ingested: verdict, block reasons, findings with their acceptances,
   criteria.

Read only: nothing here writes to the service or to the repository. The
verdict shown is the one the run published; the report does not re-judge the
findings under today's ``gate.yml``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import quote

from . import governance_env

#: (url, token) -> (status, parsed body); the same shape the sign-off lookup uses.
Fetch = Callable[[str, str], tuple[int, Any]]

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
#: How many findings the summary lists one by one (all of them in JSON).
LISTED = 15


class GovernanceReportError(Exception):
    """The published run could not be read (no credentials, no project, the
    service refused or did not answer). The CLI prints it and exits 2."""


def _default_fetch(url: str, token: str) -> tuple[int, Any]:
    from .signoffs import _default_governance_fetch

    return _default_governance_fetch(url, token)


def _get(fetch: Fetch, url: str, token: str) -> Any:
    try:
        status, body = fetch(url, token)
    except Exception as e:  # noqa: BLE001 - any transport trouble is reported, never guessed
        raise GovernanceReportError(f"governance service unreachable ({url}): {e}") from e
    if status == 401:
        raise GovernanceReportError(f"the governance token was rejected (401) by {url}")
    if status == 403:
        raise GovernanceReportError(f"the governance token may not read {url} (403)")
    if status == 404:
        raise GovernanceReportError(f"not found (404): {url}")
    if status != 200:
        raise GovernanceReportError(f"governance service answered {status} to GET {url}")
    return body


def latest_run(
    base_url: str,
    token: str,
    project: str,
    *,
    stage: str | None = None,
    fetch: Fetch | None = None,
) -> dict[str, Any] | None:
    """The newest run listed for the project (optionally of one stage), as the
    project report lists it; ``None`` when nothing was published."""
    fetch = fetch or _default_fetch
    url = f"{base_url}/v1/reports/projects/{quote(project, safe='')}?format=json"
    body = _get(fetch, url, token)
    runs = body.get("runs") if isinstance(body, dict) else None
    if not isinstance(runs, list):
        raise GovernanceReportError(f"unexpected body from {url} (no runs list)")
    runs = [r for r in runs if isinstance(r, dict) and r.get("run_id")]
    if stage:
        runs = [r for r in runs if r.get("stage") == stage]
    if not runs:
        return None
    # The service already orders by date; sorting again keeps this true even
    # for an older service that did not.
    return max(runs, key=lambda r: str(r.get("at") or ""))


def load_run(
    base_url: str, token: str, project: str, run_id: str, *, fetch: Fetch | None = None
) -> dict[str, Any]:
    fetch = fetch or _default_fetch
    url = f"{base_url}/v1/projects/{quote(project, safe='')}/gate-runs/{quote(run_id, safe='')}"
    body = _get(fetch, url, token)
    if not isinstance(body, dict) or not body.get("run_id"):
        raise GovernanceReportError(f"unexpected body from {url} (no run)")
    return body


def fetch_report(
    creds: governance_env.Credentials,
    *,
    project: str | None = None,
    run_id: str | None = None,
    stage: str | None = None,
    fetch: Fetch | None = None,
) -> dict[str, Any] | None:
    """The report payload for the last published run (or ``run_id``), or
    ``None`` when the project has no published run. Raises
    :class:`GovernanceReportError` on anything that stops the read."""
    if not creds.base_url or not creds.token:
        raise GovernanceReportError(
            "no governance credentials: set LINEBREAK_GOVERNANCE_BASE_URL and "
            "LINEBREAK_GOVERNANCE_TOKEN, or write them to ~/.config/linebreak/governance.env"
        )
    project = (project or creds.project or "").strip()
    if not project:
        raise GovernanceReportError(
            "no project id: pass --project or set LINEBREAK_GOV_PROJECT "
            "(the project id the pipeline publishes to)"
        )
    if not run_id:
        listed = latest_run(creds.base_url, creds.token, project, stage=stage, fetch=fetch)
        if listed is None:
            return None
        run_id = str(listed["run_id"])
    run = load_run(creds.base_url, creds.token, project, run_id, fetch=fetch)
    return {
        "source": "governance",
        "base_url": creds.base_url,
        "credentials": governance_env.describe_source(creds),
        "project": project,
        "run": run,
        "summary": summarize(run),
    }


def _severity(value: Any) -> str:
    sev = str(value or "").strip().lower()
    return sev if sev in SEVERITIES else "unknown"


def summarize(run: dict[str, Any]) -> dict[str, Any]:
    findings = [f for f in run.get("findings") or [] if isinstance(f, dict)]
    counts = dict.fromkeys(SEVERITIES, 0)
    for f in findings:
        counts[_severity(f.get("severity"))] += 1
    criteria: dict[str, int] = {}
    for c in run.get("criteria") or []:
        if isinstance(c, dict):
            key = str(c.get("result") or "pending")
            criteria[key] = criteria.get(key, 0) + 1
    return {
        "verdict": run.get("verdict"),
        "block_reasons": list(run.get("block_reasons") or []),
        "findings": {
            "total": len(findings),
            **counts,
            "accepted": sum(1 for f in findings if f.get("accepted")),
            "kev": sum(1 for f in findings if f.get("kev")),
        },
        "criteria": criteria,
    }


def _order(f: dict[str, Any]) -> tuple[int, int, float]:
    return (
        SEVERITIES.index(_severity(f.get("severity"))),
        0 if f.get("kev") else 1,
        -(f.get("cvss") or 0.0),
    )


def render(report: dict[str, Any]) -> list[str]:
    """The human summary, one line per entry."""
    run = report["run"]
    s = report["summary"]
    f = s["findings"]
    commit = str(run.get("commit") or "?")[:12]
    lines = [
        f"LineBreak security summary from the governance service ({report['base_url']}), "
        f"project {run.get('project') or report['project']}",
        f"  run {run.get('run_id')} · stage {run.get('stage')} · {run.get('at')} · "
        f"commit {commit} · repo {run.get('repo')}",
        f"  read with credentials from {report['credentials']} (read only)",
        f"Findings: {f['total']}: {f['critical']} critical, {f['high']} high, "
        f"{f['medium']} medium, {f['low']} low, {f['unknown']} unknown "
        f"({f['accepted']} accepted, {f['kev']} KEV)",
    ]
    findings = sorted((x for x in run.get("findings") or [] if isinstance(x, dict)), key=_order)
    for x in findings[:LISTED]:
        where = x.get("package") or ""
        if x.get("version"):
            where += f"@{x['version']}"
        fixed = f" (fixed in {x['fixed_in']})" if x.get("fixed_in") else ""
        kev = " KEV" if x.get("kev") else ""
        acc = x.get("accepted")
        accepted = ""
        if isinstance(acc, dict):
            until = f" until {str(acc['expires'])[:10]}" if acc.get("expires") else ""
            accepted = f" · accepted by {acc.get('by')}{until}"
        lines.append(
            f"  [{_severity(x.get('severity'))}{kev}] {x.get('id')} {where}{fixed}{accepted}".rstrip()
        )
    if len(findings) > LISTED:
        lines.append(f"  ... and {len(findings) - LISTED} more (--format json lists them all)")
    if s["criteria"]:
        crit = ", ".join(f"{v} {k}" for k, v in sorted(s["criteria"].items()))
        lines.append(f"Criteria: {crit}")
    verdict = str(s["verdict"] or "?").upper()
    reasons = f" (reasons: {', '.join(s['block_reasons'])})" if s["block_reasons"] else ""
    lines.append(f"VERDICT (as published by that run): {verdict}{reasons}")
    return lines
