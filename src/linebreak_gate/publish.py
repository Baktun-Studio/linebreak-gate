"""``linebreak-gate publish``: send the recorded gate run to a governance
service (the executive/audit panel).

Builds the panel's ingest body from what the gate already wrote under
``.linebreak/audit/`` (``criteria.json``, ``security.json``, ``code.json``)
plus the sign-off records and the spec manifest, and POSTs it to
``{url}/v1/projects/{project_id}/gate-runs`` with the bearer in
``LINEBREAK_GOV_TOKEN``.

Publishing NEVER blocks a change: every failure (no records, no token,
unreachable service, 4xx/5xx) prints a warning and exits 0. The gate's
verdict was already given by ``scan``/``check``; this only reports it.
Stdlib transport (urllib), injectable for tests.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import roles as _roles
from . import security_artifact as sa
from . import signoffs, spec_bundle
from .gate_config import GateConfigError, resolve_config
from .verdict import evaluate

AUDIT_DIR = str(Path(".linebreak") / "audit")
_TIMEOUT_S = 15

#: (url, json_body, headers) -> (status, body_text)
Transport = Callable[[str, dict[str, Any], dict[str, str]], tuple[int, str]]


class PublishError(Exception):
    """Anything that stops a publish. The CLI prints it and exits 0."""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], cwd=root, capture_output=True, text=True, timeout=10, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = out.stdout.strip()
    return value if out.returncode == 0 and value else None


def _repo_from_remote(remote: str | None) -> str | None:
    if not remote:
        return None
    tail = remote.rstrip("/")
    if tail.endswith(".git"):
        tail = tail[:-4]
    parts = tail.replace(":", "/").split("/")
    return "/".join(parts[-2:]) if len(parts) >= 2 else None


def _context(root: Path, env: dict[str, str]) -> dict[str, str]:
    repo = env.get("GITHUB_REPOSITORY") or _repo_from_remote(
        _git(root, "config", "--get", "remote.origin.url")
    )
    ref = env.get("GITHUB_REF") or _git(root, "symbolic-ref", "-q", "HEAD")
    commit = env.get("GITHUB_SHA") or _git(root, "rev-parse", "HEAD")
    return {"repo": repo or "unknown", "ref": ref or "unknown", "commit": commit or "unknown"}


def _run_id(env: dict[str, str], explicit: str | None, repo: str, stage: str) -> str:
    """Deterministic under GitHub Actions (same job + attempt => same id, so a
    re-run of the publish step is idempotent server-side); random otherwise."""
    if explicit:
        return explicit
    if env.get("LINEBREAK_RUN_ID"):
        return env["LINEBREAK_RUN_ID"]
    gh_run = env.get("GITHUB_RUN_ID")
    if gh_run:
        attempt = env.get("GITHUB_RUN_ATTEMPT", "1")
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"{repo}/{gh_run}/{attempt}/{stage}"))
    return str(uuid.uuid4())


_CRITERION_RESULT = {
    "pass": "pass",
    "overridden": "pass",
    "fail": "fail",
    "error": "fail",
    "needs-signoff": "pending",
    "release-only": "pending",
    # Not evaluated in the prepare phase: its sign-off attests this run.
    "awaiting-attestation": "pending",
    # Failed while a shared resource was in use, passed alone (#262).
    "collision": "pass",
}


def _criterion_hashes(bundle: dict[str, Any] | None) -> dict[str, str]:
    """``criterion id -> content hash`` for every criterion in the approved
    bundle: the panel binds a sign-off made from the web to this hash, exactly
    as a repository sign-off does."""
    if not bundle:
        return {}
    return {
        str(c["id"]): spec_bundle.criterion_hash(c)
        for story in bundle.get("stories") or []
        for c in story.get("criteria") or []
        if isinstance(c, dict) and c.get("id")
    }


def _criteria(
    doc: dict[str, Any], hashes: dict[str, str] | None = None
) -> tuple[list[dict[str, Any]], set[str]]:
    out: list[dict[str, Any]] = []
    reasons: set[str] = set()
    hashes = hashes or {}
    for f in doc.get("findings") or []:
        if not isinstance(f, dict) or not f.get("id"):
            continue
        check = f.get("check") if isinstance(f.get("check"), dict) else {}
        ctype = str(check.get("type") or "command")
        if ctype not in ("tests", "command", "build", "manual"):
            ctype = "command"
        result = str(f.get("result") or "")
        mapped = _CRITERION_RESULT.get(result, "pending")
        if result == "needs-signoff":
            reasons.add("unsigned_manual")
        elif result in ("fail", "error"):
            reasons.add("tests_failed" if ctype == "tests" else "command_failed")
        cid = str(f["id"])
        detail = str(f.get("detail") or "")
        env = f.get("environment") if isinstance(f.get("environment"), dict) else None
        if env:
            # The service keeps the detail text; the measured version travels
            # at its head so the panel shows what the verdict measured (#264).
            detail = f"{_environment_note(env)}\n{detail}".strip()
        item: dict[str, Any] = {
            "id": cid,
            "story": f.get("story"),
            "type": ctype,
            "result": mapped,
            "detail": detail[:2000],
            # Statement and content hash: what a person signs from the
            # panel, and what the gate later matches the signature against.
            "statement": str(f.get("statement") or "")[:2000] or None,
            "hash": hashes.get(cid),
        }
        if env:
            item["environment"] = env
        out.append(item)
    return out, reasons


def _environment_note(env: dict[str, Any]) -> str:
    """``[measured staging at abc1234: behind]``: one line, first in the detail."""
    version = env.get("version") or "unknown version"
    return f"[measured {env.get('name') or 'environment'} at {version}: {env.get('status')}]"


def _overrides(doc: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in doc.get("approvals") or []:
        if not isinstance(entry, dict) or entry.get("decision") != "override":
            continue
        finding = entry.get("finding") if isinstance(entry.get("finding"), dict) else {}
        target = finding.get("criterion_id")
        if not target:
            continue
        out.append(
            {
                "target": str(target),
                "by": str(entry.get("user_email") or "unknown"),
                "role": entry.get("role"),
                "at": entry.get("at") or _now_iso(),
                "expires": entry.get("expires"),
                "reason": entry.get("notes"),
                "ticket": entry.get("ticket"),
            }
        )
    return out


def _acceptances_by_id(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in doc.get("approvals") or []:
        if not isinstance(entry, dict) or entry.get("decision") != "override":
            continue
        finding = entry.get("finding") if isinstance(entry.get("finding"), dict) else {}
        fid = finding.get("id")
        if not fid or finding.get("criterion_id"):
            continue
        out[str(fid)] = {
            "by": str(entry.get("user_email") or "unknown"),
            "role": entry.get("role"),
            "at": entry.get("at"),
            "expires": entry.get("expires"),
            "ticket": entry.get("ticket"),
        }
    return out


def _findings(
    doc: dict[str, Any], detector: str, fail_on: str
) -> tuple[list[dict[str, Any]], set[str]]:
    accepted = _acceptances_by_id(doc)
    verdict = evaluate(
        doc.get("findings") or [], fail_on=fail_on, override_ids=set(accepted), detector=detector
    )
    reasons: set[str] = set()
    out: list[dict[str, Any]] = []
    for f in verdict["findings"]:
        fid = str(f.get("id"))
        item = {
            "id": str(f.get("cve_id") or f.get("title") or fid),
            "severity": f.get("severity"),
            "cvss": f.get("cvss"),
            "epss": f.get("epss"),
            "kev": bool(f.get("kev")),
            "package": f.get("package") or f.get("file"),
            "version": f.get("installed_version") or (str(f["line"]) if f.get("line") else None),
            "fixed_in": f.get("fixed_version"),
        }
        if fid in accepted:
            item["accepted"] = accepted[fid]
        if f.get("status") == "blocking":
            reasons.add("vulnerability")
            if f.get("kev"):
                reasons.add("kev")
        out.append(item)
    return out, reasons


def _signoffs(root: Path) -> list[dict[str, Any]]:
    out = []
    for rec in signoffs.load_signoffs(root):
        out.append(
            {
                "criterion_id": str(rec.get("criterion_id")),
                "by": str(rec.get("approver") or "unknown"),
                "role": "approver",
                "identity_source": rec.get("identity_source") or "client",
                "at": rec.get("signed_at") or _now_iso(),
            }
        )
    return out


def _bundle(root: Path) -> dict[str, Any] | None:
    try:
        return spec_bundle.load_bundle(root)
    except spec_bundle.SpecBundleError as e:
        raise PublishError(f"malformed spec bundle: {e}") from e


def _attestation(bundle: dict[str, Any] | None, commit: str) -> dict[str, Any]:
    envelope = (bundle or {}).get("manifest", {}).get("signed_approval")
    if not isinstance(envelope, dict):
        return {"present": False, "commit": None, "signed_by": None, "at": None}
    return {
        "present": True,
        "commit": commit,
        "signed_by": envelope.get("approver_email"),
        "at": envelope.get("approved_at"),
    }


def _spec(bundle: dict[str, Any] | None) -> dict[str, Any] | None:
    """The specification behind this run, as the panel's project list shows
    it: the bundle hash and, when the manifest carries a signed approval, who
    signed, when, with which key and whether it was a self-approval. None
    when the repository has no approved bundle."""
    if not bundle:
        return None
    envelope = bundle.get("manifest", {}).get("signed_approval")
    signed = isinstance(envelope, dict)
    return {
        "hash": spec_bundle.bundle_hash(bundle),
        "signed": signed,
        "signed_by": envelope.get("approver_email") if signed else None,
        "at": envelope.get("approved_at") if signed else None,
        "kid": envelope.get("kid") if signed else None,
        "self_approved": bool(envelope.get("self_approved")) if signed else False,
        "stories": len(bundle.get("stories") or []),
    }


def _roles_summary(root: Path) -> dict[str, Any]:
    """``.linebreak/roles.yml`` summarized for the panel: who may sign what,
    so a sign-off made from the web is checked against the same roster the
    gate enforces. Absent file: ``source: absent`` and no roles."""
    try:
        policy = _roles.load_roles(root)
    except _roles.RolesConfigError as e:
        raise PublishError(f"invalid roles file: {e}") from e
    return {
        "source": policy.source,
        "require_roles": policy.require_roles,
        "require_verified_identity": policy.require_verified_identity,
        "roles": [
            {
                "name": r.name,
                "members": list(r.members),
                "sign_criteria": list(r.sign_criteria),
                "approve_overrides": list(r.approve_overrides),
                "accept_security_risk": list(r.accept_security_risk),
            }
            for r in policy.roles
        ],
    }


def _expired(records: list[dict[str, Any]], now: str) -> bool:
    """Same rule as risk_acceptance: an acceptance is valid through its
    ``expires`` day (YYYY-MM-DD) and expired the day after, so the panel and
    the gate never disagree by one day."""
    for r in records:
        exp = r.get("expires") or (r.get("accepted") or {}).get("expires")
        if isinstance(exp, str) and exp and exp[:10] < now[:10]:
            return True
    return False


def build_payload(
    project_root: Path | str,
    *,
    run_id: str | None = None,
    stage: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """The panel's ingest body, derived from the recorded gate run. Raises
    PublishError when there is nothing to publish or a record is unreadable."""
    root = Path(project_root)
    env = dict(os.environ if env is None else env)
    criteria_doc = sa.read_artifact(root, "criteria", base_dir=AUDIT_DIR)
    security_doc = sa.read_artifact(root, "security", base_dir=AUDIT_DIR)
    code_doc = sa.read_artifact(root, "code", base_dir=AUDIT_DIR)
    if not any(d.get("kind") for d in (criteria_doc, security_doc, code_doc)):
        raise PublishError(
            f"nothing to publish: no records under {AUDIT_DIR}/ (run `scan` or `check` first)"
        )
    try:
        fail_on = resolve_config(root).fail_on
    except GateConfigError as e:
        raise PublishError(f"invalid gate config: {e}") from e

    bundle = _bundle(root)
    reasons: set[str] = set()
    criteria, r = _criteria(criteria_doc, _criterion_hashes(bundle))
    reasons |= r
    findings: list[dict[str, Any]] = []
    for doc, detector in ((security_doc, "dep"), (code_doc, "code")):
        if doc.get("kind"):
            items, r = _findings(doc, detector, fail_on)
            findings.extend(items)
            reasons |= r
    overrides = _overrides(criteria_doc)
    now = _now_iso()
    if _expired(overrides, now) or _expired(findings, now):
        reasons.add("expired_risk")

    context = _context(root, env)
    scope = criteria_doc.get("scope") if isinstance(criteria_doc.get("scope"), dict) else {}
    stage = stage or (scope.get("stage") if scope.get("stage") in ("pr", "release") else "release")
    return {
        "run_id": _run_id(env, run_id, context["repo"], stage),
        "at": now,
        "repo": context["repo"],
        "ref": context["ref"],
        "commit": context["commit"],
        "stage": stage,
        "verdict": "blocked" if reasons else "pass",
        "block_reasons": sorted(reasons),
        "criteria": criteria,
        "findings": findings,
        "signoffs": _signoffs(root),
        "overrides": overrides,
        "attestation": _attestation(bundle, context["commit"]),
        # Panel de gobierno (sep 2026): la especificación firmada y el roster
        # de roles viajan con cada corrida. Una ingesta sin ellos sigue valiendo.
        "spec": _spec(bundle),
        "roles": _roles_summary(root),
    }


def _default_transport(url: str, body: dict[str, Any], headers: dict[str, str]) -> tuple[int, str]:
    data = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_S) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def send(
    payload: dict[str, Any],
    *,
    url: str,
    project_id: str,
    token: str,
    transport: Transport | None = None,
) -> None:
    """POST the body. Raises PublishError on any non-2xx or transport failure."""
    from linebreak_gate import __version__

    endpoint = f"{url.rstrip('/')}/v1/projects/{project_id}/gate-runs"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": f"linebreak-gate/{__version__}",
    }
    try:
        status, body = (transport or _default_transport)(endpoint, payload, headers)
    except Exception as e:  # noqa: BLE001 - any transport trouble is a warning, never a block
        raise PublishError(f"could not reach {endpoint}: {e}") from e
    if status not in (200, 201):
        raise PublishError(f"{endpoint} answered {status}: {body[:300]}")
