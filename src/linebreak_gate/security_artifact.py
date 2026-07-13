"""Versioned ``_bmad-output/security/<name>.json`` security artifact.

The shared CVE "intelligence currency" for both workflows (E0.4):

* **Construction** writes a ``cve_scan`` — dependency findings + a composite
  risk score — at a gate (e.g. the architecture phase) so the result becomes a
  governed, git-committed artifact instead of a transient chat answer.
* **Construction** also writes a ``code_scan`` (A4) — first-party SAST findings
  (injection / auth / secret-exposure / crypto) discovered in the code the agent
  wrote, in the same finding envelope. The gate reads both; one override clears
  the combined verdict.
* **Investigation** (later, WF2) writes a ``remediation`` — the advisor-shaped
  plan (target / version / environment / owner / steps / rollback / backups /
  SLA) that the construction workflow consumes as intake.

Both kinds carry an **approval trail** (including the documented-justification
``override`` on a blocking gate — the override is itself evidence).

Mirrors the atomic-write / best-effort-read discipline of ``tracker_sync.py``
and ``packages/bmad-pipeline-core/lib/approvals-artifact.js``: readers treat
absence and corruption uniformly (empty doc), writers stamp ``version`` +
``generated_at`` and preserve unknown top-level keys for forward compatibility.

Schema (v1)::

    {
      "version": 1,
      "kind": "cve_scan" | "remediation",
      "id": "architecture",                 # producing phase / logical id
      "generated_at": "2026-06-01T...Z",
      "summary": "2 high-severity findings",
      "findings": [ {"cve_id","severity","cvss","epss","kev","package",
                     "ecosystem","installed_version","fixed_version",
                     "advisory_url"} ],
      "risk_score": 0-100 | null,
      "remediation": { ...remediation_block()... } | null,
      "approvals": [ {"id","role","user_email","decision","notes","at"} ]
    }
"""

from __future__ import annotations

import copy
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
KINDS = ("cve_scan", "code_scan", "remediation")
DECISIONS = ("approved", "rejected", "override")

_SECURITY_DIR = Path("_bmad-output") / "security"
# A safe single-segment slug: never lets ``name`` escape security/ via ``..``,
# ``/``, or an absolute path (which would turn read/write into a path-traversal
# primitive on the security-evidence directory).
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def artifact_path(
    project_root: Path | str, name: str, *, base_dir: Path | str = _SECURITY_DIR
) -> Path:
    """Path of the ``<name>.json`` artifact under ``base_dir``.

    ``base_dir`` defaults to the desktop's ``_bmad-output/security``; the CI
    gate passes ``.linebreak/audit`` so its records live with the repo's gate
    config while sharing the exact same document format."""
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ValueError(f"invalid security-artifact name {name!r} (expected a safe slug)")
    return Path(project_root) / base_dir / f"{name}.json"


def _empty_doc() -> dict[str, Any]:
    return {
        "version": SCHEMA_VERSION,
        "kind": None,
        "id": None,
        "summary": None,
        "findings": [],
        "risk_score": None,
        "remediation": None,
        "approvals": [],
    }


def new_artifact(
    kind: str,
    *,
    id: str,
    findings: list[dict[str, Any]] | None = None,
    risk_score: int | float | None = None,
    summary: str | None = None,
    remediation: dict[str, Any] | None = None,
    scanner: str | None = None,
) -> dict[str, Any]:
    """Build a normalized (not-yet-persisted) security artifact document.

    ``scanner`` records which engine produced the findings (e.g. ``osv-scanner``,
    ``npm audit``, ``claude-code-scan``) so a verdict is directly auditable rather
    than only inferable from the findings' shape."""
    if kind not in KINDS:
        raise ValueError(f"unknown security-artifact kind {kind!r}; expected one of {KINDS}")
    return {
        "version": SCHEMA_VERSION,
        "kind": kind,
        "id": id,
        "summary": summary,
        "scanner": scanner,
        "findings": list(findings or []),
        "risk_score": risk_score,
        "remediation": remediation,
        "approvals": [],
    }


def remediation_block(
    *,
    target: str,
    version: str | None = None,
    environment: str | None = None,
    department: str | None = None,
    owner: str | None = None,
    priority: str | None = None,
    sla: str | None = None,
    steps: list[str] | None = None,
    validation: str | None = None,
    rollback: str | None = None,
    backups: str | None = None,
) -> dict[str, Any]:
    """The advisor-confirmed remediation plan shape (§7.Q1): a direct, concise
    plan with an owner, a risk-based SLA, and an explicit rollback + backups."""
    return {
        "target": target,
        "version": version,
        "environment": environment,
        "department": department,
        "owner": owner,
        "priority": priority,
        "sla": sla,
        "steps": list(steps or []),
        "validation": validation,
        "rollback": rollback,
        "backups": backups,
    }


def read_artifact(
    project_root: Path | str, name: str, *, base_dir: Path | str = _SECURITY_DIR
) -> dict[str, Any]:
    """Read the artifact. Returns an empty document on any failure (missing
    file, malformed JSON, wrong shape) so callers treat absence and corruption
    uniformly."""
    file = artifact_path(project_root, name, base_dir=base_dir)
    if not file.exists():
        return _empty_doc()
    try:
        text = file.read_text(encoding="utf-8")
    except OSError:
        return _empty_doc()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return _empty_doc()
    if (
        not isinstance(parsed, dict)
        or not isinstance(parsed.get("findings"), list)
        or not isinstance(parsed.get("approvals"), list)
    ):
        return _empty_doc()
    return parsed


def write_artifact(
    project_root: Path | str,
    name: str,
    doc: dict[str, Any],
    *,
    base_dir: Path | str = _SECURITY_DIR,
) -> dict[str, Any]:
    """Atomically (re)write the artifact, stamping ``version`` +
    ``generated_at``. Returns a detached deep copy of the written document. The
    file carries no secrets — it is committed to the project repo alongside the
    other ``_bmad-output`` artifacts."""
    if doc.get("kind") not in KINDS:
        raise ValueError(f"security artifact needs a valid kind {KINDS}, got {doc.get('kind')!r}")
    doc = copy.deepcopy(doc)
    doc["version"] = SCHEMA_VERSION
    doc["generated_at"] = datetime.now(UTC).isoformat()
    if not isinstance(doc.get("findings"), list):
        doc["findings"] = []
    if not isinstance(doc.get("approvals"), list):
        doc["approvals"] = []

    file = artifact_path(project_root, name, base_dir=base_dir)
    file.parent.mkdir(parents=True, exist_ok=True)
    tmp = file.with_name(f"{file.name}.tmp.{os.getpid()}.{int(time.time() * 1000)}")
    try:
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, file)
    except BaseException:
        # Don't leave a partial/orphaned tmp behind (these files get committed).
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return doc


def append_approval(
    project_root: Path | str,
    name: str,
    *,
    approval_id: str,
    role: str,
    decision: str,
    user_email: str | None = None,
    notes: str | None = None,
    finding: dict[str, Any] | None = None,
    base_dir: Path | str = _SECURITY_DIR,
) -> dict[str, Any]:
    """Append an approval-trail entry and atomically rewrite the artifact.

    Idempotent by ``approval_id``: a reused id is a no-op (the first recorded
    decision for an id wins), so a peer re-import or retried request never
    duplicates the trail. ``decision`` is one of ``approved`` / ``rejected`` /
    ``override``. The artifact must already exist with a valid ``kind`` — an
    approval is evidence *about* a scan/remediation, so we refuse to fabricate a
    kindless evidence document.

    ``finding`` (optional) scopes the entry to one exact finding tuple — the CI
    gate records ``{id, package, installed_version, cve_id, ...}`` so an
    override acknowledges only that package+version+CVE, never the whole scan.
    Existing (desktop) call sites omit it and the entry shape is unchanged.
    """
    if decision not in DECISIONS:
        raise ValueError(f"unknown decision {decision!r}; expected one of {DECISIONS}")
    doc = read_artifact(project_root, name, base_dir=base_dir)
    if doc.get("kind") not in KINDS:
        raise ValueError(
            f"cannot record approval against {name!r}: no security artifact yet "
            "(write a cve_scan/remediation first)"
        )
    approvals = doc.get("approvals")
    if not isinstance(approvals, list):
        approvals = []
    if any(isinstance(a, dict) and a.get("id") == approval_id for a in approvals):
        return doc
    entry: dict[str, Any] = {
        "id": approval_id,
        "role": role,
        "user_email": user_email,
        "decision": decision,
        "notes": notes,
        "at": datetime.now(UTC).isoformat(),
    }
    if finding is not None:
        entry["finding"] = finding
    approvals.append(entry)
    doc["approvals"] = approvals
    return write_artifact(project_root, name, doc, base_dir=base_dir)
