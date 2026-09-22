"""CI-gate verdict: which findings block at the configured floor, and which
are acknowledged by a recorded human override.

Severity ranking mirrors the desktop gate's verdict policy
(``packages/bmad-pipeline-core/lib/security-artifact.js``): a finding ranks by
its declared severity string, falling back to a CVSS band (>=9 critical, >=7
high, >=4 medium, >0 low) so a cvss-only finding never ranks 0 (fail open).

Override semantics differ from the in-app gate BY DESIGN: in-app, one audited
override clears the whole combined verdict; at the CI boundary an override is
scoped to ONE exact finding tuple (package + installed version + CVE, or the
code finding's identity) — a different CVE, a bumped version, or a new finding
still blocks. The gate never auto-clears on an agent's say-so: override records
require a human reason + approver (enforced in the CLI).
"""

from __future__ import annotations

import hashlib
from typing import Any

from .security_scan import _parse_cvss, _severity_from_cvss

SEVERITY_RANK = {
    "none": 0,
    "info": 0,
    "informational": 0,
    "low": 1,
    "moderate": 2,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
FLOOR_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def finding_rank(finding: dict[str, Any]) -> int:
    """Ordinal severity of one finding — severity string first, CVSS band as
    the fallback, 0 (never blocks) only when neither says anything."""
    if not isinstance(finding, dict):
        return 0
    sev = finding.get("severity")
    if isinstance(sev, str) and sev.strip().lower() in SEVERITY_RANK:
        rank = SEVERITY_RANK[sev.strip().lower()]
        if rank > 0:
            return rank
    band = _severity_from_cvss(_parse_cvss(finding.get("cvss")))
    return SEVERITY_RANK.get(band, 0)


def finding_id(finding: dict[str, Any], detector: str = "dep") -> str:
    """Stable identifier an override is scoped to.

    Dependency findings: the exact package + installed version + CVE tuple
    (advisory URL / title stand in when the advisory has no CVE id — same
    identity the scanner's dedupe uses). Code findings: a digest of the
    finding's file/line/title/category identity.
    """
    if detector == "code":
        key = "|".join(str(finding.get(k)) for k in ("file", "line", "title", "category"))
        return "code:" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]
    advisory = finding.get("cve_id") or finding.get("advisory_url") or finding.get("title")
    package = finding.get("package") or "unknown"
    version = finding.get("installed_version") or "?"
    return f"dep:{package}@{version}:{advisory or 'unknown'}"


def evaluate(
    findings: list[dict[str, Any]],
    *,
    fail_on: str,
    override_ids: set[str],
    detector: str = "dep",
) -> dict[str, Any]:
    """Classify ``findings`` against the floor and the recorded overrides.

    Returns ``{"passes", "findings", "blocking", "acknowledged"}`` where
    ``findings`` is the input annotated once with ``id`` (the override tuple)
    and ``status`` (``blocking`` | ``acknowledged`` | ``below_floor``);
    ``blocking``/``acknowledged`` are views of the same annotated dicts, so the
    classification the gate enforces and the one reports render can never
    diverge. An acknowledged finding is one whose exact tuple id appears in
    ``override_ids`` (recorded human overrides).
    """
    floor = FLOOR_RANK[fail_on]
    annotated: list[dict[str, Any]] = []
    blocking: list[dict[str, Any]] = []
    acknowledged: list[dict[str, Any]] = []
    for f in findings or []:
        fid = finding_id(f, detector=detector)
        if finding_rank(f) < floor:
            status = "below_floor"
        elif fid in override_ids:
            status = "acknowledged"
        else:
            status = "blocking"
        item = {**f, "id": fid, "status": status}
        annotated.append(item)
        if status == "blocking":
            blocking.append(item)
        elif status == "acknowledged":
            acknowledged.append(item)
    return {
        "passes": not blocking,
        "findings": annotated,
        "blocking": blocking,
        "acknowledged": acknowledged,
    }
