"""CI-gate verdict: which findings block at the configured floor, and which
are acknowledged by a recorded human override.

Severity ranking mirrors the desktop gate's verdict policy
(``packages/bmad-pipeline-core/lib/security-artifact.js``): a finding ranks by
its declared severity string, falling back to a CVSS band (>=9 critical, >=7
high, >=4 medium, >0 low) so a cvss-only finding never ranks 0 (fail open).

Exploitation policy (banking clients' ask): besides the severity floor, a
finding blocks when it is in CISA's KEV catalog (``block_kev``) or when its
EPSS probability reaches ``epss_threshold``. The block reason is recorded per
finding and aggregated as ``block_reasons`` with exactly two values the
governance service reads: ``kev`` (in the catalog) and ``vulnerability``
(severity floor or EPSS threshold). KEV wins when both apply.

Override semantics differ from the in-app gate BY DESIGN: in-app, one audited
override clears the whole combined verdict; at the CI boundary an override is
scoped to ONE exact finding tuple (package + installed version + CVE, or the
code finding's identity): a different CVE, a bumped version, or a new finding
still blocks. The gate never auto-clears on an agent's say-so: override records
require a human reason + approver (enforced in the CLI).
"""

from __future__ import annotations

import hashlib
from typing import Any

from .exploit_intel import exploitation_label
from .security_scan import _epss_value, _parse_cvss, _severity_from_cvss, finding_risk

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

#: The only block reasons a finding can carry. Order = display/aggregation
#: order (the actively exploited one first).
BLOCK_REASON_KEV = "kev"
BLOCK_REASON_VULNERABILITY = "vulnerability"
BLOCK_REASONS = (BLOCK_REASON_KEV, BLOCK_REASON_VULNERABILITY)


def finding_rank(finding: dict[str, Any]) -> int:
    """Ordinal severity of one finding: severity string first, CVSS band as
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


def priority_key(finding: dict[str, Any]) -> tuple[int, float, int, float]:
    """Sort key (descending) for reports and the verdict: KEV first, then by
    EPSS, then by severity/CVSS. A finding with no EPSS score sorts after the
    scored ones (so an unscored id never outranks a known probability); when
    nothing in the scan has exploitation data the order is plain severity."""
    if not isinstance(finding, dict):
        return (0, -1.0, 0, 0.0)
    epss = _epss_value(finding)
    return (
        1 if finding.get("kev") is True else 0,
        epss if epss is not None else -1.0,
        finding_rank(finding),
        _parse_cvss(finding.get("cvss")) or 0.0,
    )


def sort_by_priority(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stable descending sort by :func:`priority_key` (ties keep scan order)."""
    return sorted(findings, key=priority_key, reverse=True)


def finding_id(finding: dict[str, Any], detector: str = "dep") -> str:
    """Stable identifier an override is scoped to.

    Dependency findings: the exact package + installed version + CVE tuple
    (advisory URL / title stand in when the advisory has no CVE id: same
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


def block_triggers(
    finding: dict[str, Any],
    *,
    floor: int,
    block_kev: bool,
    epss_threshold: float | None,
) -> list[str]:
    """Which policies this finding trips: ``severity`` (at/above the floor),
    ``kev`` (in the catalog, with ``block_kev``), ``epss`` (probability at or
    above ``epss_threshold``). Empty = does not block."""
    triggers: list[str] = []
    if block_kev and finding.get("kev") is True:
        triggers.append("kev")
    if finding_rank(finding) >= floor:
        triggers.append("severity")
    epss = _epss_value(finding)
    if epss_threshold is not None and epss is not None and epss >= epss_threshold:
        triggers.append("epss")
    return triggers


def block_reason_for(triggers: list[str]) -> str | None:
    """Collapse triggers to the one reason the governance contract carries:
    ``kev`` when the catalog fired, else ``vulnerability``, else None."""
    if not triggers:
        return None
    return BLOCK_REASON_KEV if "kev" in triggers else BLOCK_REASON_VULNERABILITY


def evaluate(
    findings: list[dict[str, Any]],
    *,
    fail_on: str,
    override_ids: set[str],
    detector: str = "dep",
    block_kev: bool = False,
    epss_threshold: float | None = None,
) -> dict[str, Any]:
    """Classify ``findings`` against the policy and the recorded overrides.

    Returns ``{"passes", "findings", "blocking", "acknowledged",
    "block_reasons"}`` where ``findings`` is the input annotated once with
    ``id`` (the override tuple), ``status`` (``blocking`` | ``acknowledged`` |
    ``below_floor``), ``risk`` (:func:`finding_risk`), ``exploitation`` (the
    label), ``triggers`` and ``block_reason``; ``blocking``/``acknowledged``
    are views of the same annotated dicts, so the classification the gate
    enforces and the one reports render can never diverge. All three lists
    are in priority order (KEV, EPSS, severity). An acknowledged finding is
    one whose exact tuple id appears in ``override_ids`` (recorded human
    overrides). ``block_reasons`` lists the distinct reasons of the BLOCKING
    findings, ``kev`` first.
    """
    floor = FLOOR_RANK[fail_on]
    annotated: list[dict[str, Any]] = []
    blocking: list[dict[str, Any]] = []
    acknowledged: list[dict[str, Any]] = []
    for f in sort_by_priority(list(findings or [])):
        fid = finding_id(f, detector=detector)
        triggers = block_triggers(
            f, floor=floor, block_kev=block_kev, epss_threshold=epss_threshold
        )
        reason = block_reason_for(triggers)
        if reason is None:
            status = "below_floor"
        elif fid in override_ids:
            status = "acknowledged"
        else:
            status = "blocking"
        item = {
            **f,
            "id": fid,
            "status": status,
            "risk": finding_risk(f),
            "exploitation": exploitation_label(f),
            "triggers": triggers,
            "block_reason": reason,
        }
        annotated.append(item)
        if status == "blocking":
            blocking.append(item)
        elif status == "acknowledged":
            acknowledged.append(item)
    present = {b["block_reason"] for b in blocking}
    return {
        "passes": not blocking,
        "findings": annotated,
        "blocking": blocking,
        "acknowledged": acknowledged,
        "block_reasons": [r for r in BLOCK_REASONS if r in present],
    }
