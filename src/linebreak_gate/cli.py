"""``linebreak-gate`` — the security gate at the git/CI boundary.

Commands:

* ``scan``     — dependency CVE scan (osv-scanner / npm audit) + AI SAST over
  the working tree; writes git-native audit artifacts under
  ``.linebreak/audit/``. Exit 0 = pass, 1 = blocking findings, 2 = tool/config
  error (fail closed — a scanner crash is never a clean pass).
* ``report``   — human-readable summary of the recorded scan (counts by
  severity; each finding with CVE id, CVSS, advisory link); ``--format json``
  for the machine-readable form.
* ``override`` — record a human-approved acknowledgment of ONE exact finding
  (package+version+CVE tuple). Requires ``--reason`` and ``--approver``; the
  record lands in the artifact's approval trail. The gate never auto-clears on
  an agent's say-so.
* ``publish``  sends the recorded run (criteria, findings, sign-offs,
  overrides, attestation) to a governance service for the executive/audit
  panel. Never blocks: any failure is a warning and exit 0.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

from . import (
    code_scan,
    entitlements,
    exploit_intel,
    llm,
    risk_acceptance,
    security_scan,
    tickets,
)
from . import identity as _identity
from . import roles as _roles
from . import security_artifact as sa
from .criteria_check import MANUAL_POLICIES, STAGES
from .gate_config import FAIL_ON_LEVELS, GateConfig, GateConfigError, resolve_config
from .security_scan import _norm_severity
from .verdict import BLOCK_REASONS, evaluate, finding_id, finding_rank

# CI audit records live with the gate config, committed to the repo. Same
# document format as the desktop's _bmad-output/security artifacts.
AUDIT_DIR = str(Path(".linebreak") / "audit")

_STATUS_LABELS = {
    "blocking": "BLOCKING",
    "acknowledged": "ACKNOWLEDGED (override on record)",
    "expired_risk": "EXPIRED RISK (acceptance ran out)",
    "below_floor": "below floor",
}


def _err(message: str) -> None:
    print(f"linebreak-gate: {message}", file=sys.stderr)


def _actor() -> str:
    for env in ("GITHUB_ACTOR", "GITLAB_USER_LOGIN", "CI_COMMIT_AUTHOR", "USER", "USERNAME"):
        if os.environ.get(env):
            return os.environ[env]
    try:
        return getpass.getuser()
    except OSError:
        return "unknown"


def _counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0, "total": 0}
    for f in findings:
        counts[_norm_severity(f.get("severity"))] += 1
        counts["total"] += 1
    return counts


def _summarize(findings: list[dict[str, Any]], scanner: str | None) -> str:
    if not findings:
        return f"Scan clean — no known vulnerabilities ({scanner})."
    c = _counts(findings)
    parts = ", ".join(
        f"{c[s]} {s}" for s in ("critical", "high", "medium", "low", "unknown") if c[s]
    )
    return f"{c['total']} finding(s) ({parts}) via {scanner}."


def _acceptances(docs: dict[str, dict[str, Any] | None]) -> dict[str, dict[str, Any]]:
    """The EFFECTIVE acceptance per finding id across the scan artifacts: the
    latest override recorded for that id (a renewal supersedes, never erases,
    the earlier record), classified for today (open/active/expiring/expired).
    ``_entry`` carries the record itself for the roles check; it is stripped
    before the acceptance is annotated onto a finding."""
    now = risk_acceptance.today()
    out: dict[str, dict[str, Any]] = {}
    for artifact, doc in docs.items():
        if not doc:
            continue
        latest = risk_acceptance.latest_by_target(
            doc.get("approvals") or [],
            lambda e: str((e.get("finding") or {}).get("id") or "") or None,
        )
        for fid, entry in latest.items():
            state = risk_acceptance.acceptance_state(entry, now)
            out[fid] = {
                **risk_acceptance.describe(entry, state),
                "artifact": artifact,
                "_entry": entry,
            }
    return out


def _tickets_hook(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Run a ticket hook so that NOTHING it does can change the verdict: a
    tracker problem is a warning on stderr and a note in the evidence."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:  # noqa: BLE001 - deliberately broad: the tracker never blocks
        _err(f"tickets: unexpected error ({e.__class__.__name__}: {e}); the verdict is unaffected")
        return None


def _override_ids(
    doc: dict[str, Any],
    detector: str,
    policy: _roles.RolesPolicy,
    acceptances: dict[str, dict[str, Any]],
) -> tuple[set[str], set[str], list[dict[str, Any]]]:
    """Split the effective acceptances into the ids still in force that the
    roles policy accepts, the ids whose acceptance EXPIRED (they block again
    as ``expired_risk``; no roles check can revive them), and one denial
    record per in-force acceptance the roles in force reject (the finding
    stays blocking; the entry stays on disk as audit). Denials are reported
    only for findings present in ``doc``, so the two detectors never repeat
    each other's."""
    by_id = {finding_id(f, detector=detector): f for f in doc.get("findings") or []}
    ids: set[str] = set()
    expired: set[str] = set()
    denials: list[dict[str, Any]] = []
    for fid, acc in acceptances.items():
        if acc["state"] == "expired":
            expired.add(fid)
            continue
        entry = acc["_entry"]
        finding = entry.get("finding") or {}
        role = entry.get("role") if isinstance(entry.get("role"), str) else None
        if role == "approver" and policy.role("approver") is None:
            role = None  # the pre-roles placeholder, not a roster role
        by = str(entry.get("user_email") or "unknown")
        live = by_id.get(fid, finding)
        denial = _roles.verify_record(
            policy,
            kind="override",
            subject=by,
            keys=_roles.record_keys(entry, "user_email"),
            action="accept_security_risk",
            targets=(fid,),
            severity=_roles.severity_name(finding_rank(live)),
            role=role,
            identity_source=entry.get("identity_source"),
        )
        if denial is None:
            ids.add(fid)
        elif fid in by_id:
            denials.append(
                {"finding": fid, **_roles.denial_record(denial, kind="override", by=by, role=role)}
            )
    return ids, expired, denials


def _resolve_identity(declared: str | None) -> _identity.Identity | None:
    """Who signs: the governance token, the CI provider, or the typed name.
    Prints the reason and returns None (exit 2) when none is usable."""
    try:
        return _identity.resolve(declared)
    except _identity.IdentityError as e:
        _err(str(e))
        return None


def _warn_unverified(policy: _roles.RolesPolicy, ident: _identity.Identity, kind: str) -> None:
    """Under ``require_verified_identity`` a typed name is recorded but does
    not count; say so at recording time, not only at the next check."""
    if policy.require_verified_identity and not ident.verified:
        print(
            f"linebreak-gate: WARNING: this {kind} is recorded as DECLARED (identity_source: "
            f"client) and will NOT count: policy.require_verified_identity is on in "
            f"{_roles.ROLES_RELPATH}. Record it from CI (GitHub, GitLab, Bitbucket or Azure "
            f"Pipelines) or with {_identity.GOVERNANCE_BASE_ENV} and "
            f"{_identity.GOVERNANCE_TOKEN_ENV} set.",
            file=sys.stderr,
        )


def _build_scan_artifact(
    root: Path,
    name: str,
    kind: str,
    result: dict[str, Any],
    actor: str,
    *,
    exploit_status: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build (not yet write) the scan artifact, carrying the existing approval
    trail forward so recorded overrides survive rescans (they live in the
    committed artifact). ``exploit_status`` (dependency scans only) records
    where this run's EPSS/KEV data came from, or that there was none."""
    prior = sa.read_artifact(root, name, base_dir=AUDIT_DIR)
    findings = result.get("findings") or []
    doc = sa.new_artifact(
        kind,
        id="security",
        findings=findings,
        risk_score=result.get("risk_score"),
        summary=_summarize(findings, result.get("scanner")),
        scanner=result.get("scanner"),
    )
    doc["approvals"] = prior.get("approvals") or []
    doc["actor"] = actor
    if exploit_status is not None:
        doc["exploit_intel"] = exploit_status
    return doc


def _detector_payload(
    doc: dict[str, Any] | None,
    detector: str,
    cfg: GateConfig,
    acceptances: dict[str, dict[str, Any]],
    policy: _roles.RolesPolicy = _roles.EMPTY_POLICY,
) -> dict[str, Any] | None:
    if doc is None or doc.get("kind") is None:
        return None
    findings = doc.get("findings") or []
    override_ids, expired_ids, denials = _override_ids(doc, detector, policy, acceptances)
    verdict = evaluate(
        findings,
        fail_on=cfg.fail_on,
        override_ids=override_ids,
        expired_ids=expired_ids,
        detector=detector,
        block_kev=cfg.block_kev,
        epss_threshold=cfg.epss_threshold,
    )
    denied = {d["finding"]: d for d in denials}
    for f in verdict["findings"]:
        if f["id"] in denied:
            # The override on record does not count under the roles in force;
            # the finding keeps its real status (blocking unless below floor).
            f["denial"] = denied[f["id"]]
        if f["status"] in ("acknowledged", "expired_risk"):
            f["acceptance"] = {k: v for k, v in acceptances[f["id"]].items() if k != "_entry"}
    expiring = [
        f
        for f in verdict["findings"]
        if f["status"] == "acknowledged" and f["acceptance"]["state"] == "expiring"
    ]
    payload = {
        "scanner": doc.get("scanner"),
        "generated_at": doc.get("generated_at"),
        "counts": _counts(findings),
        "findings": verdict["findings"],
        "blocking": verdict["blocking"],
        "acknowledged": verdict["acknowledged"],
        "expired": verdict["expired"],
        "expiring": expiring,
        "block_reasons": verdict["block_reasons"],
        "role_denials": denials,
        "passes": verdict["passes"],
    }
    if detector == "dep":
        # Recorded at scan time; `report` renders the same status so both
        # commands tell one story about where the exploitation data came from.
        payload["exploit_intel"] = doc.get("exploit_intel")
    return payload


def _evaluate_all(
    cfg: GateConfig,
    sec_doc: dict[str, Any] | None,
    code_doc: dict[str, Any] | None,
    *,
    code_skipped: str | None = None,
    policy: _roles.RolesPolicy = _roles.EMPTY_POLICY,
) -> dict[str, Any]:
    acceptances = _acceptances({"security": sec_doc, "code": code_doc})
    dependencies = _detector_payload(sec_doc, "dep", cfg, acceptances, policy)
    code = _detector_payload(code_doc, "code", cfg, acceptances, policy)
    parts = [p for p in (dependencies, code) if p is not None]
    passes = all(p["passes"] for p in parts)
    present = {r for p in parts for r in p["block_reasons"]}
    return {
        "passes": passes,
        "fail_on": cfg.fail_on,
        "fail_on_source": cfg.fail_on_source,
        "block_kev": cfg.block_kev,
        "epss_threshold": cfg.epss_threshold,
        # The governance contract's vocabulary, exactly: kev | vulnerability |
        # expired_risk.
        "block_reasons": [r for r in BLOCK_REASONS if r in present],
        "dependencies": dependencies,
        "code": code,
        "code_skipped": code_skipped,
    }


def _print_acceptance_notes(payload: dict[str, Any]) -> None:
    """Expired acceptances (blocking again) and acceptances about to expire
    (a warning), with who accepted them and what to do."""
    for f in payload["expired"]:
        a = f["acceptance"]
        print(
            f"  expired risk: {f['id']}  accepted by {a.get('by')} on {str(a.get('at'))[:10]}, "
            f"expired {a.get('expires')}" + (f", ticket {a['ticket']}" if a.get("ticket") else "")
        )
        print(
            "      blocks again: renew it (linebreak-gate override --finding "
            f"{f['id']} --reason ... --approver ... --expires YYYY-MM-DD) or fix the finding"
        )
    for f in payload["expiring"]:
        a = f["acceptance"]
        print(
            f"  expiring risk: {f['id']}  accepted by {a.get('by')}, expires {a['expires']} "
            f"({a['days_left']} day(s) left)"
            + (f", ticket {a['ticket']}" if a.get("ticket") else "")
            + ". Renew or fix before then (warning, not blocking)."
        )


def _status_label(f: dict[str, Any]) -> str:
    status = _STATUS_LABELS.get(f.get("status"), "below floor")
    if f.get("status") == "blocking" and f.get("block_reason"):
        return f"{status}: {f['block_reason']}"
    return status


def _print_findings(payload: dict[str, Any], detector: str) -> None:
    # The verdict already orders findings by priority (KEV, then EPSS, then
    # severity/CVSS), so the printed order can't contradict it.
    for f in payload["findings"]:
        label = f.get("cve_id") or f.get("title") or "(unidentified)"
        if detector == "dep":
            subject = f"{f.get('package')}@{f.get('installed_version')}"
            fix = f" fix: {f['fixed_version']}" if f.get("fixed_version") else ""
        else:
            subject = f"{f.get('file')}:{f.get('line')}"
            fix = ""
        cvss = f" cvss {f['cvss']}" if f.get("cvss") is not None else ""
        print(f"  [{_status_label(f)}] {label}  {f.get('severity')}{cvss}  {subject}{fix}")
        if detector == "dep":
            extra = ""
            if f.get("kev") is True and f.get("epss") is not None:
                extra = f", EPSS {float(f['epss']):.2f}"
            if f.get("kev_due_date"):
                extra += f", CISA due {f['kev_due_date']}"
            print(f"      {f.get('exploitation')}{extra}  risk {f.get('risk')}")
        if f.get("advisory_url"):
            print(f"      {f['advisory_url']}")
        print(f"      id: {f['id']}")
        if f.get("denial"):
            d = f["denial"]
            role = f" as role {d['role']}" if d.get("role") else ""
            print(
                f"      role denied: override by {_one_line(d['by'])}{role} does not count "
                f"({d['reason']}): {_one_line(d['detail'])}"
            )


def _policy_line(payload: dict[str, Any]) -> str:
    bits = [f"fail on: {payload['fail_on']} ({payload['fail_on_source']})"]
    bits.append(f"block KEV: {'yes' if payload.get('block_kev') else 'no'}")
    threshold = payload.get("epss_threshold")
    bits.append(f"EPSS threshold: {threshold if threshold is not None else 'off'}")
    return ", ".join(bits)


def _emit(payload: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    print(f"LineBreak security gate — {_policy_line(payload)}")
    for label, key, detector in (
        ("Dependencies", "dependencies", "dep"),
        ("Code scan", "code", "code"),
    ):
        part = payload[key]
        if part is None:
            if key == "code" and payload.get("code_skipped"):
                print(f"Code scan: skipped — {payload['code_skipped']}")
            continue
        c = part["counts"]
        print(
            f"{label} ({part['scanner']}): {c['total']} finding(s) — "
            f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, "
            f"{c['low']} low, {c['unknown']} unknown"
        )
        if key == "dependencies" and c["total"]:
            print(f"Exploit intel: {exploit_intel.describe_status(part.get('exploit_intel'))}")
        _print_findings(part, detector)
        _print_acceptance_notes(part)
        if key == "code" and payload.get("code_skipped"):
            print(f"Code scan note: {payload['code_skipped']}")
    deps, code = payload["dependencies"], payload["code"]
    blocking = [b for p in (deps, code) if p is not None for b in p["blocking"]]
    expired_total = sum(len(p["expired"]) for p in (deps, code) if p is not None)
    denied_total = sum(len(p["role_denials"]) for p in (deps, code) if p is not None)
    if payload["passes"]:
        print("VERDICT: PASS — no blocking findings.")
    else:
        by_reason = ", ".join(
            f"{sum(1 for b in blocking if b.get('block_reason') == r)} {r}"
            for r in payload["block_reasons"]
        )
        expired_note = (
            f" {expired_total} of them had a risk acceptance that EXPIRED (expired_risk): "
            "renew it with --expires or fix the finding."
            if expired_total
            else ""
        )
        denied_note = (
            f" {denied_total} recorded override(s) do not count under {_roles.ROLES_RELPATH} "
            "(see the role denied lines); record them again with an authorized role."
            if denied_total
            else ""
        )
        print(
            f"VERDICT: BLOCKED — {len(blocking)} blocking finding(s) ({by_reason}; "
            f"floor '{payload['fail_on']}'). Fix them or record a human-approved override "
            f"(linebreak-gate override --finding <id> --reason ... --approver ...)."
            f"{expired_note}{denied_note}"
        )


def _check_entitlement() -> bool:
    decision, notice = entitlements.gate_decision(os.environ.get("LINEBREAK_LICENSE_KEY"))
    # The notice nudges toward a license for the Pro AI review — skip it for BYOK
    # users, whose review already runs on their own ANTHROPIC_API_KEY.
    if notice and not os.environ.get("ANTHROPIC_API_KEY"):
        print(notice, file=sys.stderr)
    if not decision.allowed:
        upgrade = f" ({decision.upgrade_url})" if decision.upgrade_url else ""
        _err(f"entitlement check failed: {decision.reason}{upgrade}")
        return False
    return True


# ---------------------------------------------------------------- commands


def _cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    cfg = resolve_config(root, cli_fail_on=args.fail_on)
    if not _check_entitlement():
        return 2

    dep_result = security_scan.scan_project(root, exclude_paths=list(cfg.exclude_paths))
    if dep_result.get("error"):
        # Fail closed: no artifact is written and the check fails — a scan that
        # could not run must never be mistaken for a clean pass.
        _err(f"dependency scan failed (gate stays closed): {dep_result['error']}")
        return 2

    code_result: dict[str, Any] | None = None
    code_skipped: str | None = None
    if cfg.code_scan == "off":
        code_skipped = "code_scan is 'off' in .linebreak/gate.yml"
    else:
        ask = llm.build_ask()
        if ask is None:
            if cfg.code_scan == "on":
                _err(
                    "code_scan is 'on' but no model credentials are available — "
                    "set LINEBREAK_LICENSE_KEY (hosted, uses credits) or "
                    "ANTHROPIC_API_KEY (your own key) (gate stays closed)"
                )
                return 2
            code_skipped = "no LINEBREAK_LICENSE_KEY or ANTHROPIC_API_KEY (dependency scan only)"
            _err(
                "code scan skipped: no model credentials. Set LINEBREAK_LICENSE_KEY "
                "(hosted, uses credits) or ANTHROPIC_API_KEY (your own key) to enable the "
                "AI SAST pass, or set `code_scan: off` in .linebreak/gate.yml to silence this."
            )
        else:
            excludes = list(cfg.exclude_paths)
            code_result = code_scan.scan_code(
                str(root),
                discover=lambda r: code_scan.llm_discover(r, ask=ask, exclude_paths=excludes),
                verify=lambda f: code_scan.llm_verify(f, ask=ask),
            )
            if code_result.get("error"):
                _err(f"code scan failed (gate stays closed): {code_result['error']}")
                return 2

    # Exploitation intel (EPSS + KEV). Best effort by design: with no network
    # it reads the cache, with no cache the fields stay empty and the report
    # says so. It can never turn a scan into a tool error.
    dep_findings = dep_result.get("findings") or []
    exploit_status = exploit_intel.enrich_findings(
        dep_findings,
        root,
        enabled=cfg.intel,
        max_age_hours=cfg.intel_max_age_hours,
    )
    dep_result["risk_score"] = security_scan.compute_risk_score(dep_findings)

    actor = _actor()
    policy = _roles.load_roles(root)
    # The previously recorded artifacts are the baseline "new on main" is
    # measured against (tickets): read them before they are rewritten.
    prior_ids: dict[str, set[str] | None] = {}
    for name, detector in (("security", "dep"), ("code", "code")):
        prior = sa.read_artifact(root, name, base_dir=AUDIT_DIR)
        prior_ids[name] = (
            {finding_id(f, detector=detector) for f in prior.get("findings") or []}
            if prior.get("kind")
            else None
        )
    sec_doc = _build_scan_artifact(
        root, "security", "cve_scan", dep_result, actor, exploit_status=exploit_status
    )
    code_doc: dict[str, Any] | None = None
    if code_result is not None:
        code_doc = _build_scan_artifact(root, "code", "code_scan", code_result, actor)
    elif cfg.code_scan == "auto":
        # The detector was skipped for lack of credentials, but a committed
        # code.json is evidence on the record — it still gates (fail closed)
        # and keeps `scan` and `report` telling the same story. `code_scan:
        # off` is the explicit opt-out that ignores it on both commands.
        existing = sa.read_artifact(root, "code", base_dir=AUDIT_DIR)
        if existing.get("kind") == "code_scan":
            code_doc = existing
            code_skipped = (
                f"{code_skipped}; the committed code.json record (from an earlier scan) still gates"
            )

    payload = _evaluate_all(cfg, sec_doc, code_doc, code_skipped=code_skipped, policy=policy)
    # Each artifact records this run's verdict with its block reasons (the
    # governance service reads `kev` apart from `vulnerability`), then lands
    # atomically. `report` re-evaluates against the policy current at that time.
    to_write = [("security", sec_doc, payload["dependencies"])]
    if code_result is not None and code_doc is not None:
        to_write.append(("code", code_doc, payload["code"]))
    for name, doc, part in to_write:
        doc["verdict"] = {"passes": part["passes"], "block_reasons": part["block_reasons"]}
        written = sa.write_artifact(root, name, doc, base_dir=AUDIT_DIR)
        part["generated_at"] = written.get("generated_at")
    _emit(payload, args.format)
    if cfg.tickets is not None:
        # Only the detectors that RAN this time say anything about fixed or
        # new findings; a skipped code scan is not evidence that code findings
        # are gone.
        current = {"security": payload["dependencies"]["findings"]}
        if code_result is not None and payload["code"] is not None:
            current["code"] = payload["code"]["findings"]
        _tickets_hook(tickets.on_scan, root, cfg.tickets, current=current, prior_ids=prior_ids)
    return 0 if payload["passes"] else 1


def _cmd_report(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    cfg = resolve_config(root, cli_fail_on=args.fail_on)
    sec_doc = sa.read_artifact(root, "security", base_dir=AUDIT_DIR)
    # Mirror the scan's rule so report and scan can never disagree about the
    # code detector: `code_scan: off` ignores a committed code.json.
    code_doc = (
        None if cfg.code_scan == "off" else sa.read_artifact(root, "code", base_dir=AUDIT_DIR)
    )
    if sec_doc.get("kind") is None and (code_doc is None or code_doc.get("kind") is None):
        if args.format == "json":
            print(json.dumps({"passes": None, "error": "no scan recorded"}, indent=2))
        else:
            print(
                "No scan recorded under .linebreak/audit/ — run `linebreak-gate scan` "
                "first (a missing scan keeps the gate closed)."
            )
        return 0
    payload = _evaluate_all(cfg, sec_doc, code_doc, policy=_roles.load_roles(root))
    _emit(payload, args.format)
    return 0


def _resolve_expiry(args: argparse.Namespace, cfg: GateConfig) -> str | None:
    """``--expires`` / ``--days`` under the repo's risk-acceptance policy.
    Raises RiskAcceptanceError (the caller maps it to exit 2)."""
    return risk_acceptance.resolve_expiry(
        expires=getattr(args, "expires", None),
        days=getattr(args, "days", None),
        max_days=cfg.risk_max_days,
        required=cfg.risk_required,
    )


def _expiry_note(expires: str | None) -> str:
    if expires:
        return (
            f" It expires on {expires}: past that date the gate blocks again (expired_risk) "
            "until it is renewed or the risk is fixed."
        )
    return (
        " It has NO expiry (open-ended); set risk_acceptance in .linebreak/gate.yml to require one."
    )


def _ticket_note(result: dict[str, Any] | None) -> str:
    if not result:
        return ""
    if result.get("ticket") and not result.get("error"):
        return f" Ticket: {result['ticket']} ({result.get('url')})."
    if result.get("ticket"):
        return f" Ticket: {result['ticket']} (an update is pending: {result['error']})."
    return f" Ticket: pending ({result.get('error')}); `linebreak-gate tickets sync` retries."


def _cmd_override(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    cfg = resolve_config(root)
    reason = (args.reason or "").strip()
    if not reason:
        _err("a non-empty --reason is required to record an override")
        return 2
    ident = _resolve_identity(args.approver)
    if ident is None:
        return 2
    try:
        expires = _resolve_expiry(args, cfg)
    except risk_acceptance.RiskAcceptanceError as e:
        _err(f"{e} (nothing recorded)")
        return 2
    policy = _roles.load_roles(root)

    target: tuple[str, str, dict[str, Any]] | None = None
    # The id prefix names the artifact the finding lives in.
    detectors = (("code", "code"),) if args.finding.startswith("code:") else (("security", "dep"),)
    for name, detector in detectors:
        doc = sa.read_artifact(root, name, base_dir=AUDIT_DIR)
        if doc.get("kind") is None:
            continue
        for f in doc.get("findings") or []:
            if finding_id(f, detector=detector) == args.finding:
                target = (name, detector, f)
                break
        if target:
            break
    if target is None:
        _err(
            f"finding {args.finding!r} is not in the recorded scan — run "
            "`linebreak-gate scan` and copy the finding id from its output"
        )
        return 2

    name, detector, f = target
    if detector == "dep":
        record = {
            "id": args.finding,
            "detector": "dependencies",
            "package": f.get("package"),
            "installed_version": f.get("installed_version"),
            "cve_id": f.get("cve_id"),
            "advisory_url": f.get("advisory_url"),
            "severity": f.get("severity"),
            "title": f.get("title"),
        }
    else:
        record = {
            "id": args.finding,
            "detector": "code",
            "file": f.get("file"),
            "line": f.get("line"),
            "title": f.get("title"),
            "category": f.get("category"),
            "severity": f.get("severity"),
        }
    # Accepting a security risk is gated by severity: a role may accept
    # medium and low but not a critical.
    severity = _roles.severity_name(finding_rank(f))
    try:
        role = _roles.authorize(
            policy,
            subject=ident.subject,
            keys=ident.keys(),
            action="accept_security_risk",
            targets=(args.finding,),
            severity=severity,
            role=args.role,
        )
    except _roles.RoleDenied as e:
        _err(str(e))
        return 2
    approval_id = uuid.uuid4().hex
    doc = sa.append_approval(
        root,
        name,
        approval_id=approval_id,
        # The roster role the risk is accepted under; "approver" is the
        # pre-roles placeholder, kept so the entry shape never changes.
        role=role or "approver",
        decision="override",
        user_email=ident.subject,
        notes=reason,
        finding=record,
        # client: human-typed, unverified; vcs / governance: verified, so
        # auditors can distinguish a declared name from a session-backed one.
        identity_source=ident.source,
        identity=ident.record(),
        declared_by=ident.declared,
        expires=expires,
        base_dir=AUDIT_DIR,
    )
    entry = next(e for e in doc["approvals"] if e.get("id") == approval_id)
    # The record is saved FIRST; the ticket mirrors it and can never undo it.
    ticket = _tickets_hook(tickets.on_acceptance, root, cfg.tickets, artifact=name, entry=entry)
    rel = Path(AUDIT_DIR) / f"{name}.json"
    role_note = f" as role {role}" if role else ""
    print(
        f"Override recorded for {args.finding} by {ident.subject}{role_note} "
        f"({ident.source} identity) in {rel}. Commit this file so the acknowledgment "
        "applies in CI. It covers this exact finding only; a different CVE or version "
        f"still blocks.{_expiry_note(expires)}{_ticket_note(ticket)}"
    )
    _warn_unverified(policy, ident, "override")
    return 0


# ---------------------------------------------------------------- criteria (Piece 3)

_RESULT_ICONS = {
    "pass": "✓",
    "fail": "✗",
    "needs-signoff": "●",
    "overridden": "→",
    "error": "!",
    "release-only": "-",
    "role-denied": "✗",
}
# ASCII fallback for consoles whose encoding can't represent the glyphs
# (Windows cp1252 with redirected stdout) — printing the unicode there raises
# UnicodeEncodeError, which would crash a PASSING run as exit 1 (misreported as
# blocked). The gate must never turn its own I/O into a false verdict.
_RESULT_ICONS_ASCII = {
    "pass": "[ok]",
    "fail": "[x]",
    "needs-signoff": "[?]",
    "overridden": "[>]",
    "error": "[!]",
    "release-only": "[-]",
    "role-denied": "[x]",
}


def _result_icons() -> dict[str, str]:
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "".join(_RESULT_ICONS.values()).encode(enc)
    except (UnicodeEncodeError, LookupError):
        return _RESULT_ICONS_ASCII
    return _RESULT_ICONS


def _requested_scope(args: argparse.Namespace) -> dict[str, Any]:
    """The scope the caller ASKED for, in the SAME shape the evaluating path
    emits (empty lists, zero counts), so a JSON consumer reads one schema on
    every path: evaluated, no bundle, disabled, and signature block."""
    if getattr(args, "stories", None):
        mode = "story"
    elif getattr(args, "started_only", False):
        mode = "started"
    else:
        mode = "all"
    return {
        "mode": mode,
        "stories_evaluated": [],
        "stories_skipped": [],
        "manual": getattr(args, "manual", "block"),
        "stage": getattr(args, "stage", "release"),
        "release_only": [],
        "criteria_evaluated": 0,
        "criteria_total": 0,
    }


def _emit_check_notice(fmt: str, status: str, message: str, scope: dict[str, Any]) -> None:
    """A non-evaluating check outcome (disabled / no-bundle). Honors --format
    json so the machine-readable contract holds on EVERY path, not just when a
    bundle is present."""
    if fmt == "json":
        print(
            json.dumps(
                {
                    "passes": True,
                    "status": status,
                    "message": message,
                    "scope": scope,
                    "pending_signoffs": [],
                },
                indent=2,
            )
        )
    else:
        print(message)


def _check_label(check: dict[str, Any]) -> str:
    """``type[: payload][, when: release]``: one rendering for `check` and
    `spec show`, so both describe a criterion the same way."""
    label = check["type"] + (f": {check['payload']}" if check.get("payload") else "")
    if check.get("when"):
        label += f", when: {check['when']}"
    return label


def _one_line(text: Any) -> str:
    """Bundle-authored and command-produced text (statements, sign-off notes,
    override reasons, the first line of a failing check) is printed into the
    report the Action's comment parses line by line. Collapse it to ONE line
    so no such text can ever start a line and forge a `pending sign-off:` or
    `scope:` entry."""
    return " ".join(str(text if text is not None else "").split())


def _cmd_check(args: argparse.Namespace) -> int:
    """Evaluate the approved acceptance criteria against the working tree.

    Exit 0: all satisfied, criteria disabled, or no bundle (teams using only
    the security scan are unaffected). Exit 1: any fail / needs-signoff
    (needs-signoff blocks only under ``--manual block``, the default).
    Exit 2: malformed bundle/sign-offs, invalid config, an unknown ``--story``
    id, or an unrunnable check — fail closed, never misreported as pass or
    code failure.

    Scope (issue #256): ``--story <id>`` (repeatable) evaluates only those
    stories; ``--started-only`` evaluates only stories with a started local
    state; ``--manual warn`` reports missing sign-offs without blocking. The
    recommended wiring is a scoped check on PRs and a full ``--manual block``
    check in the release job.
    """
    from . import criteria_check, signoffs, spec_bundle

    root = Path(args.path).resolve()
    scope = _requested_scope(args)
    cfg = resolve_config(root)
    if not cfg.criteria_enforce:
        _emit_check_notice(
            args.format,
            "disabled",
            "Acceptance criteria: enforcement DISABLED (criteria.enforce: false in "
            f"{Path('.linebreak') / 'gate.yml'}). The security scan is unaffected.",
            scope,
        )
        return 0
    # Same Pro-unlock seam as the AI review: under the open provider (today's
    # default) enforcement runs and a missing key gets a notice, not a refusal;
    # the remote provider flips this to enforced later. No new licensing infra.
    key = os.environ.get("LINEBREAK_LICENSE_KEY")
    decision, _ = entitlements.gate_decision(key)
    if not decision.allowed:
        upgrade = f" ({decision.upgrade_url})" if decision.upgrade_url else ""
        _err(f"entitlement check failed: {decision.reason}{upgrade}")
        return 2
    if not key:
        print(
            "linebreak-gate: acceptance-criteria enforcement is a LineBreak Pro feature — "
            "add LINEBREAK_LICENSE_KEY (get yours at linebreakapp.com/en/pricing). "
            "It currently runs without one; a license will be required once enforcement "
            "is enabled.",
            file=sys.stderr,
        )
    try:
        payload = criteria_check.evaluate_bundle(
            root,
            write_artifact=True,
            actor=_actor(),
            approval_public_keys=cfg.approval_public_keys,
            story_ids=set(args.stories) if args.stories else None,
            started_only=args.started_only,
            manual_policy=args.manual,
            stage=args.stage,
        )
    except criteria_check.BundleSignatureError as e:
        # A verification key is configured but the bundle's signed approval is
        # missing/tampered/untrusted — BLOCK (exit 1), not a tool error. This is
        # the tamper + downgrade foreclosure: an edited-after-approval or
        # signature-stripped bundle fails here.
        return _emit_signature_block(str(e), args.format, scope)
    except spec_bundle.SpecBundleError as e:
        _err(f"malformed spec bundle (gate stays closed): {e}")
        return 2
    except signoffs.SignoffError as e:
        _err(f"sign-off records unreadable (gate stays closed): {e}")
        return 2
    except criteria_check.CriteriaToolError as e:
        # An unknown --story id or a corrupt override trail: the scope or the
        # record can't be trusted, so the gate stays closed (exit 2).
        _err(f"{e} (gate stays closed)")
        return 2
    if payload is None:
        _emit_check_notice(
            args.format,
            "no-bundle",
            "Acceptance criteria: no approved criteria found (.linebreak/spec/ absent) — "
            "nothing to enforce. Approve a spec in the LineBreak app to arm this check.",
            scope,
        )
        return 0
    _emit_check(payload, args.format)
    if cfg.tickets is not None:
        _tickets_hook(
            tickets.on_check,
            root,
            cfg.tickets,
            payload=payload,
            overrides=_tickets_hook(criteria_check._criterion_overrides, root) or [],
        )
    if payload["tool_error"]:
        return 2
    return 0 if payload["passes"] else 1


def _cmd_tickets_sync(args: argparse.Namespace) -> int:
    """Replay pending ticket operations (a tracker that was unreachable or
    refused earlier). Exit 0 when nothing is left pending, 1 otherwise, so a
    scheduled job can notice; it never touches a verdict."""
    root = Path(args.path).resolve()
    cfg = resolve_config(root)
    completed, remaining, messages = tickets.sync(root, cfg.tickets)
    for m in messages:
        print(f"  {m}")
    print(f"Tickets: {completed} operation(s) synced, {remaining} still pending.")
    return 1 if remaining else 0


def _emit_signature_block(message: str, fmt: str, scope: dict[str, Any]) -> int:
    """A configured verification key + an unverifiable bundle → BLOCKED (exit 1).
    Honors --format json so the machine contract holds on this path too."""
    if fmt == "json":
        print(
            json.dumps(
                {
                    "passes": False,
                    "status": "signature-invalid",
                    "message": message,
                    "scope": scope,
                    "pending_signoffs": [],
                },
                indent=2,
            )
        )
    else:
        print(
            f"VERDICT: BLOCKED — signed approval verification failed: {message}. "
            "The gate fails closed."
        )
    return 1


def _emit_check(payload: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    b = payload["bundle"]
    print(
        f"LineBreak acceptance criteria — bundle from {b['source_phase']} "
        f"({b['generated_at']}), approved by {b['approved_by']}, {b['stories']} story(ies)"
    )
    # Honest signature status — never imply more assurance than exists.
    if b.get("signature") == "verified":
        self_note = (
            " — SELF-APPROVED (solo org, no independent review)" if b.get("self_approved") else ""
        )
        print(
            f"  signed approval VERIFIED (key {b.get('signing_kid')}, by "
            f"{b.get('signed_by')}){self_note}"
        )
    else:
        print(
            "  bundle is UNSIGNED — no approvals.public_keys configured in .linebreak/gate.yml; "
            "criteria are enforced but the approval carries no cryptographic assurance"
        )
    _print_scope(payload["scope"])
    icons = _result_icons()
    counts: dict[str, int] = {}
    for r in payload["criteria"]:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
        icon = icons.get(r["result"], "?")
        label = _one_line(_check_label(r["check"]))
        print(
            f"  {icon} [{r['result']}] {r['story']}/{r['id']}  ({label})  "
            f"{_one_line(r['statement'])}"
        )
        if r.get("signoff"):
            s = r["signoff"]
            print(
                f"      signed off by {_one_line(s['approver'])}{_role_note(s)} at "
                f"{s['signed_at']}: {_one_line(s['note'])}"
            )
        if r.get("override"):
            o = r["override"]
            until = f", expires {o['expires']}" if o.get("expires") else ", no expiry"
            print(
                f"      overridden by {_one_line(o['approver'])}{_role_note(o)}{until}: "
                f"{_one_line(o['reason'])}"
            )
        if r.get("override_expired"):
            o = r["override_expired"]
            print(
                f"      expired risk: accepted by {_one_line(o['approver'])}{_role_note(o)}, "
                f"expired {o['expires']}. Renew (override --criterion {r['id']} ... --expires) "
                "or fix."
            )
        for d in r.get("denials") or []:
            role = f" as role {d['role']}" if d.get("role") else ""
            print(
                f"      {d['kind']} by {_one_line(d['by'])}{role} does not count "
                f"({d['reason']}): {_one_line(d['detail'])}"
            )
        if r["result"] in ("fail", "error") and r.get("detail"):
            first = r["detail"].strip().splitlines()
            print(f"      {_one_line(first[0])[:200]}" if first else "")
    for e in payload.get("expiring_overrides") or []:
        print(
            f"  expiring exception: {e['id']} ({e['story']}) accepted by "
            f"{_one_line(e.get('approver'))}, expires {e['expires']} ({e['days_left']} day(s) "
            "left). Renew or fix before then (warning, not blocking)."
        )
    # One line per missing sign-off, in a fixed shape the Action comment can
    # lift out of the log ("pending sign-off: <id> (<story>)").
    warn = payload["scope"]["manual"] == "warn"
    for p in payload["pending_signoffs"]:
        note = " (not blocking under --manual warn)" if warn else ""
        print(f"  pending sign-off: {p['id']} ({p['story']}){note}")
    # One line per rejected approval, same fixed shape ("role denied: <id>
    # (<story>): <why>"), always blocking whatever --manual says.
    for r in payload["criteria"]:
        if r["result"] == "role-denied":
            why = "; ".join(_one_line(d["detail"]) for d in r.get("denials") or [])
            print(f"  role denied: {r['id']} ({r['story']}): {why}")
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    if payload["tool_error"]:
        print(
            f"VERDICT: ERROR — {summary}. A check could not RUN (unsupported stack or "
            "missing runner); fix the runner or declare it as a `command` criterion. "
            "The gate fails closed."
        )
    elif payload["passes"]:
        n = len(payload["pending_signoffs"])
        tail = (
            f"; {n} manual criterion(s) still need a sign-off before release (not blocking "
            "under --manual warn; the release check with --manual block will require them)"
            if n
            else ""
        )
        skipped = len(payload["scope"]["release_only"])
        if skipped:
            tail += (
                f"; {skipped} release-only criterion(s) not evaluated at stage pr "
                "(the release check owns them)"
            )
        head = (
            f"Every evaluated criterion satisfied ({summary})"
            if payload["scope"]["criteria_evaluated"]
            else f"No criterion evaluated at this stage ({summary})"
        )
        print(f"VERDICT: PASS. {head}{tail}.")
    else:
        reasons = ", ".join(payload.get("block_reasons") or []) or "blocking criteria"
        expired = len(payload.get("expired_overrides") or [])
        expired_note = (
            f" {expired} criterion exception(s) EXPIRED (expired_risk): renew with --expires "
            "or fix the check."
            if expired
            else ""
        )
        denied = counts.get("role-denied", 0)
        denied_note = (
            f" {denied} recorded approval(s) do not count under {_roles.ROLES_RELPATH} "
            "(see the role denied lines); record them again with an authorized role."
            if denied
            else ""
        )
        print(
            f"VERDICT: BLOCKED — {summary} (reasons: {reasons}). Fix the code, record a "
            "sign-off for `manual` criteria (linebreak-gate signoff), or record an attributed "
            f"override (linebreak-gate override --criterion <id> ...).{expired_note}{denied_note}"
        )


def _role_note(block: dict[str, Any]) -> str:
    """`` as role X`` plus the identity source when it is not the typed default,
    so the log says who signed AND how the gate knows it was them."""
    note = f" as role {block['role']}" if block.get("role") else ""
    source = block.get("identity_source")
    if source and source != "client":
        note += f" ({source} identity)"
    return note


def _print_scope(scope: dict[str, Any]) -> None:
    """State what was evaluated so a reader never mistakes a scoped run for
    the full bundle (and vice versa). Shape is stable: the Action comment
    parses the ``scope:`` and ``not started`` lines."""
    evaluated = scope["stories_evaluated"]
    skipped = scope["stories_skipped"]
    total = len(evaluated) + len(skipped)
    if scope["mode"] == "story":
        label = "story" if len(evaluated) == 1 else "stories"
        head = f"{label} {', '.join(evaluated)} ({len(evaluated)} of {total} stories)"
    elif scope["mode"] == "started":
        head = f"started stories only ({len(evaluated)} of {total}: {', '.join(evaluated)})"
    else:
        head = f"all stories ({total})"
    print(
        f"  scope: {head}, {scope['criteria_evaluated']} of {scope['criteria_total']} criteria, "
        f"manual criteria: {scope['manual']}, stage: {scope['stage']}"
    )
    if scope["mode"] == "started" and skipped:
        print(f"  not started (not counted): {', '.join(skipped)}")
    if scope["release_only"]:
        listed = ", ".join(f"{r['id']} ({r['story']})" for r in scope["release_only"])
        print(f"  release-only (not evaluated at stage pr): {listed}")


def _cmd_signoff(args: argparse.Namespace) -> int:
    from . import signoffs

    root = Path(args.path).resolve()
    ident = _resolve_identity(args.approver)
    if ident is None:
        return 2
    policy = _roles.load_roles(root)
    try:
        record = signoffs.record_signoff(
            root,
            criterion_id=args.criterion,
            note=args.note,
            identity=ident,
            role=args.role,
            policy=policy,
        )
    except signoffs.SignoffError as e:
        _err(str(e))
        return 2
    rel = signoffs.SIGNOFFS_DIR
    print(
        f"Sign-off recorded for {args.criterion} by {record['approver']}{_role_note(record)} "
        f"under {rel}/. Commit it so the approval applies in CI. It binds to the criterion "
        "as approved TODAY: editing the criterion and re-approving the spec makes this "
        "sign-off stale."
    )
    _warn_unverified(policy, ident, "sign-off")
    return 0


def _cmd_override_criterion(args: argparse.Namespace) -> int:
    from . import criteria_check

    root = Path(args.path).resolve()
    cfg = resolve_config(root)
    if not (args.reason or "").strip():
        _err("--reason and --approver are both required for an override")
        return 2
    ident = _resolve_identity(args.approver)
    if ident is None:
        return 2
    try:
        expires = _resolve_expiry(args, cfg)
    except risk_acceptance.RiskAcceptanceError as e:
        _err(f"{e} (nothing recorded)")
        return 2
    policy = _roles.load_roles(root)
    try:
        entry = criteria_check.record_criterion_override(
            root,
            criterion_id=args.criterion,
            reason=args.reason,
            identity=ident,
            role=args.role,
            policy=policy,
            expires=expires,
        )
    except criteria_check.CriteriaToolError as e:
        _err(str(e))
        return 2
    ticket = _tickets_hook(
        tickets.on_acceptance, root, cfg.tickets, artifact="criteria", entry=entry
    )
    rel = Path(AUDIT_DIR) / "criteria.json"
    note = _role_note(
        {
            "role": entry.get("role") if entry.get("role") != "approver" else None,
            "identity_source": ident.source,
        }
    )
    print(
        f"Override recorded for criterion {args.criterion} by {ident.subject}{note} in {rel}. "
        "Commit this file so it applies in CI. It covers this criterion AS CURRENTLY "
        "WORDED only; editing the criterion re-arms the check. Other criteria still block."
        f"{_expiry_note(expires)}{_ticket_note(ticket)}"
    )
    _warn_unverified(policy, ident, "override")
    return 0


# ---------------------------------------------------------------- spec (read-only)


def _cmd_spec_list(args: argparse.Namespace) -> int:
    """Render the approved spec bundle. Read-only — this NEVER enforces
    criteria (that's Piece 3); it validates plumbing and exits 2 on a
    malformed bundle (fail closed on structure, consistent with the gate)."""
    from . import spec_bundle

    root = Path(args.path).resolve()
    try:
        bundle = spec_bundle.load_bundle(root)
    except spec_bundle.SpecBundleError as e:
        _err(f"malformed spec bundle: {e}")
        return 2
    if bundle is None:
        print(f"No spec bundle found ({spec_bundle.SPEC_DIR}/ absent).")
        return 0

    manifest = bundle["manifest"]
    approval = manifest.get("approval") or {}
    print(
        f"Spec bundle v{manifest.get('bundle_version')} — source: "
        f"{manifest.get('source_phase')}, generated {manifest.get('generated_at')}"
    )
    approver = approval.get("approved_by") or approval.get("user_email") or "unknown"
    print(
        f"Approved by {approver} ({approval.get('role', 'unknown role')}) "
        f"at {approval.get('approved_at', 'unknown time')}"
    )
    stories = bundle["stories"]
    if not stories:
        print("0 stories.")
        return 0
    print(f"{len(stories)} story(ies):")
    for story in stories:
        print()
        _print_story(story)
    return 0


def _print_story(story: dict[str, Any]) -> None:
    epic = f" [{story['epic']}]" if story.get("epic") else ""
    status = f" ({story['status']})" if story.get("status") else ""
    print(f"{story['id']}{epic}{status} — {story['title']}")
    for c in story["criteria"]:
        print(f"  [{_check_label(c['check'])}] {c['id']}  {c['statement']}")


def _bridge_fail(out: dict[str, Any]) -> int:
    """Shared exit contract for a bridge not-ok response: an ABSENT spec is a
    stated fact (exit 0); a MALFORMED bundle fails closed (exit 2, same as
    `spec list`/`check`); anything else (unknown story, tracker refusal) is an
    ordinary error (exit 1)."""
    if out.get("error") == "no-spec":
        print(out["message"])
        return 0
    if out.get("error") == "malformed":
        _err(out["message"])
        return 2
    _err(out["message"])
    return 1


def _warn_invalid_signature(out: dict[str, Any]) -> bool:
    """Print the loud tamper warning when the bridge flagged the bundle.
    Returns True when it fired, so `spec check` can fold it into its exit."""
    if out.get("signature") == "invalid":
        print(f"\nWARNING — approval signature INVALID: {out['signature_detail']}")
        return True
    return False


def _cmd_spec_next(args: argparse.Namespace) -> int:
    """LIN-55: the next approved story not yet done. No spec / all done are
    stated facts (exit 0); malformed fails closed (exit 2)."""
    from . import bridge

    out = bridge.next_story(Path(args.path).resolve())
    if not out["ok"]:
        return _bridge_fail(out)
    if out["story"] is None:
        print(out["message"])
    else:
        _print_story(out["story"])
    _warn_invalid_signature(out)
    return 0


def _cmd_spec_show(args: argparse.Namespace) -> int:
    from . import bridge

    out = bridge.get_story(Path(args.path).resolve(), args.story_id)
    if not out["ok"]:
        return _bridge_fail(out)
    _print_story(out["story"])
    _warn_invalid_signature(out)
    return 0


def _cmd_spec_check(args: argparse.Namespace) -> int:
    """LIN-55: run ONE story's criteria — same engine and exit contract as
    `check` (0 pass, 1 blocking, 2 tool error), scoped to the story. GATE
    PARITY includes the signature: an invalid/unverifiable signed approval is
    a block (exit 1) even when the criteria pass, because the merge gate will
    refuse exactly that bundle."""
    from . import bridge

    out = bridge.check_story(Path(args.path).resolve(), args.story_id, stage=args.stage)
    if not out["ok"]:
        return _bridge_fail(out)
    icons = _result_icons()
    for r in out["criteria"]:
        icon = icons.get(r["result"], "?")
        print(f"  {icon} [{r['result']}] {r['story']}/{r['id']}  {r['statement']}")
        if r.get("detail"):
            print(f"      {r['detail']}")
    signature_blocked = _warn_invalid_signature(out)
    if out["tool_error"]:
        return 2
    return 0 if out["passes"] and not signature_blocked else 1


# ---------------------------------------------------------------- badge

#: shields.io STATIC badge — the whole badge is encoded in the URL, so the
#: command itself never makes a network call (the image renders when the
#: README is viewed).
BADGE_IMAGE_URL = "https://img.shields.io/badge/gated%20by-LineBreak-14120F?labelColor=FAF8F4"
BADGE_LINK_URL = "https://www.linebreakapp.com/en/gate"
BADGE_ALT = "gated by LineBreak"
BADGE_HINT = "Paste this into your README."


def _cmd_badge(args: argparse.Namespace) -> int:
    """Print a ready-to-paste "gated by LineBreak" README badge. The snippet
    goes to stdout and the hint to stderr, so ``linebreak-gate badge >>
    README.md`` appends only the badge."""
    if args.format == "url":
        snippet = BADGE_IMAGE_URL
    elif args.format == "html":
        snippet = (
            f'<a href="{BADGE_LINK_URL}"><img src="{BADGE_IMAGE_URL}" alt="{BADGE_ALT}" /></a>'
        )
    else:
        snippet = f"[![{BADGE_ALT}]({BADGE_IMAGE_URL})]({BADGE_LINK_URL})"
    print(snippet)
    print(BADGE_HINT, file=sys.stderr)
    return 0


def _cmd_publish(args: argparse.Namespace) -> int:
    """Send the recorded run to a governance service (the panel). ALWAYS exits
    0: a missing token, an unreachable service, or a malformed record prints
    a warning and the pipeline continues. Publishing reports the verdict;
    it never decides it."""
    from . import publish

    try:
        root = Path(args.path).resolve()
        payload = publish.build_payload(root, run_id=args.run_id, stage=args.stage)
        if args.dry_run:
            print(json.dumps(payload, indent=2))
            return 0
        token = os.environ.get("LINEBREAK_GOV_TOKEN", "").strip()
        project = (args.project or os.environ.get("LINEBREAK_GOV_PROJECT", "")).strip()
        if not token:
            raise publish.PublishError("LINEBREAK_GOV_TOKEN is not set")
        if not project:
            raise publish.PublishError("no project id (--project or LINEBREAK_GOV_PROJECT)")
        publish.send(payload, url=args.to, project_id=project, token=token)
    except Exception as e:  # noqa: BLE001 - publishing never blocks a change
        _err(f"publish skipped (this never blocks the change): {e}")
        return 0
    print(
        f"linebreak-gate: published run {payload['run_id']} ({payload['verdict']}) "
        f"to {args.to.rstrip('/')} for project {project}"
    )
    return 0


def _cmd_mcp(args: argparse.Namespace) -> int:
    if args.mcp_action == "install":
        from . import mcp_install

        return mcp_install.run_install(
            Path(args.path).resolve(), editor=args.editor, print_only=args.print_only
        )
    from . import mcp_server

    mcp_server.serve(Path(args.path).resolve())
    return 0


# ---------------------------------------------------------------- spec (authoring)

#: Where ``spec new`` scaffolds a draft. Deliberately OUTSIDE ``.linebreak/spec/``
#: — that directory holds only APPROVED content; a draft next to the manifest
#: would blur the one line that matters (drafted vs. approved).
DRAFT_REL = str(Path(".linebreak") / "spec-draft.yml")

_DRAFT_TEMPLATE = """\
# LineBreak spec draft — acceptance criteria BEFORE approval.
#
# Author this with any tool you like (your editor, Claude Code, ChatGPT...),
# then a human approves it:
#
#     linebreak-gate spec approve {draft} --approver "Ana Lopez <ana@example.com>"
#
# Approval writes the bundle to .linebreak/spec/ and commits it. From there
# `linebreak-gate mcp` serves it to your editor's agent and `linebreak-gate
# check` enforces it in CI. This draft file itself is never read by the gate.
#
# Rules the approval will enforce:
#   - story/criterion ids: stable slugs (letters, digits, . _ -), unique
#     across the WHOLE file — approvals bind to bare criterion ids.
#   - check.type is a fixed vocabulary: build | tests | command | manual.
#     `tests` and `command` require a `payload` (what to run).
#     `manual` means a human must record a sign-off (`linebreak-gate signoff`).
#   - check.when: release marks a criterion that runs only at release
#     (`linebreak-gate check --stage release`, the default); `check --stage pr`
#     lists it as release-only without evaluating it. Use it for checks against
#     a shared staging environment so a regression there does not block every
#     PR. Absent means always.
stories:
  - id: example-story
    title: Replace me with a real story
    epic: example-epic
    criteria:
      - id: example-builds
        statement: The project builds cleanly.
        check:
          type: build
      - id: example-tests
        statement: Unit tests for the new behavior pass.
        check:
          type: tests
          payload: pytest tests/test_example.py
      - id: example-command
        statement: The linter reports no new issues.
        check:
          type: command
          payload: ruff check .
      - id: example-manual
        statement: A human verified the flow end to end in staging.
        check:
          type: manual
      - id: example-staging
        statement: The smoke script passes against the shared staging environment.
        check:
          type: command
          payload: ./scripts/smoke-staging.sh
          when: release
"""


def _cmd_spec_new(args: argparse.Namespace) -> int:
    """Scaffold a draft stories file a human (or their AI) fills in. Never
    touches ``.linebreak/spec/`` — drafting and approval stay distinct."""
    root = Path(args.path).resolve()
    out_path = Path(args.out) if args.out else root / DRAFT_REL
    if not out_path.is_absolute():
        out_path = root / out_path
    if out_path.exists() and not args.force:
        _err(f"{out_path} already exists — pass --force to overwrite it")
        return 1
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rel = _rel_or_abs(out_path, root)
    out_path.write_text(_DRAFT_TEMPLATE.format(draft=rel), encoding="utf-8")
    print(f"Draft written to {rel}. Edit the stories, then approve with:")
    print(f'  linebreak-gate spec approve {rel} --approver "Your Name <you@example.com>"')
    return 0


def _rel_or_abs(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _cmd_spec_approve(args: argparse.Namespace) -> int:
    """Approve a draft: validate, land it as ``.linebreak/spec/``, commit.

    The CLI counterpart of the desktop's spec-to-git handoff — same schema,
    same writer (:mod:`.spec_write`), so the bytes on disk never depend on
    which surface approved. The approval is attributed but UNSIGNED
    (``identity_source: client``, like sign-offs and overrides — human-typed,
    unverified); signed approvals are issued by the governance service.
    Exit 0 = approved (commit warnings printed, never fatal), 1 = environment
    failure (unwritable tree), 2 = invalid draft (fail closed on structure).
    """
    import datetime as _dt

    import yaml

    from . import spec_bundle, spec_write

    root = Path(args.path).resolve()
    draft_path = Path(args.draft)
    if not draft_path.is_absolute():
        draft_path = root / draft_path
    if not draft_path.exists():
        _err(f"draft not found: {draft_path}")
        return 2
    try:
        data = yaml.safe_load(draft_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        _err(f"could not parse {draft_path.name}: {e}")
        return 2
    errors = spec_bundle.validate_sidecar(data)
    if errors:
        _err(f"invalid draft — nothing approved ({len(errors)} error(s)):")
        for line in errors:
            print(f"  - {line}", file=sys.stderr)
        return 2
    stories = data["stories"]

    now = _dt.datetime.now(tz=_dt.UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    approval = {
        "role": args.role,
        "user_email": args.approver,
        "approved_by": args.approver,
        "approved_at": now,
        "gate": "spec-approve",
        # LIN-41: human-typed and unverified, same as sign-offs/overrides — an
        # auditor can tell this attribution was not account-backed.
        "identity_source": "client",
    }
    try:
        spec_write.write_bundle(
            root,
            stories,
            source_phase="cli",
            approval=approval,
            generated_at=now,
        )
    except (OSError, spec_bundle.SpecBundleError) as e:
        _err(f"could not write the bundle: {e}")
        return 1

    committed, warning = spec_write.commit_bundle(root, source_phase="cli")
    n = len(stories)
    print(f"Approved: {n} story(ies) landed in {spec_bundle.SPEC_DIR}/ by {args.approver}.")
    if committed:
        print("Committed to git (spec: approved acceptance criteria).")
    elif warning:
        print(f"WARNING: {warning}")
    print("Unsigned local approval — git history is the audit trail; cryptographically")
    print("signed, offline-verifiable approvals come from the governance service (license key).")
    print("Next: `linebreak-gate spec list` to review, `linebreak-gate mcp install`")
    print("to serve it to your editor, `linebreak-gate check` to enforce it in CI.")
    return 0


# ---------------------------------------------------------------- entrypoint


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--path", default=".", help="project root to scan (default: .)")
    p.add_argument(
        "--fail-on",
        choices=FAIL_ON_LEVELS,
        default=None,
        help="blocking severity floor; overrides .linebreak/gate.yml (default: critical)",
    )
    p.add_argument(
        "--format",
        choices=("summary", "json"),
        default="summary",
        help="output format (default: summary)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linebreak-gate",
        description="LineBreak security gate at the git/CI boundary",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run the dependency + code scan and gate on the result")
    _add_common(scan)

    report = sub.add_parser("report", help="human-readable summary of the recorded scan")
    _add_common(report)

    override = sub.add_parser(
        "override",
        help="record a human-approved override for one exact finding or criterion",
    )
    override.add_argument("--path", default=".", help="project root (default: .)")
    target = override.add_mutually_exclusive_group(required=True)
    target.add_argument("--finding", help="security finding id from `linebreak-gate scan` output")
    target.add_argument(
        "--criterion", help="acceptance-criterion id from `linebreak-gate check` output"
    )
    override.add_argument("--reason", required=True, help="why shipping despite this is acceptable")
    override.add_argument(
        "--approver",
        required=True,
        help="name/email of the human approving the override. In CI (GitHub, GitLab, "
        "Bitbucket, Azure Pipelines) or with a governance token "
        "(LINEBREAK_GOVERNANCE_BASE_URL/_TOKEN) the verified identity is recorded and this "
        "value is kept as declared_by",
    )
    override.add_argument(
        "--role",
        default=None,
        help="role from .linebreak/roles.yml this override is made under; inferred when the "
        "person holds exactly one role that allows it",
    )
    # Accepted risks expire: past the date the gate blocks again (expired_risk)
    # until the acceptance is renewed (a new record) or the risk is fixed.
    expiry = override.add_mutually_exclusive_group()
    expiry.add_argument(
        "--expires",
        metavar="YYYY-MM-DD",
        default=None,
        help="date the acceptance expires (required when risk_acceptance.required is true "
        "in .linebreak/gate.yml; capped by risk_acceptance.max_days)",
    )
    expiry.add_argument(
        "--days",
        type=int,
        metavar="N",
        default=None,
        help="alternative to --expires: the acceptance expires N days from today",
    )

    check = sub.add_parser(
        "check", help="evaluate the approved acceptance criteria against the working tree"
    )
    check.add_argument("--path", default=".", help="project root (default: .)")
    check.add_argument(
        "--format",
        choices=("summary", "json"),
        default="summary",
        help="output format (default: summary)",
    )
    # Scope (issue #256): per-story on PRs, the full bundle at release.
    scope = check.add_mutually_exclusive_group()
    scope.add_argument(
        "--story",
        dest="stories",
        action="append",
        metavar="ID",
        default=None,
        help="evaluate only this story's criteria (repeatable); an unknown id is exit 2",
    )
    scope.add_argument(
        "--started-only",
        action="store_true",
        help="evaluate only stories whose local state is doing/review/done; stories "
        "without a state are listed as not started and do not count",
    )
    check.add_argument(
        "--stage",
        choices=STAGES,
        default="release",
        help="release (default): evaluate every criterion in scope; pr: skip criteria "
        "marked `check.when: release` and list them as release-only (not evaluated)",
    )
    check.add_argument(
        "--manual",
        choices=MANUAL_POLICIES,
        default="block",
        help="how `manual` criteria without a sign-off affect the verdict: block "
        "(default, as before) or warn (reported as needs-signoff, not blocking)",
    )

    signoff = sub.add_parser(
        "signoff", help="record an attributed human sign-off for one `manual` criterion"
    )
    signoff.add_argument("--path", default=".", help="project root (default: .)")
    signoff.add_argument(
        "--criterion", required=True, help="criterion id from `linebreak-gate check` output"
    )
    signoff.add_argument(
        "--approver",
        required=True,
        help="name/email of the human signing off. In CI (GitHub, GitLab, Bitbucket, Azure "
        "Pipelines) or with a governance token (LINEBREAK_GOVERNANCE_BASE_URL/_TOKEN) the "
        "verified identity is recorded and this value is kept as declared_approver",
    )
    signoff.add_argument(
        "--role",
        default=None,
        help="role from .linebreak/roles.yml this sign-off is made under; inferred when the "
        "person holds exactly one role that allows it",
    )
    signoff.add_argument(
        "--note", required=True, help="what was verified (recorded with the sign-off)"
    )

    init = sub.add_parser(
        "init", help="set this repo up with the gate (workflow file, secrets, protection)"
    )
    init.add_argument("--path", default=".", help="repo root (default: .)")
    init.add_argument(
        "--fail-on",
        choices=FAIL_ON_LEVELS,
        default=None,
        help="also write .linebreak/gate.yml with this blocking floor",
    )
    init.add_argument(
        "--force", action="store_true", help="overwrite existing workflow/config files"
    )
    init.add_argument(
        "--non-interactive",
        action="store_true",
        help="never prompt; print deep links for the manual steps instead",
    )

    # The spec bundle (.linebreak/spec/): read-only inspection (list/next/
    # show/check) plus the tool-agnostic authoring path (new/approve) — draft
    # with any tool, approve with an attributed human on the record.
    spec = sub.add_parser("spec", help="author, approve, and inspect the spec bundle")
    spec_sub = spec.add_subparsers(dest="spec_action", required=True)
    spec_new = spec_sub.add_parser(
        "new", help="scaffold a draft stories file to fill in (never touches spec/)"
    )
    spec_new.add_argument("--path", default=".", help="project root (default: .)")
    spec_new.add_argument(
        "--out", default=None, help=f"where to write the draft (default: {DRAFT_REL})"
    )
    spec_new.add_argument("--force", action="store_true", help="overwrite an existing draft")
    spec_approve = spec_sub.add_parser(
        "approve", help="validate a draft and land it as the approved bundle, committed"
    )
    spec_approve.add_argument("draft", help="path to the draft stories file (YAML or JSON)")
    spec_approve.add_argument("--path", default=".", help="project root (default: .)")
    spec_approve.add_argument(
        "--approver", required=True, help="name/email of the human approving the spec"
    )
    spec_approve.add_argument(
        "--role",
        default="architect",
        help="role recorded with the approval (default: architect)",
    )
    spec_list = spec_sub.add_parser(
        "list", help="print approved stories, criteria, and approval attribution"
    )
    spec_list.add_argument("--path", default=".", help="project root to read (default: .)")
    # LIN-55 CLI equivalents of the MCP bridge — same information, any terminal.
    spec_next = spec_sub.add_parser(
        "next", help="the next approved story not yet done, per local story state"
    )
    spec_next.add_argument("--path", default=".", help="project root to read (default: .)")
    spec_show = spec_sub.add_parser(
        "show", help="one approved story in full: criteria, statements, check types"
    )
    spec_show.add_argument("story_id", help="story id from `linebreak-gate spec list`")
    spec_show.add_argument("--path", default=".", help="project root to read (default: .)")
    spec_check = spec_sub.add_parser(
        "check", help="run ONE story's criteria against the working tree"
    )
    spec_check.add_argument("story_id", help="story id from `linebreak-gate spec list`")
    spec_check.add_argument("--path", default=".", help="project root to read (default: .)")
    spec_check.add_argument(
        "--stage",
        choices=STAGES,
        default="release",
        help="pr: skip `check.when: release` criteria (listed as release-only), e.g. before "
        "pushing a PR; release (default): evaluate everything, as the release gate does",
    )

    # LIN-55 MCP bridge: serve the approved spec to the developer's editor.
    mcp = sub.add_parser(
        "mcp", help="serve the approved spec over MCP (stdio) to your editor's agent"
    )
    mcp.add_argument("--path", default=".", help="project root to serve (default: .)")
    mcp_sub = mcp.add_subparsers(dest="mcp_action")
    mcp.set_defaults(mcp_action=None)  # bare `mcp` = serve
    install = mcp_sub.add_parser("install", help="write your editor's MCP config for this repo")
    # SUPPRESS, not '.': a subparser's default would silently clobber a --path
    # given before the subcommand (`mcp --path X install`); with SUPPRESS the
    # parent's value survives and an install-side --path still wins when given.
    install.add_argument("--path", default=argparse.SUPPRESS, help="repo root (default: .)")
    from . import mcp_install as _mcp_install

    install.add_argument(
        "--editor",
        choices=_mcp_install.EDITORS,
        default=None,
        help="which editor config to write (omit to print the generic stdio config)",
    )
    install.add_argument(
        "--print",
        dest="print_only",
        action="store_true",
        help="print the config instead of writing any file",
    )

    # Ticket mirroring: the tracker never blocks a verdict, so failed
    # operations queue up in .linebreak/audit/tickets.json and `sync` replays them.
    tickets_p = sub.add_parser(
        "tickets", help="ticket-tracker mirroring of accepted risks (Jira, GitHub Issues)"
    )
    tickets_sub = tickets_p.add_subparsers(dest="tickets_action", required=True)
    tickets_sync = tickets_sub.add_parser(
        "sync", help="retry the pending ticket operations recorded by override/scan/check"
    )
    tickets_sync.add_argument("--path", default=".", help="project root (default: .)")

    publish = sub.add_parser(
        "publish", help="send the recorded gate run to a governance service (never blocks)"
    )
    publish.add_argument("--to", required=True, help="governance service base URL")
    publish.add_argument(
        "--project", default=None, help="project id on the service (or LINEBREAK_GOV_PROJECT)"
    )
    publish.add_argument("--path", default=".", help="project root (default: .)")
    publish.add_argument(
        "--stage",
        choices=STAGES,
        default=None,
        help="stage to report (default: the stage recorded by `check`, else release)",
    )
    publish.add_argument(
        "--run-id",
        default=None,
        help="idempotency key (default: derived from the CI run, else random)",
    )
    publish.add_argument(
        "--dry-run", action="store_true", help="print the body that would be sent; send nothing"
    )

    badge = sub.add_parser("badge", help="print a ready-to-paste 'gated by LineBreak' README badge")
    badge.add_argument(
        "--format",
        choices=("markdown", "html", "url"),
        default="markdown",
        help="snippet flavor: README markdown, an <a><img> tag, or the bare "
        "shields.io URL (default: markdown)",
    )
    return parser


def _harden_stdio() -> None:
    """Never let output encoding turn into a false verdict: on a console that
    can't encode our glyphs (Windows cp1252 with redirected stdout), a bare
    print would raise UnicodeEncodeError and exit 1 — misreporting a clean run
    as a failure. Degrade unencodable chars instead of crashing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):  # not a reconfigurable TextIO
            pass


def main(argv: list[str] | None = None) -> int:
    _harden_stdio()
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "report":
            return _cmd_report(args)
        if args.command == "init":
            from . import init_cmd

            # No usable stdin (CI, piped scripts) degrades to deep links —
            # prompts must never hang or crash a scripted run.
            has_tty = sys.stdin is not None and sys.stdin.isatty()
            return init_cmd.run_init(
                path=args.path,
                fail_on=args.fail_on,
                force=args.force,
                interactive=not args.non_interactive and has_tty,
            )
        if args.command == "spec":
            if args.spec_action == "new":
                return _cmd_spec_new(args)
            if args.spec_action == "approve":
                return _cmd_spec_approve(args)
            if args.spec_action == "next":
                return _cmd_spec_next(args)
            if args.spec_action == "show":
                return _cmd_spec_show(args)
            if args.spec_action == "check":
                return _cmd_spec_check(args)
            return _cmd_spec_list(args)
        if args.command == "mcp":
            return _cmd_mcp(args)
        if args.command == "badge":
            return _cmd_badge(args)
        if args.command == "publish":
            return _cmd_publish(args)
        if args.command == "check":
            return _cmd_check(args)
        if args.command == "signoff":
            return _cmd_signoff(args)
        if args.command == "tickets":
            return _cmd_tickets_sync(args)
        # override: dispatch on WHICH target was supplied (the group is
        # required, so exactly one of finding/criterion is present) — never on
        # truthiness, or an explicit empty `--criterion ""` would fall through
        # to the CVE path and deref a None `--finding`.
        if args.criterion is not None:
            return _cmd_override_criterion(args)
        return _cmd_override(args)
    except GateConfigError as e:
        _err(f"config error: {e}")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
