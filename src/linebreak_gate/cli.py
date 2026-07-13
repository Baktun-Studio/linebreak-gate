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

from . import code_scan, entitlements, llm, security_scan
from . import security_artifact as sa
from .gate_config import FAIL_ON_LEVELS, GateConfig, GateConfigError, resolve_config
from .security_scan import _norm_severity
from .verdict import evaluate, finding_id, finding_rank

# CI audit records live with the gate config, committed to the repo. Same
# document format as the desktop's _bmad-output/security artifacts.
AUDIT_DIR = str(Path(".linebreak") / "audit")

_STATUS_LABELS = {
    "blocking": "BLOCKING",
    "acknowledged": "ACKNOWLEDGED (override on record)",
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


def _override_ids(doc: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    for entry in doc.get("approvals") or []:
        if not isinstance(entry, dict) or entry.get("decision") != "override":
            continue
        finding = entry.get("finding")
        if isinstance(finding, dict) and finding.get("id"):
            ids.add(str(finding["id"]))
    return ids


def _write_scan_artifact(
    root: Path, name: str, kind: str, result: dict[str, Any], actor: str
) -> dict[str, Any]:
    """Write the scan artifact, carrying the existing approval trail forward so
    recorded overrides survive rescans (they live in the committed artifact)."""
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
    return sa.write_artifact(root, name, doc, base_dir=AUDIT_DIR)


def _detector_payload(
    doc: dict[str, Any] | None, detector: str, cfg: GateConfig, override_ids: set[str]
) -> dict[str, Any] | None:
    if doc is None or doc.get("kind") is None:
        return None
    findings = doc.get("findings") or []
    verdict = evaluate(findings, fail_on=cfg.fail_on, override_ids=override_ids, detector=detector)
    return {
        "scanner": doc.get("scanner"),
        "generated_at": doc.get("generated_at"),
        "counts": _counts(findings),
        "findings": verdict["findings"],
        "blocking": verdict["blocking"],
        "acknowledged": verdict["acknowledged"],
        "passes": verdict["passes"],
    }


def _evaluate_all(
    cfg: GateConfig,
    sec_doc: dict[str, Any] | None,
    code_doc: dict[str, Any] | None,
    *,
    code_skipped: str | None = None,
) -> dict[str, Any]:
    override_ids: set[str] = set()
    for doc in (sec_doc, code_doc):
        if doc:
            override_ids |= _override_ids(doc)
    dependencies = _detector_payload(sec_doc, "dep", cfg, override_ids)
    code = _detector_payload(code_doc, "code", cfg, override_ids)
    passes = all(p["passes"] for p in (dependencies, code) if p is not None)
    return {
        "passes": passes,
        "fail_on": cfg.fail_on,
        "fail_on_source": cfg.fail_on_source,
        "dependencies": dependencies,
        "code": code,
        "code_skipped": code_skipped,
    }


def _print_findings(payload: dict[str, Any], detector: str) -> None:
    # Worst first, ranked by the SAME rule that decides blocking (severity
    # string with CVSS fallback) so the printed order can't contradict the
    # verdict.
    ordered = sorted(payload["findings"], key=finding_rank, reverse=True)
    for f in ordered:
        status = _STATUS_LABELS.get(f.get("status"), "below floor")
        label = f.get("cve_id") or f.get("title") or "(unidentified)"
        if detector == "dep":
            subject = f"{f.get('package')}@{f.get('installed_version')}"
            fix = f" fix: {f['fixed_version']}" if f.get("fixed_version") else ""
        else:
            subject = f"{f.get('file')}:{f.get('line')}"
            fix = ""
        cvss = f" cvss {f['cvss']}" if f.get("cvss") is not None else ""
        print(f"  [{status}] {label}  {f.get('severity')}{cvss}  {subject}{fix}")
        if f.get("advisory_url"):
            print(f"      {f['advisory_url']}")
        print(f"      id: {f['id']}")


def _emit(payload: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    print(f"LineBreak security gate — fail on: {payload['fail_on']} ({payload['fail_on_source']})")
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
        _print_findings(part, detector)
        if key == "code" and payload.get("code_skipped"):
            print(f"Code scan note: {payload['code_skipped']}")
    deps, code = payload["dependencies"], payload["code"]
    blocking_total = sum(len(p["blocking"]) for p in (deps, code) if p is not None)
    if payload["passes"]:
        print("VERDICT: PASS — no blocking findings.")
    else:
        print(
            f"VERDICT: BLOCKED — {blocking_total} blocking finding(s) at/above "
            f"'{payload['fail_on']}'. Fix them or record a human-approved override "
            "(linebreak-gate override --finding <id> --reason ... --approver ...)."
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

    actor = _actor()
    sec_doc = _write_scan_artifact(root, "security", "cve_scan", dep_result, actor)
    code_doc: dict[str, Any] | None = None
    if code_result is not None:
        code_doc = _write_scan_artifact(root, "code", "code_scan", code_result, actor)
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

    payload = _evaluate_all(cfg, sec_doc, code_doc, code_skipped=code_skipped)
    _emit(payload, args.format)
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
    payload = _evaluate_all(cfg, sec_doc, code_doc)
    _emit(payload, args.format)
    return 0


def _cmd_override(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    reason = (args.reason or "").strip()
    approver = (args.approver or "").strip()
    if not reason:
        _err("a non-empty --reason is required to record an override")
        return 2
    if not approver:
        _err("a non-empty --approver (name/email) is required to record an override")
        return 2

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
    sa.append_approval(
        root,
        name,
        approval_id=uuid.uuid4().hex,
        role="approver",
        decision="override",
        user_email=approver,
        notes=reason,
        finding=record,
        base_dir=AUDIT_DIR,
    )
    rel = Path(AUDIT_DIR) / f"{name}.json"
    print(
        f"Override recorded for {args.finding} by {approver} in {rel} — commit this "
        "file so the acknowledgment applies in CI. It covers this exact finding "
        "only; a different CVE or version still blocks."
    )
    return 0


# ---------------------------------------------------------------- criteria (Piece 3)

_RESULT_ICONS = {
    "pass": "✓",
    "fail": "✗",
    "needs-signoff": "●",
    "overridden": "→",
    "error": "!",
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
}


def _result_icons() -> dict[str, str]:
    enc = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        "".join(_RESULT_ICONS.values()).encode(enc)
    except (UnicodeEncodeError, LookupError):
        return _RESULT_ICONS_ASCII
    return _RESULT_ICONS


def _emit_check_notice(fmt: str, status: str, message: str) -> None:
    """A non-evaluating check outcome (disabled / no-bundle). Honors --format
    json so the machine-readable contract holds on EVERY path, not just when a
    bundle is present."""
    if fmt == "json":
        print(json.dumps({"passes": True, "status": status, "message": message}, indent=2))
    else:
        print(message)


def _cmd_check(args: argparse.Namespace) -> int:
    """Evaluate the approved acceptance criteria against the working tree.

    Exit 0: all satisfied, criteria disabled, or no bundle (teams using only
    the security scan are unaffected). Exit 1: any fail / needs-signoff.
    Exit 2: malformed bundle/sign-offs, invalid config, or an unrunnable
    check — fail closed, never misreported as pass or code failure.
    """
    from . import criteria_check, signoffs, spec_bundle

    root = Path(args.path).resolve()
    cfg = resolve_config(root)
    if not cfg.criteria_enforce:
        _emit_check_notice(
            args.format,
            "disabled",
            "Acceptance criteria: enforcement DISABLED (criteria.enforce: false in "
            f"{Path('.linebreak') / 'gate.yml'}). The security scan is unaffected.",
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
            "add LINEBREAK_LICENSE_KEY (generated in the desktop app, Settings → Security). "
            "It currently runs without one; a license will be required once enforcement "
            "is enabled.",
            file=sys.stderr,
        )
    try:
        payload = criteria_check.evaluate_bundle(root, write_artifact=True, actor=_actor())
    except spec_bundle.SpecBundleError as e:
        _err(f"malformed spec bundle (gate stays closed): {e}")
        return 2
    except signoffs.SignoffError as e:
        _err(f"sign-off records unreadable (gate stays closed): {e}")
        return 2
    if payload is None:
        _emit_check_notice(
            args.format,
            "no-bundle",
            "Acceptance criteria: no approved criteria found (.linebreak/spec/ absent) — "
            "nothing to enforce. Approve a spec in the LineBreak app to arm this check.",
        )
        return 0
    _emit_check(payload, args.format)
    if payload["tool_error"]:
        return 2
    return 0 if payload["passes"] else 1


def _emit_check(payload: dict[str, Any], fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2))
        return
    b = payload["bundle"]
    print(
        f"LineBreak acceptance criteria — bundle from {b['source_phase']} "
        f"({b['generated_at']}), approved by {b['approved_by']}, {b['stories']} story(ies)"
    )
    icons = _result_icons()
    counts: dict[str, int] = {}
    for r in payload["criteria"]:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
        icon = icons.get(r["result"], "?")
        check = r["check"]
        spec = check["type"] + (f": {check['payload']}" if check.get("payload") else "")
        print(f"  {icon} [{r['result']}] {r['story']}/{r['id']}  ({spec})  {r['statement']}")
        if r.get("signoff"):
            s = r["signoff"]
            print(f"      signed off by {s['approver']} at {s['signed_at']}: {s['note']}")
        if r.get("override"):
            o = r["override"]
            print(f"      overridden by {o['approver']}: {o['reason']}")
        if r["result"] in ("fail", "error") and r.get("detail"):
            first = r["detail"].strip().splitlines()
            print(f"      {first[0][:200]}" if first else "")
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
    if payload["tool_error"]:
        print(
            f"VERDICT: ERROR — {summary}. A check could not RUN (unsupported stack or "
            "missing runner); fix the runner or declare it as a `command` criterion. "
            "The gate fails closed."
        )
    elif payload["passes"]:
        print(f"VERDICT: PASS — all acceptance criteria satisfied ({summary}).")
    else:
        print(
            f"VERDICT: BLOCKED — {summary}. Fix the code, record a sign-off for `manual` "
            "criteria (linebreak-gate signoff), or record an attributed override "
            "(linebreak-gate override --criterion <id> ...)."
        )


def _cmd_signoff(args: argparse.Namespace) -> int:
    from . import signoffs

    root = Path(args.path).resolve()
    try:
        record = signoffs.record_signoff(
            root, criterion_id=args.criterion, approver=args.approver, note=args.note
        )
    except signoffs.SignoffError as e:
        _err(str(e))
        return 2
    rel = signoffs.SIGNOFFS_DIR
    print(
        f"Sign-off recorded for {args.criterion} by {record['approver']} under {rel}/ — "
        "commit it so the approval applies in CI. It binds to the criterion as approved "
        "TODAY: editing the criterion and re-approving the spec makes this sign-off stale."
    )
    return 0


def _cmd_override_criterion(args: argparse.Namespace) -> int:
    from . import criteria_check

    root = Path(args.path).resolve()
    try:
        criteria_check.record_criterion_override(
            root, criterion_id=args.criterion, reason=args.reason, approver=args.approver
        )
    except criteria_check.CriteriaToolError as e:
        _err(str(e))
        return 2
    rel = Path(AUDIT_DIR) / "criteria.json"
    print(
        f"Override recorded for criterion {args.criterion} by {args.approver} in {rel} — "
        "commit this file so it applies in CI. It covers this criterion AS CURRENTLY "
        "WORDED only; editing the criterion re-arms the check. Other criteria still block."
    )
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
        epic = f" [{story['epic']}]" if story.get("epic") else ""
        print(f"\n{story['id']}{epic} — {story['title']}")
        for c in story["criteria"]:
            check = c["check"]
            payload = f": {check['payload']}" if check.get("payload") else ""
            print(f"  [{check['type']}{payload}] {c['id']}  {c['statement']}")
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
        "--approver", required=True, help="name/email of the human approving the override"
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

    signoff = sub.add_parser(
        "signoff", help="record an attributed human sign-off for one `manual` criterion"
    )
    signoff.add_argument("--path", default=".", help="project root (default: .)")
    signoff.add_argument(
        "--criterion", required=True, help="criterion id from `linebreak-gate check` output"
    )
    signoff.add_argument("--approver", required=True, help="name/email of the human signing off")
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

    # Read-only view of the approved spec bundle (.linebreak/spec/). This is
    # the Piece-3 seam: NO enforcement, no scan changes, no blocking behavior.
    spec = sub.add_parser("spec", help="inspect the approved spec bundle (.linebreak/spec/)")
    spec_sub = spec.add_subparsers(dest="spec_action", required=True)
    spec_list = spec_sub.add_parser(
        "list", help="print approved stories, criteria, and approval attribution"
    )
    spec_list.add_argument("--path", default=".", help="project root to read (default: .)")
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
            return _cmd_spec_list(args)
        if args.command == "check":
            return _cmd_check(args)
        if args.command == "signoff":
            return _cmd_signoff(args)
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
