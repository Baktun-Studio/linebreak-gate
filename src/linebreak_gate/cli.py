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
    if notice:
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
                    "set ANTHROPIC_API_KEY (gate stays closed)"
                )
                return 2
            code_skipped = "no ANTHROPIC_API_KEY (dependency scan only)"
            _err(
                "code scan skipped: no ANTHROPIC_API_KEY. Set the key to enable the "
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
        "override", help="record a human-approved override for one exact finding"
    )
    override.add_argument("--path", default=".", help="project root (default: .)")
    override.add_argument(
        "--finding", required=True, help="finding id from `linebreak-gate scan` output"
    )
    override.add_argument(
        "--reason", required=True, help="why shipping with this finding is acceptable"
    )
    override.add_argument(
        "--approver", required=True, help="name/email of the human approving the override"
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
    return parser


def main(argv: list[str] | None = None) -> int:
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
        return _cmd_override(args)
    except GateConfigError as e:
        _err(f"config error: {e}")
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
