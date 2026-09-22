"""E1.1 CVE scanner core — pure parsing of scanner output into the canonical
cve_scan finding shape the gate reads, plus a severity-based risk score.

Findings shape (one per vulnerability), matching what the gate's verdict policy
reads (lib/security-artifact.js): ``{cve_id, severity, cvss, package, ecosystem,
installed_version, fixed_version, advisory_url, title}``. ``severity`` is one of
critical|high|medium|low (lowercased) or "unknown".

The subprocess runner + lockfile detection live with the run_cve_scan tool;
these functions are pure so they are deterministically testable.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

_SEVERITY_SCORE = {"critical": 100, "high": 80, "medium": 50, "low": 20}


def _osv_bin() -> str:
    """The osv-scanner executable. Prefers the app-bundled binary (the Tauri
    shell points LINEBREAK_OSV_SCANNER_BIN at it), else ``osv-scanner`` on PATH.
    Bundling means users get cross-ecosystem dependency scanning with NO manual
    install — the gate isn't silently crippled in a packaged build."""
    return os.environ.get("LINEBREAK_OSV_SCANNER_BIN") or "osv-scanner"


# How long any single scanner subprocess may run before we treat it as a failed
# scan (fail closed). Dependency scans can be slow, but must be bounded — an
# unbounded scan would hang the agent turn at the security phase.
_SCAN_TIMEOUT_SECONDS = 180


def _norm_severity(value: Any) -> str:
    s = str(value or "").strip().lower()
    if s == "moderate":  # npm/GitHub vocab
        return "medium"
    if s in ("critical", "high", "medium", "low"):
        return s
    return "unknown"


def _parse_cvss(value: Any) -> float | None:
    """Coerce a CVSS score (osv-scanner emits it as a string like "9.8") to a
    positive float, or None when absent/zero/unparseable."""
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    return score if score > 0 else None


def _severity_from_cvss(score: float | None) -> str:
    """Map a CVSS base score to a severity band. Thresholds MUST match the gate's
    CVSS fallback (lib/security-artifact.js _findingRank) so the scanner and the
    gate agree: >=9 critical, >=7 high, >=4 medium, >0 low."""
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _ghsa_from_url(url: str | None) -> str | None:
    if not url:
        return None
    seg = url.rstrip("/").rsplit("/", 1)[-1]
    return seg if seg.startswith("GHSA-") else None


def parse_npm_audit(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse ``npm audit --json`` (npm v7+) into findings."""
    findings: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return findings
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, dict):
        return findings
    for pkg_name, info in vulns.items():
        if not isinstance(info, dict):
            continue
        pkg_severity = info.get("severity")
        fix = info.get("fixAvailable")
        fixed_version = fix.get("version") if isinstance(fix, dict) else None
        via_list = info.get("via")
        via_objs = (
            [v for v in via_list if isinstance(v, dict)] if isinstance(via_list, list) else []
        )
        if not via_objs:
            # Flagged only via transitive string refs — still record the package.
            findings.append(
                {
                    "cve_id": None,
                    "severity": _norm_severity(pkg_severity),
                    "cvss": None,
                    "package": info.get("name") or pkg_name,
                    "ecosystem": "npm",
                    "installed_version": None,
                    "fixed_version": fixed_version,
                    "advisory_url": None,
                    "title": None,
                }
            )
            continue
        for via in via_objs:
            cvss = via.get("cvss")
            cvss_score = cvss.get("score") if isinstance(cvss, dict) else None
            url = via.get("url")
            findings.append(
                {
                    "cve_id": via.get("cve") or _ghsa_from_url(url),
                    "severity": _norm_severity(via.get("severity") or pkg_severity),
                    "cvss": cvss_score,
                    "package": via.get("name") or info.get("name") or pkg_name,
                    "ecosystem": "npm",
                    "installed_version": None,
                    "fixed_version": fixed_version,
                    "advisory_url": url,
                    "title": via.get("title"),
                }
            )
    return findings


def _cve_from_aliases(aliases: Any, fallback: str | None) -> str | None:
    if isinstance(aliases, list):
        for a in aliases:
            if isinstance(a, str) and a.upper().startswith("CVE-"):
                return a
    return fallback


def _osv_cvss_by_id(groups: Any) -> dict[str, float]:
    """Map each vuln id/alias to its group's ``max_severity`` (a CVSS base score
    osv-scanner computes per alias-group). Many OSV records — especially PyPI,
    Go, and RustSec — omit ``database_specific.severity``, so this computed CVSS
    is the only severity signal; without it those findings would arrive as
    "unknown" (CVSS null), which the gate ranks 0 and lets through (fail open)."""
    out: dict[str, float] = {}
    if not isinstance(groups, list):
        return out
    for g in groups:
        if not isinstance(g, dict):
            continue
        score = _parse_cvss(g.get("max_severity"))
        if score is None:
            continue
        for key in ("ids", "aliases"):
            members = g.get(key)
            if isinstance(members, list):
                for m in members:
                    if isinstance(m, str):
                        # Worst CVSS wins: an id may appear in more than one group;
                        # a lower first-seen score must never mask a higher real one.
                        out[m] = max(out.get(m, 0.0), score)
    return out


def _segments_below_root(norm_path: str, root: Path | None) -> set[str]:
    """The path segments of an osv source path that lie BELOW the scan root.

    osv emits absolute paths and is invoked with ``str(root)`` as the target, so
    its results are prefixed by root. The skip-dir filter must match only
    segments below root — never root's own ancestors — otherwise a project that
    happens to live under a directory named e.g. ``build``/``target``/``dist``
    would have EVERY finding dropped → a false clean (the worst outcome). This
    mirrors ``_npm_audit_dirs``, which prunes only the walked subtree, not the
    path leading down to root. When root is unknown or the path isn't under it,
    fall back to every segment so genuine installed copies are still dropped."""
    if root is not None:
        root_norm = str(root).replace("\\", "/").rstrip("/")
        if norm_path.startswith(root_norm + "/"):
            return set(norm_path[len(root_norm) + 1 :].split("/"))
    return set(norm_path.split("/"))


def _rel_below_root(norm_path: str, root: Path | None) -> str:
    """The portion of an osv source path below the scan root (see
    _segments_below_root for why matching must be scoped below root), or the
    whole normalized path when root is unknown / the path isn't under it."""
    if root is not None:
        root_norm = str(root).replace("\\", "/").rstrip("/")
        if norm_path.startswith(root_norm + "/"):
            return norm_path[len(root_norm) + 1 :]
    return norm_path


def _path_excluded(rel_posix: str, exclude_paths: list[str] | None) -> bool:
    """True when a root-relative posix path matches a configured exclusion.

    Patterns are fnmatch globs; a bare directory name/path excludes everything
    beneath it (``fixtures`` matches ``fixtures/vuln/lockfile``). Used for the
    repo-level ``exclude_paths`` in .linebreak/gate.yml — default None keeps
    behavior identical to the pre-CI-gate scanner."""
    for raw in exclude_paths or ():
        pat = str(raw).strip().strip("/")
        if not pat:
            continue
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(rel_posix, pat + "/*"):
            return True
    return False


def _osv_result_skipped(
    result: Any, root: Path | None = None, exclude_paths: list[str] | None = None
) -> bool:
    """Skip an osv result we don't want in findings: a malformed entry, or a
    lockfile under a directory we never treat as project source. `--no-ignore`
    makes osv scan every lockfile (so a gitignored-but-committed one is still
    seen — the point), but it also descends into installed/vendored/build dirs
    (node_modules, .venv, vendor, dist, build, target, ...). The project's own
    root/sub-package lockfiles already cover those, so drop any result whose path
    crosses a dir in _SKIP_WALK_DIRS *below the scan root* — the same set the
    npm-audit walk prunes — to avoid over-reporting installed copies the
    developer doesn't ship/track."""
    if not isinstance(result, dict):
        return True
    src = result.get("source")
    p = src.get("path") if isinstance(src, dict) else None
    if not isinstance(p, str):
        return False
    norm = p.replace("\\", "/")
    if _path_excluded(_rel_below_root(norm, root), exclude_paths):
        return True
    return bool(_segments_below_root(norm, root) & _SKIP_WALK_DIRS)


def parse_osv_scanner(
    data: dict[str, Any],
    root: Path | None = None,
    exclude_paths: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Parse ``osv-scanner --format json`` into findings (all ecosystems).

    ``root`` (the scanned project root) scopes the installed/vendored-dir filter
    to source paths below it — pass it so a project living under a skip-named
    ancestor (``build``/``target``/…) isn't wrongly emptied to a false clean."""
    findings: list[dict[str, Any]] = []
    if not isinstance(data, dict):
        return findings
    results = data.get("results")
    if not isinstance(results, list):
        return findings
    for result in results:
        if _osv_result_skipped(result, root, exclude_paths):
            continue
        packages = result.get("packages")
        if not isinstance(packages, list):
            continue
        for pkg in packages:
            if not isinstance(pkg, dict):
                continue
            meta = pkg.get("package") or {}
            name = meta.get("name")
            ecosystem = str(meta.get("ecosystem") or "").strip().lower() or None
            version = meta.get("version")
            cvss_by_id = _osv_cvss_by_id(pkg.get("groups"))
            vulns = pkg.get("vulnerabilities")
            if not isinstance(vulns, list):
                continue
            for v in vulns:
                if not isinstance(v, dict):
                    continue
                vid = v.get("id")
                db = v.get("database_specific")
                db_sev = db.get("severity") if isinstance(db, dict) else None
                cvss = cvss_by_id.get(vid)
                # Prefer the advisory's explicit severity label; fall back to the
                # band derived from osv-scanner's computed CVSS so a real critical
                # never reaches the gate as "unknown".
                severity = _norm_severity(db_sev)
                if severity == "unknown":
                    severity = _severity_from_cvss(cvss)
                findings.append(
                    {
                        "cve_id": _cve_from_aliases(v.get("aliases"), vid),
                        "severity": severity,
                        "cvss": cvss,
                        "package": name,
                        "ecosystem": ecosystem,
                        "installed_version": version,
                        "fixed_version": None,
                        "advisory_url": f"https://osv.dev/vulnerability/{vid}" if vid else None,
                        "title": v.get("summary"),
                    }
                )
    return findings


def _finding_weight(finding: dict[str, Any]) -> int:
    """Severity weight for one finding, falling back to the finding's CVSS band
    so a cvss-only finding (recognized severity word absent) is not scored 0 —
    which would contradict the gate, whose verdict also falls back to CVSS."""
    weight = _SEVERITY_SCORE.get(_norm_severity(finding.get("severity")), 0)
    if weight == 0:
        # Mirror the gate's CVSS coercion (Number(cvss)): _parse_cvss also accepts
        # a numeric string, so a string CVSS is not silently scored 0.
        band = _severity_from_cvss(_parse_cvss(finding.get("cvss")))
        weight = _SEVERITY_SCORE.get(band, 0)
    return weight


def compute_risk_score(findings: list[dict[str, Any]]) -> int | None:
    """A 0-100 risk score = the worst finding's severity weight; None if clean.

    Deliberately simple and deterministic. (The CVE MCP's ``calculate_risk_score``
    also weights EPSS/KEV; that can refine this later.)
    """
    if not findings:
        return None
    return max(_finding_weight(f) for f in findings)


def _run_scanner(run, cmd: list[str], **kwargs) -> subprocess.CompletedProcess | None:
    """Run a scanner subprocess with a bounded timeout, returning the completed
    process or ``None`` on ANY failure (timeout, missing binary, OS error). A
    scanner that hung or crashed must surface as None → the caller falls through
    and ultimately fails closed; it must never look like a clean scan."""
    try:
        return run(cmd, capture_output=True, text=True, timeout=_SCAN_TIMEOUT_SECONDS, **kwargs)
    except (subprocess.SubprocessError, OSError):
        return None


def _result(findings: list[dict[str, Any]], scanner: str) -> dict[str, Any]:
    return {
        "findings": findings,
        "risk_score": compute_risk_score(findings),
        "scanner": scanner,
        "error": None,
    }


def _no_scan(error: str) -> dict[str, Any]:
    """Fail-closed result: nothing was scanned, so the caller must keep the gate
    blocked (NOT treat empty findings as a clean pass)."""
    return {"findings": [], "risk_score": None, "scanner": None, "error": error}


# Directories never worth walking for workspace lockfiles.
_SKIP_WALK_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".venv",
        "venv",
        "dist",
        "build",
        ".next",
        "target",
        "vendor",
        "coverage",
        "_bmad-output",
        ".bmad-output",
        "__pycache__",
    }
)
# Cap how many workspaces we shell ``npm audit`` into so a pathological tree
# can't fan out into hundreds of subprocesses.
_AUDIT_DISCOVERY_CAP = 40


def _npm_audit_dirs(root: Path, exclude_paths: list[str] | None = None) -> list[Path]:
    """Directories ``npm audit`` can scan — those with a ``package-lock.json`` (it
    needs a lockfile), walking ``root`` and skipping vendored/build dirs. A
    monorepo with per-workspace lockfiles yields each; a single root lockfile
    (npm workspaces) yields just the root (one audit covers the hoisted tree).
    Capped to bound the subprocess fan-out."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = Path(dirpath).relative_to(root).as_posix()
        dirnames[:] = [
            d
            for d in dirnames
            if d not in _SKIP_WALK_DIRS
            and not _path_excluded(d if rel == "." else f"{rel}/{d}", exclude_paths)
        ]
        if "package-lock.json" in filenames:
            # Honor exclusions against BOTH the workspace dir and its lockfile
            # path, so `sandbox/*` and file-shaped globs behave the same here
            # as on the osv path (same verdict regardless of scanner engine).
            lock_rel = "package-lock.json" if rel == "." else f"{rel}/package-lock.json"
            if _path_excluded(rel, exclude_paths) or _path_excluded(lock_rel, exclude_paths):
                continue
            found.append(Path(dirpath))
            if len(found) >= _AUDIT_DISCOVERY_CAP:
                break
    return found


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse duplicate findings (same package + advisory) that aggregating
    across workspaces — or a recursive osv scan — produces: the same dependency
    vuln in N places is one vuln. On a key collision KEEP THE HIGHER-SEVERITY
    finding (CVSS as tiebreak, via _finding_weight). A blind first-wins would let
    a low-severity copy seen first MASK an at/above-floor sibling sharing the key
    (e.g. two workspaces flagging the same package at different severities; npm
    transitive-only findings collide on an all-None advisory key) — and since the
    gate blocks by filtering this deduped array (NOT risk_score), that masking
    would pass a project that must block: a false clean."""
    best: dict[tuple[Any, Any], dict[str, Any]] = {}
    order: list[tuple[Any, Any]] = []
    for f in findings:
        key = (f.get("package"), f.get("cve_id") or f.get("advisory_url") or f.get("title"))
        prev = best.get(key)
        if prev is None:
            best[key] = f
            order.append(key)
        elif _finding_weight(f) > _finding_weight(prev):
            best[key] = f
    return [best[k] for k in order]


def scan_project(
    project_root: str | Path,
    *,
    run=subprocess.run,
    which=shutil.which,
    exclude_paths: list[str] | None = None,
) -> dict[str, Any]:
    """Run a dependency CVE scan on a project and return its findings.

    Stack-agnostic: prefers ``osv-scanner`` (one tool, all ecosystems via OSV.dev),
    falling back to ``npm audit`` for npm projects (zero-install). Returns
    ``{findings, risk_score, scanner, error}``. A CLEAN scan = empty findings +
    ``error`` None. If NO scanner could successfully run, findings is empty,
    scanner is None, and ``error`` is set — the caller must NOT treat that as a
    pass (fail closed). A scanner that RAN but could not audit (e.g. npm with no
    lockfile) is a failure, never a clean pass.

    ``run`` / ``which`` are injectable for testing. ``exclude_paths``
    (root-relative globs, from .linebreak/gate.yml) drops findings whose source
    lockfile lives under an excluded path; default None is byte-identical to
    the pre-CI-gate behavior.
    """
    root = Path(project_root)

    # 1. osv-scanner — covers npm/pip/cargo/go/maven against OSV.dev. Resolved
    # from the bundled binary first (no user install), else PATH.
    # `--no-ignore`: scan EVERY lockfile, even ones the project .gitignores. A
    # repo standardized on pnpm commonly gitignores `package-lock.json`, yet a
    # sub-package may still COMMIT one (with real vulns). osv honors .gitignore
    # by default and would SILENTLY skip that lockfile, so the gate would
    # under-report — a false pass. The installed-dependency noise this could add
    # (lockfiles under node_modules) is dropped in parse_osv_scanner.
    osv = _osv_bin()
    if which(osv):
        proc = _run_scanner(run, [osv, "--format", "json", "-r", "--no-ignore", str(root)])
        # Exit 1 means "vulnerabilities found" (not an error); 0 means clean.
        # Any other code (127 bad-usage, 128 no-packages-found, timeout->None)
        # is NOT a usable scan -> fall through.
        if proc is not None and proc.returncode in (0, 1) and (proc.stdout or "").strip():
            try:
                data = json.loads(proc.stdout)
            except json.JSONDecodeError:
                data = None
            if isinstance(data, dict):
                # Dedupe across sources: `osv-scanner -r` reports the same
                # dependency vuln once per lockfile, so a vuln present in N
                # workspaces would otherwise inflate (and destabilize) the count.
                # Mirrors the npm-audit aggregation path below.
                return _result(
                    _dedupe_findings(parse_osv_scanner(data, root, exclude_paths)),
                    "osv-scanner",
                )

    # 2. npm audit — zero-install fallback for npm projects. MONOREPO-AWARE:
    # audit every workspace lockfile and aggregate into one canonical findings
    # list. A monorepo with per-workspace lockfiles (or no root lockfile at all)
    # still produces THE canonical cve_scan artifact instead of failing — the
    # failure that previously pushed the agent to roll its own per-workspace
    # scan + hand-write an artifact the gate couldn't read. Once npm is present
    # this branch OWNS the outcome (a result or an npm-specific failure).
    has_npm_project = (root / "package-lock.json").exists() or (root / "package.json").exists()
    if which("npm"):
        audit_dirs = _npm_audit_dirs(root, exclude_paths)
        if audit_dirs:
            all_findings: list[dict[str, Any]] = []
            failed = 0
            npm_err: str | None = None
            for d in audit_dirs:
                proc = _run_scanner(run, ["npm", "audit", "--json"], cwd=str(d))
                data = None
                if proc is not None and (proc.stdout or "").strip():
                    try:
                        data = json.loads(proc.stdout)
                    except json.JSONDecodeError:
                        data = None
                # A genuine npm v7+ audit ALWAYS carries a `vulnerabilities` map.
                # Anything else (ENOLOCK `error` object, npm v6 `advisories`, an
                # empty failure) means this workspace did NOT audit.
                if isinstance(data, dict) and isinstance(data.get("vulnerabilities"), dict):
                    all_findings.extend(parse_npm_audit(data))
                else:
                    failed += 1
                    if isinstance(data, dict) and isinstance(data.get("error"), dict):
                        npm_err = data["error"].get("summary") or data["error"].get("code")
            # Vulns found anywhere -> report them (block on the findings). Every
            # workspace audited clean -> a genuine clean. But if a lockfile
            # workspace could NOT be audited and nothing else turned up vulns,
            # fail CLOSED — a partial scan must never be reported as clean.
            if all_findings:
                return _result(_dedupe_findings(all_findings), "npm audit")
            if failed == 0:
                return _result([], "npm audit")
            return _no_scan(
                "npm audit could not complete"
                + (f": {npm_err}" if npm_err else f" for {failed} workspace(s)")
            )
        if has_npm_project:
            # npm is present and this is an npm project, but there's no lockfile
            # anywhere to audit — fail closed (npm WAS available, so this is an
            # npm-specific failure, not "no scanner").
            return _no_scan("npm audit could not complete (no lockfile? run `npm install` first)")

    return _no_scan(
        "no supported scanner available — install osv-scanner "
        "(brew install osv-scanner) for any stack, or ensure npm is on PATH "
        "for an npm project"
    )
