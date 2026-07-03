"""CS2 (A4) — the first-party code-scan engine.

The construction analogue of ``security_scan`` (which scans *dependencies* for
known CVEs): this scans the *code the agent wrote* for discoverable
vulnerabilities (injection / auth / secret-exposure / crypto), writing a
``code_scan`` security artifact the combined gate (CS3) reads alongside the
``cve_scan``.

Detection is LLM-based, so ``scan_code`` takes injected ``discover`` and
``verify`` callables — the agent tool (CS2b) wires the real model-backed ones
(Anthropic's ``security-review`` prompt for discovery + adversarial skeptics for
verification); tests pass deterministic fakes. The orchestration here — normalize,
adversarially filter, score, **fail closed** — is pure and deterministically
tested.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import security_artifact
from .security_scan import _norm_severity, _path_excluded, compute_risk_score

_SCANNER = "claude-code-scan"
_ARTIFACT_NAME = "code"

# Source extensions worth scanning (first-party code; dependency CVEs are the
# cve_scan's job). Binaries / data / lockfiles are skipped.
_SOURCE_EXT = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".go",
    ".rb",
    ".java",
    ".php",
    ".cs",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".sql",
    ".sh",
    ".html",
    ".vue",
    ".svelte",
}
# Directories never worth scanning (vendored deps, build output, VCS, artifacts).
_SKIP_DIRS = {
    "node_modules",
    ".venv",
    "venv",
    ".git",
    "dist",
    "build",
    "__pycache__",
    ".next",
    "target",
    "vendor",
    "_bmad-output",
    ".bmad-output",
    "coverage",
    ".turbo",
}


def parse_findings(raw: Any) -> list[dict[str, Any]]:
    """Normalize raw discovery output into the canonical code-finding envelope,
    dropping noise (non-dicts, and entries with nothing identifying). Severity is
    normalized to critical|high|medium|low|unknown; ``line`` is kept only when an
    int."""
    out: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return out
    for f in raw:
        if not isinstance(f, dict):
            continue
        # Require something identifying — a title or a category — so a malformed
        # blob can't masquerade as a finding (and silently inflate the count).
        title = f.get("title") or f.get("category")
        if not title:
            continue
        out.append(
            {
                "category": f.get("category"),
                "severity": _norm_severity(f.get("severity")),
                "file": f.get("file"),
                "line": f.get("line") if isinstance(f.get("line"), int) else None,
                "title": title,
                "description": f.get("description"),
                "remediation": f.get("remediation"),
                "confidence": f.get("confidence"),
            }
        )
    return out


def scan_code(
    project_root: str,
    *,
    discover: Callable[[str], Any],
    verify: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    """Discover first-party code vulnerabilities, adversarially verify each, and
    return the surviving findings + a risk score.

    ``discover(project_root)`` returns raw findings; ``verify(finding)`` returns
    True when the finding survives skepticism (real) and False when refuted (a
    false positive to drop). Both are injected so the LLM stays out of the unit
    tests.

    **Fail closed**: if discovery raises, return an error result with NO findings
    so the gate stays blocked (a failed scan is never a clean pass). A verifier
    that *crashes* keeps its finding — never silently drop a possibly-real bug.
    """
    try:
        raw = discover(project_root)
    except Exception as e:  # noqa: BLE001 — any discovery failure must fail closed
        return {
            "findings": [],
            "risk_score": None,
            "scanner": None,
            "error": f"code scan failed: {e}",
        }

    kept: list[dict[str, Any]] = []
    for finding in parse_findings(raw):
        try:
            survives = verify(finding)
        except Exception:  # noqa: BLE001 — conservative: keep on verifier error
            survives = True
        if survives:
            kept.append(finding)
    return {
        "findings": kept,
        "risk_score": compute_risk_score(kept),
        "scanner": _SCANNER,
        "error": None,
    }


def _summarize(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return f"Code scan clean — no discoverable vulnerabilities ({_SCANNER})."
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.get("severity") or "unknown"] = by_sev.get(f.get("severity") or "unknown", 0) + 1
    parts = ", ".join(f"{n} {sev}" for sev, n in by_sev.items())
    return f"{len(findings)} code finding(s) ({parts}) via {_SCANNER}."


def run_code_scan_and_write(
    project_root: str | None,
    *,
    discover: Callable[[str], Any],
    verify: Callable[[dict[str, Any]], bool],
) -> dict[str, Any]:
    """Run the code scan and write the ``code_scan`` artifact. Mirrors
    ``security_scan.run_scan_and_write``: a failed scan writes NOTHING (fail
    closed) so the gate stays blocked."""
    if not project_root:
        return {"ok": False, "error": "no active project; open or create one first"}
    result = scan_code(project_root, discover=discover, verify=verify)
    if result.get("error"):
        return {
            "ok": False,
            "scanner": None,
            "error": result["error"],
            "artifact_written": False,
        }
    findings = result.get("findings") or []
    doc = security_artifact.new_artifact(
        "code_scan",
        id="security",
        findings=findings,
        risk_score=result.get("risk_score"),
        summary=_summarize(findings),
        scanner=result.get("scanner"),
    )
    security_artifact.write_artifact(project_root, _ARTIFACT_NAME, doc)
    return {
        "ok": True,
        "scanner": _SCANNER,
        "findings_count": len(findings),
        "risk_score": result.get("risk_score"),
        "artifact_path": f"_bmad-output/security/{_ARTIFACT_NAME}.json",
        "artifact_written": True,
        "summary": _summarize(findings),
    }


# --------------------------------------------------------------------------
# CS2b — the real LLM-backed discover/verify (adapted from Anthropic's
# `security-review` methodology). The model call is isolated behind `ask` so the
# discovery/verification logic stays unit-testable with an injected fake.
# --------------------------------------------------------------------------

_DISCOVERY_SYSTEM = (
    "You are a security reviewer. Find HIGH-CONFIDENCE, exploitable vulnerabilities "
    "in the first-party source below: injection (SQL/command/path/template/XXE), "
    "broken authentication/authorization, secret exposure, SSRF, unsafe "
    "deserialization, and cryptographic misuse. IGNORE code style, dependency CVEs "
    "(a separate scanner covers those), and purely theoretical issues. Return ONLY a "
    "JSON array (use [] when there are none). Each item: "
    '{"category","severity"(critical|high|medium|low),"file","line"(integer),'
    '"title","description","remediation","confidence"(0.0-1.0)}.'
)
_SKEPTIC_SYSTEM = (
    "You are an adversarial reviewer trying to REFUTE a reported vulnerability. "
    "Decide whether it is a REAL, exploitable issue or a FALSE POSITIVE. Default to "
    "REFUTED when uncertain. Reply with exactly one word: REAL or REFUTED."
)

# An `ask` invokes the model: ``ask(system_prompt, user_prompt) -> text``.
Ask = Callable[[str, str], str]


def _gather_changeset(
    project_root: str,
    *,
    max_files: int = 40,
    max_bytes: int = 200_000,
    exclude_paths: list[str] | None = None,
) -> list[tuple[str, str]]:
    """Collect first-party source files to scan, skipping vendored deps, build
    output, and binaries, bounded by ``max_files`` / ``max_bytes`` so a huge repo
    can't blow up the prompt. (v1 baseline scope; git-diff incremental is a
    refinement.)"""
    root = Path(project_root)
    files: list[tuple[str, str]] = []
    total = 0
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip-dirs IN PLACE so os.walk never descends into a huge
        # node_modules/.venv — the caps bound the prompt, not the traversal.
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        for name in sorted(filenames):
            if len(files) >= max_files or total >= max_bytes:
                return files
            p = Path(dirpath) / name
            if p.suffix.lower() not in _SOURCE_EXT:
                continue
            rel = p.relative_to(root).as_posix()
            if _path_excluded(rel, exclude_paths):
                continue
            try:
                # A single oversized file (committed bundle, generated dump)
                # must not blow the prompt budget past max_bytes on its own.
                if p.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            try:
                content = p.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            files.append((rel, content))
            total += len(content)
    return files


def build_discovery_prompt(files: list[tuple[str, str]]) -> str:
    blocks = [f"=== {rel} ===\n{content}" for rel, content in files]
    return "Review the following first-party source files:\n\n" + "\n\n".join(blocks)


def _coerce_findings(snippet: str) -> list[dict[str, Any]] | None:
    """Parse one snippet into a findings list, or None if not parseable.

    Decides array-vs-object by the FIRST structural char so an inner array field
    (e.g. ``"cwe":[89]`` on a lone finding object) can't masquerade as the
    payload — that mis-slice was a fail-OPEN. Accepts a bare array, a
    ``{"findings":[...]}`` wrapper, or a single finding object.
    """
    s = snippet.strip()
    if not s:
        return None
    a, o = s.find("["), s.find("{")
    starts = [(i, c) for i, c in ((a, "["), (o, "{")) if i != -1]
    if not starts:
        return None
    start, kind = min(starts)  # whichever bracket opens first
    end = s.rfind("]" if kind == "[" else "}")
    if end <= start:
        return None
    try:
        data = json.loads(s[start : end + 1])
    except (ValueError, TypeError):
        return None
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "results", "vulnerabilities"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]  # a lone finding object the model forgot to wrap
    return None


def _extract_findings(text: Any) -> list[dict[str, Any]]:
    """Parse the findings out of a model response — tolerant of ```json fences,
    surrounding prose, a single unwrapped finding object, and a ``{findings:[...]}``
    wrapper. Tries each fenced block in order, then the whole text; returns [] on
    anything unparseable (the caller treats empty discovery as 'clean'; a
    model/transport failure is raised separately so it fails closed)."""
    if not isinstance(text, str) or not text.strip():
        return []
    # Each fenced block first (a leading prose fence must not shadow a later JSON
    # fence), then the whole text as a fallback.
    snippets = [m.group(1) for m in re.finditer(r"```(?:json)?\s*(.+?)```", text, re.DOTALL)]
    snippets.append(text)
    for snippet in snippets:
        parsed = _coerce_findings(snippet)
        if parsed is not None:
            return parsed
    return []


def llm_discover(
    project_root: str, *, ask: Ask, exclude_paths: list[str] | None = None
) -> list[dict[str, Any]]:
    """Discover first-party vulnerabilities via the security-review prompt. Skips
    the model entirely when there's no source to scan."""
    files = _gather_changeset(project_root, exclude_paths=exclude_paths)
    if not files:
        return []
    return _extract_findings(ask(_DISCOVERY_SYSTEM, build_discovery_prompt(files)))


def _skeptic_prompt(finding: dict[str, Any]) -> str:
    keep = {
        k: finding.get(k) for k in ("category", "severity", "file", "line", "title", "description")
    }
    return f"Reported finding:\n{json.dumps(keep, indent=2)}\n\nREAL or FALSE POSITIVE?"


def llm_verify(finding: dict[str, Any], *, ask: Ask, votes: int = 3) -> bool:
    """Adversarially verify a finding: poll ``votes`` independent skeptics and
    keep it only if a MAJORITY call it REAL. Substitutes for sandbox PoC
    verification (not feasible in the desktop flow), per the A4 sign-off."""
    real = 0
    for i in range(votes):
        verdict = (ask(_SKEPTIC_SYSTEM, _skeptic_prompt(finding)) or "").strip().upper()
        if verdict.startswith("REAL"):
            real += 1
        remaining = votes - i - 1
        # Early exit once the outcome is decided: majority already reached, or
        # unreachable even if every remaining skeptic says REAL. Saves model
        # calls without changing any verdict.
        if real * 2 >= votes or (real + remaining) * 2 < votes:
            break
    return real * 2 >= votes
