"""Acceptance-criteria enforcement at the boundary (LIN-37, Piece 3 of LIN-28).

Evaluates the approved spec bundle (``.linebreak/spec/``, written on gate
approval by the desktop app — LIN-35) against the working tree:

* ``build`` / ``tests`` / ``command`` — machine checks, run for real. The
  runner for ``build``/``tests`` is resolved from a CLOSED, documented stack
  table; an unresolvable runner is a TOOL ERROR (exit-2 material), never a
  silent pass and never a fail blamed on the code. ``command`` runs the
  declared payload in the repo root — same trust model as any CI step.
* ``manual`` — cannot be machine-verified. Satisfied ONLY by a recorded,
  attributed sign-off (:mod:`signoffs`); otherwise it blocks as
  needs-signoff. Never an LLM's own claim of compliance.
* Overrides — a failed machine check can be overridden with reason +
  approver, recorded in the audit artifact (``.linebreak/audit/
  criteria.json``, same format as CVE overrides) and bound to the criterion's
  content hash: editing the criterion re-arms the check.

Results per criterion: ``pass | fail | needs-signoff | overridden | error``.
The bundle loader fails closed on malformation (SpecBundleError → exit 2).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import approval_sig, signoffs, spec_bundle
from . import security_artifact as sa

AUDIT_DIR = str(Path(".linebreak") / "audit")
ARTIFACT_NAME = "criteria"

#: Ceiling for one machine check. CI runners impose their own job timeouts;
#: this one exists so a hung build fails THIS criterion with a message instead
#: of eating the whole job silently.
CHECK_TIMEOUT_S = 30 * 60


class CriteriaToolError(Exception):
    """A check could not be RUN (unsupported stack, missing runner) — exit-2
    material: fail closed, never misreport tool trouble as a code failure."""


class BundleSignatureError(Exception):
    """A verification key is configured (``gate.yml`` ``approvals.public_keys``)
    but the bundle's signed approval is missing, untrusted, tampered, or does
    not cover this bundle — the gate BLOCKS (exit 1). Distinct from
    :class:`spec_bundle.SpecBundleError` (malformed structure, exit 2): this is a
    governance BLOCK on a well-formed but unverifiable bundle."""


def verify_bundle_signature(
    bundle: dict[str, Any], approval_public_keys: tuple[tuple[str, str], ...]
) -> dict[str, Any] | None:
    """Verify the manifest's ``signed_approval`` envelope OFFLINE (LIN-51).

    ``approval_public_keys`` is the ``(kid, public_key_b64)`` list from
    ``gate.yml``. This function makes NO network call — it holds public keys and
    verifies locally.

    * Empty list → unsigned mode: returns ``None``. This is the ONLY path that
      skips verification, and it keys off CONFIG, never off the manifest, so an
      attacker cannot strip the signature to downgrade to honest-unsigned.
    * Non-empty → signature REQUIRED. Raises :class:`BundleSignatureError` when
      the ``signed_approval`` block is absent, its ``kid`` is untrusted, the
      signature does not verify, the ``artifact_hash`` does not equal
      :func:`spec_bundle.bundle_hash` (the bundle was edited after approval), or
      the signed ``phase`` does not match the manifest ``source_phase``.

    Returns the verified payload dict on success.
    """
    if not approval_public_keys:
        return None
    manifest = bundle["manifest"]
    envelope = manifest.get("signed_approval")
    if not isinstance(envelope, dict):
        raise BundleSignatureError(
            "a signed approval is REQUIRED (approvals.public_keys is configured in "
            ".linebreak/gate.yml) but this bundle carries no signed_approval block — refusing "
            "to treat an unsigned bundle as approved"
        )
    keys = {kid: approval_sig.public_key_from_b64(pub) for kid, pub in approval_public_keys}
    try:
        payload = approval_sig.verify_envelope(envelope, keys)
    except approval_sig.ApprovalSignatureError as e:
        raise BundleSignatureError(str(e)) from e
    expected_hash = spec_bundle.bundle_hash(bundle)
    if payload.get("artifact_hash") != expected_hash:
        raise BundleSignatureError(
            "the signed approval does not cover this bundle — it was edited after it was "
            f"approved (bundle hashes to {expected_hash}, the approval signed "
            f"{payload.get('artifact_hash')})"
        )
    source_phase = manifest.get("source_phase")
    if payload.get("phase") != source_phase:
        raise BundleSignatureError(
            f"the signed approval is for phase {payload.get('phase')!r} but this bundle's "
            f"source_phase is {source_phase!r}"
        )
    # Carry the verifying key id for honest output (it is not part of the signed
    # payload, but naming which trusted key verified it is useful in the gate log).
    payload["kid"] = envelope.get("kid")
    return payload


@dataclass(frozen=True)
class RunOutcome:
    ok: bool
    detail: str


# ---------------------------------------------------------------- runner resolution
# A closed, documented table (see docs/CRITERIA_ENFORCEMENT.md). Deliberately
# conservative: anything outside it is a CriteriaToolError telling the team to
# declare a `command` criterion instead — we never guess a build system.


def _node_package(root: Path) -> dict[str, Any] | None:
    pkg = root / "package.json"
    if not pkg.exists():
        return None
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (ValueError, OSError) as e:
        raise CriteriaToolError(f"package.json is unreadable: {e}") from e
    return data if isinstance(data, dict) else None


def _node_runner(root: Path) -> str:
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (root / "yarn.lock").exists():
        return "yarn"
    return "npm"


def resolve_build_command(root: Path) -> list[str]:
    """The build command for this stack, or CriteriaToolError."""
    pkg = _node_package(root)
    if pkg is not None:
        scripts = pkg.get("scripts") or {}
        if isinstance(scripts, dict) and "build" in scripts:
            return [_node_runner(root), "run", "build"]
        raise CriteriaToolError(
            "package.json has no `build` script — add one, or declare the build as a "
            "`command` criterion"
        )
    if (root / "Cargo.toml").exists():
        return ["cargo", "build"]
    if (root / "go.mod").exists():
        return ["go", "build", "./..."]
    raise CriteriaToolError(
        "no supported build stack detected (package.json build script, Cargo.toml, go.mod) — "
        "declare the build as a `command` criterion instead"
    )


_PY_MARKERS = ("pyproject.toml", "pytest.ini", "setup.cfg", "setup.py", "tox.ini")


def resolve_tests_command(root: Path, payload: str) -> list[str]:
    """The test command for this stack + pattern, or CriteriaToolError.

    Payload extension wins over stack markers so a polyglot repo resolves
    deterministically (documented). A payload whose extension names ONE
    ecosystem is never handed to another ecosystem's runner — a JS payload
    with no Node test runner is a tool error, not `cargo test <file>` (which
    would match zero tests and exit 0, a silent pass)."""
    is_py = payload.endswith(".py") or "::" in payload
    is_js = payload.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"))
    # sys.executable, not bare "python": the current interpreter is the one the
    # gate (and thus the project's pytest, if co-installed) runs under; bare
    # "python" is absent on stock macOS and may resolve to a pytest-less env.
    if is_py or (not is_js and any((root / m).exists() for m in _PY_MARKERS)):
        return [sys.executable, "-m", "pytest", payload]
    if is_js or _node_package(root) is not None:
        pkg = _node_package(root)
        deps: dict[str, Any] = {}
        for key in ("devDependencies", "dependencies"):
            block = (pkg or {}).get(key)
            if isinstance(block, dict):
                deps.update(block)
        if "vitest" in deps:
            return ["npx", "--no-install", "vitest", "run", payload]
        if "jest" in deps:
            return ["npx", "--no-install", "jest", payload]
        raise CriteriaToolError(
            "no supported Node test runner detected (vitest or jest in package.json) — "
            "declare the test run as a `command` criterion"
        )
    if (root / "go.mod").exists():
        return ["go", "test", payload]
    if (root / "Cargo.toml").exists():
        return ["cargo", "test", payload]
    raise CriteriaToolError(
        "no supported test stack detected (pytest markers, vitest/jest, go.mod, Cargo.toml) — "
        "declare the test run as a `command` criterion"
    )


#: How long a runner-availability probe may take. Probes are `--version`
#: calls; anything slower than this is broken tooling.
_PROBE_TIMEOUT_S = 120

#: Cap on captured output kept per check. A 30-minute build can emit gigabytes;
#: we only ever show the tail, so bound what we hold in memory (avoids OOM-ing
#: the runner on a chatty command).
_OUTPUT_TAIL = 4000


def _which(exe: str) -> str:
    """Resolve an executable to a full path, so Windows console shims
    (``npm.cmd``, ``npx.cmd``, ``yarn.cmd``) — which ``CreateProcess`` can't
    launch by bare name — run as any other tool. Raises CriteriaToolError when
    the tool isn't on PATH (fail closed, exit 2 — never a code failure)."""
    resolved = shutil.which(exe)
    if resolved is None:
        raise CriteriaToolError(
            f"runner {exe!r} is not on PATH — install the project's toolchain in the job "
            "before the gate step, or declare the check as a `command` criterion"
        )
    return resolved


def probe_command(argv: list[str]) -> list[str]:
    """The cheap availability probe for a resolved runner command.

    A missing runner often exits with the SAME code as a genuine failure
    (`pytest` without pytest installed exits 1), so without a probe the gate
    would blame the code for tool trouble. Probing first keeps the boundary
    honest: broken tooling is exit-2 material, a red test is exit-1 material.
    """
    # `<python> -m <mod>` → `<python> -m <mod> --version`
    if len(argv) >= 3 and argv[1] == "-m":
        return [argv[0], "-m", argv[2], "--version"]
    if argv[:2] == ["npx", "--no-install"]:
        return ["npx", "--no-install", argv[2], "--version"]
    if argv[0] == "go":
        return ["go", "version"]
    return [argv[0], "--version"]


def _capture(proc: subprocess.CompletedProcess[str]) -> str:
    tail = (proc.stdout + proc.stderr)[-_OUTPUT_TAIL:].strip()
    return f"exit {proc.returncode}\n{tail}".strip()


def _execute(cmd: list[str] | str, root: Path, *, shell: bool = False) -> RunOutcome:
    """Run a resolved command, capping captured output. Timeout → fail (not a
    tool error: the check genuinely didn't pass in time)."""
    try:
        proc = subprocess.run(
            cmd, shell=shell, cwd=root, capture_output=True, text=True, timeout=CHECK_TIMEOUT_S
        )
    except subprocess.TimeoutExpired:
        return RunOutcome(ok=False, detail=f"timed out after {CHECK_TIMEOUT_S}s")
    return RunOutcome(ok=proc.returncode == 0, detail=_capture(proc))


def _run_argv(argv: list[str], root: Path) -> RunOutcome:
    # Resolve argv[0] to a real path first (handles Windows .cmd shims and
    # surfaces a missing runner as a clean tool error, not a launch crash).
    argv = [_which(argv[0]), *argv[1:]]
    probe = [_which(probe_command(argv)[0]), *probe_command(argv)[1:]]
    try:
        result = subprocess.run(
            probe, cwd=root, capture_output=True, text=True, timeout=_PROBE_TIMEOUT_S
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        raise CriteriaToolError(f"runner not available on this machine: {e}") from e
    if result.returncode != 0:
        raise CriteriaToolError(
            f"runner `{' '.join(probe_command(argv)[:3])}` is not available here: "
            f"{(result.stdout + result.stderr).strip()[-300:]}"
        )
    return _execute(argv, root)


def default_runner(criterion: dict[str, Any], root: Path) -> RunOutcome:
    """Execute one machine criterion for real. Raises CriteriaToolError when
    the runner can't be resolved (fail closed)."""
    check = criterion["check"]
    ctype = check["type"]
    if ctype == "build":
        return _run_argv(resolve_build_command(root), root)
    if ctype == "tests":
        return _run_argv(resolve_tests_command(root, check["payload"]), root)
    if ctype == "command":
        # Runs on the client's CI runner with the repo's own trust model —
        # exactly like any other CI step the team declares (documented).
        return _execute(check["payload"], root, shell=True)
    raise CriteriaToolError(f"unknown check type {ctype!r}")  # pragma: no cover — schema-blocked


# ---------------------------------------------------------------- overrides


def _read_criteria_doc(root: Path) -> dict[str, Any]:
    """Read the criteria audit artifact, failing CLOSED on corruption.

    ``sa.read_artifact`` returns an empty doc for both absence and corruption,
    which is right for scans but wrong here: a corrupt ``criteria.json`` holds
    the attributed override trail, and silently treating it as empty would let
    the next check overwrite (erase) it. So if the file exists but doesn't
    parse as a valid artifact, raise — a corrupt governance record is exit-2
    material, exactly like a malformed sign-off."""
    file = sa.artifact_path(root, ARTIFACT_NAME, base_dir=AUDIT_DIR)
    doc = sa.read_artifact(root, ARTIFACT_NAME, base_dir=AUDIT_DIR)
    if file.exists() and doc.get("kind") is None:
        raise CriteriaToolError(
            f"{Path(AUDIT_DIR) / f'{ARTIFACT_NAME}.json'} is present but unreadable/corrupt — "
            "the override trail can't be trusted; fix or restore it (the gate stays closed "
            "rather than silently discard recorded overrides)"
        )
    return doc


def _criterion_overrides(root: Path) -> list[dict[str, Any]]:
    doc = _read_criteria_doc(root)
    out: list[dict[str, Any]] = []
    for entry in doc.get("approvals") or []:
        if isinstance(entry, dict) and entry.get("decision") == "override":
            finding = entry.get("finding")
            if isinstance(finding, dict) and finding.get("criterion_id"):
                out.append(entry)
    return out


def _matching_override(
    overrides: list[dict[str, Any]], criterion: dict[str, Any]
) -> dict[str, Any] | None:
    """An override valid for this criterion's CURRENT content — same staleness
    rule as sign-offs: the record binds to the content hash, so editing the
    criterion re-arms the check."""
    want = spec_bundle.criterion_hash(criterion)
    for entry in overrides:
        finding = entry["finding"]
        if finding["criterion_id"] == criterion["id"] and finding.get("criterion_hash") == want:
            return entry
    return None


def record_criterion_override(
    project_root: Path | str, *, criterion_id: str, reason: str, approver: str
) -> dict[str, Any]:
    """Record a human-approved override for one failed machine criterion, in
    the same audit format as CVE overrides. Raises CriteriaToolError on a
    missing bundle/criterion or a `manual` target (manual wants a sign-off)."""
    root = Path(project_root)
    reason = reason.strip()
    approver = approver.strip()
    if not reason or not approver:
        raise CriteriaToolError("--reason and --approver are both required for an override")
    try:
        bundle = spec_bundle.load_bundle(root)
    except spec_bundle.SpecBundleError as e:
        raise CriteriaToolError(f"malformed spec bundle: {e}") from e
    if bundle is None:
        raise CriteriaToolError(f"no approved spec bundle ({spec_bundle.SPEC_DIR}/ absent)")
    try:
        story, criterion = spec_bundle.find_criterion(bundle, criterion_id)
    except spec_bundle.SpecBundleError as e:
        raise CriteriaToolError(str(e)) from e
    if criterion["check"]["type"] == "manual":
        raise CriteriaToolError(
            f"criterion {criterion_id!r} is `manual` — it wants a recorded sign-off "
            "(`linebreak-gate signoff ...`), not an override"
        )
    record = {
        "criterion_id": criterion_id,
        "story_id": story["id"],
        "statement": criterion["statement"],
        "check_type": criterion["check"]["type"],
        "criterion_hash": spec_bundle.criterion_hash(criterion),
        "bundle_generated_at": bundle["manifest"].get("generated_at"),
    }
    # Ensure the artifact exists with the right kind before appending.
    existing = sa.read_artifact(root, ARTIFACT_NAME, base_dir=AUDIT_DIR)
    if existing.get("kind") is None:
        doc = sa.new_artifact(
            "criteria_check", id="criteria", summary="criteria overrides (no check recorded yet)"
        )
        sa.write_artifact(root, ARTIFACT_NAME, doc, base_dir=AUDIT_DIR)
    return sa.append_approval(
        root,
        ARTIFACT_NAME,
        approval_id=uuid.uuid4().hex,
        role="approver",
        decision="override",
        user_email=approver,
        notes=reason,
        finding=record,
        identity_source="client",  # LIN-41: human-typed, unverified
        base_dir=AUDIT_DIR,
    )


# ---------------------------------------------------------------- evaluation


def _evaluate_criterion(
    criterion: dict[str, Any],
    story_id: str,
    root: Path,
    records: list[dict[str, Any]],
    overrides: list[dict[str, Any]],
    run: Callable[[dict[str, Any], Path], RunOutcome],
    run_cache: dict[tuple[str, str], RunOutcome | CriteriaToolError],
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": criterion["id"],
        "story": story_id,
        "statement": criterion["statement"],
        "check": criterion["check"],
    }
    if criterion["check"]["type"] == "manual":
        match = signoffs.matching_signoff(records, criterion)
        if match:
            entry["result"] = "pass"
            entry["signoff"] = {
                "approver": match["approver"],
                "note": match["note"],
                "signed_at": match["signed_at"],
            }
        else:
            entry["result"] = "needs-signoff"
        return entry

    # Run the check even when an override is on file: an override MASKS an
    # actual failure, it doesn't skip verification. So a criterion that now
    # passes is reported `pass` (honest), and `overridden` only ever shows for
    # a check that genuinely failed — no "overridden" badge on green checks,
    # and a preemptive override can't hide that a check is currently passing.
    key = (criterion["check"]["type"], criterion["check"].get("payload") or "")
    cached = run_cache.get(key)
    if cached is None:
        try:
            cached = run(criterion, root)
        except CriteriaToolError as e:
            cached = e
        run_cache[key] = cached
    if isinstance(cached, CriteriaToolError):
        entry["result"] = "error"
        entry["detail"] = str(cached)
        return entry
    if cached.ok:
        entry["result"] = "pass"
    else:
        override = _matching_override(overrides, criterion)
        if override:
            entry["result"] = "overridden"
            entry["override"] = {
                "approver": override.get("user_email"),
                "reason": override.get("notes"),
            }
        else:
            entry["result"] = "fail"
    if cached.detail and entry["result"] != "overridden":
        entry["detail"] = cached.detail
    return entry


def evaluate_bundle(
    project_root: Path | str,
    *,
    run: Callable[[dict[str, Any], Path], RunOutcome] = default_runner,
    write_artifact: bool = False,
    actor: str | None = None,
    approval_public_keys: tuple[tuple[str, str], ...] = (),
) -> dict[str, Any] | None:
    """Evaluate every approved criterion against the working tree.

    Returns None when no bundle exists (teams without an approved spec are
    unaffected). Raises SpecBundleError on a malformed bundle and SignoffError
    on malformed sign-off records (both exit-2 at the CLI: fail closed).

    Result: ``{"passes": bool, "tool_error": bool, "criteria": [...],
    "bundle": {...}}`` — each criterion entry carries ``result`` in
    ``pass | fail | needs-signoff | overridden | error`` plus attribution for
    sign-offs and overrides.
    """
    root = Path(project_root)
    bundle = spec_bundle.load_bundle(root)
    if bundle is None:
        return None
    # Verify the signed approval BEFORE running any check: an unverifiable
    # bundle is not trustworthy, so we don't spend a build on it. Raises
    # BundleSignatureError (exit 1) when a key is configured but the bundle is
    # unsigned/tampered/untrusted; returns None in unsigned mode.
    signed = verify_bundle_signature(bundle, approval_public_keys)
    records = signoffs.load_signoffs(root)
    overrides = _criterion_overrides(root)

    # Memoize identical machine checks within one pass: two stories that each
    # declare `build` (no payload) resolve to the same run — do the work once.
    run_cache: dict[tuple[str, str], RunOutcome | CriteriaToolError] = {}

    results = [
        _evaluate_criterion(criterion, story["id"], root, records, overrides, run, run_cache)
        for story in bundle["stories"]
        for criterion in story["criteria"]
    ]

    tool_error = any(r["result"] == "error" for r in results)
    blocking = [r for r in results if r["result"] in ("fail", "needs-signoff", "error")]
    payload = {
        "passes": not blocking,
        "tool_error": tool_error,
        "criteria": results,
        "bundle": {
            "generated_at": bundle["manifest"].get("generated_at"),
            "source_phase": bundle["manifest"].get("source_phase"),
            "approved_by": (bundle["manifest"].get("approval") or {}).get("approved_by"),
            "stories": len(bundle["stories"]),
            # Honest signature status: "verified" only when a key was configured
            # AND the signed approval checked out; "unsigned" when no key is
            # configured (the bundle carries no cryptographic assurance). Never
            # implies more assurance than exists.
            "signature": "verified" if signed else "unsigned",
            "signed_by": signed.get("approver_email") if signed else None,
            "signing_kid": signed.get("kid") if signed else None,
            # Surface a self-approval to the CI auditor (only ever true in a solo
            # org). Signed, so it cannot be stripped from the record.
            "self_approved": bool(signed.get("self_approved")) if signed else False,
        },
    }
    if write_artifact:
        _write_results_artifact(root, payload, actor=actor)
    return payload


def _write_results_artifact(root: Path, payload: dict[str, Any], *, actor: str | None) -> None:
    """Record the evaluation in ``.linebreak/audit/criteria.json`` — same
    versioned document format as the scans, carrying the approval trail
    (overrides) forward so they survive re-checks."""
    prior = sa.read_artifact(root, ARTIFACT_NAME, base_dir=AUDIT_DIR)
    counts: dict[str, int] = {}
    for r in payload["criteria"]:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "no criteria"
    doc = sa.new_artifact(
        "criteria_check",
        id="criteria",
        findings=[
            {k: r.get(k) for k in ("id", "story", "statement", "check", "result", "detail")}
            for r in payload["criteria"]
        ],
        summary=f"acceptance criteria: {summary}",
        scanner="linebreak-gate check",
    )
    doc["approvals"] = prior.get("approvals") or []
    doc["bundle"] = payload["bundle"]
    if actor:
        doc["actor"] = actor
    sa.write_artifact(root, ARTIFACT_NAME, doc, base_dir=AUDIT_DIR)
