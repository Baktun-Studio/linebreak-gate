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

Results per criterion: ``pass | fail | needs-signoff | overridden | error``,
plus ``release-only`` for a ``check.when: release`` criterion at ``stage="pr"``
(not evaluated: neither pass nor fail), ``awaiting-attestation`` for a
``check.when: attestation`` criterion in the ``prepare`` phase of a release
(not evaluated: its sign-off attests the very run being prepared), and
``collision`` for a check on a shared ``resource`` that failed and then passed
when re-run alone (issue #262: a clash over the resource, not a defect).
The bundle loader fails closed on malformation (SpecBundleError → exit 2).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from . import (
    approval_sig,
    environment,
    gate_config,
    resource_lock,
    risk_acceptance,
    runner_counts,
    signoffs,
    spec_bundle,
    spec_integrity,
    story_state,
)
from . import identity as _identity
from . import roles as _roles
from . import security_artifact as sa

AUDIT_DIR = str(Path(".linebreak") / "audit")
ARTIFACT_NAME = "criteria"

#: How `manual` criteria without a sign-off affect the verdict (issue #256).
#: ``block`` is the historical behavior and the default; ``warn`` reports them
#: as needs-signoff (and lists them under ``pending_signoffs``) without
#: blocking, so a per-story PR check is not held by a sign-off that belongs to
#: the release.
MANUAL_POLICIES = ("block", "warn")

#: The check stage. ``release`` (default) evaluates every criterion in scope;
#: ``pr`` skips criteria marked ``check.when: release`` and reports them as
#: ``release-only`` (not evaluated, never pass nor fail). A release-only
#: criterion that fails at ``release`` still blocks: fail closed is unchanged.
STAGES = ("release", "pr")

#: The release phases. ``verify`` (default) enforces every criterion in scope.
#: ``prepare`` is the run an attestation is made ON: criteria marked
#: ``check.when: attestation`` are reported ``awaiting-attestation`` (not
#: evaluated, not blocking) because their sign-off can only exist after this
#: run; everything else, other manual criteria included, is enforced as usual.
#: The release is the ``verify`` run that follows, once the sign-off exists.
PHASES = ("verify", "prepare")

AWAITING_ATTESTATION = "awaiting-attestation"
COLLISION = "collision"

#: Local story states that count as "started" for ``started_only`` (the same
#: vocabulary the bridge writes; a story with no recorded state is not started).
STARTED_STATES = frozenset(story_state.VALID_STATES)

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
    """One executed check. ``detail`` is the printable tail; ``exit_code`` and
    ``output`` (a bounded copy of stdout and stderr) are what the gate
    inspects after the run: the test count (issue #259) and the criterion's
    ``expect`` block (issue #260). Runners that leave them unset are judged
    on ``ok`` and ``detail`` alone."""

    ok: bool
    detail: str
    exit_code: int | None = None
    output: str | None = None
    #: What the check measured, when it declares ``check.environment`` (#264).
    environment: dict[str, Any] | None = None
    #: The shared resource it held, when it declares ``check.resource`` (#262).
    resource: dict[str, Any] | None = None


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

#: How much of each stream is kept for inspection (test counts, ``expect``).
#: Runner summaries and the lines a check prints about its outcome are at the
#: end; half a megabyte per stream is far more than any summary needs.
_INSPECT_TAIL = 512 * 1024


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
    return RunOutcome(
        ok=proc.returncode == 0,
        detail=_capture(proc),
        exit_code=proc.returncode,
        output=f"{proc.stdout[-_INSPECT_TAIL:]}\n{proc.stderr[-_INSPECT_TAIL:]}",
    )


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


class _MeasuredRunner:
    """Wraps the runner with what a criterion declares about the world it runs
    against: the shared ``resource`` it must hold alone (#262) and the deployed
    ``environment`` whose version it measures (#264). A criterion that declares
    neither runs exactly as before."""

    def __init__(
        self,
        run: Callable[[dict[str, Any], Path], RunOutcome],
        *,
        env: Mapping[str, str],
        env_fetch: environment.Fetch | None,
        lock_timeout_s: float,
    ) -> None:
        self._run = run
        self._env = env
        self._env_fetch = env_fetch
        self._lock_timeout_s = lock_timeout_s

    def __call__(self, criterion: dict[str, Any], root: Path) -> RunOutcome:
        check = criterion["check"]
        resource = check.get("resource")
        if not resource:
            return self._measure(criterion, root)
        try:
            with resource_lock.hold(
                resource, holder=criterion["id"], timeout_s=self._lock_timeout_s
            ) as held:
                outcome = self._measure(criterion, root)
        except resource_lock.ResourceBusy as e:
            raise CriteriaToolError(str(e)) from e
        info = {"name": resource, "waited_s": held["waited_s"]}
        if held.get("waited_for"):
            info["waited_for"] = held["waited_for"]
        return replace(outcome, resource=info)

    def _measure(self, criterion: dict[str, Any], root: Path) -> RunOutcome:
        spec = criterion["check"].get("environment")
        if not isinstance(spec, dict):
            return self._run(criterion, root)
        before = environment.probe(spec, self._env, self._env_fetch)
        outcome = self._run(criterion, root)
        after = environment.probe(spec, self._env, self._env_fetch)
        record = environment.measure(spec, root, before, after, env=self._env)
        return replace(outcome, environment=record)


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
    criterion re-arms the check. When several records match (a renewal), the
    LATEST one is the effective acceptance; the earlier ones are history."""
    want = spec_bundle.criterion_hash(criterion)
    matching = [
        entry
        for entry in overrides
        if entry["finding"]["criterion_id"] == criterion["id"]
        and entry["finding"].get("criterion_hash") == want
    ]
    latest = risk_acceptance.latest_by_target(matching, lambda e: criterion["id"])
    return latest.get(criterion["id"])


def _select_override(
    overrides: list[dict[str, Any]],
    story: dict[str, Any],
    criterion: dict[str, Any],
    policy: _roles.RolesPolicy,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """:func:`_matching_override` under the roles in force: the LATEST
    hash-matching override the current policy accepts (a renewal supersedes
    the earlier record without erasing it), plus a denial record per
    hash-matching override it rejects (same contract as
    :func:`signoffs.select_signoff`)."""
    want = spec_bundle.criterion_hash(criterion)
    targets = _roles.criterion_targets(story, criterion)
    denials: list[dict[str, Any]] = []
    matching = [
        entry
        for entry in overrides
        if entry["finding"]["criterion_id"] == criterion["id"]
        and entry["finding"].get("criterion_hash") == want
    ]
    # Newest first: the effective acceptance is the most recent one the
    # policy accepts; older records are history (and denials, if rejected).
    for entry in sorted(matching, key=lambda e: str(e.get("at") or ""), reverse=True):
        # Entries recorded before roles existed carry the fixed word
        # "approver" in `role`; it is not a roster role unless the file names one.
        role = entry.get("role") if isinstance(entry.get("role"), str) else None
        if role == "approver" and policy.role("approver") is None:
            role = None
        by = str(entry.get("user_email") or "unknown")
        denial = _roles.verify_record(
            policy,
            kind="override",
            subject=by,
            keys=_roles.record_keys(entry, "user_email"),
            action="approve_overrides",
            targets=targets,
            role=role,
            identity_source=entry.get("identity_source"),
        )
        if denial is None:
            return entry, denials
        denials.append(_roles.denial_record(denial, kind="override", by=by, role=role))
    return None, denials


def record_criterion_override(
    project_root: Path | str,
    *,
    criterion_id: str,
    reason: str,
    approver: str | None = None,
    identity: _identity.Identity | None = None,
    role: str | None = None,
    policy: _roles.RolesPolicy | None = None,
    expires: str | None = None,
) -> dict[str, Any]:
    """Record a human-approved override for one failed machine criterion, in
    the same audit format as CVE overrides. Raises CriteriaToolError on a
    missing bundle/criterion, a `manual` target (manual wants a sign-off), or
    a person not authorized under ``.linebreak/roles.yml`` (the message names
    the roles that would be needed). ``identity`` / ``role`` / ``policy`` work
    as in :func:`signoffs.record_signoff`. ``expires`` (``YYYY-MM-DD``) bounds
    the exception in time; a renewal is a new record, the earlier one stays.
    Returns the recorded approval entry."""
    root = Path(project_root)
    reason = reason.strip()
    if identity is None:
        try:
            identity = _identity.client(approver or "")
        except _identity.IdentityError as e:
            raise CriteriaToolError(
                "--reason and --approver are both required for an override"
            ) from e
    if not reason:
        raise CriteriaToolError("--reason and --approver are both required for an override")
    if policy is None:
        policy = _roles.load_roles(root)
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
    try:
        role = _roles.authorize(
            policy,
            subject=identity.subject,
            keys=identity.keys(),
            action="approve_overrides",
            targets=_roles.criterion_targets(story, criterion),
            role=role,
        )
    except _roles.RoleDenied as e:
        raise CriteriaToolError(str(e)) from e
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
    approval_id = uuid.uuid4().hex
    doc = sa.append_approval(
        root,
        ARTIFACT_NAME,
        approval_id=approval_id,
        # The roster role the override is made under; "approver" is the
        # pre-roles placeholder, kept so the entry shape never changes.
        role=role or "approver",
        decision="override",
        user_email=identity.subject,
        notes=reason,
        finding=record,
        identity_source=identity.source,
        identity=identity.record(),
        declared_by=identity.declared,
        expires=expires,
        base_dir=AUDIT_DIR,
    )
    return next(e for e in doc["approvals"] if e.get("id") == approval_id)


# ---------------------------------------------------------------- scope


def _select_stories(
    root: Path,
    bundle: dict[str, Any],
    *,
    story_ids: set[str] | None,
    started_only: bool,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """The stories in scope, in bundle order, plus the ``scope`` block that
    the summary, the JSON, and the Action comment all render. Modes:

    * ``all``: every story (the historical behavior).
    * ``story``: only ``story_ids``; unknown ids are a CriteriaToolError.
    * ``started``: only stories with a started local state; the others are
      ``stories_skipped`` (the summary calls them "not started"). A scope
      that selects NO story is a CriteriaToolError (exit 2), never a pass:
      the state store is absent, unreadable, or managed by an external
      tracker without local states, and none of those is evidence that the
      bundle is satisfied.
    """
    all_stories = bundle["stories"]
    known = [s["id"] for s in all_stories]
    if story_ids is not None:
        unknown = sorted(story_ids - set(known))
        if unknown:
            raise CriteriaToolError(
                f"no approved story {', '.join(repr(u) for u in unknown)} in this spec "
                f"(approved stories: {', '.join(known)})"
            )
        selected = [s for s in all_stories if s["id"] in story_ids]
        mode = "story"
    elif started_only:
        states = story_state.read_states(root)
        selected = [s for s in all_stories if states.get(s["id"]) in STARTED_STATES]
        mode = "started"
        if not selected:
            raise CriteriaToolError(
                "--started-only selects no story: no approved story has a started local "
                f"state ({'/'.join(sorted(STARTED_STATES))}) in "
                f"{story_state.ARTIFACT_RELATIVE_PATH.as_posix()} (the file is absent, "
                "unreadable, or managed by an external tracker without local states). Mark "
                "the stories in progress (set_story_status from the editor bridge, or the "
                "`spec next` flow), pass --story <id>, or run the full check"
            )
    else:
        selected = list(all_stories)
        mode = "all"
    evaluated = {s["id"] for s in selected}
    scope = {
        "mode": mode,
        "stories_evaluated": [sid for sid in known if sid in evaluated],
        "stories_skipped": [sid for sid in known if sid not in evaluated],
    }
    return selected, scope


# ---------------------------------------------------------------- evaluation


#: The one sentence explaining a release-only entry (also what the Action's
#: comment regex anchors on, via the aggregated scope line).
RELEASE_ONLY_DETAIL = "not evaluated at stage pr (check.when: release)"
AWAITING_DETAIL = (
    "not evaluated in the prepare phase (check.when: attestation): sign it off against "
    "this run, then run the verify phase"
)

#: Why a test run that executed nothing is not a pass (issue #259).
ZERO_TESTS_DETAIL = (
    "0 tests ran: the runner finished without executing a single test (a path or filter "
    "that matches nothing checks nothing)"
)


def _judge_run(
    criterion: dict[str, Any], outcome: RunOutcome
) -> tuple[bool, list[str], int | None, bool, bool]:
    """Judge one executed machine check beyond its exit code.

    Returns ``(ok, notes, tests_run, counted, zero_tests)``:

    * the runner's own summary is read for the number of tests EXECUTED
      (:mod:`runner_counts`); a ``tests`` criterion that executed zero tests
      FAILS, whatever the exit code said (issue #259);
    * a declared ``expect`` block must be observed: the exit code it names
      (default 0) and every ``output`` string in the check's output
      (issue #260). A check that exits 0 for a different reason than the one
      the criterion states no longer passes;
    * ``zero_tests`` is true for a ``command`` criterion whose output shows a
      test runner that executed nothing: an integrity finding, governed by
      ``criteria.integrity.zero_tests``.
    """
    check = criterion["check"]
    ctype = check["type"]
    text = outcome.output if outcome.output is not None else outcome.detail
    ok = outcome.ok
    notes: list[str] = []
    tests_run: int | None = None
    counted = False
    if ctype in ("tests", "command"):
        count = runner_counts.count_tests(text)
        if count.runners:
            counted = True
            tests_run = count.executed
    expect = check.get("expect")
    if isinstance(expect, dict):
        want_exit = expect.get("exit", 0)
        got = outcome.exit_code
        # A runner that reports no exit code (a timeout) never satisfies an
        # expectation of a non-zero exit.
        exit_ok = (got == want_exit) if got is not None else (outcome.ok and want_exit == 0)
        if not exit_ok:
            shown = got if got is not None else "no exit code"
            notes.append(f"expected exit {want_exit}, got {shown}")
        raw = expect.get("output")
        wanted = [] if raw is None else (raw if isinstance(raw, list) else [raw])
        missing = [w for w in wanted if w not in text]
        if missing:
            notes.append("expected output not observed: " + ", ".join(repr(m) for m in missing))
        ok = exit_ok and not missing
    zero = counted and tests_run == 0
    if ctype == "tests" and zero:
        ok = False
        notes.append(ZERO_TESTS_DETAIL)
    return ok, notes, tests_run, counted, (ctype == "command" and zero and ok)


def _integrity_entries(
    findings: list[dict[str, Any]], policy: gate_config.IntegrityPolicy
) -> list[dict[str, Any]]:
    """The findings for one criterion with the policy that applies to each;
    ``off`` kinds are dropped."""
    out = []
    for f in findings:
        mode = policy.of(f["kind"])
        if mode == "off":
            continue
        out.append({"kind": f["kind"], "policy": mode, "detail": f["detail"]})
    return out


def _integrity_block_notes(entries: list[dict[str, Any]]) -> list[str]:
    return [
        f"integrity ({e['kind']}: block in criteria.integrity): {e['detail']}"
        for e in entries
        if e["policy"] == "block"
    ]


def _evaluate_criterion(
    criterion: dict[str, Any],
    story_id: str,
    root: Path,
    records: list[dict[str, Any]],
    overrides: list[dict[str, Any]],
    run: Callable[[dict[str, Any], Path], RunOutcome],
    run_cache: dict[tuple[str, str], RunOutcome | CriteriaToolError],
    stage: str = "release",
    policy: _roles.RolesPolicy = _roles.EMPTY_POLICY,
    story: dict[str, Any] | None = None,
    phase: str = "verify",
    integrity_findings: list[dict[str, Any]] | None = None,
    integrity_policy: gate_config.IntegrityPolicy | None = None,
) -> dict[str, Any]:
    integrity_policy = integrity_policy or gate_config.IntegrityPolicy()
    entry: dict[str, Any] = {
        "id": criterion["id"],
        "story": story_id,
        "statement": criterion["statement"],
        "check": criterion["check"],
    }
    story = story if story is not None else {"id": story_id}
    when = criterion["check"].get("when")
    if stage == "pr" and when in ("release", spec_bundle.ATTESTATION_WHEN):
        # NOT evaluated: the check never runs, the result is neither pass nor
        # fail, and the release check still owns it.
        entry["result"] = "release-only"
        entry["detail"] = RELEASE_ONLY_DETAIL
        return entry
    if phase == "prepare" and when == spec_bundle.ATTESTATION_WHEN:
        # NOT evaluated: this sign-off attests the run being prepared, so the
        # run cannot demand it of itself. The verify run enforces it.
        entry["result"] = AWAITING_ATTESTATION
        entry["detail"] = AWAITING_DETAIL
        return entry
    integrity = _integrity_entries(integrity_findings or [], integrity_policy)
    if criterion["check"]["type"] == "manual":
        if integrity:
            entry["integrity"] = integrity
        match, denials = signoffs.select_signoff(records, story, criterion, policy)
        if match:
            entry["result"] = "pass"
            entry["signoff"] = {
                "approver": match["approver"],
                "note": match["note"],
                "signed_at": match["signed_at"],
                "role": match.get("role"),
                "identity_source": match.get("identity_source") or "client",
            }
        elif denials:
            # A sign-off is on file but the roles in force reject it: blocking,
            # and said in one line. The record stays on disk (audit); signing
            # again with an authorized role is the repair.
            entry["result"] = "role-denied"
            entry["denials"] = denials
            entry["detail"] = denials[-1]["detail"]
        else:
            entry["result"] = "needs-signoff"
        blocked = _integrity_block_notes(integrity)
        if blocked and entry["result"] in ("pass", "needs-signoff"):
            # The signed text no longer matches the code and the policy says
            # block: a sign-off on a stale statement does not satisfy it.
            # Rewording the statement (a re-approval) is the repair.
            entry["result"] = "fail"
            entry["detail"] = "\n".join(blocked)
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
    if cached.environment is not None:
        entry["environment"] = cached.environment
    if cached.resource is not None:
        entry["resource"] = cached.resource
    ok, notes, tests_run, counted, zero_tests = _judge_run(criterion, cached)
    if counted or criterion["check"]["type"] == "tests":
        entry["tests_run"] = tests_run
    if zero_tests:
        integrity += _integrity_entries(
            [{"kind": "zero_tests", "detail": ZERO_TESTS_DETAIL}], integrity_policy
        )
    if integrity:
        entry["integrity"] = integrity
    blocked = _integrity_block_notes(integrity)
    if blocked:
        ok = False
        notes = blocked + notes
    run_detail = "\n".join([*notes, cached.detail] if cached.detail else notes)
    if ok:
        entry["result"] = "pass"
    else:
        override, denials = _select_override(overrides, story, criterion, policy)
        if override:
            state = risk_acceptance.acceptance_state(override, risk_acceptance.today())
            acceptance = {
                "approver": override.get("user_email"),
                "reason": override.get("notes"),
                "role": override.get("role"),
                "identity_source": override.get("identity_source") or "client",
                "at": override.get("at"),
                "expires": state["expires"],
                "state": state["state"],
                "days_left": state["days_left"],
                "ticket": override.get("ticket"),
            }
            if state["state"] == "expired":
                # The acceptance ran out: the criterion blocks again, with the
                # reason on the record. Renewing is a NEW override (history is
                # kept); fixing the check is the other way out.
                entry["result"] = "fail"
                entry["override_expired"] = acceptance
                entry["detail"] = (
                    f"risk acceptance by {override.get('user_email')} expired on "
                    f"{state['expires']}: renew it (linebreak-gate override --criterion "
                    f"{criterion['id']} --reason ... --approver ... --expires YYYY-MM-DD) "
                    "or fix the check"
                )
                return entry
            entry["result"] = "overridden"
            entry["override"] = acceptance
        elif denials:
            entry["result"] = "role-denied"
            entry["denials"] = denials
        else:
            entry["result"] = "fail"
    if entry["result"] == "role-denied":
        # The check genuinely failed AND the override on file does not count:
        # lead with the denial, keep the failing output for the reader.
        entry["detail"] = entry["denials"][-1]["detail"] + (f"\n{run_detail}" if run_detail else "")
    elif run_detail and entry["result"] != "overridden":
        entry["detail"] = run_detail
    return entry


#: Results a re-run alone can change: the check itself failed.
_RETRYABLE = ("fail", "overridden", "role-denied")


def _retry_alone(
    results: list[dict[str, Any]],
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    root: Path,
    measured: _MeasuredRunner,
    run_cache: dict[tuple[str, str], RunOutcome | CriteriaToolError],
) -> None:
    """Issue #262: a failed check on a shared ``resource`` runs once more,
    alone, after every other check. Passing alone makes it ``collision`` (the
    red was a clash over the resource, not a defect: said, not painted red);
    failing again keeps the failure and says it was reproduced alone, which is
    what makes a red worth reading. Identical checks are re-run once.

    Both runs are judged like any other (:func:`_judge_run`: ``expect``, zero
    tests executed), so a run that exits 0 without observing what the
    criterion expects is a failure alone too. A criterion that an integrity
    finding blocks is never turned into a collision: the re-run cannot clear
    that finding."""
    retried: dict[tuple[str, str], RunOutcome | CriteriaToolError] = {}
    for i, (entry, (_story, criterion)) in enumerate(zip(results, pairs, strict=True)):
        resource = criterion["check"].get("resource")
        if not resource or entry["result"] not in _RETRYABLE:
            continue
        if _integrity_block_notes(entry.get("integrity") or []):
            continue
        key = (criterion["check"]["type"], criterion["check"].get("payload") or "")
        first = run_cache.get(key)
        if not isinstance(first, RunOutcome) or _judge_run(criterion, first)[0]:
            continue
        if key not in retried:
            try:
                retried[key] = measured(criterion, root)
            except CriteriaToolError as e:
                retried[key] = e
        second = retried[key]
        if isinstance(second, CriteriaToolError):
            entry["detail"] = (
                f"could not re-run alone on resource {resource} ({second}); the first "
                f"failure stands\n{entry.get('detail') or ''}"
            ).strip()
            continue
        second_ok, _notes, second_tests_run, second_counted, _zero = _judge_run(criterion, second)
        if not second_ok:
            entry["retried_alone"] = "fail"
            entry["detail"] = (
                f"reproduced when re-run alone on resource {resource}: a defect, not a "
                f"collision\n{entry.get('detail') or ''}"
            ).strip()
            continue
        collision: dict[str, Any] = {k: entry[k] for k in ("id", "story", "statement", "check")}
        collision["result"] = COLLISION
        collision["detail"] = (
            f"failed while resource {resource} was in use, passed when re-run alone: a "
            "collision over the resource, not a defect"
        )
        collision["collision"] = {
            "resource": resource,
            "first_detail": " ".join(first.detail.split())[:300],
            "retry": "pass",
        }
        if second_counted or criterion["check"]["type"] == "tests":
            collision["tests_run"] = second_tests_run
        if entry.get("integrity"):
            collision["integrity"] = entry["integrity"]
        if second.environment is not None:
            collision["environment"] = second.environment
        if second.resource is not None:
            collision["resource"] = second.resource
        results[i] = collision


def evaluate_bundle(
    project_root: Path | str,
    *,
    run: Callable[[dict[str, Any], Path], RunOutcome] = default_runner,
    write_artifact: bool = False,
    actor: str | None = None,
    approval_public_keys: tuple[tuple[str, str], ...] = (),
    story_ids: set[str] | None = None,
    started_only: bool = False,
    manual_policy: str = "block",
    stage: str = "release",
    roles_policy: _roles.RolesPolicy | None = None,
    extra_signoffs: list[dict[str, Any]] | None = None,
    phase: str = "verify",
    environ: Mapping[str, str] | None = None,
    env_fetch: environment.Fetch | None = None,
    lock_timeout_s: float = CHECK_TIMEOUT_S,
    integrity_policy: gate_config.IntegrityPolicy | None = None,
) -> dict[str, Any] | None:
    """Evaluate the approved criteria against the working tree.

    ``phase`` (release only): ``verify`` (default) enforces everything;
    ``prepare`` reports the ``check.when: attestation`` criteria as
    ``awaiting-attestation`` instead of evaluating them (their sign-off is made
    on this run, so the run cannot require it) and lists them under
    ``awaiting_attestation``. The record says ``phase: prepare``: it is the run
    to attest, never the release verdict.

    Shared resources and environments (issues #262 and #264): a check that
    declares ``check.resource`` runs holding that resource alone
    (:mod:`resource_lock`); when it fails it is re-run ONCE, alone, after every
    other check: failing again confirms a defect (``detail`` says it was
    reproduced alone), passing makes it ``collision`` (not blocking, listed
    under ``collisions``). A check that declares ``check.environment`` records
    the deployed version it measured (``environment`` on the entry, read from
    ``environ`` with ``env_fetch``); anything but ``current`` is listed under
    ``environment_warnings``, never blocking.

    ``integrity_policy`` is ``criteria.integrity`` from ``gate.yml`` (read
    from the repository when not given): what to do with a criterion that
    shares its tests with another story (#263), whose statement names
    identifiers gone from the code (#261), or whose ``command`` ran a test
    runner that executed nothing (#259). ``warn`` (default) reports them
    under each criterion's ``integrity`` and the payload's ``integrity``
    block; ``block`` fails the criterion. Independently of that policy, a
    ``tests`` criterion that executed zero tests fails, and a declared
    ``expect`` that is not observed fails (#260).

    ``extra_signoffs`` are sign-off records from outside the repository (the
    governance service's, see :func:`signoffs.load_governance_signoffs`);
    they are subject to exactly the same rules as the ones on disk: content
    hash of the criterion, roles in force, identity policy.

    ``roles_policy`` is the parsed ``.linebreak/roles.yml`` (loaded from the
    repo when not given). Every recorded sign-off and override is re-checked
    against it: one the roles in force reject yields ``role-denied`` for its
    criterion (always blocking, whatever ``manual_policy`` says: a recorded
    approval that violates policy is a governance finding, not a missing
    signature) with a ``denials`` list saying who, which role, and why.

    Returns None when no bundle exists (teams without an approved spec are
    unaffected). Raises SpecBundleError on a malformed bundle and SignoffError
    on malformed sign-off records (both exit-2 at the CLI: fail closed).

    Scope (issue #256): by default every story is evaluated. ``story_ids``
    narrows the evaluation to those stories (LIN-55's per-story check and the
    CLI's ``--story``); an id that is not in the bundle is a CriteriaToolError
    (exit 2: a scope that names nothing is a config mistake, never a pass).
    ``started_only`` evaluates only stories whose local state (the LIN-45
    ``tracker-sync.json`` store) is doing/review/done; the rest are reported
    under ``scope.not_started`` and never count toward the verdict. The two
    are mutually exclusive. ``manual_policy`` is ``block`` (a ``manual``
    criterion without a sign-off blocks, the historical default) or ``warn``
    (reported as needs-signoff and listed under ``pending_signoffs``, but not
    blocking).

    ``write_artifact`` records the run in ``.linebreak/audit/criteria.json``
    stamped with its ``scope`` and ``pending_signoffs``, so a partial or
    relaxed run is evidence of that run and can never be read as a full
    verdict (the CLI always writes; the bridge's per-story check never does).

    Result: ``{"passes": bool, "tool_error": bool, "criteria": [...],
    "bundle": {...}, "scope": {...}, "pending_signoffs": [...]}`` — each
    criterion entry carries ``result`` in ``pass | fail | needs-signoff |
    overridden | error | release-only`` plus attribution for sign-offs and
    overrides. ``scope.release_only`` lists the ``{id, story}`` pairs that
    were not evaluated at ``stage="pr"``.
    """
    if manual_policy not in MANUAL_POLICIES:
        raise ValueError(f"manual_policy must be one of {MANUAL_POLICIES}, got {manual_policy!r}")
    if stage not in STAGES:
        raise ValueError(f"stage must be one of {STAGES}, got {stage!r}")
    if story_ids is not None and started_only:
        raise ValueError("story_ids and started_only are mutually exclusive")
    if phase not in PHASES:
        raise ValueError(f"phase must be one of {PHASES}, got {phase!r}")
    if phase == "prepare" and stage != "release":
        raise ValueError("phase 'prepare' applies only to stage 'release'")
    root = Path(project_root)
    bundle = spec_bundle.load_bundle(root)
    if bundle is None:
        return None
    # Verify the signed approval BEFORE running any check: an unverifiable
    # bundle is not trustworthy, so we don't spend a build on it. Raises
    # BundleSignatureError (exit 1) when a key is configured but the bundle is
    # unsigned/tampered/untrusted; returns None in unsigned mode.
    signed = verify_bundle_signature(bundle, approval_public_keys)
    records = signoffs.load_signoffs(root) + list(extra_signoffs or [])
    overrides = _criterion_overrides(root)
    policy = roles_policy if roles_policy is not None else _roles.load_roles(root)

    stories, scope = _select_stories(root, bundle, story_ids=story_ids, started_only=started_only)
    scope["manual"] = manual_policy
    if integrity_policy is None:
        integrity_policy = gate_config.resolve_config(root).criteria_integrity
    static_findings, integrity_skipped = _static_integrity(root, bundle, stories, integrity_policy)

    # Memoize identical machine checks within one pass: two stories that each
    # declare `build` (no payload) resolve to the same run — do the work once.
    run_cache: dict[tuple[str, str], RunOutcome | CriteriaToolError] = {}
    measured = _MeasuredRunner(
        run,
        env=os.environ if environ is None else environ,
        env_fetch=env_fetch,
        lock_timeout_s=lock_timeout_s,
    )

    pairs = [(story, criterion) for story in stories for criterion in story["criteria"]]
    results = [
        _evaluate_criterion(
            criterion,
            story["id"],
            root,
            records,
            overrides,
            measured,
            run_cache,
            stage=stage,
            policy=policy,
            story=story,
            phase=phase,
            integrity_findings=static_findings.get(criterion["id"]),
            integrity_policy=integrity_policy,
        )
        for story, criterion in pairs
    ]
    _retry_alone(results, pairs, root, measured, run_cache)
    release_only = [
        {"id": r["id"], "story": r["story"]} for r in results if r["result"] == "release-only"
    ]
    awaiting = [
        {"id": r["id"], "story": r["story"]} for r in results if r["result"] == AWAITING_ATTESTATION
    ]
    scope["stage"] = stage
    scope["release_only"] = release_only
    scope["criteria_evaluated"] = len(results) - len(release_only) - len(awaiting)
    scope["criteria_total"] = sum(len(s["criteria"]) for s in bundle["stories"])

    tool_error = any(r["result"] == "error" for r in results)
    blocking_results = {"fail", "error", "role-denied"}
    if manual_policy == "block":
        blocking_results.add("needs-signoff")
    blocking = [r for r in results if r["result"] in blocking_results]
    pending = [
        {"id": r["id"], "story": r["story"]} for r in results if r["result"] == "needs-signoff"
    ]
    expired_overrides = [
        {"id": r["id"], "story": r["story"], **r["override_expired"]}
        for r in results
        if r.get("override_expired")
    ]
    expiring_overrides = [
        {"id": r["id"], "story": r["story"], **r["override"]}
        for r in results
        if r.get("override") and r["override"].get("state") == "expiring"
    ]
    block_reasons: list[str] = []
    if any(r["result"] == "error" for r in blocking):
        block_reasons.append("command_failed")
    if any(r["result"] == "fail" and not r.get("override_expired") for r in blocking):
        block_reasons.append("tests_failed")
    if any(r.get("override_expired") for r in blocking):
        block_reasons.append("expired_risk")
    if any(r["result"] == "role-denied" for r in blocking):
        block_reasons.append("role_denied")
    if any(r["result"] == "needs-signoff" for r in blocking):
        block_reasons.append("unsigned_manual")
    payload = {
        "passes": not blocking,
        "tool_error": tool_error,
        "block_reasons": block_reasons,
        "criteria": results,
        "scope": scope,
        "pending_signoffs": pending,
        "expired_overrides": expired_overrides,
        "expiring_overrides": expiring_overrides,
        # How many sign-offs came from the governance service (0 when it was
        # not consulted), so the record says where the signatures were read.
        "governance_signoffs": len(extra_signoffs or []),
        # Release phase (prepare / verify) and the attestation criteria the
        # prepare phase did not evaluate: they are signed on THIS run.
        "phase": phase,
        "awaiting_attestation": awaiting,
        # Checks on a shared resource that failed and then passed alone (#262).
        "collisions": [
            {
                "id": r["id"],
                "story": r["story"],
                "resource": (r.get("resource") or {}).get("name"),
                "first_detail": r["collision"]["first_detail"],
            }
            for r in results
            if r["result"] == COLLISION
        ],
        # What each environment-bound check measured, when it was not the
        # evaluated commit (#264). Warnings: the verdict stands, now it says
        # what it measured.
        "environment_warnings": [
            {"id": r["id"], "story": r["story"], "status": r["environment"]["status"], "message": w}
            for r in results
            if r.get("environment")
            and (w := environment.warning(r["id"], r["environment"])) is not None
        ],
        "integrity": {
            "policy": integrity_policy.as_dict(),
            "findings": [
                {"id": r["id"], "story": r["story"], **f}
                for r in results
                for f in r.get("integrity") or []
            ],
            "skipped": integrity_skipped,
        },
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


def _static_integrity(
    root: Path,
    bundle: dict[str, Any],
    stories: list[dict[str, Any]],
    policy: gate_config.IntegrityPolicy,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    """The findings that need no run: shared tests across the WHOLE bundle
    (a story in scope may borrow from one out of scope) and stale statements
    for the stories in scope. Returns ``(criterion id -> findings, skipped)``
    where ``skipped`` says, per kind, why it was not looked at."""
    by_criterion: dict[str, list[dict[str, Any]]] = {}
    skipped: dict[str, str] = {}
    found: list[dict[str, Any]] = []
    if policy.of("shared_tests") != "off":
        found += spec_integrity.shared_tests(bundle["stories"])
    if policy.of("stale_statements") != "off":
        report = spec_integrity.stale_statements(root, stories)
        found += report.findings
        if report.skipped:
            skipped["stale_statements"] = report.skipped
    for f in found:
        by_criterion.setdefault(f["id"], []).append(f)
    return by_criterion, skipped


#: Keys every recorded finding carries; the others appear only when set (a
#: ``tests_run`` of 0 is recorded: it is the finding).
_ALWAYS_RECORDED = frozenset({"id", "story", "statement", "check", "result", "detail"})


#: What each criterion keeps in the audit record: the identity and the result
#: always, the rest when present (denials, the tests the runner executed, the
#: integrity findings, what a check measured, the resource it held, a
#: collision's first failure).
_FINDING_KEYS = (
    "id",
    "story",
    "statement",
    "check",
    "result",
    "detail",
    "denials",
    "tests_run",
    "integrity",
    "environment",
    "resource",
    "collision",
)


def _write_results_artifact(root: Path, payload: dict[str, Any], *, actor: str | None) -> None:
    """Record the evaluation in ``.linebreak/audit/criteria.json`` — same
    versioned document format as the scans, carrying the approval trail
    (overrides) forward so they survive re-checks.

    The record is stamped with the run's ``scope`` and ``pending_signoffs``
    (issue #256): a scoped or ``--manual warn`` run is evidence of THAT run,
    never a full verdict, and the stamp is what says so. Writing it on every
    CLI run (instead of skipping scoped runs) keeps the uploaded CI artifact
    honest: it always carries the verdict this run produced, not a stale
    committed one from an earlier full run.
    """
    prior = sa.read_artifact(root, ARTIFACT_NAME, base_dir=AUDIT_DIR)
    counts: dict[str, int] = {}
    for r in payload["criteria"]:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in sorted(counts.items())) or "no criteria"
    scope = payload["scope"]
    phase = payload.get("phase", "verify")
    if (
        scope["mode"] != "all"
        or scope["manual"] != "block"
        or scope["release_only"]
        or phase != "verify"
    ):
        phase_note = f", phase: {phase}" if phase != "verify" else ""
        summary = (
            f"{summary} (scope: {scope['mode']}, manual: {scope['manual']}, "
            f"stage: {scope['stage']}{phase_note}; not a full verdict)"
        )
    doc = sa.new_artifact(
        "criteria_check",
        id="criteria",
        findings=[
            {
                k: r.get(k)
                for k in _FINDING_KEYS
                if k in _ALWAYS_RECORDED or r.get(k) is not None and r.get(k) != []
            }
            for r in payload["criteria"]
        ],
        summary=f"acceptance criteria: {summary}",
        scanner="linebreak-gate check",
    )
    doc["approvals"] = prior.get("approvals") or []
    doc["bundle"] = payload["bundle"]
    doc["scope"] = scope
    doc["pending_signoffs"] = payload["pending_signoffs"]
    doc["phase"] = phase
    for key in ("awaiting_attestation", "collisions", "environment_warnings"):
        if payload.get(key):
            doc[key] = payload[key]
    if actor:
        doc["actor"] = actor
    sa.write_artifact(root, ARTIFACT_NAME, doc, base_dir=AUDIT_DIR)
