"""Recorded human sign-off for ``manual`` acceptance criteria (LIN-37 D2).

A ``manual`` criterion cannot be machine-verified; it is satisfied ONLY by a
record written here — never by an agent's claim of compliance. Records are:

* **attributed** — approver and note are required, refusal otherwise;
* **additive** — one file per sign-off under ``.linebreak/spec/signoffs/``,
  never rewritten or deleted (the git history of approvals is the audit);
* **bound to the standard they approved** — each record carries the
  criterion's content hash (see :func:`spec_bundle.criterion_hash`). Editing
  the criterion and re-approving changes the hash, so prior sign-offs go
  stale automatically and the criterion returns to needs-signoff. The bundle
  manifest's ``generated_at`` is recorded for audit context.

Commit conventions match the rest of ``.linebreak/spec/`` (git-includable per
the scoped ignore rules); like ``override``, the CLI writes the record and
tells the human to commit it — it never commits on its own.
"""

from __future__ import annotations

import datetime as _dt
import json
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import yaml

from . import governance_env, spec_bundle
from . import identity as _identity
from . import roles as _roles

SIGNOFFS_DIR = spec_bundle.SPEC_DIR / "signoffs"

_REQUIRED = ("criterion_id", "criterion_hash", "approver", "note", "signed_at")


class SignoffError(Exception):
    """A sign-off could not be recorded or read — the CLI exits 2."""


def record_signoff(
    project_root: Path | str,
    *,
    criterion_id: str,
    approver: str | None = None,
    note: str,
    identity: _identity.Identity | None = None,
    role: str | None = None,
    policy: _roles.RolesPolicy | None = None,
) -> dict[str, Any]:
    """Write one attributed sign-off record. Returns the record.

    Refuses: missing approver/note, an id absent from the approved bundle,
    an ambiguous id, and non-``manual`` criteria (machine-checkable criteria
    are satisfied by the machine check or an override — a sign-off must not
    become a side door around a failing test).

    ``identity`` is who signs (see :mod:`identity`); when absent, ``approver``
    is taken as a typed ``client`` identity, exactly as before. ``role`` is the
    role the sign-off is made under; when absent it is inferred from
    ``policy`` (``.linebreak/roles.yml``, loaded from the repo when not given).
    A person not authorized under ``policy.require_roles`` is refused with a
    message naming the roles that would be needed.
    """
    root = Path(project_root)
    note = note.strip()
    if identity is None:
        try:
            identity = _identity.client(approver or "")
        except _identity.IdentityError as e:
            raise SignoffError(str(e)) from e
    if not note:
        raise SignoffError("a non-empty --note explaining what was verified is required")
    if policy is None:
        policy = _roles.load_roles(root)

    try:
        bundle = spec_bundle.load_bundle(root)
    except spec_bundle.SpecBundleError as e:
        raise SignoffError(f"malformed spec bundle: {e}") from e
    if bundle is None:
        raise SignoffError(f"no approved spec bundle ({spec_bundle.SPEC_DIR}/ absent)")
    try:
        story, criterion = spec_bundle.find_criterion(bundle, criterion_id)
    except spec_bundle.SpecBundleError as e:
        raise SignoffError(str(e)) from e
    if criterion["check"]["type"] != "manual":
        raise SignoffError(
            f"criterion {criterion_id!r} has check type {criterion['check']['type']!r} — "
            "sign-offs apply to `manual` criteria only; a failed machine check is "
            "overridden with `linebreak-gate override --criterion ...` instead"
        )

    try:
        role = _roles.authorize(
            policy,
            subject=identity.subject,
            keys=identity.keys(),
            action="sign_criteria",
            targets=_roles.criterion_targets(story, criterion),
            role=role,
        )
    except _roles.RoleDenied as e:
        raise SignoffError(str(e)) from e

    record: dict[str, Any] = {
        "criterion_id": criterion_id,
        "story_id": story["id"],
        "criterion_hash": spec_bundle.criterion_hash(criterion),
        "bundle_generated_at": bundle["manifest"].get("generated_at"),
        "approver": identity.subject,
        "note": note,
        # The role this sign-off is made under (None: no roles file, or the
        # person holds no role and roles are not required).
        "role": role,
        # client: human-typed, unverified. vcs / governance: verified by the CI
        # provider or the governance service (see identity.py).
        "identity_source": identity.source,
        "signed_at": _dt.datetime.now(tz=_dt.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
    if identity.record():
        record["identity"] = identity.record()
    if identity.declared:
        record["declared_approver"] = identity.declared
    signoffs_dir = root / SIGNOFFS_DIR
    signoffs_dir.mkdir(parents=True, exist_ok=True)
    # One file per record: additive by construction — recording a new sign-off
    # can never rewrite a prior one.
    name = f"{criterion_id}-{uuid.uuid4().hex[:8]}.yml"
    (signoffs_dir / name).write_text(
        yaml.safe_dump(record, sort_keys=False, default_flow_style=False, allow_unicode=True),
        encoding="utf-8",
    )
    return record


def load_signoffs(project_root: Path | str) -> list[dict[str, Any]]:
    """Read every sign-off record. Fails closed (:class:`SignoffError`) on a
    malformed record — governance records that can't be parsed must never be
    silently skipped."""
    signoffs_dir = Path(project_root) / SIGNOFFS_DIR
    if not signoffs_dir.exists():
        return []
    records: list[dict[str, Any]] = []
    for path in sorted(signoffs_dir.iterdir()):
        # Unlike stories/ (a machine-managed dir where a stray file signals
        # tampering), signoffs/ is a dir humans browse and commit from, so
        # OS/editor droppings (.DS_Store, .gitkeep, *.swp) are expected noise —
        # skip anything that isn't a `.yml` file rather than block every merge.
        # A malformed `.yml` record still fails closed below.
        if not path.is_file() or path.suffix != ".yml":
            continue
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as e:
            raise SignoffError(f"could not parse sign-off {path.name}: {e}") from e
        if not isinstance(data, dict) or any(
            not isinstance(data.get(k), str) or not data[k].strip() for k in _REQUIRED
        ):
            raise SignoffError(f"sign-off {path.name} is missing required fields {list(_REQUIRED)}")
        records.append(data)
    return records


#: Where the project id on the governance service comes from when the check
#: consults its sign-offs (the same variable ``publish`` already reads).
GOVERNANCE_PROJECT_ENVS = ("LINEBREAK_GOVERNANCE_PROJECT", "LINEBREAK_GOV_PROJECT")
_GOVERNANCE_TIMEOUT_S = 15

#: (url, token) -> (status, parsed body)
GovernanceFetch = Callable[[str, str], tuple[int, Any]]


def _default_governance_fetch(url: str, token: str) -> tuple[int, Any]:
    from . import __version__

    request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"linebreak-gate/{__version__}",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=_GOVERNANCE_TIMEOUT_S) as response:
            return response.status, json.loads(response.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8") or "null")
        except ValueError:
            return e.code, None


def governance_record(item: Any) -> dict[str, Any] | None:
    """One sign-off as ``GET /v1/projects/{id}/signoffs`` returns it, in the
    shape of a repository record so :func:`select_signoff` treats both the
    same way (content hash, roles in force, identity). ``None`` when the
    entry lacks a required field: a remote record the gate cannot bind to a
    criterion satisfies nothing."""
    if not isinstance(item, dict):
        return None
    record = {
        "criterion_id": item.get("criterion_id"),
        "criterion_hash": item.get("criterion_hash"),
        "approver": item.get("by") or item.get("approver"),
        "note": item.get("note"),
        "signed_at": item.get("at") or item.get("signed_at"),
    }
    if any(not isinstance(v, str) or not v.strip() for v in record.values()):
        return None
    record["story_id"] = item.get("story_id")
    record["role"] = item.get("role") if isinstance(item.get("role"), str) else None
    # The service vouches for the identity behind the session that signed:
    # the same verified source a governance token gives `signoff` on the CLI.
    record["identity_source"] = "governance"
    record["identity"] = {"provider": "governance", "email": record["approver"]}
    if isinstance(item.get("id"), str):
        record["governance_id"] = item["id"]
    return record


def load_governance_signoffs(
    env: Mapping[str, str] | None = None, fetch: GovernanceFetch | None = None
) -> tuple[list[dict[str, Any]], str | None]:
    """The sign-offs recorded on the governance service for this project, when
    ``LINEBREAK_GOVERNANCE_BASE_URL`` and ``LINEBREAK_GOVERNANCE_TOKEN`` are set.

    Returns ``(records, notice)``. A service that does not answer, answers an
    error, or has no project id configured NEVER blocks and never approves:
    ``records`` is empty and ``notice`` says why, so the check goes on with
    the repository's own sign-offs alone. Without the two variables it is
    silent: ``([], None)``.
    """
    env = governance_env.merged() if env is None else env
    base = (env.get(_identity.GOVERNANCE_BASE_ENV) or "").strip().rstrip("/")
    token = (env.get(_identity.GOVERNANCE_TOKEN_ENV) or "").strip()
    if not base or not token:
        return [], None
    project = next((env[k].strip() for k in GOVERNANCE_PROJECT_ENVS if env.get(k, "").strip()), "")
    if not project:
        return [], (
            "governance sign-offs not consulted: no project id "
            f"({' or '.join(GOVERNANCE_PROJECT_ENVS)}); using the repository's sign-offs only"
        )
    url = f"{base}/v1/projects/{project}/signoffs"
    try:
        status, body = (fetch or _default_governance_fetch)(url, token)
    except Exception as e:  # noqa: BLE001 - an unreachable service is a notice, never a verdict
        return [], (
            f"governance service unreachable at {base} ({e}); using the repository's sign-offs only"
        )
    if status != 200:
        return [], (
            f"governance service answered {status} to GET {url}; using the repository's "
            "sign-offs only"
        )
    items = body.get("signoffs") if isinstance(body, dict) else body
    if not isinstance(items, list):
        return [], f"governance service returned an unexpected body from {url}; ignored"
    records = [r for r in (governance_record(i) for i in items) if r is not None]
    skipped = len(items) - len(records)
    notice = (
        f"{skipped} governance sign-off(s) lacked a criterion, hash, approver, note or date "
        "and were ignored"
        if skipped
        else None
    )
    return records, notice


def matching_signoff(
    records: list[dict[str, Any]], criterion: dict[str, Any]
) -> dict[str, Any] | None:
    """The most recent sign-off that matches this criterion's CURRENT content
    hash, or None. A hash mismatch means the standard changed after signing —
    the record stays on disk (audit) but no longer satisfies anything."""
    want = spec_bundle.criterion_hash(criterion)
    valid = [
        r for r in records if r["criterion_id"] == criterion["id"] and r["criterion_hash"] == want
    ]
    return max(valid, key=lambda r: r["signed_at"]) if valid else None


def select_signoff(
    records: list[dict[str, Any]],
    story: dict[str, Any],
    criterion: dict[str, Any],
    policy: _roles.RolesPolicy,
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    """:func:`matching_signoff` under the roles in force.

    Returns ``(match, denials)``: the most recent hash-matching sign-off that
    the current ``policy`` still accepts, plus one denial record per
    hash-matching sign-off it rejects (role removed, member gone, identity
    only declared). A criterion with denials and no match is what the check
    reports as ``role-denied``; a later authorized sign-off supersedes an
    earlier rejected one, so a mistake is repaired by signing again, never by
    deleting evidence.
    """
    want = spec_bundle.criterion_hash(criterion)
    valid = [
        r for r in records if r["criterion_id"] == criterion["id"] and r["criterion_hash"] == want
    ]
    accepted: list[dict[str, Any]] = []
    denials: list[dict[str, Any]] = []
    targets = _roles.criterion_targets(story, criterion)
    for r in sorted(valid, key=lambda r: r["signed_at"]):
        role = r.get("role") if isinstance(r.get("role"), str) else None
        denial = _roles.verify_record(
            policy,
            kind="sign-off",
            subject=str(r["approver"]),
            keys=_roles.record_keys(r, "approver"),
            action="sign_criteria",
            targets=targets,
            role=role,
            identity_source=r.get("identity_source"),
        )
        if denial is None:
            accepted.append(r)
        else:
            denials.append(
                _roles.denial_record(denial, kind="signoff", by=str(r["approver"]), role=role)
            )
    return (accepted[-1] if accepted else None), denials
