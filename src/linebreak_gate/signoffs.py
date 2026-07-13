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
import uuid
from pathlib import Path
from typing import Any

import yaml

from . import spec_bundle

SIGNOFFS_DIR = spec_bundle.SPEC_DIR / "signoffs"

_REQUIRED = ("criterion_id", "criterion_hash", "approver", "note", "signed_at")


class SignoffError(Exception):
    """A sign-off could not be recorded or read — the CLI exits 2."""


def record_signoff(
    project_root: Path | str,
    *,
    criterion_id: str,
    approver: str,
    note: str,
) -> dict[str, Any]:
    """Write one attributed sign-off record. Returns the record.

    Refuses: missing approver/note, an id absent from the approved bundle,
    an ambiguous id, and non-``manual`` criteria (machine-checkable criteria
    are satisfied by the machine check or an override — a sign-off must not
    become a side door around a failing test).
    """
    root = Path(project_root)
    approver = approver.strip()
    note = note.strip()
    if not approver:
        raise SignoffError("a non-empty --approver (name/email) is required")
    if not note:
        raise SignoffError("a non-empty --note explaining what was verified is required")

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

    record = {
        "criterion_id": criterion_id,
        "story_id": story["id"],
        "criterion_hash": spec_bundle.criterion_hash(criterion),
        "bundle_generated_at": bundle["manifest"].get("generated_at"),
        "approver": approver,
        "note": note,
        "signed_at": _dt.datetime.now(tz=_dt.UTC)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
    }
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
