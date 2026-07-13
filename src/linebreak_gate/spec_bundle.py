"""The spec bundle — approved acceptance criteria as data in the repo (LIN-35).

Piece 2 of the spec-to-git direction: when the human approves the phase that
finalizes stories, the approved acceptance criteria land in the project repo
under ``.linebreak/spec/`` in a structured, machine-readable form, attributed
to the approver. This module is the ONE schema implementation — the desktop
app writes bundles through it (via its dependency on this package) and the
gate CLI reads them (``linebreak-gate spec list``); Piece 3's enforcement
will read the same files.

This module enforces structure only. It never enforces criteria — nothing
here blocks anything.

Layout (all YAML, deterministic key order so re-approval diffs are readable):

    .linebreak/spec/manifest.yml          bundle version, timestamp, source
                                          phase, approval attribution
    .linebreak/spec/stories/<id>.yml      one file per story: metadata +
                                          criteria

Check vocabulary is deliberately small and honest — only what a CI boundary
could realistically run later: ``build`` | ``tests`` | ``command`` | ``manual``
(``manual`` = explicitly not machine-checkable; requires human sign-off).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

BUNDLE_VERSION = 1
SPEC_DIR = Path(".linebreak") / "spec"
STORIES_DIR = SPEC_DIR / "stories"
MANIFEST_NAME = "manifest.yml"

#: The fixed, closed vocabulary of check types. Do not extend casually — every
#: type here is a promise that the boundary can evaluate it in Piece 3.
CHECK_TYPES = {"build", "tests", "command", "manual"}

#: Check types whose ``payload`` is required (what to run / which tests).
_PAYLOAD_REQUIRED = {"tests", "command"}

#: A story id becomes a filename (``stories/<id>.yml``), so it must be a safe
#: slug — no path separators, no ``..``. The sidecar is LLM-authored and
#: hand-editable, so this is a security boundary, not just tidiness.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Keys the schema knows. Unknown keys are rejected rather than silently
#: round-tripped — the bundle is the agreed standard; junk must not accrete.
_STORY_ALLOWED = {"id", "title", "epic", "criteria"}
_CRITERION_ALLOWED = {"id", "statement", "check"}
_CHECK_ALLOWED = {"type", "payload"}


class SpecBundleError(Exception):
    """A bundle on disk is malformed. Read-back fails closed on this."""


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------


def validate_criterion(criterion: Any, *, story_id: str = "?") -> list[str]:
    """Errors for one criterion (empty list = valid)."""
    errors: list[str] = []
    if not isinstance(criterion, dict):
        errors.append(f"story {story_id}: criterion must be a mapping")
        return errors
    cid = criterion.get("id")
    if not isinstance(cid, str) or not cid.strip():
        errors.append(f"story {story_id}: criterion missing a stable string 'id'")
    extra = set(criterion) - _CRITERION_ALLOWED
    if extra:
        errors.append(f"story {story_id}/{cid}: unknown criterion key(s) {sorted(extra)}")
    if not isinstance(criterion.get("statement"), str) or not criterion["statement"].strip():
        errors.append(f"story {story_id}/{cid}: criterion missing a 'statement'")
    check = criterion.get("check")
    if not isinstance(check, dict):
        errors.append(f"story {story_id}/{cid}: 'check' must be a mapping with a 'type'")
        return errors
    check_extra = set(check) - _CHECK_ALLOWED
    if check_extra:
        errors.append(f"story {story_id}/{cid}: unknown check key(s) {sorted(check_extra)}")
    ctype = check.get("type")
    if ctype not in CHECK_TYPES:
        allowed = " | ".join(sorted(CHECK_TYPES))
        errors.append(
            f"story {story_id}/{cid}: check type {ctype!r} is not in the fixed "
            f"vocabulary ({allowed})"
        )
    elif ctype in _PAYLOAD_REQUIRED and not (
        isinstance(check.get("payload"), str) and check["payload"].strip()
    ):
        errors.append(f"story {story_id}/{cid}: check type '{ctype}' requires a string 'payload'")
    return errors


def validate_story(story: Any) -> list[str]:
    """Errors for one story (empty list = valid)."""
    errors: list[str] = []
    if not isinstance(story, dict):
        return ["story must be a mapping"]
    sid = story.get("id")
    if not isinstance(sid, str) or not sid.strip():
        errors.append("story missing a stable string 'id'")
        sid = "?"
    elif not _ID_RE.match(sid):
        # Path-safety: the id is used verbatim as a filename.
        errors.append(f"story {sid!r}: id must match {_ID_RE.pattern} (no path separators or '..')")
    extra = set(story) - _STORY_ALLOWED
    if extra:
        errors.append(f"story {sid}: unknown key(s) {sorted(extra)}")
    if not isinstance(story.get("title"), str) or not story["title"].strip():
        errors.append(f"story {sid}: missing a 'title'")
    criteria = story.get("criteria")
    if not isinstance(criteria, list) or not criteria:
        errors.append(f"story {sid}: 'criteria' must be a non-empty list")
        return errors
    seen: set[str] = set()
    for c in criteria:
        errors.extend(validate_criterion(c, story_id=sid))
        cid = c.get("id") if isinstance(c, dict) else None
        if isinstance(cid, str):
            if cid in seen:
                errors.append(f"story {sid}: duplicate criterion id {cid!r}")
            seen.add(cid)
    return errors


def validate_sidecar(data: Any) -> list[str]:
    """Errors for a whole stories sidecar (``{"stories": [...]}``) — the ONE
    validation both the authoring-time tool and the handoff call, so they can
    never disagree. Includes the cross-story duplicate-id check (two stories
    with one id collapse to a single file, silently dropping a story)."""
    if not isinstance(data, dict):
        return ["sidecar must be a mapping with a 'stories' list"]
    stories = data.get("stories")
    if not isinstance(stories, list) or not stories:
        return ["'stories' must be a non-empty list"]
    errors: list[str] = []
    seen: set[str] = set()
    for story in stories:
        errors.extend(validate_story(story))
        sid = story.get("id") if isinstance(story, dict) else None
        if isinstance(sid, str):
            if sid in seen:
                errors.append(f"duplicate story id {sid!r} (would overwrite a story file)")
            seen.add(sid)
    return errors


# --------------------------------------------------------------------------
# Deterministic serialization
# --------------------------------------------------------------------------
# Key order is schema-defined (not alphabetical, not insertion-luck) so that
# editing one criterion and re-approving produces a minimal, readable diff —
# the same governance property CI_GATE.md documents for gate.yml.

_STORY_KEYS = ("id", "title", "epic", "criteria")
_CRITERION_KEYS = ("id", "statement", "check")
_CHECK_KEYS = ("type", "payload")


def _ordered(mapping: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    # Emit ONLY known schema keys, in schema order. Validation rejects unknown
    # story/criterion keys, so there is nothing else to carry — the output is
    # guaranteed canonical.
    return {k: mapping[k] for k in keys if k in mapping and mapping[k] is not None}


def _canonical_story(story: dict[str, Any]) -> dict[str, Any]:
    data = _ordered(story, _STORY_KEYS)
    data["criteria"] = [
        {
            **_ordered(c, _CRITERION_KEYS),
            "check": _ordered(c.get("check", {}), _CHECK_KEYS),
        }
        for c in story.get("criteria", [])
    ]
    return data


def _dump(data: dict[str, Any]) -> str:
    # sort_keys=False keeps our schema-defined order; default_flow_style=False
    # keeps block style so line-based diffs stay meaningful.
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def dump_story_yaml(story: dict[str, Any]) -> str:
    """Serialize one story deterministically. Raises on an invalid story."""
    errors = validate_story(story)
    if errors:
        raise SpecBundleError("; ".join(errors))
    return _dump(_canonical_story(story))


def dump_manifest_yaml(
    *,
    generated_at: str,
    source_phase: str,
    approval: dict[str, Any],
) -> str:
    """Serialize the bundle manifest deterministically."""
    data = {
        "bundle_version": BUNDLE_VERSION,
        "generated_at": generated_at,
        "source_phase": source_phase,
        "approval": _ordered(
            approval, ("role", "user_email", "approved_by", "approved_at", "gate")
        ),
    }
    return _dump(data)


# --------------------------------------------------------------------------
# Read-back
# --------------------------------------------------------------------------


def load_bundle(project_root: Path | str) -> dict[str, Any] | None:
    """Load ``.linebreak/spec/`` from a project root.

    Returns ``None`` when no bundle exists (absence is not an error — the
    project simply hasn't handed off a spec). Raises :class:`SpecBundleError`
    on ANY malformation: unparseable YAML, missing manifest, invalid story, a
    story file whose name disagrees with the story id inside it, a STRAY file
    in ``stories/`` (e.g. ``.yaml``, ``.orig`` — a writer only ever emits
    ``<id>.yml``, so a mismatch means the bundle was tampered with), or a
    version-1 manifest with zero stories (no writer emits an empty bundle).
    Fail closed on structure — never silently drop part of the approved set.
    """
    root = Path(project_root)
    spec_dir = root / SPEC_DIR
    if not spec_dir.exists():
        return None
    manifest_path = spec_dir / MANIFEST_NAME
    if not manifest_path.exists():
        raise SpecBundleError(f"{SPEC_DIR}/ exists but {MANIFEST_NAME} is missing")
    manifest = _load_yaml(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("bundle_version") != BUNDLE_VERSION:
        raise SpecBundleError(f"manifest is not a version-{BUNDLE_VERSION} bundle: {manifest_path}")

    stories: list[dict[str, Any]] = []
    stories_dir = root / STORIES_DIR
    for path in sorted(stories_dir.iterdir()) if stories_dir.exists() else []:
        # Only ``<safe-id>.yml`` files belong here; anything else means the
        # bundle was hand-modified and can no longer be trusted whole.
        if not path.is_file() or path.suffix != ".yml" or not _ID_RE.match(path.stem):
            raise SpecBundleError(f"unexpected file in stories/: {path.name}")
        story = _load_yaml(path)
        errors = validate_story(story)
        if errors:
            raise SpecBundleError(f"{path.name}: " + "; ".join(errors))
        if story["id"] != path.stem:
            raise SpecBundleError(f"{path.name}: filename disagrees with story id {story['id']!r}")
        stories.append(story)
    if not stories:
        raise SpecBundleError(
            f"{SPEC_DIR}/ has a v{BUNDLE_VERSION} manifest but no stories — a truncated bundle"
        )
    return {"manifest": manifest, "stories": stories}


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        raise SpecBundleError(f"could not parse {path.name}: {e}") from e
