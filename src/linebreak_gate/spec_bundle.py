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

import hashlib
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

#: When a criterion is evaluated: ``always`` (implicit default) or ``release``
#: (skipped by ``check --stage pr`` and listed as release-only; evaluated, and
#: blocking as usual, by ``--stage release``). Criteria that run scripts
#: against a shared staging environment belong here, so a staging regression
#: does not turn every PR red, including the one that fixes it.
CHECK_WHEN = ("always", "release", "attestation")

#: ``when: attestation`` marks the ``manual`` criterion whose sign-off attests
#: a release RUN (for example "the release carries a signed attestation"). Such
#: a sign-off can only exist after a green run, so the run cannot demand it of
#: itself: ``check --stage release --phase prepare`` reports it as
#: ``awaiting-attestation`` (not evaluated, not blocking) while every other
#: criterion, manual ones included, is enforced as usual; ``--phase verify``
#: (the default) enforces it like any manual criterion. At ``--stage pr`` it is
#: release-only.
ATTESTATION_WHEN = "attestation"

#: Keys of ``check.environment`` (issue #264): the deployed environment a
#: check measures and where it answers its version (see ``environment.py``).
_ENVIRONMENT_KEYS = ("name", "version_url", "field")

#: A story id becomes a filename (``stories/<id>.yml``), so it must be a safe
#: slug — no path separators, no ``..``. The sidecar is LLM-authored and
#: hand-editable, so this is a security boundary, not just tidiness.
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

#: Keys the schema knows, in canonical order. Unknown keys are rejected rather
#: than silently round-tripped (the bundle is the agreed standard; junk must
#: not accrete). The validation whitelists are DERIVED from these tuples so a
#: key can never be accepted by the lint yet dropped by the serializer (which
#: would hide it from the criterion hash).
_STORY_KEYS = ("id", "title", "epic", "criteria")
_CRITERION_KEYS = ("id", "statement", "check")
#: ``resource`` (issue #262) names a shared resource the check mutates; checks
#: naming the same resource run alone (see ``resource_lock.py``).
_CHECK_KEYS = ("type", "payload", "when", "expect", "resource", "environment")
#: What a machine check declares it expects to OBSERVE (issue #260), beyond a
#: zero exit: ``output`` (a string, or a list of strings, every one of which
#: must appear in the check's output) and ``exit`` (the exit code the check
#: must end with, default 0). Canonical order, like every other key.
_EXPECT_KEYS = ("output", "exit")
#: Check types that run something and therefore have an output to inspect.
_EXPECT_TYPES = {"build", "tests", "command"}
_STORY_ALLOWED = set(_STORY_KEYS)
_CRITERION_ALLOWED = set(_CRITERION_KEYS)
_CHECK_ALLOWED = set(_CHECK_KEYS)


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
    elif not _ID_RE.match(cid):
        # Path-safety: a criterion id becomes a filename too (the sign-off
        # record ``signoffs/<criterion-id>-<uuid>.yml``, LIN-37), so it needs
        # the SAME slug guarantee as a story id — the bundle is LLM-authored
        # and hand-editable, so this is a security boundary.
        errors.append(
            f"story {story_id}/{cid}: criterion id must match {_ID_RE.pattern} "
            "(no path separators or '..')"
        )
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
    if "when" in check and check["when"] not in CHECK_WHEN:
        errors.append(
            f"story {story_id}/{cid}: check 'when' must be one of {' | '.join(CHECK_WHEN)}, "
            f"got {check['when']!r}"
        )
    elif check.get("when") == ATTESTATION_WHEN and ctype != "manual":
        errors.append(
            f"story {story_id}/{cid}: check 'when: attestation' is for a `manual` criterion "
            f"(the sign-off that attests a release run), not for a `{ctype}` check"
        )
    if "resource" in check:
        resource = check["resource"]
        if not isinstance(resource, str) or not _ID_RE.match(resource):
            errors.append(
                f"story {story_id}/{cid}: check 'resource' must be a slug matching "
                f"{_ID_RE.pattern} (it names a lock), got {resource!r}"
            )
        elif ctype == "manual":
            errors.append(
                f"story {story_id}/{cid}: check 'resource' applies to a check that runs "
                "something; a `manual` criterion runs nothing"
            )
    if "environment" in check:
        errors.extend(_validate_environment(check["environment"], ctype, f"{story_id}/{cid}"))
    if "expect" in check:
        errors.extend(_validate_expect(check["expect"], ctype, where=f"story {story_id}/{cid}"))
    return errors


def _validate_environment(env: Any, ctype: Any, where: str) -> list[str]:
    """``check.environment``: a mapping with a ``version_url`` (``$VAR`` allowed)
    and an optional ``name`` and JSON ``field``."""
    if ctype == "manual":
        return [
            f"story {where}: check 'environment' applies to a check that runs something; "
            "a `manual` criterion measures no environment"
        ]
    if not isinstance(env, dict):
        return [f"story {where}: check 'environment' must be a mapping with a 'version_url'"]
    errors: list[str] = []
    extra = set(env) - set(_ENVIRONMENT_KEYS)
    if extra:
        errors.append(f"story {where}: unknown environment key(s) {sorted(extra)}")
    url = env.get("version_url")
    if not isinstance(url, str) or not url.strip():
        errors.append(f"story {where}: check 'environment' requires a string 'version_url'")
    elif not url.startswith(("http://", "https://", "$")):
        errors.append(
            f"story {where}: environment 'version_url' must be an http(s) URL "
            f"(a $VARIABLE prefix is allowed), got {url!r}"
        )
    for key in ("name", "field"):
        if key in env and (not isinstance(env[key], str) or not env[key].strip()):
            errors.append(f"story {where}: environment '{key}' must be a non-empty string")
    return errors


def _validate_expect(expect: Any, ctype: Any, *, where: str) -> list[str]:
    """Errors for a check's ``expect`` block (issue #260)."""
    if ctype not in _EXPECT_TYPES:
        return [f"{where}: 'expect' only applies to build, tests and command checks"]
    if not isinstance(expect, dict) or not expect:
        return [f"{where}: 'expect' must be a mapping with 'output' and/or 'exit'"]
    errors: list[str] = []
    extra = set(expect) - set(_EXPECT_KEYS)
    if extra:
        errors.append(f"{where}: unknown expect key(s) {sorted(extra)}")
    if "output" in expect:
        output = expect["output"]
        items = output if isinstance(output, list) else [output]
        if not items or not all(isinstance(x, str) and x.strip() for x in items):
            errors.append(
                f"{where}: expect 'output' must be a non-empty string or a list of non-empty "
                "strings"
            )
    if "exit" in expect:
        code = expect["exit"]
        if isinstance(code, bool) or not isinstance(code, int) or not 0 <= code <= 255:
            errors.append(f"{where}: expect 'exit' must be an integer between 0 and 255")
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
    criterion_ids: set[str] = set()
    for story in stories:
        errors.extend(validate_story(story))
        sid = story.get("id") if isinstance(story, dict) else None
        if isinstance(sid, str):
            if sid in seen:
                errors.append(f"duplicate story id {sid!r} (would overwrite a story file)")
            seen.add(sid)
        # Criterion ids must be unique across the WHOLE bundle, not just within
        # a story: sign-offs and overrides bind to a bare criterion id, so a
        # reused id would let one approval satisfy a criterion in another story
        # (LIN-37 — enforcement matches by id, not by story).
        for c in story.get("criteria", []) if isinstance(story, dict) else []:
            ccid = c.get("id") if isinstance(c, dict) else None
            if isinstance(ccid, str) and ccid.strip():
                if ccid in criterion_ids:
                    errors.append(
                        f"criterion id {ccid!r} appears in more than one place — criterion "
                        "ids must be unique across the whole bundle so approvals bind unambiguously"
                    )
                criterion_ids.add(ccid)
    return errors


# --------------------------------------------------------------------------
# Deterministic serialization
# --------------------------------------------------------------------------
# Key order is schema-defined (not alphabetical, not insertion-luck) so that
# editing one criterion and re-approving produces a minimal, readable diff —
# the same governance property CI_GATE.md documents for gate.yml.


def _ordered(mapping: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    # Emit ONLY known schema keys, in schema order. Validation rejects unknown
    # story/criterion keys, so there is nothing else to carry — the output is
    # guaranteed canonical.
    return {k: mapping[k] for k in keys if k in mapping and mapping[k] is not None}


def _canonical_criterion(c: dict[str, Any]) -> dict[str, Any]:
    check = _ordered(c.get("check", {}), _CHECK_KEYS)
    # `when: always` is the implicit default: an explicit spelling is a no-op
    # for evaluation, so it must be a no-op for the hash too (otherwise writing
    # it would stale every sign-off and override for a change that changed
    # nothing). Normalize it away; only `when: release` is content.
    if check.get("when") == "always":
        del check["when"]
    if isinstance(check.get("environment"), dict):
        check["environment"] = _ordered(check["environment"], _ENVIRONMENT_KEYS)
    if isinstance(check.get("expect"), dict):
        expect = _canonical_expect(check["expect"])
        if expect:
            check["expect"] = expect
        else:
            del check["expect"]
    return {**_ordered(c, _CRITERION_KEYS), "check": check}


def _canonical_expect(expect: dict[str, Any]) -> dict[str, Any]:
    """``expect`` in canonical form: ``output`` always a list, ``exit: 0`` (the
    implicit default) dropped, keys in schema order. Two spellings that mean
    the same expectation hash the same."""
    out: dict[str, Any] = {}
    if "output" in expect:
        output = expect["output"]
        out["output"] = list(output) if isinstance(output, list) else [output]
    if expect.get("exit") not in (None, 0):
        out["exit"] = expect["exit"]
    return out


def _canonical_story(story: dict[str, Any]) -> dict[str, Any]:
    data = _ordered(story, _STORY_KEYS)
    data["criteria"] = [_canonical_criterion(c) for c in story.get("criteria", [])]
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


def criterion_hash(criterion: dict[str, Any]) -> str:
    """Content hash of one criterion (id + statement + check), over the same
    canonical serialization the bundle uses — key order can't change it.

    This is what sign-offs and criterion overrides BIND to: editing the
    criterion and re-approving changes the hash, so prior approvals go stale
    automatically (changing the standard invalidates old approvals), while
    edits to OTHER criteria or stories leave it untouched.
    """
    # Hash over the SAME canonical form the story files serialize, so the hash
    # can never drift from what's on disk.
    return hashlib.sha256(_dump(_canonical_criterion(criterion)).encode("utf-8")).hexdigest()


def bundle_hash(bundle: dict[str, Any]) -> str:
    """Content hash of a whole loaded bundle (LIN-51) — the artifact a signed
    approval covers.

    Over the SAME deterministic serialization the story files use (``_dump`` of
    the canonical form), so it can never drift from what is on disk. Covers
    ``bundle_version``, ``source_phase`` and every story (canonical form, sorted
    by id). Deliberately EXCLUDES the manifest's ``approval`` / ``signed_approval``
    blocks and ``generated_at``: those are attestation metadata, not the approved
    content, and ``generated_at`` would make the hash volatile across re-writes.

    Editing any criterion (or the source phase) changes the hash, so a bundle
    tampered with after signing fails ``artifact_hash`` verification at the gate.
    """
    manifest = bundle["manifest"]
    stories = sorted(bundle["stories"], key=lambda s: s["id"])
    canonical = {
        "bundle_version": manifest.get("bundle_version"),
        "source_phase": manifest.get("source_phase"),
        "stories": [_canonical_story(s) for s in stories],
    }
    return hashlib.sha256(_dump(canonical).encode("utf-8")).hexdigest()


def prospective_bundle_hash(stories: list[dict[str, Any]], source_phase: str) -> str:
    """The :func:`bundle_hash` the bundle WILL have once written, computed from
    the stories sidecar BEFORE writing (LIN-52).

    Delegates to :func:`bundle_hash` with a synthetic manifest so the prospective
    hash and the on-disk hash can never diverge. The desktop uses this to bind a
    governance approval request to exactly the content ``perform_spec_handoff``
    will land on disk — the request/decision hash and the manifest hash match by
    construction (``bundle_hash`` excludes ``generated_at`` and the attestation
    blocks, so only the story content + source phase matter).
    """
    synthetic = {
        "manifest": {"bundle_version": BUNDLE_VERSION, "source_phase": source_phase},
        "stories": stories,
    }
    return bundle_hash(synthetic)


def find_criterion(
    bundle: dict[str, Any], criterion_id: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Resolve a criterion id against a loaded bundle → (story, criterion).

    Raises :class:`SpecBundleError` when the id is absent or appears in more
    than one story (an approval bound to an ambiguous id could satisfy a
    criterion nobody signed).
    """
    matches = [
        (story, c)
        for story in bundle["stories"]
        for c in story["criteria"]
        if c["id"] == criterion_id
    ]
    if not matches:
        raise SpecBundleError(f"criterion {criterion_id!r} is not in the approved bundle")
    if len(matches) > 1:
        stories = ", ".join(s["id"] for s, _ in matches)
        raise SpecBundleError(
            f"criterion id {criterion_id!r} appears in more than one story ({stories}) — "
            "make criterion ids unique before recording approvals against them"
        )
    return matches[0]


#: Envelope key order for the manifest ``signed_approval`` block (LIN-51). The
#: cryptographic envelope is kept SEPARATE from the human-readable ``approval``
#: block so the existing attribution diffs stay surgical and the two never
#: conflate. Mirrors ``approval_sig.ENVELOPE_KEYS``.
_SIGNED_APPROVAL_KEYS = (
    "project_id",
    "phase",
    "artifact_hash",
    "approver_email",
    "approver_role",
    "self_approved",
    "approved_at",
    "bundle_version",
    "instance_id",
    "kid",
    "signature",
)


def dump_manifest_yaml(
    *,
    generated_at: str,
    source_phase: str,
    approval: dict[str, Any],
    signed_approval: dict[str, Any] | None = None,
) -> str:
    """Serialize the bundle manifest deterministically.

    ``signed_approval`` (LIN-51) is the Ed25519 envelope issued by the
    governance service; when absent (local, unsigned mode) the manifest is
    byte-for-byte what it was before signing existed. It is EXCLUDED from
    :func:`bundle_hash` — the hash covers the approved content, not the
    attestation over it.
    """
    data: dict[str, Any] = {
        "bundle_version": BUNDLE_VERSION,
        "generated_at": generated_at,
        "source_phase": source_phase,
        "approval": _ordered(
            approval,
            ("role", "user_email", "approved_by", "approved_at", "gate", "identity_source"),
        ),
    }
    if signed_approval is not None:
        data["signed_approval"] = _ordered(signed_approval, _SIGNED_APPROVAL_KEYS)
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
    # Criterion ids must be globally unique — enforcement (LIN-37) binds an
    # approval to a bare criterion id, so a reused id would let one sign-off
    # or override satisfy a criterion in another story. Fail closed on read.
    seen_cids: set[str] = set()
    for story in stories:
        for c in story["criteria"]:
            if c["id"] in seen_cids:
                raise SpecBundleError(
                    f"criterion id {c['id']!r} appears in more than one story — ids must be "
                    "unique across the bundle so approvals bind unambiguously"
                )
            seen_cids.add(c["id"])
    return {"manifest": manifest, "stories": stories}


def _load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        raise SpecBundleError(f"could not parse {path.name}: {e}") from e
