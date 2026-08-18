"""LIN-55 MCP bridge core: the approved spec, served to the developer's editor.

These functions are the single implementation behind BOTH the MCP server
(``linebreak-gate mcp``) and the plain-CLI equivalents (``linebreak-gate spec
next|show|check``). Editor-agnostic by construction: they take a repo root and
return plain dicts.

Architectural constraints (the whole point):

- **Git is the transport.** Everything reads ``.linebreak/spec/`` from the
  working tree. No network, no governance-backend call, no LineBreak account.
  A developer who was merely handed a clone can use all of it.
- **Read-only over the approved standard.** Only :func:`set_story_status`
  writes, and only local story state (the LIN-45 mechanism). Nothing here can
  write, edit, or invalidate an approved criterion — criteria change in the
  governance surface and get re-approved there.
- **Honest states.** No spec is a plainly-stated fact, not an error. An
  unsigned bundle works and says it is unsigned. A tampered bundle is reported
  loudly but does NOT block these tools — blocking is the merge gate's job.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import criteria_check, gate_config, signoffs, spec_bundle, story_state

#: The exact phrasing every op uses when `.linebreak/spec/` is absent.
NO_SPEC_MESSAGE = "no approved spec found in this repository"

_DONE = "done"
_DEFAULT_STATE = "todo"


# ---------------------------------------------------------------- loading


def _load(project_root: Path | str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """(bundle, error_response). Absence and malformedness are both stated
    plainly; neither raises out of the bridge. The ``error`` marker lets the
    CLI keep spec list's exit contract (malformed = fail closed exit 2,
    absent = a fact, exit 0)."""
    try:
        bundle = spec_bundle.load_bundle(Path(project_root))
    except spec_bundle.SpecBundleError as e:
        return None, {"ok": False, "error": "malformed", "message": f"malformed spec bundle: {e}"}
    if bundle is None:
        return None, {"ok": False, "error": "no-spec", "message": NO_SPEC_MESSAGE}
    return bundle, None


def _signature_status(project_root: Path | str, bundle: dict[str, Any]) -> tuple[str, str | None]:
    """Classify the bundle's approval signature OFFLINE: ``verified`` |
    ``invalid`` | ``signed-unverified`` | ``unsigned`` (+ human detail).

    GATE PARITY is the invariant: whenever a verification key is configured,
    this delegates to the SAME :func:`criteria_check.verify_bundle_signature`
    the merge gate runs — so a bundle the gate would block (missing envelope,
    untrusted kid, bad signature, hash or phase mismatch) is ``invalid`` here,
    never a benign-sounding tier the developer discovers at the merge.

    With no key configured, tamper is still evident: the signed envelope's
    ``artifact_hash`` must equal the current bundle hash and its ``phase``
    must match the manifest ``source_phase`` (the same bindings the gate
    checks, minus the cryptography).
    """
    try:
        keys = gate_config.resolve_config(project_root).approval_public_keys
    except gate_config.GateConfigError as e:
        keys = ()
        # A broken gate.yml can't verify anything; fall through to the
        # keyless checks and say why full verification was unavailable.
        config_note = f"gate.yml could not be read ({e})"
    else:
        config_note = None

    if keys:
        # The gate's own verifier: raises on missing/untrusted/tampered/
        # phase-mismatched — every one of those is a merge-time block.
        try:
            criteria_check.verify_bundle_signature(bundle, keys)
        except criteria_check.BundleSignatureError as e:
            return "invalid", str(e)
        return "verified", None

    envelope = bundle["manifest"].get("signed_approval")
    if not isinstance(envelope, dict):
        return "unsigned", None

    # No verification key: the hash + phase bindings are still tamper-evident.
    current = spec_bundle.bundle_hash(bundle)
    signed_hash = envelope.get("artifact_hash")
    if signed_hash != current:
        return (
            "invalid",
            "the signed approval does not cover this bundle — it was edited after it was "
            f"approved (bundle hashes to {current}, the approval signed {signed_hash})",
        )
    source_phase = bundle["manifest"].get("source_phase")
    if envelope.get("phase") != source_phase:
        return (
            "invalid",
            f"the signed approval is for phase {envelope.get('phase')!r} but this bundle's "
            f"source_phase is {source_phase!r}",
        )
    detail = config_note or "a signature is present but no verification key is configured"
    return "signed-unverified", detail


def _flag_if_tampered(project_root: Path | str, bundle: dict[str, Any], out: dict[str, Any]):
    """Attach a loud signature flag to a read response when the bundle was
    edited after approval — the tools keep working, but tampered criteria are
    never presented as verified-approved."""
    status, detail = _signature_status(project_root, bundle)
    if status == "invalid":
        out["signature"] = "invalid"
        out["signature_detail"] = detail
    return out


def _states(project_root: Path | str) -> dict[str, str]:
    return story_state.read_states(project_root)


def _story_summary(story: dict[str, Any], states: dict[str, str]) -> dict[str, Any]:
    return {
        "id": story["id"],
        "title": story["title"],
        "epic": story.get("epic"),
        "status": states.get(story["id"], _DEFAULT_STATE),
        "criteria_count": len(story["criteria"]),
    }


def _story_full(story: dict[str, Any], states: dict[str, str]) -> dict[str, Any]:
    return {
        "id": story["id"],
        "title": story["title"],
        "epic": story.get("epic"),
        "status": states.get(story["id"], _DEFAULT_STATE),
        "criteria": [
            {"id": c["id"], "statement": c["statement"], "check": dict(c["check"])}
            for c in story["criteria"]
        ],
    }


def _find(bundle: dict[str, Any], story_id: str) -> dict[str, Any] | None:
    return next((s for s in bundle["stories"] if s["id"] == story_id), None)


def _unknown_story(bundle: dict[str, Any], story_id: str) -> dict[str, Any]:
    known = ", ".join(s["id"] for s in bundle["stories"])
    return {
        "ok": False,
        "message": f"no approved story {story_id!r} in this spec (approved stories: {known})",
    }


# ---------------------------------------------------------------- the six ops


def list_stories(project_root: Path | str) -> dict[str, Any]:
    """All approved stories: id, title, epic, local status, criteria count."""
    bundle, err = _load(project_root)
    if err:
        return err
    states = _states(project_root)
    out = {"ok": True, "stories": [_story_summary(s, states) for s in bundle["stories"]]}
    return _flag_if_tampered(project_root, bundle, out)


def get_story(project_root: Path | str, story_id: str) -> dict[str, Any]:
    """One full story: title, epic, and every acceptance criterion with its
    id, statement, and check type — the payload the editor's agent holds as
    context before it writes a line."""
    bundle, err = _load(project_root)
    if err:
        return err
    story = _find(bundle, story_id)
    if story is None:
        return _unknown_story(bundle, story_id)
    out = {"ok": True, "story": _story_full(story, _states(project_root))}
    return _flag_if_tampered(project_root, bundle, out)


def next_story(project_root: Path | str) -> dict[str, Any]:
    """The next approved story not yet done, in bundle order, per local story
    state. All-done is a fact worth congratulating, not an error."""
    bundle, err = _load(project_root)
    if err:
        return err
    states = _states(project_root)
    for story in bundle["stories"]:
        if states.get(story["id"], _DEFAULT_STATE) != _DONE:
            out = {"ok": True, "story": _story_full(story, states)}
            return _flag_if_tampered(project_root, bundle, out)
    out = {
        "ok": True,
        "story": None,
        "message": "every approved story is done — nothing left in this spec",
    }
    return _flag_if_tampered(project_root, bundle, out)


def set_story_status(
    project_root: Path | str, story_id: str, status: str, *, comment: str | None = None
) -> dict[str, Any]:
    """Record a story-state transition (doing | review | done) via the LIN-45
    local mechanism. The ONLY write in the bridge — and never against a
    configured external tracker, never against the approved criteria."""
    bundle, err = _load(project_root)
    if err:
        return err
    if _find(bundle, story_id) is None:
        return _unknown_story(bundle, story_id)
    result = story_state.set_state(project_root, story_id, status, comment=comment)
    if not result["ok"]:
        return {"ok": False, "message": result["reason"]}
    return result


def check_story(
    project_root: Path | str,
    story_id: str,
    *,
    run: Callable[[dict[str, Any], Path], criteria_check.RunOutcome] | None = None,
) -> dict[str, Any]:
    """Run THIS story's criteria against the working tree with the same
    evaluation engine as ``linebreak-gate check`` — so the developer's agent
    verifies its work before pushing instead of discovering it at the merge.
    Never writes the results artifact (a partial run is not the project verdict)
    and never blocks on signature state (that is the merge gate's job)."""
    bundle, err = _load(project_root)
    if err:
        return err
    if _find(bundle, story_id) is None:
        return _unknown_story(bundle, story_id)
    kwargs: dict[str, Any] = {"story_ids": {story_id}, "write_artifact": False}
    if run is not None:
        kwargs["run"] = run
    # Never raises out of the bridge: malformed structures and broken sign-off
    # records are honest messages (the engine re-loads the bundle itself, so a
    # concurrent deletion can also surface here as None).
    try:
        payload = criteria_check.evaluate_bundle(project_root, **kwargs)
    except criteria_check.CriteriaToolError as e:
        return {"ok": False, "message": f"could not run the checks: {e}"}
    except spec_bundle.SpecBundleError as e:
        return {"ok": False, "error": "malformed", "message": f"malformed spec bundle: {e}"}
    except signoffs.SignoffError as e:
        return {"ok": False, "error": "malformed", "message": f"sign-off records unreadable: {e}"}
    if payload is None:
        return {"ok": False, "error": "no-spec", "message": NO_SPEC_MESSAGE}
    out = {
        "ok": True,
        "story_id": story_id,
        "passes": payload["passes"],
        "tool_error": payload["tool_error"],
        "criteria": payload["criteria"],
    }
    return _flag_if_tampered(project_root, bundle, out)


def spec_status(project_root: Path | str) -> dict[str, Any]:
    """Is there an approved bundle, what version, approved by whom and when,
    and is the signature present/valid — verified entirely offline."""
    bundle, err = _load(project_root)
    if err:
        return err
    manifest = bundle["manifest"]
    status, detail = _signature_status(project_root, bundle)
    envelope = manifest.get("signed_approval") if isinstance(manifest, dict) else None
    envelope = envelope if isinstance(envelope, dict) else {}
    out: dict[str, Any] = {
        "ok": True,
        "available": True,
        "bundle_version": manifest.get("bundle_version"),
        "source_phase": manifest.get("source_phase"),
        "generated_at": manifest.get("generated_at"),
        "approved_by": (manifest.get("approval") or {}).get("approved_by"),
        "stories": len(bundle["stories"]),
        "signature": status,
        "signed_by": envelope.get("approver_email"),
        "self_approved": bool(envelope.get("self_approved")),
    }
    if detail:
        out["signature_detail"] = detail
    return out
