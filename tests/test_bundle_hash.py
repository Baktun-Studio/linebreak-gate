"""``bundle_hash`` (LIN-51) — the content hash a signed approval covers.

Pins what the hash binds (stories + source_phase) and what it deliberately
ignores (attestation metadata + generated_at), so a bundle edited after signing
fails verification while a mere re-write does not.
"""

from __future__ import annotations

import copy

from linebreak_gate import spec_bundle
from linebreak_gate.spec_bundle import bundle_hash

MANIFEST = {
    "bundle_version": 1,
    "generated_at": "2026-07-15T00:00:00Z",
    "source_phase": "epics_and_stories",
    "approval": {"role": "architect", "user_email": "a@example.com"},
}
STORIES = [
    {
        "id": "S1",
        "title": "Sign in",
        "criteria": [{"id": "S1-AC1", "statement": "builds", "check": {"type": "build"}}],
    },
    {
        "id": "S2",
        "title": "Sign out",
        "criteria": [
            {"id": "S2-AC1", "statement": "tested", "check": {"type": "tests", "payload": "t.py"}}
        ],
    },
]


def _bundle():
    return {"manifest": copy.deepcopy(MANIFEST), "stories": copy.deepcopy(STORIES)}


def test_bundle_hash_is_deterministic():
    assert bundle_hash(_bundle()) == bundle_hash(_bundle())


def test_bundle_hash_is_story_order_independent():
    b1 = _bundle()
    b2 = _bundle()
    b2["stories"].reverse()
    assert bundle_hash(b1) == bundle_hash(b2)


def test_bundle_hash_ignores_generated_at_and_approval():
    # A re-write (new timestamp, re-attributed approval, added signature block)
    # must NOT change the hash — those are attestation metadata, not content.
    b = _bundle()
    baseline = bundle_hash(b)
    b["manifest"]["generated_at"] = "2099-01-01T00:00:00Z"
    b["manifest"]["approval"] = {"role": "admin", "user_email": "other@example.com"}
    b["manifest"]["signed_approval"] = {"kid": "x", "signature": "y"}
    assert bundle_hash(b) == baseline


def test_bundle_hash_changes_when_a_criterion_is_edited():
    b = _bundle()
    baseline = bundle_hash(b)
    b["stories"][0]["criteria"][0]["statement"] = "builds AND lints"
    assert bundle_hash(b) != baseline


def test_bundle_hash_changes_when_source_phase_changes():
    b = _bundle()
    baseline = bundle_hash(b)
    b["manifest"]["source_phase"] = "prd"
    assert bundle_hash(b) != baseline


def test_bundle_hash_changes_when_a_story_is_added():
    b = _bundle()
    baseline = bundle_hash(b)
    b["stories"].append(
        {
            "id": "S3",
            "title": "extra",
            "criteria": [{"id": "S3-AC1", "statement": "x", "check": {"type": "manual"}}],
        }
    )
    assert bundle_hash(b) != baseline


def test_bundle_hash_over_canonical_form_survives_key_reorder():
    # Building a story dict with keys in a different insertion order must not
    # change the hash — the canonicalizer fixes key order.
    b = _bundle()
    baseline = bundle_hash(b)
    reordered = {
        "criteria": b["stories"][0]["criteria"],
        "title": b["stories"][0]["title"],
        "id": b["stories"][0]["id"],
    }
    b["stories"][0] = reordered
    assert bundle_hash(b) == baseline


def test_manifest_serializer_emits_signed_approval_block():
    yaml_out = spec_bundle.dump_manifest_yaml(
        generated_at="2026-07-15T00:00:00Z",
        source_phase="prd",
        approval={"role": "architect"},
        signed_approval={
            "project_id": "p",
            "phase": "prd",
            "artifact_hash": "h",
            "approver_email": "a@example.com",
            "approver_role": "architect",
            "approved_at": "2026-07-15T00:00:00Z",
            "bundle_version": 1,
            "instance_id": "i",
            "kid": "k",
            "signature": "s",
        },
    )
    assert "signed_approval:" in yaml_out
    # Deterministic key order: project_id before signature.
    assert yaml_out.index("project_id") < yaml_out.index("signature")


def test_manifest_serializer_omits_signed_approval_when_absent():
    yaml_out = spec_bundle.dump_manifest_yaml(
        generated_at="2026-07-15T00:00:00Z",
        source_phase="prd",
        approval={"role": "architect"},
    )
    assert "signed_approval" not in yaml_out
