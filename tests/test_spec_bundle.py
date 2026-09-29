"""The spec bundle (LIN-35): approved acceptance criteria as structured data.

One canonical schema module serves both writers (the desktop app's handoff on
phase approval) and readers (``linebreak-gate spec list`` today, enforcement in
Piece 3). Tests pin the fixed check vocabulary, the deterministic
serialization (diffs between approvals must be meaningful), and fail-closed
loading of malformed bundles."""

from pathlib import Path

import pytest

from linebreak_gate import spec_bundle
from linebreak_gate.spec_bundle import (
    CHECK_TYPES,
    SpecBundleError,
    dump_manifest_yaml,
    dump_story_yaml,
    load_bundle,
    validate_story,
)

STORY = {
    "id": "S1",
    "title": "User can sign in",
    "epic": "Auth",
    "criteria": [
        {
            "id": "S1-AC1",
            "statement": "The project builds cleanly",
            "check": {"type": "build"},
        },
        {
            "id": "S1-AC2",
            "statement": "Login round-trip is covered by tests",
            "check": {"type": "tests", "payload": "tests/test_login.py"},
        },
        {
            "id": "S1-AC3",
            "statement": "Sign-in flow demo approved by design",
            "check": {"type": "manual"},
        },
    ],
}

MANIFEST_FIELDS = {
    "generated_at": "2026-07-13T00:00:00Z",
    "source_phase": "epics_and_stories",
    "approval": {
        "role": "architect",
        "user_email": "v@example.com",
        "approved_by": "v@example.com",
        "approved_at": "2026-07-13T00:00:01Z",
    },
}


def test_vocabulary_is_exactly_the_four_check_types():
    assert CHECK_TYPES == {"build", "tests", "command", "manual"}


def test_valid_story_has_no_errors():
    assert validate_story(STORY) == []


@pytest.mark.parametrize(
    "mutate, expected",
    [
        (lambda s: s.pop("id"), "id"),
        (lambda s: s.pop("title"), "title"),
        (lambda s: s.update(criteria="nope"), "criteria"),
        (lambda s: s["criteria"][0].pop("id"), "id"),
        (lambda s: s["criteria"][0].pop("statement"), "statement"),
        (lambda s: s["criteria"][0].update(check={"type": "vibes"}), "vibes"),
        (lambda s: s["criteria"][0].update(check={}), "type"),
        (lambda s: s["criteria"][0].update(check="build"), "check"),
    ],
)
def test_invalid_stories_are_rejected_with_a_named_error(mutate, expected):
    import copy

    story = copy.deepcopy(STORY)
    mutate(story)
    errors = validate_story(story)
    assert errors, "expected validation errors"
    assert any(expected in e for e in errors)


def test_duplicate_criterion_ids_rejected():
    import copy

    story = copy.deepcopy(STORY)
    story["criteria"][1]["id"] = "S1-AC1"
    assert any("duplicate" in e for e in validate_story(story))


def test_dump_story_yaml_is_deterministic_and_stable_key_order():
    a = dump_story_yaml(STORY)
    b = dump_story_yaml(dict(reversed(list(STORY.items()))))  # same data, scrambled order
    assert a == b
    # Schema-defined key order, not alphabetical: id before title before criteria.
    assert a.index("id:") < a.index("title:") < a.index("criteria:")


def test_manifest_dump_contains_version_and_attribution():
    text = dump_manifest_yaml(**MANIFEST_FIELDS)
    assert "bundle_version: 1" in text
    assert "source_phase: epics_and_stories" in text
    assert "approved_by: v@example.com" in text


def _write_bundle(root: Path, stories=None):
    spec_dir = root / ".linebreak" / "spec"
    (spec_dir / "stories").mkdir(parents=True)
    (spec_dir / "manifest.yml").write_text(dump_manifest_yaml(**MANIFEST_FIELDS), encoding="utf-8")
    for s in stories or [STORY]:
        (spec_dir / "stories" / f"{s['id']}.yml").write_text(dump_story_yaml(s), encoding="utf-8")


def test_load_bundle_roundtrip(tmp_path):
    _write_bundle(tmp_path)
    bundle = load_bundle(tmp_path)
    assert bundle["manifest"]["approval"]["role"] == "architect"
    assert bundle["stories"][0]["id"] == "S1"
    assert bundle["stories"][0]["criteria"][1]["check"]["payload"] == "tests/test_login.py"


def test_load_bundle_missing_returns_none(tmp_path):
    assert load_bundle(tmp_path) is None


@pytest.mark.parametrize(
    "corrupt",
    [
        lambda d: (d / "manifest.yml").write_text(": not yaml [", encoding="utf-8"),
        lambda d: (d / "manifest.yml").unlink(),
        lambda d: (d / "stories" / "S1.yml").write_text(
            "id: S1\n", encoding="utf-8"
        ),  # no title/criteria
        lambda d: (d / "stories" / "S1.yml").write_text("- just\n- a list\n", encoding="utf-8"),
    ],
)
def test_load_bundle_malformed_raises(tmp_path, corrupt):
    _write_bundle(tmp_path)
    corrupt(tmp_path / ".linebreak" / "spec")
    with pytest.raises(SpecBundleError):
        load_bundle(tmp_path)


def test_story_filename_mismatch_raises(tmp_path):
    _write_bundle(tmp_path)
    stories = tmp_path / ".linebreak" / "spec" / "stories"
    (stories / "S1.yml").rename(stories / "S9.yml")
    with pytest.raises(SpecBundleError):
        load_bundle(tmp_path)


@pytest.mark.parametrize("bad_id", ["../evil", "a/b", "..", ".", "/abs", "a b"])
def test_story_id_must_be_a_path_safe_slug(bad_id):
    # The id becomes a filename; a separator or ``..`` would escape stories/.
    import copy

    story = copy.deepcopy(STORY)
    story["id"] = bad_id
    assert any("match" in e or "id" in e for e in validate_story(story))


def test_unknown_story_and_check_keys_are_rejected():
    import copy

    story = copy.deepcopy(STORY)
    story["surprise"] = "junk"
    story["criteria"][0]["check"]["extra"] = "x"
    errors = validate_story(story)
    assert any("unknown key" in e for e in errors)
    assert any("unknown check key" in e for e in errors)


def test_validate_sidecar_flags_cross_story_duplicate_id():
    import copy

    dup = copy.deepcopy(STORY)
    errors = spec_bundle.validate_sidecar({"stories": [STORY, dup]})
    assert any("duplicate story id" in e for e in errors)


def test_validate_sidecar_requires_non_empty_stories_list():
    assert spec_bundle.validate_sidecar({"stories": []})
    assert spec_bundle.validate_sidecar({})
    assert spec_bundle.validate_sidecar([STORY])  # not a mapping


def test_load_bundle_rejects_stray_files_in_stories_dir(tmp_path):
    _write_bundle(tmp_path)
    stories = tmp_path / ".linebreak" / "spec" / "stories"
    (stories / "S1.yaml").write_text(dump_story_yaml(STORY), encoding="utf-8")  # wrong ext
    with pytest.raises(SpecBundleError):
        load_bundle(tmp_path)


def test_load_bundle_rejects_manifest_with_no_stories(tmp_path):
    spec_dir = tmp_path / ".linebreak" / "spec"
    (spec_dir / "stories").mkdir(parents=True)
    (spec_dir / "manifest.yml").write_text(dump_manifest_yaml(**MANIFEST_FIELDS), encoding="utf-8")
    with pytest.raises(SpecBundleError):
        load_bundle(tmp_path)


def test_module_is_stdlib_plus_yaml_only():
    # The desktop backend imports this module through its gate dependency —
    # keep it free of anthropic/network imports so importing it stays cheap.
    import inspect

    src = inspect.getsource(spec_bundle)
    assert "anthropic" not in src
    assert "urllib" not in src


# ---------------------------------------------------------------- LIN-37 hardening


def test_criterion_id_must_be_path_safe():
    import copy

    story = copy.deepcopy(STORY)
    story["criteria"][0]["id"] = "../../evil"
    errors = validate_story(story)
    assert any("path separators" in e or "must match" in e for e in errors)


def test_criterion_ids_must_be_unique_across_the_bundle():
    s1 = {
        "id": "S1",
        "title": "A",
        "criteria": [{"id": "AC1", "statement": "x", "check": {"type": "manual"}}],
    }
    s2 = {
        "id": "S2",
        "title": "B",
        "criteria": [{"id": "AC1", "statement": "y", "check": {"type": "manual"}}],
    }
    errors = spec_bundle.validate_sidecar({"stories": [s1, s2]})
    assert any("unique across the whole bundle" in e for e in errors)


def test_load_bundle_rejects_cross_story_duplicate_criterion_id(tmp_path):
    spec = tmp_path / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "manifest.yml").write_text(dump_manifest_yaml(**MANIFEST_FIELDS), encoding="utf-8")
    for sid in ("S1", "S2"):
        story = {
            "id": sid,
            "title": sid,
            "criteria": [{"id": "AC1", "statement": "x", "check": {"type": "manual"}}],
        }
        (spec / "stories" / f"{sid}.yml").write_text(dump_story_yaml(story), encoding="utf-8")
    with pytest.raises(SpecBundleError):
        load_bundle(tmp_path)


def test_criterion_hash_matches_on_disk_canonical_form():
    # The hash is computed over the SAME canonical serialization the story file
    # uses, so it can never drift from disk.
    c = STORY["criteria"][1]
    story_yaml = dump_story_yaml(STORY)
    assert c["check"]["payload"] in story_yaml
    assert spec_bundle.criterion_hash(c) == spec_bundle.criterion_hash(
        dict(reversed(list(c.items())))
    )
