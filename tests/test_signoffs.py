"""Recorded human sign-off for `manual` criteria (LIN-37 D2). Sign-offs are
attributed, additive (one file per record, never rewritten), bound to the
criterion id AND its content hash, and refuse missing approver/note."""

from __future__ import annotations

import pytest
from test_criteria_check import STORY, write_bundle

from linebreak_gate import signoffs


def test_signoff_writes_an_attributed_record(tmp_path):
    write_bundle(tmp_path)
    rec = signoffs.record_signoff(
        tmp_path, criterion_id="S1-AC4", approver="qa@example.com", note="demo reviewed"
    )
    assert rec["approver"] == "qa@example.com"
    assert rec["note"] == "demo reviewed"
    assert rec["criterion_id"] == "S1-AC4"
    assert rec["criterion_hash"]
    assert rec["signed_at"].endswith("Z")
    files = list((tmp_path / ".linebreak" / "spec" / "signoffs").glob("*.yml"))
    assert len(files) == 1


def test_signoffs_are_additive_never_rewritten(tmp_path):
    write_bundle(tmp_path)
    signoffs.record_signoff(tmp_path, criterion_id="S1-AC4", approver="a@x.com", note="first")
    first = {
        p.name: p.read_text(encoding="utf-8")
        for p in (tmp_path / ".linebreak" / "spec" / "signoffs").glob("*.yml")
    }
    signoffs.record_signoff(tmp_path, criterion_id="S1-AC4", approver="b@x.com", note="second")
    after = {
        p.name: p.read_text(encoding="utf-8")
        for p in (tmp_path / ".linebreak" / "spec" / "signoffs").glob("*.yml")
    }
    assert len(after) == 2
    for name, content in first.items():
        assert after[name] == content, "prior records are never rewritten"


@pytest.mark.parametrize("missing", ["approver", "note"])
def test_signoff_refuses_missing_attribution(tmp_path, missing):
    write_bundle(tmp_path)
    kwargs = {"criterion_id": "S1-AC4", "approver": "qa@example.com", "note": "ok"}
    kwargs[missing] = "   "
    with pytest.raises(signoffs.SignoffError):
        signoffs.record_signoff(tmp_path, **kwargs)


def test_signoff_refuses_unknown_criterion(tmp_path):
    write_bundle(tmp_path)
    with pytest.raises(signoffs.SignoffError):
        signoffs.record_signoff(tmp_path, criterion_id="NOPE", approver="a@x.com", note="n")


def test_signoff_refuses_non_manual_criterion(tmp_path):
    # Machine-checkable criteria are satisfied by the machine check (or an
    # override) — a sign-off must not become a side door around a failing test.
    write_bundle(tmp_path)
    with pytest.raises(signoffs.SignoffError):
        signoffs.record_signoff(tmp_path, criterion_id="S1-AC1", approver="a@x.com", note="n")


def test_load_signoffs_fails_closed_on_malformed_record(tmp_path):
    write_bundle(tmp_path)
    d = tmp_path / ".linebreak" / "spec" / "signoffs"
    d.mkdir(parents=True, exist_ok=True)
    (d / "junk.yml").write_text(": not yaml [", encoding="utf-8")
    with pytest.raises(signoffs.SignoffError):
        signoffs.load_signoffs(tmp_path)


def test_ambiguous_criterion_id_across_stories_is_refused(tmp_path):
    import copy

    s1 = copy.deepcopy(STORY)
    s2 = copy.deepcopy(STORY)
    s2["id"] = "S2"
    # Same criterion id in two stories — a sign-off for it would be ambiguous.
    s2["criteria"] = [{"id": "S1-AC4", "statement": "other", "check": {"type": "manual"}}]
    write_bundle(tmp_path, [s1, s2])
    with pytest.raises(signoffs.SignoffError):
        signoffs.record_signoff(tmp_path, criterion_id="S1-AC4", approver="a@x.com", note="n")


# ---------------------------------------------------------------- LIN-37 review hardening


def test_junk_files_in_signoffs_dir_are_ignored_not_fatal(tmp_path):
    # signoffs/ is a human-browsed, committed dir — OS/editor droppings must
    # not block every merge (fail closed only on a malformed .yml record).
    write_bundle(tmp_path)
    signoffs.record_signoff(tmp_path, criterion_id="S1-AC4", approver="a@x.com", note="n")
    d = tmp_path / ".linebreak" / "spec" / "signoffs"
    (d / ".DS_Store").write_text("junk", encoding="utf-8")
    (d / ".gitkeep").write_text("", encoding="utf-8")
    (d / "notes.txt").write_text("hi", encoding="utf-8")
    records = signoffs.load_signoffs(tmp_path)  # does not raise
    assert len(records) == 1


def test_path_traversal_criterion_id_never_reaches_the_bundle():
    # The path-safety guard lives at the schema boundary (validate_criterion),
    # so a traversal id can't be in an approved bundle — record_signoff resolves
    # against the bundle and cleanly refuses.
    from linebreak_gate import spec_bundle

    bad = {"id": "../../evil", "statement": "s", "check": {"type": "manual"}}
    assert spec_bundle.validate_criterion(bad)
