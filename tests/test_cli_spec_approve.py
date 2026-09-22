"""``linebreak-gate spec new`` / ``spec approve`` — the tool-agnostic
authoring path (CLI counterpart of the desktop spec-to-git handoff).

Exit contract: approve → 0 approved (commit trouble is a printed warning,
never fatal), 1 environment failure, 2 invalid draft (fail closed on
structure). The written bundle must be indistinguishable from an app-written
one to every reader (``load_bundle``, ``spec list``, the bridge)."""

import subprocess

import yaml

from linebreak_gate.cli import main
from linebreak_gate.spec_bundle import load_bundle

DRAFT = {
    "stories": [
        {
            "id": "S1",
            "title": "User can sign in",
            "criteria": [
                {"id": "S1-AC1", "statement": "Builds cleanly", "check": {"type": "build"}},
                {
                    "id": "S1-AC2",
                    "statement": "Covered by tests",
                    "check": {"type": "tests", "payload": "tests/test_login.py"},
                },
                {
                    "id": "S1-AC3",
                    "statement": "A human verified staging",
                    "check": {"type": "manual"},
                },
            ],
        }
    ]
}


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)


def _init_repo(root):
    _git(root, "init")
    _git(root, "config", "user.email", "test@example.com")
    _git(root, "config", "user.name", "Test")


def _write_draft(root, data=DRAFT, name="draft.yml"):
    path = root / name
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


# ---------------------------------------------------------------- spec new


def test_spec_new_scaffolds_a_valid_draft(tmp_path, capsys):
    assert main(["spec", "new", "--path", str(tmp_path)]) == 0
    draft = tmp_path / ".linebreak" / "spec-draft.yml"
    assert draft.exists()
    out = capsys.readouterr().out
    assert "spec approve" in out
    # The scaffold itself must APPROVE cleanly — a template that fails its own
    # approval teaches the wrong format.
    assert (
        main(["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "a@b.com"]) == 0
    )


def test_spec_new_refuses_to_overwrite_without_force(tmp_path, capsys):
    assert main(["spec", "new", "--path", str(tmp_path)]) == 0
    assert main(["spec", "new", "--path", str(tmp_path)]) == 1
    assert "--force" in capsys.readouterr().err
    assert main(["spec", "new", "--path", str(tmp_path), "--force"]) == 0


# ---------------------------------------------------------------- spec approve


def test_approve_lands_a_bundle_every_reader_accepts(tmp_path, capsys):
    _init_repo(tmp_path)
    draft = _write_draft(tmp_path)
    code = main(
        [
            "spec",
            "approve",
            str(draft),
            "--path",
            str(tmp_path),
            "--approver",
            "Ana Lopez <ana@example.com>",
        ]
    )
    assert code == 0
    bundle = load_bundle(tmp_path)
    assert bundle is not None
    assert [s["id"] for s in bundle["stories"]] == ["S1"]
    approval = bundle["manifest"]["approval"]
    assert approval["approved_by"] == "Ana Lopez <ana@example.com>"
    assert approval["role"] == "architect"
    # Human-typed, unverified — same honesty marker as sign-offs/overrides.
    assert approval["identity_source"] == "client"
    out = capsys.readouterr().out
    assert "Approved: 1 story(ies)" in out
    assert "Unsigned local approval" in out
    # And the read-side renders it like any app-written bundle.
    assert main(["spec", "list", "--path", str(tmp_path)]) == 0


def test_approve_commits_the_bundle(tmp_path):
    _init_repo(tmp_path)
    draft = _write_draft(tmp_path)
    assert (
        main(["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "a@b.com"]) == 0
    )
    log = _git(tmp_path, "log", "--oneline", "--", ".linebreak/spec").stdout
    assert "spec: approved acceptance criteria" in log
    # Only the bundle is committed — the draft stays untracked.
    status = _git(tmp_path, "status", "--porcelain").stdout
    assert "draft.yml" in status


def test_approve_without_git_repo_warns_but_succeeds(tmp_path, capsys):
    draft = _write_draft(tmp_path)
    assert (
        main(["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "a@b.com"]) == 0
    )
    out = capsys.readouterr().out
    assert "NOT committed" in out
    assert load_bundle(tmp_path) is not None


def test_approve_invalid_draft_exits_2_and_writes_nothing(tmp_path, capsys):
    bad = {
        "stories": [
            {
                "id": "S1",
                "title": "t",
                "criteria": [{"id": "A", "statement": "s", "check": {"type": "vibes"}}],
            }
        ]
    }
    draft = _write_draft(tmp_path, data=bad)
    assert (
        main(["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "a@b.com"]) == 2
    )
    err = capsys.readouterr().err
    assert "nothing approved" in err and "vibes" in err
    assert not (tmp_path / ".linebreak" / "spec").exists()


def test_approve_missing_draft_exits_2(tmp_path, capsys):
    assert (
        main(["spec", "approve", "nope.yml", "--path", str(tmp_path), "--approver", "a@b.com"]) == 2
    )
    assert "draft not found" in capsys.readouterr().err


def test_rewriting_same_approval_is_idempotent(tmp_path):
    """The writer's guarantee: re-landing the SAME approval event over
    identical content re-uses the prior timestamp — no churn. (Deterministic
    unit-level pin; the CLI path can't promise this across seconds because a
    re-approval is a genuinely new approval event, tested below.)"""
    from linebreak_gate import spec_write

    approval = {
        "role": "architect",
        "user_email": "a@b.com",
        "approved_by": "a@b.com",
        "approved_at": "2026-08-05T00:00:00Z",
        "gate": "spec-approve",
        "identity_source": "client",
    }
    spec_write.write_bundle(
        tmp_path,
        DRAFT["stories"],
        source_phase="cli",
        approval=approval,
        generated_at="2026-08-05T00:00:00Z",
    )
    manifest = tmp_path / ".linebreak" / "spec" / "manifest.yml"
    before = manifest.read_text()
    # Same approval, later wall clock (a retry) — the prior timestamp wins.
    spec_write.write_bundle(
        tmp_path,
        DRAFT["stories"],
        source_phase="cli",
        approval=approval,
        generated_at="2026-08-05T00:00:59Z",
    )
    assert manifest.read_text() == before


def test_reapproving_identical_draft_records_new_approval_only(tmp_path):
    """Re-running `spec approve` is a NEW approval event: the manifest may
    update its attribution, but the approved stories stay byte-identical and
    the bundle stays valid — never a duplicate or a churned story file."""
    _init_repo(tmp_path)
    draft = _write_draft(tmp_path)
    args = ["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "a@b.com"]
    assert main(args) == 0
    stories_dir = tmp_path / ".linebreak" / "spec" / "stories"
    stories_before = {p.name: p.read_bytes() for p in stories_dir.iterdir()}
    assert main(args) == 0
    assert {p.name: p.read_bytes() for p in stories_dir.iterdir()} == stories_before
    assert load_bundle(tmp_path) is not None


def test_reapproving_edited_draft_prunes_removed_stories(tmp_path):
    _init_repo(tmp_path)
    two = {
        "stories": DRAFT["stories"]
        + [
            {
                "id": "S2",
                "title": "Second",
                "criteria": [{"id": "S2-AC1", "statement": "s", "check": {"type": "build"}}],
            }
        ]
    }
    draft = _write_draft(tmp_path, data=two)
    args = ["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "a@b.com"]
    assert main(args) == 0
    assert (tmp_path / ".linebreak" / "spec" / "stories" / "S2.yml").exists()
    _write_draft(tmp_path)  # back to one story
    assert main(args) == 0
    # The bundle IS the approved set — a story removed between approvals goes.
    assert not (tmp_path / ".linebreak" / "spec" / "stories" / "S2.yml").exists()
    assert [s["id"] for s in load_bundle(tmp_path)["stories"]] == ["S1"]


def test_approve_accepts_the_app_sidecar_json(tmp_path):
    # The desktop's _bmad-output/epics-and-stories.json is valid YAML too —
    # one draft format, not two.
    _init_repo(tmp_path)
    sidecar = tmp_path / "epics-and-stories.json"
    import json

    sidecar.write_text(json.dumps(DRAFT), encoding="utf-8")
    assert (
        main(["spec", "approve", str(sidecar), "--path", str(tmp_path), "--approver", "a@b.com"])
        == 0
    )
    assert load_bundle(tmp_path) is not None
