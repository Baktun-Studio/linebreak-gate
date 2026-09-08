"""LIN-55 MCP bridge core ops — editor-agnostic, offline, account-free.

These are the functions both the MCP server and the CLI equivalents call.
Everything reads `.linebreak/spec/` from the working tree; nothing here may
touch the network or mutate an approved criterion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from linebreak_gate import approval_sig, bridge, spec_bundle, story_state

NO_SPEC = "no approved spec found in this repository"


# ---------------------------------------------------------------- fixtures


def _write_bundle(root: Path, stories: list[dict], *, signed: bool = False, tamper: bool = False):
    """Author a minimal on-disk bundle the way spec_handoff would."""
    spec_dir = root / ".linebreak" / "spec"
    stories_dir = spec_dir / "stories"
    stories_dir.mkdir(parents=True, exist_ok=True)
    for story in stories:
        (stories_dir / f"{story['id']}.yml").write_text(
            spec_bundle.dump_story_yaml(story), encoding="utf-8"
        )
    signed_approval = None
    if signed:
        bundle = {
            "manifest": {"bundle_version": 1, "source_phase": "epics_and_stories"},
            "stories": stories,
        }
        payload = {
            "project_id": "p1",
            "phase": "epics_and_stories",
            "artifact_hash": spec_bundle.bundle_hash(bundle),
            "approver_email": "approver@x.test",
            "approver_role": "architect",
            "self_approved": False,
            "approved_at": "2026-07-16T00:00:00Z",
            "bundle_version": 1,
            "instance_id": "inst",
        }
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        # gate.yml validation requires the kid to be DERIVED from the public key.
        kid = approval_sig.kid_for_public_key(private_key.public_key())
        signed_approval = approval_sig.sign(payload, private_key, kid=kid)
        _write_bundle.public_key = approval_sig.public_key_to_b64(private_key.public_key())
        _write_bundle.kid = kid
    manifest = spec_bundle.dump_manifest_yaml(
        generated_at="2026-07-16T00:00:00Z",
        source_phase="epics_and_stories",
        approval={"approved_by": "someone@x.test", "role": "architect"},
        signed_approval=signed_approval,
    )
    (spec_dir / "manifest.yml").write_text(manifest, encoding="utf-8")
    if tamper:
        # Edit approved content AFTER signing — the classic post-approval edit.
        target = stories_dir / f"{stories[0]['id']}.yml"
        doc = yaml.safe_load(target.read_text(encoding="utf-8"))
        doc["title"] = doc["title"] + " (tampered)"
        target.write_text(spec_bundle.dump_story_yaml(doc), encoding="utf-8")


def _stories():
    return [
        {
            "id": "S1",
            "title": "Sign in",
            "epic": "E1",
            "criteria": [
                {"id": "S1-AC1", "statement": "builds clean", "check": {"type": "build"}},
                {"id": "S1-AC2", "statement": "reviewed by a human", "check": {"type": "manual"}},
            ],
        },
        {
            "id": "S2",
            "title": "Sign out",
            "epic": "E1",
            "criteria": [
                {
                    "id": "S2-AC1",
                    "statement": "exits zero",
                    "check": {"type": "command", "payload": "true"},
                }
            ],
        },
    ]


@pytest.fixture
def repo(tmp_path):
    _write_bundle(tmp_path, _stories())
    return tmp_path


# ---------------------------------------------------------------- no spec


def test_every_op_states_the_no_spec_fact_plainly(tmp_path):
    for op in (
        bridge.list_stories(tmp_path),
        bridge.get_story(tmp_path, "S1"),
        bridge.next_story(tmp_path),
        bridge.set_story_status(tmp_path, "S1", "doing"),
        bridge.check_story(tmp_path, "S1"),
        bridge.spec_status(tmp_path),
    ):
        assert op["ok"] is False
        assert NO_SPEC in op["message"]


# ---------------------------------------------------------------- reads


def test_list_stories(repo):
    out = bridge.list_stories(repo)
    assert out["ok"] is True
    assert [s["id"] for s in out["stories"]] == ["S1", "S2"]
    s1 = out["stories"][0]
    assert s1["title"] == "Sign in" and s1["epic"] == "E1"
    assert s1["criteria_count"] == 2
    assert s1["status"] == "todo"  # no local state yet — implicit starting state


def test_list_stories_reflects_local_state(repo):
    story_state.set_state(repo, "S1", "done")
    out = bridge.list_stories(repo)
    assert {s["id"]: s["status"] for s in out["stories"]} == {"S1": "done", "S2": "todo"}


def test_get_story_full_payload(repo):
    out = bridge.get_story(repo, "S1")
    assert out["ok"] is True
    story = out["story"]
    assert story["id"] == "S1" and story["title"] == "Sign in" and story["epic"] == "E1"
    kinds = [c["check"]["type"] for c in story["criteria"]]
    assert kinds == ["build", "manual"]
    assert story["criteria"][0]["statement"] == "builds clean"


def test_get_story_unknown_id(repo):
    out = bridge.get_story(repo, "S9")
    assert out["ok"] is False and "S9" in out["message"]
    assert "S1" in out["message"]  # tells the caller what exists


def test_next_story_walks_bundle_order_skipping_done(repo):
    assert bridge.next_story(repo)["story"]["id"] == "S1"
    story_state.set_state(repo, "S1", "done")
    assert bridge.next_story(repo)["story"]["id"] == "S2"
    story_state.set_state(repo, "S2", "done")
    out = bridge.next_story(repo)
    assert out["ok"] is True and out["story"] is None
    assert "done" in out["message"]  # all stories done — a fact, not an error


def test_next_story_includes_in_progress_state(repo):
    story_state.set_state(repo, "S1", "doing")
    out = bridge.next_story(repo)
    assert out["story"]["id"] == "S1" and out["story"]["status"] == "doing"


# ---------------------------------------------------------------- writes


def test_set_story_status_writes_lin45_local_state(repo):
    out = bridge.set_story_status(repo, "S1", "doing")
    assert out["ok"] is True
    assert story_state.read_states(repo) == {"S1": "doing"}


def test_set_story_status_rejects_unknown_story(repo):
    out = bridge.set_story_status(repo, "S9", "doing")
    assert out["ok"] is False and "S9" in out["message"]
    assert story_state.read_states(repo) == {}  # nothing written


def test_set_story_status_never_touches_configured_tracker(repo):
    sync = repo / "_bmad-output" / "tracker-sync.json"
    sync.parent.mkdir(parents=True, exist_ok=True)
    sync.write_text(
        json.dumps({"version": 1, "provider": "github-projects", "items": []}), encoding="utf-8"
    )
    out = bridge.set_story_status(repo, "S1", "doing")
    assert out["ok"] is False and "github-projects" in out["message"]


# ---------------------------------------------------------------- check_story


def test_check_story_runs_only_that_story(repo):
    ran: list[str] = []

    def fake_run(criterion, root):
        ran.append(criterion["id"])
        from linebreak_gate.criteria_check import RunOutcome

        return RunOutcome(ok=True, detail="")

    out = bridge.check_story(repo, "S2", run=fake_run)
    assert out["ok"] is True
    assert ran == ["S2-AC1"]  # S1's build check never executed
    (result,) = out["criteria"]
    assert result["id"] == "S2-AC1" and result["result"] == "pass"


def test_check_story_reports_fail_and_needs_signoff(repo):
    def failing_run(criterion, root):
        from linebreak_gate.criteria_check import RunOutcome

        return RunOutcome(ok=False, detail="exit 1")

    out = bridge.check_story(repo, "S1", run=failing_run)
    results = {r["id"]: r["result"] for r in out["criteria"]}
    assert results == {"S1-AC1": "fail", "S1-AC2": "needs-signoff"}
    assert out["passes"] is False


def test_check_story_fix_flips_to_pass(repo):
    """Acceptance 2: a story whose check fails reports fail; fixing flips it."""
    from linebreak_gate.criteria_check import RunOutcome

    verdict = {"ok": False}
    out = bridge.check_story(repo, "S2", run=lambda c, r: RunOutcome(verdict["ok"], ""))
    assert out["criteria"][0]["result"] == "fail"
    verdict["ok"] = True  # "the code was fixed"
    out = bridge.check_story(repo, "S2", run=lambda c, r: RunOutcome(verdict["ok"], ""))
    assert out["criteria"][0]["result"] == "pass"


# ---------------------------------------------------------------- spec_status


def test_spec_status_unsigned_is_honest(repo):
    out = bridge.spec_status(repo)
    assert out["ok"] is True and out["available"] is True
    assert out["stories"] == 2
    assert out["approved_by"] == "someone@x.test"
    assert out["signature"] == "unsigned"


def test_spec_status_signed_and_verified(tmp_path):
    _write_bundle(tmp_path, _stories(), signed=True)
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        f"approvals:\n  public_keys:\n    - kid: {_write_bundle.kid}\n"
        f"      public_key: {_write_bundle.public_key}\n",
        encoding="utf-8",
    )
    out = bridge.spec_status(tmp_path)
    assert out["signature"] == "verified"
    assert out["signed_by"] == "approver@x.test"


def test_spec_status_signed_but_no_key_configured(tmp_path):
    _write_bundle(tmp_path, _stories(), signed=True)
    out = bridge.spec_status(tmp_path)
    # A signature is present but nothing local can verify it — say exactly that.
    assert out["signature"] == "signed-unverified"


def test_spec_status_tampered_reports_mismatch_loudly(tmp_path):
    _write_bundle(tmp_path, _stories(), signed=True, tamper=True)
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        f"approvals:\n  public_keys:\n    - kid: {_write_bundle.kid}\n"
        f"      public_key: {_write_bundle.public_key}\n",
        encoding="utf-8",
    )
    out = bridge.spec_status(tmp_path)
    assert out["ok"] is True  # the tool is not blocked — the merge gate blocks
    assert out["signature"] == "invalid"
    assert "edited after" in out["signature_detail"]


def test_spec_status_tampered_detected_even_without_keys(tmp_path):
    """The hash mismatch is tamper-evident without any crypto configured."""
    _write_bundle(tmp_path, _stories(), signed=True, tamper=True)
    out = bridge.spec_status(tmp_path)
    assert out["signature"] == "invalid"


def test_tampered_bundle_does_not_block_reads_but_is_flagged(tmp_path):
    _write_bundle(tmp_path, _stories(), signed=True, tamper=True)
    out = bridge.list_stories(tmp_path)
    assert out["ok"] is True  # developer tools keep working
    assert out["signature"] == "invalid"  # but never presented as verified-approved


# ---------------------------------------------------------------- read-only invariant


def test_no_bridge_op_can_modify_approved_criteria(repo):
    """Acceptance 4: exercise EVERY op; the approved spec bytes must not change.
    Only set_story_status writes, and only to tracker-sync.json."""
    spec_dir = repo / ".linebreak" / "spec"
    before = {p: p.read_bytes() for p in sorted(spec_dir.rglob("*")) if p.is_file()}

    bridge.list_stories(repo)
    bridge.get_story(repo, "S1")
    bridge.next_story(repo)
    bridge.set_story_status(repo, "S1", "doing")
    from linebreak_gate.criteria_check import RunOutcome

    bridge.check_story(repo, "S1", run=lambda c, r: RunOutcome(True, ""))
    bridge.spec_status(repo)

    after = {p: p.read_bytes() for p in sorted(spec_dir.rglob("*")) if p.is_file()}
    assert before == after


# ------------------------------------------------- review fixes (LIN-55)


def test_keys_configured_but_envelope_missing_is_invalid_not_unsigned(tmp_path):
    """Review fix: with a verification key configured, a bundle carrying NO
    signed_approval is what the merge gate hard-blocks — reporting it as the
    benign 'unsigned' tier would send the developer into the gate blind."""
    _write_bundle(tmp_path, _stories(), signed=True)  # produces a valid kid/key
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        f"approvals:\n  public_keys:\n    - kid: {_write_bundle.kid}\n"
        f"      public_key: {_write_bundle.public_key}\n",
        encoding="utf-8",
    )
    # Strip the signature: rewrite the manifest unsigned.
    manifest = spec_bundle.dump_manifest_yaml(
        generated_at="2026-07-16T00:00:00Z",
        source_phase="epics_and_stories",
        approval={"approved_by": "someone@x.test"},
    )
    (tmp_path / ".linebreak" / "spec" / "manifest.yml").write_text(manifest, encoding="utf-8")
    out = bridge.spec_status(tmp_path)
    assert out["signature"] == "invalid"
    assert "REQUIRED" in out["signature_detail"]


def test_keyless_phase_mismatch_is_invalid(tmp_path):
    """Review fix: the keyless tamper check must ALSO bind the signed phase to
    the manifest source_phase, like the gate does — else the bridge calls a
    bundle 'signed-unverified' that the gate rejects."""
    _write_bundle(tmp_path, _stories(), signed=True)
    manifest_path = tmp_path / ".linebreak" / "spec" / "manifest.yml"
    text = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        text.replace("  phase: epics_and_stories", "  phase: prd"), encoding="utf-8"
    )
    out = bridge.spec_status(tmp_path)
    assert out["signature"] == "invalid"


def test_next_story_all_done_still_flags_tampered(tmp_path):
    _write_bundle(tmp_path, _stories(), signed=True, tamper=True)
    for sid in ("S1", "S2"):
        story_state.set_state(tmp_path, sid, "done")
    out = bridge.next_story(tmp_path)
    assert out["story"] is None
    assert out["signature"] == "invalid"  # the flag rides EVERY read path


def test_check_story_flags_invalid_signature(tmp_path):
    from linebreak_gate.criteria_check import RunOutcome

    _write_bundle(tmp_path, _stories(), signed=True, tamper=True)
    out = bridge.check_story(tmp_path, "S2", run=lambda c, r: RunOutcome(True, ""))
    assert out["ok"] is True  # tools keep working
    assert out["signature"] == "invalid"  # but the gate-parity flag rides along


def test_check_story_survives_malformed_signoffs(tmp_path):
    """Review fix: SignoffError must not escape the bridge's never-raises
    contract — a malformed sign-off record is an honest message."""
    from linebreak_gate.criteria_check import RunOutcome

    _write_bundle(tmp_path, _stories())
    signoffs_dir = tmp_path / ".linebreak" / "spec" / "signoffs"
    signoffs_dir.mkdir(parents=True)
    # A .yml record missing every required field — load_signoffs fails closed.
    (signoffs_dir / "bad.yml").write_text("not-a-signoff: true\n", encoding="utf-8")
    out = bridge.check_story(tmp_path, "S1", run=lambda c, r: RunOutcome(True, ""))
    assert out["ok"] is False
    assert "sign-off" in out["message"].lower() or "signoff" in out["message"].lower()


def test_check_story_carries_tool_error_flag(tmp_path):
    """Review fix: the engine's canonical tool_error rides the bridge payload
    so the CLI shares check's exit contract instead of re-deriving it."""

    def _tool_broken(criterion, root):
        from linebreak_gate.criteria_check import CriteriaToolError

        raise CriteriaToolError("runner missing")

    _write_bundle(tmp_path, _stories())
    out = bridge.check_story(tmp_path, "S2", run=_tool_broken)
    assert out["ok"] is True and out["tool_error"] is True


def test_malformed_bundle_is_marked_distinct_from_no_spec(tmp_path):
    """Review fix: the CLI needs to exit 2 on malformed (fail closed, like
    spec list) but 0 on absent — the bridge marks which it is."""
    spec_dir = tmp_path / ".linebreak" / "spec"
    (spec_dir / "stories").mkdir(parents=True)
    (spec_dir / "manifest.yml").write_text("bundle_version: [broken", encoding="utf-8")
    out = bridge.list_stories(tmp_path)
    assert out["ok"] is False and out["error"] == "malformed"
    absent = bridge.list_stories(tmp_path / "elsewhere")
    assert absent["ok"] is False and absent["error"] == "no-spec"
