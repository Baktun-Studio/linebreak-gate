"""LIN-55 CLI equivalents — the same information as the MCP tools, for any
terminal. No MCP required, no network, no account. ``spec list`` behavior
(LIN-35) is untouched; these tests cover the new ``spec next|show|check`` and
the ``mcp`` command's parser wiring."""

from __future__ import annotations

from linebreak_gate import story_state
from linebreak_gate.cli import build_parser, main
from linebreak_gate.spec_bundle import dump_manifest_yaml, dump_story_yaml

STORIES = [
    {
        "id": "S1",
        "title": "User can sign in",
        "epic": "E1",
        "criteria": [
            {
                "id": "S1-AC1",
                "statement": "exits zero",
                "check": {"type": "command", "payload": "true"},
            }
        ],
    },
    {
        "id": "S2",
        "title": "User can sign out",
        "epic": "E1",
        "criteria": [
            {
                "id": "S2-AC1",
                "statement": "always fails (for the flip test)",
                "check": {"type": "command", "payload": "false"},
            }
        ],
    },
]


def _write_bundle(root):
    spec = root / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "manifest.yml").write_text(
        dump_manifest_yaml(
            generated_at="2026-07-16T00:00:00Z",
            source_phase="epics_and_stories",
            approval={"approved_by": "v@example.com", "role": "architect"},
        ),
        encoding="utf-8",
    )
    for story in STORIES:
        (spec / "stories" / f"{story['id']}.yml").write_text(
            dump_story_yaml(story), encoding="utf-8"
        )


# ---------------------------------------------------------------- spec next


def test_spec_next_prints_first_undone_story(tmp_path, capsys):
    _write_bundle(tmp_path)
    assert main(["spec", "next", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "S1" in out and "User can sign in" in out
    assert "S1-AC1" in out  # criteria ride along — that's the working payload


def test_spec_next_skips_done_stories(tmp_path, capsys):
    _write_bundle(tmp_path)
    story_state.set_state(tmp_path, "S1", "done")
    assert main(["spec", "next", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "S2" in out and "S1 " not in out


def test_spec_next_all_done_is_a_fact(tmp_path, capsys):
    _write_bundle(tmp_path)
    story_state.set_state(tmp_path, "S1", "done")
    story_state.set_state(tmp_path, "S2", "done")
    assert main(["spec", "next", "--path", str(tmp_path)]) == 0
    assert "done" in capsys.readouterr().out


def test_spec_next_no_spec_is_a_fact_exit_zero(tmp_path, capsys):
    assert main(["spec", "next", "--path", str(tmp_path)]) == 0
    assert "no approved spec found in this repository" in capsys.readouterr().out


# ---------------------------------------------------------------- spec show


def test_spec_show_renders_story_and_check_types(tmp_path, capsys):
    _write_bundle(tmp_path)
    assert main(["spec", "show", "S2", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "User can sign out" in out
    assert "command" in out and "S2-AC1" in out


def test_spec_show_unknown_story_exits_1_and_names_known(tmp_path, capsys):
    _write_bundle(tmp_path)
    assert main(["spec", "show", "S9", "--path", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "S9" in err and "S1" in err


# ---------------------------------------------------------------- spec check


def test_spec_check_pass_and_fail_per_criterion(tmp_path, capsys):
    _write_bundle(tmp_path)
    # S1's check is `true` → pass, exit 0
    assert main(["spec", "check", "S1", "--path", str(tmp_path)]) == 0
    assert "pass" in capsys.readouterr().out
    # S2's check is `false` → fail, exit 1 (same contract as `check`)
    assert main(["spec", "check", "S2", "--path", str(tmp_path)]) == 1
    assert "fail" in capsys.readouterr().out


def test_spec_check_only_runs_that_story(tmp_path, capsys):
    """S2's failing check must not poison an S1-only check."""
    _write_bundle(tmp_path)
    assert main(["spec", "check", "S1", "--path", str(tmp_path)]) == 0


def test_spec_list_behavior_unchanged(tmp_path, capsys):
    _write_bundle(tmp_path)
    assert main(["spec", "list", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "2 story(ies):" in out


# ---------------------------------------------------------------- mcp parser


def test_mcp_command_is_wired():
    args = build_parser().parse_args(["mcp"])
    assert args.command == "mcp"
    assert args.mcp_action is None  # default action = serve


def test_mcp_install_parses_editor_and_print():
    args = build_parser().parse_args(["mcp", "install", "--editor", "cursor", "--print"])
    assert args.mcp_action == "install"
    assert args.editor == "cursor" and args.print_only is True


# ---------------------------------------------------------------- tampered


def test_spec_next_warns_loudly_on_tampered_bundle(tmp_path, capsys):
    """Deliverable 4: tampered criteria keep the tools working but are never
    presented as approved — the warning rides the output."""
    import yaml

    from linebreak_gate import approval_sig, spec_bundle

    _write_bundle(tmp_path)
    # Sign the bundle, then edit a story after signing.
    bundle = spec_bundle.load_bundle(tmp_path)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    kid = approval_sig.kid_for_public_key(key.public_key())
    envelope = approval_sig.sign(
        {
            "project_id": "p",
            "phase": "epics_and_stories",
            "artifact_hash": spec_bundle.bundle_hash(bundle),
            "approver_email": "a@x.test",
            "approver_role": "architect",
            "self_approved": False,
            "approved_at": "2026-07-16T00:00:00Z",
            "bundle_version": 1,
            "instance_id": "i",
        },
        key,
        kid=kid,
    )
    manifest = spec_bundle.dump_manifest_yaml(
        generated_at="2026-07-16T00:00:00Z",
        source_phase="epics_and_stories",
        approval={"approved_by": "v@example.com"},
        signed_approval=envelope,
    )
    (tmp_path / ".linebreak" / "spec" / "manifest.yml").write_text(manifest, encoding="utf-8")
    story_file = tmp_path / ".linebreak" / "spec" / "stories" / "S1.yml"
    doc = yaml.safe_load(story_file.read_text(encoding="utf-8"))
    doc["title"] = "quietly changed after approval"
    story_file.write_text(spec_bundle.dump_story_yaml(doc), encoding="utf-8")

    assert main(["spec", "next", "--path", str(tmp_path)]) == 0  # not blocked
    out = capsys.readouterr().out
    assert "WARNING" in out and "INVALID" in out


# ------------------------------------------------- review fixes (LIN-55)


def test_malformed_bundle_exits_2_on_every_spec_subcommand(tmp_path, capsys):
    """Review fix: malformed = fail closed (exit 2) consistently, matching
    spec list — not 0 (next) or 1 (show/check) depending on the subcommand."""
    spec = tmp_path / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "manifest.yml").write_text("bundle_version: [broken", encoding="utf-8")
    assert main(["spec", "next", "--path", str(tmp_path)]) == 2
    capsys.readouterr()
    assert main(["spec", "show", "S1", "--path", str(tmp_path)]) == 2
    capsys.readouterr()
    assert main(["spec", "check", "S1", "--path", str(tmp_path)]) == 2
    capsys.readouterr()
    assert main(["spec", "list", "--path", str(tmp_path)]) == 2


def test_mcp_parent_path_survives_install_subcommand(tmp_path):
    """Review fix (CONFIRMED by parse): the install subparser's --path default
    must not clobber a --path given before the subcommand."""
    args = build_parser().parse_args(["mcp", "--path", str(tmp_path), "install"])
    assert args.path == str(tmp_path)
    # And the subcommand-side flag still wins when given explicitly.
    args = build_parser().parse_args(
        ["mcp", "--path", "/ignored", "install", "--path", str(tmp_path)]
    )
    assert args.path == str(tmp_path)


def test_spec_check_signature_block_exits_1_like_the_gate(tmp_path, capsys):
    """Review fix: with a verification key configured, spec check must not
    green-light a bundle the merge gate blocks — a signature failure is exit 1
    even when the criteria themselves pass (gate parity)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from linebreak_gate import approval_sig

    _write_bundle(tmp_path)  # UNSIGNED bundle
    key = Ed25519PrivateKey.generate()
    kid = approval_sig.kid_for_public_key(key.public_key())
    pub = approval_sig.public_key_to_b64(key.public_key())
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        f"approvals:\n  public_keys:\n    - kid: {kid}\n      public_key: {pub}\n",
        encoding="utf-8",
    )
    # S1's criterion (`true`) passes — but the signature requirement doesn't.
    assert main(["spec", "check", "S1", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "WARNING" in out and "INVALID" in out
