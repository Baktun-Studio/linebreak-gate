"""``linebreak-gate spec list`` — read-only bundle rendering (LIN-35).

Exit contract: 0 on a valid or absent bundle, 2 on a malformed one. No
enforcement anywhere — these tests double as the guarantee that the spec
subcommand never gates."""

from linebreak_gate.cli import main
from linebreak_gate.spec_bundle import dump_manifest_yaml, dump_story_yaml

STORY = {
    "id": "S1",
    "title": "User can sign in",
    "criteria": [
        {"id": "S1-AC1", "statement": "Builds cleanly", "check": {"type": "build"}},
        {
            "id": "S1-AC2",
            "statement": "Covered by tests",
            "check": {"type": "tests", "payload": "tests/test_login.py"},
        },
    ],
}


def _write_bundle(root):
    spec = root / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "manifest.yml").write_text(
        dump_manifest_yaml(
            generated_at="2026-07-13T00:00:00Z",
            source_phase="epics_and_stories",
            approval={
                "role": "architect",
                "user_email": "v@example.com",
                "approved_by": "v@example.com",
                "approved_at": "2026-07-13T00:00:01Z",
            },
        ),
        encoding="utf-8",
    )
    (spec / "stories" / "S1.yml").write_text(dump_story_yaml(STORY), encoding="utf-8")


def test_spec_list_renders_bundle(tmp_path, capsys):
    _write_bundle(tmp_path)
    assert main(["spec", "list", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "S1" in out and "User can sign in" in out
    assert "[build]" in out
    assert "[tests: tests/test_login.py]" in out
    assert "v@example.com" in out and "architect" in out


def test_spec_list_absent_bundle_is_not_an_error(tmp_path, capsys):
    assert main(["spec", "list", "--path", str(tmp_path)]) == 0
    assert "No spec bundle" in capsys.readouterr().out


def test_spec_list_malformed_bundle_exits_2(tmp_path, capsys):
    _write_bundle(tmp_path)
    (tmp_path / ".linebreak" / "spec" / "stories" / "S1.yml").write_text(
        "id: S1\n", encoding="utf-8"
    )
    assert main(["spec", "list", "--path", str(tmp_path)]) == 2
    assert "malformed spec bundle" in capsys.readouterr().err


def test_spec_list_bad_check_type_exits_2(tmp_path, capsys):
    _write_bundle(tmp_path)
    (tmp_path / ".linebreak" / "spec" / "stories" / "S1.yml").write_text(
        "id: S1\ntitle: t\ncriteria:\n- id: A\n  statement: s\n  check:\n    type: vibes\n",
        encoding="utf-8",
    )
    assert main(["spec", "list", "--path", str(tmp_path)]) == 2
    assert "vibes" in capsys.readouterr().err
