"""LIN-55 `linebreak-gate mcp install` — write (or print) the MCP config for
the developer's editor. The hard rule: NEVER silently overwrite an existing
config — merge or print, and say which."""

from __future__ import annotations

import json

import pytest

from linebreak_gate import mcp_install


@pytest.fixture
def home(tmp_path, monkeypatch):
    # Path.home() reads HOME on POSIX but USERPROFILE on Windows — set both,
    # or the Windows run writes into the real user profile.
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    return home_dir


# ---------------------------------------------------------------- claude-code


def test_claude_code_fresh_write(tmp_path, capsys):
    rc = mcp_install.run_install(tmp_path, editor="claude-code")
    assert rc == 0
    doc = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    server = doc["mcpServers"]["linebreak"]
    assert server["command"] == "linebreak-gate" and server["args"] == ["mcp"]
    assert ".mcp.json" in capsys.readouterr().out  # says where it wrote


def test_claude_code_merges_into_existing_config(tmp_path, capsys):
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"other": {"command": "x"}}}), encoding="utf-8"
    )
    assert mcp_install.run_install(tmp_path, editor="claude-code") == 0
    doc = json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8"))
    assert set(doc["mcpServers"]) == {"other", "linebreak"}  # merged, not clobbered
    assert "merged" in capsys.readouterr().out.lower()


def test_claude_code_existing_linebreak_entry_is_never_clobbered(tmp_path, capsys):
    custom = {"mcpServers": {"linebreak": {"command": "my-fork", "args": ["--special"]}}}
    (tmp_path / ".mcp.json").write_text(json.dumps(custom), encoding="utf-8")
    assert mcp_install.run_install(tmp_path, editor="claude-code") == 0
    # File untouched; the desired config was PRINTED for the human to apply.
    assert json.loads((tmp_path / ".mcp.json").read_text(encoding="utf-8")) == custom
    out = capsys.readouterr().out
    assert "left untouched" in out and "linebreak-gate" in out


def test_malformed_existing_config_is_printed_not_rewritten(tmp_path, capsys):
    (tmp_path / ".mcp.json").write_text("{broken", encoding="utf-8")
    assert mcp_install.run_install(tmp_path, editor="claude-code") == 0
    assert (tmp_path / ".mcp.json").read_text(encoding="utf-8") == "{broken"
    out = capsys.readouterr().out
    assert "could not be parsed" in out


# ---------------------------------------------------------------- cursor


def test_cursor_writes_dot_cursor_mcp_json(tmp_path):
    assert mcp_install.run_install(tmp_path, editor="cursor") == 0
    doc = json.loads((tmp_path / ".cursor" / "mcp.json").read_text(encoding="utf-8"))
    assert doc["mcpServers"]["linebreak"]["command"] == "linebreak-gate"


# ---------------------------------------------------------------- codex


def test_codex_appends_toml_section(tmp_path, home):
    assert mcp_install.run_install(tmp_path, editor="codex") == 0
    text = (home / ".codex" / "config.toml").read_text(encoding="utf-8")
    assert "[mcp_servers.linebreak]" in text
    assert 'command = "linebreak-gate"' in text


def test_codex_existing_section_is_never_touched(tmp_path, home, capsys):
    cfg = home / ".codex" / "config.toml"
    cfg.parent.mkdir(parents=True)
    original = '[mcp_servers.linebreak]\ncommand = "my-fork"\n'
    cfg.write_text(original, encoding="utf-8")
    assert mcp_install.run_install(tmp_path, editor="codex") == 0
    assert cfg.read_text(encoding="utf-8") == original
    assert "left untouched" in capsys.readouterr().out


def test_codex_preserves_unrelated_toml(tmp_path, home):
    cfg = home / ".codex" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text('model = "o5"\n', encoding="utf-8")
    assert mcp_install.run_install(tmp_path, editor="codex") == 0
    text = cfg.read_text(encoding="utf-8")
    assert text.startswith('model = "o5"\n')  # untouched prefix
    assert "[mcp_servers.linebreak]" in text


# ---------------------------------------------------------------- print / generic


def test_print_only_writes_nothing(tmp_path, capsys):
    assert mcp_install.run_install(tmp_path, editor="claude-code", print_only=True) == 0
    assert not (tmp_path / ".mcp.json").exists()
    out = capsys.readouterr().out
    assert "linebreak-gate" in out and "mcp" in out


def test_no_editor_prints_generic_config_plus_per_editor_notes(tmp_path, capsys):
    assert mcp_install.run_install(tmp_path, editor=None) == 0
    assert not (tmp_path / ".mcp.json").exists()
    out = capsys.readouterr().out
    assert '"mcpServers"' in out  # the generic stdio config
    for editor in ("claude-code", "cursor", "codex"):
        assert editor in out  # one-line note each
