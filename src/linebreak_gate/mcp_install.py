"""LIN-55 ``linebreak-gate mcp install``: editor configuration for the bridge.

Writes (or, with ``--print``, prints) the MCP server config so the developer's
editor launches ``linebreak-gate mcp`` in the repo. Supported directly:
Claude Code (``.mcp.json``), Cursor (``.cursor/mcp.json``), Codex
(``~/.codex/config.toml``); anything else that speaks MCP takes the generic
stdio config.

The hard rule: **never silently overwrite an existing config.** A fresh file is
written; a parseable file without our entry is merged (and says so); a file
that already carries a ``linebreak`` entry — or that we cannot parse — is left
byte-for-byte untouched and the desired config is printed for the human to
apply. Config in the repo uses no absolute paths, so it works for every clone
and teammate.
"""

from __future__ import annotations

import json
from pathlib import Path

EDITORS = ("claude-code", "cursor", "codex")

#: The stdio server every editor launches. Relative invocation on purpose —
#: the editor runs it with the workspace as cwd, so the config is portable
#: across clones and machines.
SERVER_ENTRY = {"command": "linebreak-gate", "args": ["mcp"]}

_CODEX_SECTION = (
    "\n# LineBreak spec bridge — the approved stories/criteria for the repo you're in\n"
    "[mcp_servers.linebreak]\n"
    'command = "linebreak-gate"\n'
    'args = ["mcp"]\n'
)


def _generic_json() -> str:
    return json.dumps({"mcpServers": {"linebreak": SERVER_ENTRY}}, indent=2)


def _install_json(path: Path, *, print_only: bool) -> int:
    """Claude Code / Cursor: a JSON file with an ``mcpServers`` map."""
    if print_only:
        print(f"Add to {path}:")
        print(_generic_json())
        return 0
    if path.exists():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("top level is not an object")
        except (ValueError, OSError) as e:
            print(f"{path} could not be parsed ({e}) — left untouched. Add this yourself:")
            print(_generic_json())
            return 0
        servers = doc.get("mcpServers")
        if "mcpServers" in doc and not isinstance(servers, dict):
            # A hand-edited/foreign shape we don't understand — replacing it
            # would silently destroy the user's value. Leave it, print ours.
            print(
                f"{path} has an mcpServers entry that is not an object — left untouched. "
                "Add this yourself:"
            )
            print(_generic_json())
            return 0
        servers = servers if isinstance(servers, dict) else {}
        if "linebreak" in servers:
            if servers["linebreak"] == SERVER_ENTRY:
                print(f"{path} already configures the linebreak server — nothing to do.")
                return 0
            print(
                f"{path} already has a DIFFERENT 'linebreak' entry — left untouched. "
                "The standard entry, if you want to switch:"
            )
            print(_generic_json())
            return 0
        servers["linebreak"] = SERVER_ENTRY
        doc["mcpServers"] = servers
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"Merged the linebreak server into the existing {path}.")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_generic_json() + "\n", encoding="utf-8")
    print(f"Wrote {path}.")
    return 0


def _install_codex(*, print_only: bool) -> int:
    """Codex keeps MCP servers in the GLOBAL ``~/.codex/config.toml``; it runs
    them with the session's working directory, so the entry stays repo-relative."""
    path = Path.home() / ".codex" / "config.toml"
    if print_only:
        print(f"Add to {path}:")
        print(_CODEX_SECTION.strip())
        return 0
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            print(f"{path} could not be read ({e}) — left untouched. Add this yourself:")
            print(_CODEX_SECTION.strip())
            return 0
        if "[mcp_servers.linebreak]" in text:
            print(
                f"{path} already has an [mcp_servers.linebreak] section — left untouched. "
                "The standard entry, if you want to switch:"
            )
            print(_CODEX_SECTION.strip())
            return 0
        # Append-only merge: TOML has no safe in-place rewrite without a writer
        # dependency, and appending a new table never alters existing content.
        path.write_text(text + _CODEX_SECTION, encoding="utf-8")
        print(f"Appended the linebreak server to the existing {path}.")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_CODEX_SECTION.lstrip("\n"), encoding="utf-8")
    print(f"Wrote {path}.")
    return 0


def run_install(repo_root: Path | str, *, editor: str | None = None, print_only: bool = False):
    """Entry point for ``linebreak-gate mcp install``. Returns an exit code."""
    root = Path(repo_root)
    if editor in ("claude-code", "cursor"):
        target = root / ".mcp.json" if editor == "claude-code" else root / ".cursor" / "mcp.json"
        rc = _install_json(target, print_only=print_only)
        # Editors hold a repo-provided MCP server DISCONNECTED until the human
        # enables it once (their prompt-injection guard). Say so, or the first
        # session silently falls back to file searching.
        print(
            "Note: enable the 'linebreak' server once in your editor "
            "(Cursor: Settings → MCP; Claude Code: approve the project-server prompt)."
        )
        return rc
    if editor == "codex":
        return _install_codex(print_only=print_only)
    if editor is not None:
        print(f"unknown editor {editor!r}; expected one of {', '.join(EDITORS)}")
        return 2
    # No editor named: the generic stdio config plus one line per editor.
    print("Generic MCP (stdio) config — any MCP client can use this:")
    print(_generic_json())
    print()
    print("Or write it for your editor:")
    print(
        "  claude-code  linebreak-gate mcp install --editor claude-code   (.mcp.json in the repo)"
    )
    print("  cursor       linebreak-gate mcp install --editor cursor        (.cursor/mcp.json)")
    print("  codex        linebreak-gate mcp install --editor codex         (~/.codex/config.toml)")
    return 0
