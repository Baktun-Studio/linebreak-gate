"""LIN-55: the MCP server — the approved spec, in the developer's own editor.

``linebreak-gate mcp`` serves the repo's ``.linebreak/spec/`` over MCP (stdio
transport) to Claude Code, Cursor, Codex, or anything else that speaks the
protocol. Every tool delegates to :mod:`linebreak_gate.bridge`; there is no
editor-specific behavior here and no way through this server to write, edit,
or invalidate an approved criterion — criteria change in the governance
surface and are re-approved there.

Offline by construction: the server reads the working tree. No network, no
governance backend, no LineBreak account. A developer who was merely handed a
clone gets the full bridge.

The ``mcp`` SDK import is LAZY (inside the functions): the desktop app imports
``linebreak_gate`` from source and must never need the SDK; only the actual
``linebreak-gate mcp`` command does.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import bridge

SERVER_NAME = "linebreak"

_INSTRUCTIONS = (
    "LineBreak spec bridge: the human-approved stories and acceptance criteria "
    "for this repository, read from .linebreak/spec/ (git is the transport — "
    "no network, no account). Call next_story or get_story BEFORE writing code "
    "so the approved criteria are your working instruction, and check_story "
    "AFTER so failures surface before the merge gate. Criteria cannot be "
    "changed here; they are re-approved in the LineBreak governance surface."
)


def build_server(project_root: Path | str):
    """Construct the FastMCP server bound to ``project_root``. Separated from
    :func:`serve` so tests can drive it over an in-memory session."""
    from mcp.server.fastmcp import FastMCP

    root = Path(project_root)
    server = FastMCP(SERVER_NAME, instructions=_INSTRUCTIONS)

    @server.tool()
    def list_stories() -> dict[str, Any]:
        """All approved stories in this repository: id, title, epic, local
        status (todo|doing|review|done), and how many acceptance criteria each
        carries. The list IS the approved scope — nothing else is in spec."""
        return bridge.list_stories(root)

    @server.tool()
    def get_story(story_id: str) -> dict[str, Any]:
        """One approved story in full: title, epic, and every acceptance
        criterion with its id, statement, and check type (build | tests |
        command | manual). Read this BEFORE implementing the story — the
        criteria are the approved definition of done."""
        return bridge.get_story(root, story_id)

    @server.tool()
    def next_story() -> dict[str, Any]:
        """The next approved story that is not yet done, per local story
        state. Use this to pick up work without guessing at priorities."""
        return bridge.next_story(root)

    @server.tool()
    def set_story_status(story_id: str, status: str, comment: str | None = None) -> dict[str, Any]:
        """Record story progress: status is doing | review | done. Writes
        LOCAL story state only (the repo's tracker-sync artifact) — never a
        configured external tracker, and never the approved criteria."""
        return bridge.set_story_status(root, story_id, status, comment=comment)

    @server.tool()
    def check_story(story_id: str) -> dict[str, Any]:
        """Run this story's acceptance criteria against the working tree with
        the SAME engine as the merge gate (`linebreak-gate check`). Returns
        pass | fail | needs-signoff per criterion — verify your work here
        BEFORE pushing instead of discovering failures at the merge."""
        return bridge.check_story(root, story_id)

    @server.tool()
    def spec_status() -> dict[str, Any]:
        """Is there an approved spec bundle: version, source phase, approver,
        story count, and the approval signature state (verified | invalid |
        signed-unverified | unsigned), verified entirely offline."""
        return bridge.spec_status(root)

    return server


def serve(project_root: Path | str) -> None:
    """Blocking stdio entrypoint for ``linebreak-gate mcp``."""
    build_server(project_root).run(transport="stdio")
