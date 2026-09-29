"""LIN-55: the MCP server over the bridge — real protocol round-trips via the
SDK's in-memory session (initialize → tools/list → tools/call), no stdio
subprocess needed. The stdio CLI entry is covered by the CLI tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from linebreak_gate import spec_bundle

pytest.importorskip("mcp", reason="mcp SDK not installed")

from mcp.shared.memory import create_connected_server_and_client_session  # noqa: E402

from linebreak_gate import mcp_server  # noqa: E402

EXPECTED_TOOLS = {
    "list_stories",
    "get_story",
    "next_story",
    "set_story_status",
    "check_story",
    "spec_status",
}


def _write_bundle(root: Path) -> None:
    spec_dir = root / ".linebreak" / "spec"
    (spec_dir / "stories").mkdir(parents=True)
    story = {
        "id": "S1",
        "title": "Sign in",
        "epic": "E1",
        "criteria": [
            {
                "id": "S1-AC1",
                "statement": "exits zero",
                "check": {"type": "command", "payload": "true"},
            }
        ],
    }
    (spec_dir / "stories" / "S1.yml").write_text(
        spec_bundle.dump_story_yaml(story), encoding="utf-8"
    )
    (spec_dir / "manifest.yml").write_text(
        spec_bundle.dump_manifest_yaml(
            generated_at="2026-07-16T00:00:00Z",
            source_phase="epics_and_stories",
            approval={"approved_by": "someone@x.test"},
        ),
        encoding="utf-8",
    )


async def _call(session, name: str, args: dict | None = None) -> dict:
    result = await session.call_tool(name, args or {})
    assert not result.isError, result.content
    return json.loads(result.content[0].text)


@pytest.mark.asyncio
async def test_tool_list_is_exactly_the_six_bridge_ops(tmp_path):
    """Acceptance 4 at the protocol layer: the server exposes NOTHING that
    could write, edit, or invalidate an approved criterion."""
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        tools = await session.list_tools()
        assert {t.name for t in tools.tools} == EXPECTED_TOOLS


@pytest.mark.asyncio
async def test_list_and_get_story_over_the_protocol(tmp_path):
    _write_bundle(tmp_path)
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        listed = await _call(session, "list_stories")
        assert listed["ok"] is True and listed["stories"][0]["id"] == "S1"

        story = await _call(session, "get_story", {"story_id": "S1"})
        assert story["story"]["criteria"][0]["check"]["type"] == "command"


@pytest.mark.asyncio
async def test_status_write_and_next_over_the_protocol(tmp_path):
    _write_bundle(tmp_path)
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        nxt = await _call(session, "next_story")
        assert nxt["story"]["id"] == "S1"

        set_out = await _call(session, "set_story_status", {"story_id": "S1", "status": "done"})
        assert set_out["ok"] is True

        nxt = await _call(session, "next_story")
        assert nxt["story"] is None  # everything done


@pytest.mark.asyncio
async def test_check_story_over_the_protocol(tmp_path):
    _write_bundle(tmp_path)  # its one criterion runs `true` → pass
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        out = await _call(session, "check_story", {"story_id": "S1"})
        assert out["passes"] is True
        assert out["criteria"][0]["result"] == "pass"


@pytest.mark.asyncio
async def test_no_spec_is_a_fact_not_a_protocol_error(tmp_path):
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        out = await _call(session, "spec_status")
        assert out["ok"] is False
        assert "no approved spec found in this repository" in out["message"]


@pytest.mark.asyncio
async def test_protocol_session_cannot_change_spec_bytes(tmp_path):
    _write_bundle(tmp_path)
    spec_dir = tmp_path / ".linebreak" / "spec"
    before = {p: p.read_bytes() for p in sorted(spec_dir.rglob("*")) if p.is_file()}
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        for name in EXPECTED_TOOLS:
            args = {}
            if name in ("get_story", "check_story"):
                args = {"story_id": "S1"}
            elif name == "set_story_status":
                args = {"story_id": "S1", "status": "doing"}
            await session.call_tool(name, args)
    after = {p: p.read_bytes() for p in sorted(spec_dir.rglob("*")) if p.is_file()}
    assert before == after


def test_importing_linebreak_gate_never_imports_the_mcp_sdk():
    """The desktop imports linebreak_gate from source (sys.modules shims); the
    SDK must stay a lazy import so that path never needs it."""
    import subprocess
    import sys

    code = (
        "import sys\n"
        "import linebreak_gate, linebreak_gate.bridge, linebreak_gate.cli\n"
        "assert not any(m == 'mcp' or m.startswith('mcp.') for m in sys.modules), "
        "'importing linebreak_gate pulled in the mcp SDK'\n"
        "print('lazy OK')\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.asyncio
async def test_structured_content_carries_real_fields(tmp_path):
    """Review fix: tools return dicts so structured-content clients get
    first-class fields (ok/stories/criteria), not a double-encoded string."""
    _write_bundle(tmp_path)
    server = mcp_server.build_server(tmp_path)
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool("list_stories", {})
        assert result.structuredContent is not None
        sc = result.structuredContent
        payload = sc.get("result", sc)  # tolerate SDK wrapping for plain dicts
        assert payload["ok"] is True
        assert payload["stories"][0]["id"] == "S1"
