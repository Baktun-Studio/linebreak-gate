"""LIN-55 acceptance 1 + 8: a REAL ``linebreak-gate mcp`` stdio process, spoken
to over raw JSON-RPC by this test acting as the MCP client — in a repo the
developer "merely cloned", with no LineBreak account and the network poisoned.

This is deliberately not the SDK's in-memory session: it proves the actual
subprocess an editor launches (initialize → initialized → tools/list →
tools/call) works end to end.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from linebreak_gate.spec_bundle import dump_manifest_yaml, dump_story_yaml

pytest.importorskip("mcp", reason="mcp SDK not installed")


def _write_clone(root: Path) -> None:
    """A repo as a teammate would receive it: just files, no state, no config."""
    spec = root / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "manifest.yml").write_text(
        dump_manifest_yaml(
            generated_at="2026-07-16T00:00:00Z",
            source_phase="epics_and_stories",
            approval={"approved_by": "author@team.test"},
        ),
        encoding="utf-8",
    )
    story = {
        "id": "S1",
        "title": "Parse CSV",
        "epic": "E1",
        "criteria": [{"id": "S1-AC1", "statement": "handles quotes", "check": {"type": "manual"}}],
    }
    (spec / "stories" / "S1.yml").write_text(dump_story_yaml(story), encoding="utf-8")


def _offline_env() -> dict[str, str]:
    """No account, no backend, and any HTTP client that ignores that dies on a
    dead proxy port."""
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("LINEBREAK_", "ANTHROPIC_", "OPENAI_"))
    }
    dead = "http://127.0.0.1:9"
    env.update({"HTTP_PROXY": dead, "HTTPS_PROXY": dead, "http_proxy": dead, "https_proxy": dead})
    return env


class _Client:
    """A minimal MCP stdio client: newline-delimited JSON-RPC over pipes."""

    def __init__(self, proc: subprocess.Popen):
        self.proc = proc
        self._id = 0

    def _send(self, doc: dict) -> None:
        self.proc.stdin.write(json.dumps(doc) + "\n")
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        while True:
            line = self.proc.stdout.readline()
            assert line, "server closed stdout"
            msg = json.loads(line)
            if msg.get("id") == self._id:
                assert "error" not in msg, msg
                return msg["result"]

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})


def test_stdio_end_to_end_offline_no_account(tmp_path):
    _write_clone(tmp_path)
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "from linebreak_gate.cli import main; raise SystemExit(main(['mcp']))",
        ],
        cwd=tmp_path,  # editors launch the server with the workspace as cwd
        env={**_offline_env(), "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        client = _Client(proc)
        init = client.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e-test", "version": "0"},
            },
        )
        assert init["serverInfo"]["name"] == "linebreak"
        client.notify("notifications/initialized")

        tools = client.request("tools/list")
        names = {t["name"] for t in tools["tools"]}
        assert names == {
            "list_stories",
            "get_story",
            "next_story",
            "set_story_status",
            "check_story",
            "spec_status",
        }

        listed = client.request("tools/call", {"name": "list_stories", "arguments": {}})
        payload = json.loads(listed["content"][0]["text"])
        assert payload["ok"] is True
        assert payload["stories"][0]["id"] == "S1"

        story = client.request("tools/call", {"name": "get_story", "arguments": {"story_id": "S1"}})
        payload = json.loads(story["content"][0]["text"])
        assert payload["story"]["criteria"][0]["check"]["type"] == "manual"
    finally:
        proc.kill()
        proc.wait(timeout=10)


def test_bridge_module_graph_pulls_no_http_client():
    """Review focus pinned structurally: importing every bridge-path module
    must not load an HTTP client library. A network call path appearing in the
    bridge would show up here as a new import."""
    code = (
        "import sys\n"
        "from linebreak_gate import bridge, story_state, mcp_install\n"
        "bad = [m for m in sys.modules if m.split('.')[0] in "
        "('httpx', 'requests', 'aiohttp', 'anthropic', 'urllib3')]\n"
        "assert not bad, f'bridge imports pulled HTTP clients: {bad}'\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")},
    )
    assert proc.returncode == 0, proc.stderr
