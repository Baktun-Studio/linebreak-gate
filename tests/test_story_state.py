"""LIN-55 MCP bridge: local story state, LIN-45-compatible.

The bridge writes story state through the SAME store the desktop's no-tracker
fallback uses (``_bmad-output/tracker-sync.json``, provider ``local``, rows
``{local_id, state, local_only, comment}``) — never a second state store, and
never a write against a configured external tracker (the bridge is offline; a
tracker-managed repo updates state in the tracker, not behind its back).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from linebreak_gate import story_state

SYNC_REL = Path("_bmad-output") / "tracker-sync.json"


def _write_sync(root: Path, doc: dict) -> None:
    path = root / SYNC_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")


def _read_sync(root: Path) -> dict:
    return json.loads((root / SYNC_REL).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- reads


def test_read_states_empty_when_no_file(tmp_path):
    assert story_state.read_states(tmp_path) == {}


def test_read_states_maps_local_id_to_state(tmp_path):
    _write_sync(
        tmp_path,
        {
            "version": 1,
            "provider": "local",
            "items": [
                {"local_id": "S1", "state": "done", "local_only": True},
                {"local_id": "S2", "state": "doing", "local_only": True},
                {"local_id": "S3"},  # no state recorded — not in the map
            ],
        },
    )
    assert story_state.read_states(tmp_path) == {"S1": "done", "S2": "doing"}


def test_read_states_tolerates_malformed_file(tmp_path):
    (tmp_path / SYNC_REL).parent.mkdir(parents=True)
    (tmp_path / SYNC_REL).write_text("{not json", encoding="utf-8")
    assert story_state.read_states(tmp_path) == {}


# ---------------------------------------------------------------- writes


def test_set_state_creates_lin45_local_row(tmp_path):
    result = story_state.set_state(tmp_path, "S1", "doing")
    assert result["ok"] is True and result["state"] == "doing"
    doc = _read_sync(tmp_path)
    assert doc["provider"] == "local"
    (row,) = doc["items"]
    assert row["local_id"] == "S1" and row["state"] == "doing"
    assert row["local_only"] is True
    assert "external_id" not in row or not row["external_id"]  # never a fake mapping


def test_set_state_rejects_unknown_status(tmp_path):
    result = story_state.set_state(tmp_path, "S1", "shipped")
    assert result["ok"] is False
    assert "doing" in result["reason"] and "done" in result["reason"]
    assert not (tmp_path / SYNC_REL).exists()  # nothing written on refusal


def test_set_state_merges_without_clobbering_other_rows(tmp_path):
    _write_sync(
        tmp_path,
        {
            "version": 1,
            "provider": "local",
            "items": [{"local_id": "S1", "state": "doing", "local_only": True}],
        },
    )
    story_state.set_state(tmp_path, "S2", "review", comment="ready for eyes")
    doc = _read_sync(tmp_path)
    by_id = {r["local_id"]: r for r in doc["items"]}
    assert by_id["S1"]["state"] == "doing"  # untouched
    assert by_id["S2"]["state"] == "review" and by_id["S2"]["comment"] == "ready for eyes"


def test_set_state_refuses_when_external_tracker_recorded(tmp_path):
    """A repo mirrored to a real tracker: state lives THERE. The offline bridge
    must not mutate story state behind the tracker's back — refuse, say why."""
    _write_sync(
        tmp_path,
        {
            "version": 1,
            "provider": "azure-devops",
            "items": [
                {"local_id": "S1", "external_id": "4321", "url": "https://x", "kind": "story"}
            ],
        },
    )
    result = story_state.set_state(tmp_path, "S1", "done")
    assert result["ok"] is False
    assert "azure-devops" in result["reason"]
    # And the file is byte-for-byte untouched.
    doc = _read_sync(tmp_path)
    assert doc["provider"] == "azure-devops"
    assert doc["items"][0]["external_id"] == "4321"
    assert "state" not in doc["items"][0]


def test_set_state_updates_own_prior_row(tmp_path):
    story_state.set_state(tmp_path, "S1", "doing")
    result = story_state.set_state(tmp_path, "S1", "done")
    assert result["ok"] is True and result["changed"] is True
    doc = _read_sync(tmp_path)
    (row,) = doc["items"]
    assert row["state"] == "done"


def test_set_state_reports_unchanged_transition(tmp_path):
    story_state.set_state(tmp_path, "S1", "doing")
    result = story_state.set_state(tmp_path, "S1", "doing")
    assert result["ok"] is True and result["changed"] is False


def test_set_state_preserves_unknown_top_level_keys(tmp_path):
    """Forward compatibility contract of the artifact: writers preserve keys
    they don't understand."""
    _write_sync(
        tmp_path,
        {"version": 1, "provider": "local", "items": [], "future_field": {"keep": "me"}},
    )
    story_state.set_state(tmp_path, "S1", "doing")
    assert _read_sync(tmp_path)["future_field"] == {"keep": "me"}


@pytest.mark.parametrize("status", ["doing", "review", "done"])
def test_valid_statuses(tmp_path, status):
    assert story_state.set_state(tmp_path, "S1", status)["ok"] is True
