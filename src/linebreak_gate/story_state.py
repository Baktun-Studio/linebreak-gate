"""Local story state for the MCP bridge (LIN-55), LIN-45-compatible.

This is the SAME store the desktop's no-tracker fallback writes
(``_bmad-output/tracker-sync.json``, provider ``local``): rows carry
``{local_id, state, local_only: true, comment}`` and deliberately NO
``external_id``, so they are never mistaken for items mirrored to a real
tracker. The bridge never invents a second state store.

Two hard rules:

- **Never touch a configured external tracker.** When the artifact records an
  external provider (the repo's stories are mirrored to Azure DevOps, GitHub
  Projects, …), story state lives THERE and the offline bridge refuses to
  mutate it behind the tracker's back — a plain refusal with the provider
  named, not a silent local shadow that would drift.
- **Preserve everything else.** Merge by ``local_id``; other rows, external
  mappings, and unknown top-level keys survive a rewrite byte-for-byte in
  content terms (forward-compatibility contract of the artifact).
"""

from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: Relative location of the artifact — must match the desktop's
#: ``app/tracker_sync.py`` ARTIFACT_RELATIVE_PATH exactly.
ARTIFACT_RELATIVE_PATH = Path("_bmad-output") / "tracker-sync.json"
SCHEMA_VERSION = 1

#: The states the bridge may write (mirrors the desktop's story-state tool;
#: ``todo`` is the implicit starting state, so the bridge never needs to set it).
VALID_STATES = ("doing", "review", "done")


def sync_path(project_root: Path | str) -> Path:
    return Path(project_root) / ARTIFACT_RELATIVE_PATH


def _read_doc(project_root: Path | str) -> dict[str, Any]:
    """Read the artifact; absence and corruption read as an empty document."""
    file = sync_path(project_root)
    try:
        parsed = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"version": SCHEMA_VERSION, "provider": None, "items": []}
    if not isinstance(parsed, dict) or not isinstance(parsed.get("items"), list):
        return {"version": SCHEMA_VERSION, "provider": None, "items": []}
    return parsed


def read_states(project_root: Path | str) -> dict[str, str]:
    """``{local_id: state}`` for every row that carries a state. Read-only and
    provider-agnostic: whatever local knowledge exists is worth showing."""
    out: dict[str, str] = {}
    for row in _read_doc(project_root).get("items") or []:
        if isinstance(row, dict) and isinstance(row.get("local_id"), str):
            state = row.get("state")
            if isinstance(state, str) and state:
                out[row["local_id"]] = state
    return out


def set_state(
    project_root: Path | str,
    story_id: str,
    status: str,
    *,
    comment: str | None = None,
) -> dict[str, Any]:
    """Record a story-state transition via the LIN-45 local mechanism.

    Returns ``{"ok": bool, ...}`` — never raises for expected conditions.
    Refuses (a) unknown statuses and (b) repos whose artifact records an
    external tracker provider.
    """
    if status not in VALID_STATES:
        return {
            "ok": False,
            "reason": f"invalid status {status!r}; expected one of {list(VALID_STATES)}",
        }

    doc = _read_doc(project_root)
    provider = doc.get("provider")
    if provider and provider != "local":
        return {
            "ok": False,
            "reason": (
                f"story state for this repository is managed by the {provider!r} tracker — "
                "update it there (the offline bridge never writes behind a configured tracker)"
            ),
        }

    items = [row for row in (doc.get("items") or []) if isinstance(row, dict)]
    prev_state: str | None = None
    merged = False
    for row in items:
        if row.get("local_id") == story_id:
            prev_state = row.get("state") if isinstance(row.get("state"), str) else None
            row["state"] = status
            row["local_only"] = True
            # Always set so a comment-less transition clears the previous
            # transition's note instead of misattributing it (LIN-45 contract).
            row["comment"] = comment
            merged = True
            break
    if not merged:
        items.append(
            {"local_id": story_id, "state": status, "local_only": True, "comment": comment}
        )

    doc["version"] = SCHEMA_VERSION
    doc["provider"] = "local"
    doc["generated_at"] = datetime.now(UTC).isoformat()
    doc["items"] = items

    file = sync_path(project_root)
    file.parent.mkdir(parents=True, exist_ok=True)
    tmp = file.with_name(f"{file.name}.tmp.{os.getpid()}.{int(time.time() * 1000)}")
    tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, file)

    return {
        "ok": True,
        "local_id": story_id,
        "state": status,
        "local_only": True,
        "changed": prev_state != status,
    }
