"""Writing the spec bundle — the ONE writer implementation.

:mod:`.spec_bundle` is the ONE schema implementation (validation, canonical
serialization, hashes, read-back). This module is its writing counterpart:
landing an approved set of stories in ``.linebreak/spec/`` and committing it.
Both writers in the product go through here — the desktop app's spec-to-git
handoff (LIN-35) and the CLI's ``spec approve`` — so the bytes on disk can
never depend on which surface approved.

Same governance properties as the schema module documents:

- Deterministic serialization → a re-approval diff shows exactly what changed.
- Idempotent re-approval → identical content re-uses the prior ``generated_at``
  so a no-change approval never churns a timestamp-only commit.
- The commit is minimal and local (``git add .linebreak/spec`` + ``git
  commit`` scoped to the bundle), using the ambient git identity. Never a
  push, never a history rewrite. A failed commit is a WARNING, never a lost
  bundle — the files are already on disk.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from . import spec_bundle

_GIT_TIMEOUT_S = 30


def write_bundle(
    root: Path,
    stories: list[dict[str, Any]],
    *,
    source_phase: str,
    approval: dict[str, Any],
    generated_at: str,
    signed_approval: dict[str, Any] | None = None,
) -> None:
    """Write ``.linebreak/spec/`` from validated stories.

    Callers validate first (:func:`spec_bundle.validate_sidecar`);
    :func:`spec_bundle.dump_story_yaml` still re-raises on an invalid story,
    so an unvalidated call fails closed rather than landing junk. Raises
    ``OSError`` / :class:`spec_bundle.SpecBundleError` on failure — the caller
    decides whether that aborts (CLI) or degrades to a warning (app handoff).
    """
    spec_dir = root / spec_bundle.SPEC_DIR
    stories_dir = root / spec_bundle.STORIES_DIR
    stories_dir.mkdir(parents=True, exist_ok=True)

    # Canonical story text, keyed by target filename.
    new_files = {f"{s['id']}.yml": spec_bundle.dump_story_yaml(s) for s in stories}

    effective = _reuse_timestamp_if_unchanged(
        root,
        stories_dir,
        spec_dir,
        new_files,
        source_phase=source_phase,
        approval=approval,
        signed_approval=signed_approval,
        fallback=generated_at,
    )

    # Write the approved stories BEFORE pruning removed ones: an interrupted
    # write should never leave the on-disk bundle missing an approved story.
    for name, text in new_files.items():
        (stories_dir / name).write_text(text, encoding="utf-8")
    # The bundle IS the approved set: a story removed between approvals must
    # disappear from the repo too, or the diff lies about the agreed standard.
    for stale in stories_dir.glob("*.yml"):
        if stale.name not in new_files:
            stale.unlink()

    manifest = spec_bundle.dump_manifest_yaml(
        generated_at=effective,
        source_phase=source_phase,
        approval=approval,
        signed_approval=signed_approval,
    )
    (spec_dir / spec_bundle.MANIFEST_NAME).write_text(manifest, encoding="utf-8")


def _reuse_timestamp_if_unchanged(
    root: Path,
    stories_dir: Path,
    spec_dir: Path,
    new_files: dict[str, str],
    *,
    source_phase: str,
    approval: dict[str, Any],
    signed_approval: dict[str, Any] | None,
    fallback: str,
) -> str:
    """Return the prior ``generated_at`` when re-running would change ONLY the
    timestamp, else ``fallback``. Keeps an idempotent re-approval from churning
    a timestamp-only commit. Reconstructs the manifest the prior timestamp
    would produce and compares it byte-for-byte, so it never guesses at YAML
    round-trip types."""
    manifest_path = spec_dir / spec_bundle.MANIFEST_NAME
    if not manifest_path.exists():
        return fallback
    existing_stories = {p.name: p.read_text(encoding="utf-8") for p in stories_dir.glob("*.yml")}
    if existing_stories != new_files:
        return fallback
    try:
        prior = spec_bundle.load_bundle(root)
    except spec_bundle.SpecBundleError:
        return fallback
    if prior is None:
        return fallback
    prior_ts = str(prior["manifest"].get("generated_at", ""))
    candidate = spec_bundle.dump_manifest_yaml(
        generated_at=prior_ts,
        source_phase=source_phase,
        approval=approval,
        signed_approval=signed_approval,
    )
    if candidate == manifest_path.read_text(encoding="utf-8"):
        return prior_ts or fallback
    return fallback


def commit_bundle(root: Path, *, source_phase: str) -> tuple[bool, str | None]:
    """Best-effort ``git add + commit`` of the bundle. (committed, warning)."""
    if not (root / ".git").exists():
        return False, (
            "spec bundle written to .linebreak/spec/ but NOT committed: the project "
            "has no git repository. Initialize one and commit the bundle so the "
            "approved criteria land in history."
        )

    def _git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_S,
        )

    try:
        # ``-f`` guards against a stale blanket ``.linebreak/`` ignore rule:
        # older bootstraps wrote one. Current versions scope it so spec/audit/
        # gate.yml are committable — but a user-EDITED block is deliberately
        # never auto-healed, and a plain add would then stage nothing.
        add = _git("add", "-f", "--", str(spec_bundle.SPEC_DIR))
        if add.returncode != 0:
            return False, f"spec bundle written but git add failed: {add.stderr.strip()}"
        # Nothing staged (re-approval with zero changes) is a clean no-op, not
        # an error — the approved standard is already in history.
        diff = _git("diff", "--cached", "--quiet", "--", str(spec_bundle.SPEC_DIR))
        if diff.returncode == 0:
            return True, None
        commit = _git(
            "commit",
            "-m",
            f"spec: approved acceptance criteria ({source_phase})",
            "--",
            str(spec_bundle.SPEC_DIR),
        )
        if commit.returncode != 0:
            return False, (
                "spec bundle written but the commit failed: "
                f"{(commit.stderr or commit.stdout).strip()[:300]}"
            )
        return True, None
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"spec bundle written but git was unavailable: {e}"
