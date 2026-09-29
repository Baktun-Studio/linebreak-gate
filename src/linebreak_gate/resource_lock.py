"""Exclusive use of a shared resource by the checks that declare it (issue #262).

A criterion whose check mutates a shared environment (a staging tenant, a test
merchant) declares it::

    check:
      type: command
      payload: node scripts/qa/flujos.mjs --flujo f1
      resource: staging-comercio-demo

Every check that names the same resource runs alone: inside one run the gate
runs them one after another, and across runs ON THE SAME MACHINE (two checks
on one self-hosted runner, a developer's check next to a CI job) an OS file
lock in :func:`lock_dir` serializes them. Runs on different machines cannot
see each other's lock; for those the gate re-runs a failed exclusive check
alone (see ``criteria_check``) and the CI side should serialize the jobs
(a ``concurrency`` group per resource) or, better, give every end-to-end run
its own disposable tenant.

The lock file carries who holds it (pid, host, criterion, since when), so a
check that had to wait says for whom.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import sys
import tempfile
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

#: Where the lock files live; the default is shared by every user of the
#: machine's temp directory. Point it elsewhere to scope the locks.
LOCK_DIR_ENV = "LINEBREAK_LOCK_DIR"
_POLL_S = 0.5


class ResourceBusy(Exception):
    """The resource stayed held for longer than the wait allowed."""


def lock_dir() -> Path:
    configured = (os.environ.get(LOCK_DIR_ENV) or "").strip()
    return Path(configured) if configured else Path(tempfile.gettempdir()) / "linebreak-gate-locks"


def _try_lock(fd: int) -> bool:
    if sys.platform == "win32":
        import msvcrt

        try:
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    import fcntl

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt

        with contextlib.suppress(OSError):
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    with contextlib.suppress(OSError):
        fcntl.flock(fd, fcntl.LOCK_UN)


def _holder_path(resource: str) -> Path:
    return lock_dir() / f"{resource}.holder.json"


def _read_holder(resource: str) -> dict[str, Any] | None:
    try:
        data = json.loads(_holder_path(resource).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


@contextlib.contextmanager
def hold(resource: str, *, holder: str, timeout_s: float) -> Iterator[dict[str, Any]]:
    """Hold ``resource`` exclusively. Yields ``{"resource", "waited_s",
    "waited_for"}``; ``waited_for`` names the holder seen while waiting.
    Raises :class:`ResourceBusy` after ``timeout_s`` without the lock."""
    directory = lock_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{resource}.lock"
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o666)
    info: dict[str, Any] = {"resource": resource, "waited_s": 0.0, "waited_for": None}
    start = time.monotonic()
    try:
        while not _try_lock(fd):
            if info["waited_for"] is None:
                info["waited_for"] = _read_holder(resource)
            if time.monotonic() - start >= timeout_s:
                seen = info["waited_for"] or {}
                raise ResourceBusy(
                    f"resource {resource!r} stayed held for more than {int(timeout_s)}s "
                    f"(by {seen.get('holder', 'another check')} on {seen.get('host', '?')}, "
                    f"pid {seen.get('pid', '?')})"
                )
            time.sleep(_POLL_S)
        info["waited_s"] = round(time.monotonic() - start, 1)
        with contextlib.suppress(OSError):
            _holder_path(resource).write_text(
                json.dumps(
                    {
                        "holder": holder,
                        "pid": os.getpid(),
                        "host": socket.gethostname(),
                        "since": datetime.now(UTC).isoformat(timespec="seconds"),
                    }
                ),
                encoding="utf-8",
            )
        try:
            yield info
        finally:
            with contextlib.suppress(OSError):
                _holder_path(resource).unlink()
            _unlock(fd)
    finally:
        os.close(fd)
