"""Entitlements layer shared by the desktop backend and the CI gate.

The provider-agnostic contract (:class:`Decision`, :class:`Verdict`,
:class:`EntitlementsProvider`) and the permissive :class:`OpenEntitlements`
default moved here from ``app/entitlements`` so the standalone ``linebreak-gate``
CLI wires its licensing check through the SAME provider seam the desktop uses —
no parallel licensing infrastructure.

Provider resolution mirrors the desktop's: ``LINEBREAK_ENTITLEMENTS_PROVIDER``
selects ``open`` (default, allow-everything) or ``remote``. ``remote`` is the
real evaluator (:mod:`.remote`): it validates ``LINEBREAK_LICENSE_KEY``
against the license service and fails closed on every error — an unlicensed
or unreachable runner must not silently fall back to open.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from .base import (
    Decision,
    EntitlementsError,
    EntitlementsProvider,
    Scope,
    Verdict,
)
from .open_entitlements import OpenEntitlements
from .remote import RemoteCiEntitlements

__all__ = [
    "Decision",
    "EntitlementsError",
    "EntitlementsProvider",
    "GATE_ACTION",
    "OpenEntitlements",
    "RemoteCiEntitlements",
    "Scope",
    "Verdict",
    "gate_decision",
    "resolve_provider",
]

# The action the CI gate asks about. Kept stable so a future remote policy doc
# can gate it per-tier without a client change.
GATE_ACTION = "security.ci_gate"


def resolve_provider() -> EntitlementsProvider:
    """Resolve the configured provider for a CLI run.

    Mirrors the desktop's ``_build_default``: ``open`` (default) is the
    permissive provider; unknown values warn (to stderr — stdout carries the
    machine-readable scan output) and fall back to open so the gate keeps
    working; ``remote`` validates the license key and fails closed.
    """
    name = (os.environ.get("LINEBREAK_ENTITLEMENTS_PROVIDER") or "open").strip().lower()
    if name == "remote":
        return RemoteCiEntitlements()
    if name not in {"", "open"}:
        print(
            f"[linebreak-gate] unknown entitlements provider {name!r}; falling back to open. "
            "Set LINEBREAK_ENTITLEMENTS_PROVIDER=open or =remote to silence this warning.",
            file=sys.stderr,
        )
    return OpenEntitlements()


def gate_decision(license_key: str | None) -> tuple[Decision, str | None]:
    """Evaluate the CI-gate entitlement.

    Returns ``(decision, notice)``. Under the ``open`` provider (the default,
    freemium posture) the gate always runs — the dependency scan is free. When
    no ``LINEBREAK_LICENSE_KEY`` is present a notice points out that the AI code
    review is the Pro upgrade — printed, not fatal. The caller suppresses the
    notice for BYOK users, whose AI review already runs on their own key.
    """
    provider = resolve_provider()
    decision = provider.allow(GATE_ACTION, {"license_key_present": bool(license_key)})
    notice: str | None = None
    if decision.allowed and not license_key and provider.name == "open":
        notice = (
            "linebreak-gate: the dependency scan is free and ran without a license key. "
            "The AI code review is a LineBreak Pro feature — add LINEBREAK_LICENSE_KEY "
            "(hosted, uses credits) or ANTHROPIC_API_KEY (your own key) to enable it."
        )
    return decision, notice
