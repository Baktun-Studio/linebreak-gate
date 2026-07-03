"""Entitlements layer shared by the desktop backend and the CI gate.

The provider-agnostic contract (:class:`Decision`, :class:`Verdict`,
:class:`EntitlementsProvider`) and the permissive :class:`OpenEntitlements`
default moved here from ``app/entitlements`` so the standalone ``linebreak-gate``
CLI wires its licensing check through the SAME provider seam the desktop uses —
no parallel licensing infrastructure.

Provider resolution mirrors the desktop's: ``LINEBREAK_ENTITLEMENTS_PROVIDER``
selects ``open`` (default, allow-everything) or ``remote``. The desktop's
remote provider needs the app's auth/session stack and stays in the app
(``app/entitlements``); in a CLI run ``remote`` resolves to a fail-closed
denier, which is what an enforcement flip must mean at a CI boundary (an
unlicensed runner must not silently fall back to open). A CI-usable remote
provider ships with the licensing work that makes license keys verifiable.
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

__all__ = [
    "Decision",
    "EntitlementsError",
    "EntitlementsProvider",
    "GATE_ACTION",
    "OpenEntitlements",
    "Scope",
    "Verdict",
    "gate_decision",
    "resolve_provider",
]

# The action the CI gate asks about. Kept stable so a future remote policy doc
# can gate it per-tier without a client change.
GATE_ACTION = "security.ci_gate"


class _RemoteUnavailable:
    """Fail-closed stand-in when ``remote`` is selected: the CLI has no
    remote-policy evaluator today.

    Denying — rather than warning and falling back to open — is deliberate:
    once an operator flips ``LINEBREAK_ENTITLEMENTS_PROVIDER=remote``, an
    environment that cannot evaluate the policy must not pass the gate check.
    """

    name = "remote-unavailable"

    def allow(self, action: str, _scope: Scope) -> Decision:
        return Decision.require_upgrade(
            action,
            reason=(
                "entitlements provider 'remote' is not available in this "
                "environment; a valid LineBreak license is required"
            ),
            upgrade_url="https://linebreakapp.com/#pricing",
        )

    def policy_snapshot(self) -> dict[str, Any]:
        return {"policy": self.name, "default_verdict": "deny"}


def resolve_provider() -> EntitlementsProvider:
    """Resolve the configured provider for a CLI run.

    Mirrors the desktop's ``_build_default``: ``open`` (default) is the
    permissive provider; unknown values warn (to stderr — stdout carries the
    machine-readable scan output) and fall back to open so the gate keeps
    working; ``remote`` fails closed.
    """
    name = (os.environ.get("LINEBREAK_ENTITLEMENTS_PROVIDER") or "open").strip().lower()
    if name == "remote":
        return _RemoteUnavailable()
    if name not in {"", "open"}:
        print(
            f"[linebreak-gate] unknown entitlements provider {name!r}; falling back to open. "
            "Set LINEBREAK_ENTITLEMENTS_PROVIDER=open or =remote to silence this warning.",
            file=sys.stderr,
        )
    return OpenEntitlements()


def gate_decision(license_key: str | None) -> tuple[Decision, str | None]:
    """Evaluate the CI-gate entitlement.

    Returns ``(decision, notice)``. Under the ``open`` provider the gate always
    runs; when no ``LINEBREAK_LICENSE_KEY`` is present a notice explains that
    the gate is a Pro feature and enforcement is coming — printed, not fatal,
    matching the currently-open entitlements posture.
    """
    provider = resolve_provider()
    decision = provider.allow(GATE_ACTION, {"license_key_present": bool(license_key)})
    notice: str | None = None
    if decision.allowed and not license_key and provider.name == "open":
        notice = (
            "linebreak-gate: running without a license key. The security gate is a "
            "LineBreak Pro feature; set LINEBREAK_LICENSE_KEY in your CI secrets so "
            "this keeps working when license enforcement is enabled."
        )
    return decision, notice
