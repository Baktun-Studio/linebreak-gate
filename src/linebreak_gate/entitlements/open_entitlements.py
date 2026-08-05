"""Open-access entitlements provider.

The default provider. Allows every action on every scope so the
entitlements seam exists and callers are gated correctly without
enforcing any business model yet. Switching to paid tiers only requires
flipping ``LINEBREAK_ENTITLEMENTS_PROVIDER=remote`` and having the
licensing service emit a richer policy — no client rebuild needed.

The richer scope passed in by call sites is preserved verbatim in
the returned :class:`Decision`'s ``reason`` so audit logs still show
*what* was let through.
"""

from __future__ import annotations

from typing import Any

from .base import Decision, Scope


class OpenEntitlements:
    """Permissive provider. Always allows every action."""

    name = "open"

    def allow(self, action: str, _scope: Scope) -> Decision:
        return Decision.allow(action, reason="open: all actions permitted")

    def policy_snapshot(self) -> dict[str, Any]:
        return {
            "policy": self.name,
            "default_verdict": "allow",
            "actions": {"*": "allow"},
        }
