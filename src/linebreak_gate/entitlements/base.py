"""Entitlements contract.

Provider-agnostic types and the :class:`EntitlementsProvider`
protocol every concrete implementation must satisfy. Nothing in this
module knows about pricing, billing, or seats; concrete providers
encode those semantics.

Design notes
------------
* :class:`Decision` is intentionally rich (``verdict``, ``reason``,
  ``upgrade_url``, ``quota_remaining``) so the licensing service can
  later return things like "soft cap exceeded — show paywall but
  allow this run" without changing call sites.
* :class:`Scope` is an open dict the caller fills with everything
  that *might* matter to a future pricing dimension (project_id,
  tokens_in, mcp_server_id, …). Capturing rich scope today is the
  thing that lets us flip the policy later without a rebuild.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable


class EntitlementsError(Exception):
    """Raised when an entitlements operation fails or denies access.

    Carries an HTTP-shaped ``status_code`` so the orchestrator's REST
    boundary can translate it into an :class:`HTTPException` without
    importing FastAPI from this module.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 403,
        decision: Decision | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.decision = decision


class Verdict(StrEnum):
    """Coarse outcome of an entitlement check.

    ``ALLOW`` and ``DENY`` are self-explanatory. ``ALLOW_WITH_WARNING``
    lets the licensing service say "you're past a soft cap" without
    blocking the run. ``REQUIRE_UPGRADE`` is a denial that should
    surface an upgrade-funnel CTA in the UI.
    """

    ALLOW = "allow"
    ALLOW_WITH_WARNING = "allow_with_warning"
    REQUIRE_UPGRADE = "require_upgrade"
    DENY = "deny"


# Open-ended scope dict. We intentionally don't lock the keys down so
# call sites can populate everything that *might* be billable later.
Scope = dict[str, Any]


@dataclass(frozen=True)
class Decision:
    """The result of evaluating an action against the active policy.

    The most common shape is ``Decision.allow()``; remote policies
    populate ``reason`` / ``upgrade_url`` / ``quota_remaining`` to
    drive UI hints.
    """

    action: str
    verdict: Verdict
    reason: str | None = None
    upgrade_url: str | None = None
    quota_remaining: int | None = None

    @property
    def allowed(self) -> bool:
        return self.verdict in {Verdict.ALLOW, Verdict.ALLOW_WITH_WARNING}

    @classmethod
    def allow(cls, action: str, *, reason: str | None = None) -> Decision:
        return cls(action=action, verdict=Verdict.ALLOW, reason=reason)

    @classmethod
    def warn(cls, action: str, *, reason: str | None = None) -> Decision:
        return cls(action=action, verdict=Verdict.ALLOW_WITH_WARNING, reason=reason)

    @classmethod
    def deny(
        cls,
        action: str,
        *,
        reason: str | None = None,
        upgrade_url: str | None = None,
    ) -> Decision:
        return cls(
            action=action,
            verdict=Verdict.DENY,
            reason=reason,
            upgrade_url=upgrade_url,
        )

    @classmethod
    def require_upgrade(
        cls,
        action: str,
        *,
        reason: str | None = None,
        upgrade_url: str | None = None,
    ) -> Decision:
        return cls(
            action=action,
            verdict=Verdict.REQUIRE_UPGRADE,
            reason=reason,
            upgrade_url=upgrade_url,
        )

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form for telemetry / API responses."""
        return {
            "action": self.action,
            "verdict": self.verdict.value,
            "allowed": self.allowed,
            "reason": self.reason,
            "upgrade_url": self.upgrade_url,
            "quota_remaining": self.quota_remaining,
        }


@runtime_checkable
class EntitlementsProvider(Protocol):
    """Everything the rest of the backend needs from the active policy."""

    name: str

    def allow(self, action: str, scope: Scope) -> Decision: ...

    def policy_snapshot(self) -> dict[str, Any]:
        """Inspectable view of the active policy (for /api/auth/status,
        diagnostics bundles, etc.). Implementations that have nothing
        meaningful to expose can return ``{"policy": self.name}``."""
        ...
