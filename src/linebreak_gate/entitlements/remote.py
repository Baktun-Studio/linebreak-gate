"""The CI gate's remote entitlements evaluator (LIN-32).

Validates ``LINEBREAK_LICENSE_KEY`` against the LineBreak license service
(``POST /v1/ci/validate``) and maps the answer onto the shared
:class:`Decision` contract. Selected via ``LINEBREAK_ENTITLEMENTS_PROVIDER=
remote``; under that flip every failure mode — missing key, invalid/revoked
key, unreachable service — is a denial. A CI boundary that cannot evaluate
policy must not pass (fail closed).

Stdlib-only transport (urllib) so the standalone package stays lean; the
User-Agent is set explicitly because the API's Cloudflare WAF rejects default
library agents.
"""

from __future__ import annotations

import http.client
import json
import os
import urllib.error
import urllib.request
from typing import Any

from .base import Decision, Scope

DEFAULT_LICENSE_BASE_URL = "https://api.linebreakapp.com"
_TIMEOUT_SECONDS = 15
_UPGRADE_URL = "https://www.linebreakapp.com/en/pricing"


def license_base_url() -> str:
    """The license-service base URL — shared with the hosted-AI path in
    :mod:`linebreak_gate.llm` so the two can't drift apart."""
    return (os.environ.get("LINEBREAK_LICENSE_BASE_URL") or DEFAULT_LICENSE_BASE_URL).rstrip("/")


def user_agent() -> str:
    """The WAF-safe User-Agent — shared with the hosted-AI path in
    :mod:`linebreak_gate.llm` (Cloudflare rejects default library agents)."""
    from linebreak_gate import __version__

    return f"linebreak-gate/{__version__}"


def _default_transport(url: str, headers: dict[str, str]) -> tuple[int, dict[str, Any]]:
    """POST ``url`` and return (status, parsed-json). Raises on transport
    failure; non-2xx statuses are returned, not raised."""
    request = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return response.status, json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8") or "{}")
        except (ValueError, OSError):
            body = {}
        return e.code, body


class RemoteCiEntitlements:
    """Evaluate the CI-gate entitlement against the license service."""

    name = "remote"

    def __init__(self, base_url: str | None = None, transport=None) -> None:
        self._base_url = base_url.rstrip("/") if base_url else license_base_url()
        self._transport = transport or _default_transport

    def allow(self, action: str, scope: Scope) -> Decision:
        key = os.environ.get("LINEBREAK_LICENSE_KEY", "").strip()
        if not key:
            return Decision.require_upgrade(
                action,
                reason=(
                    "license enforcement is enabled and no LINEBREAK_LICENSE_KEY is set — "
                    "add your key to CI secrets"
                ),
                upgrade_url=_UPGRADE_URL,
            )
        headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "User-Agent": user_agent(),
        }
        # ValueError covers json.JSONDecodeError (a 200 with an HTML body from a
        # corporate proxy/challenge page); http.client.HTTPException covers
        # BadStatusLine/IncompleteRead — neither is an OSError, and an escape
        # here would crash the CLI with exit 1 (the "blocking findings" code)
        # instead of producing a fail-closed denial.
        try:
            status, body = self._transport(f"{self._base_url}/v1/ci/validate", headers)
        except (OSError, ValueError, http.client.HTTPException) as e:
            return Decision.deny(
                action,
                reason=(
                    f"could not reach the license service ({e}) — remote entitlements "
                    "fail closed; retry, or check LINEBREAK_LICENSE_BASE_URL"
                ),
            )
        if status == 401 or (200 <= status < 300 and not body.get("valid")):
            return Decision.deny(
                action,
                reason="the LINEBREAK_LICENSE_KEY is invalid or was revoked — generate a new key",
                upgrade_url=_UPGRADE_URL,
            )
        if not 200 <= status < 300:
            # A 5xx/403/429 is the service's problem, not the key's — saying
            # "regenerate" here would push operators to revoke a good key
            # (create atomically revokes the old one) during a transient outage.
            return Decision.deny(
                action,
                reason=(
                    f"the license service answered HTTP {status} — remote entitlements "
                    "fail closed; retry, this is not a problem with your key"
                ),
            )
        if not body.get("gate_entitled"):
            return Decision.require_upgrade(
                action,
                reason=(
                    f"the security gate is a Pro feature; this key is on the "
                    f"'{body.get('plan', 'free')}' plan"
                ),
                upgrade_url=_UPGRADE_URL,
            )
        return Decision.allow(action, reason=f"licensed ({body.get('plan')})")

    def policy_snapshot(self) -> dict[str, Any]:
        return {"policy": self.name, "base_url": self._base_url}
