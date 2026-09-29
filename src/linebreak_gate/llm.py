"""The CI gate's model seam for the AI SAST pass.

Two credential paths, BYOK first:

* ``ANTHROPIC_API_KEY`` — the client's own key, straight to Anthropic.
* ``LINEBREAK_LICENSE_KEY`` (no Anthropic key) — the hosted path: the same
  official SDK pointed at LineBreak's proxy (``/v1/messages`` drop-in on the
  license service), authenticated by the license key as a bearer token and
  billed as LineBreak credits. The User-Agent is set explicitly because the
  API's Cloudflare WAF rejects default SDK agents.

Both feed the SAME ``ask(system, user) -> text`` contract into the shared
:mod:`linebreak_gate.code_scan` discovery/verification core.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from .code_scan import ScanAbort
from .entitlements.remote import license_base_url, user_agent

# Claude Opus — the default engine for the security review. Overridable via
# LINEBREAK_GATE_MODEL for teams that want a cheaper/faster tier.
DEFAULT_MODEL = "claude-opus-4-8"
_MAX_TOKENS = 16000

Ask = Callable[[str, str], str]


def build_ask() -> Ask | None:
    """Build the model callable, or return ``None`` when no credentials exist.

    BYOK (``ANTHROPIC_API_KEY``) takes precedence — enterprise/air-gapped
    users keep full control and are never billed credits. Otherwise
    ``LINEBREAK_LICENSE_KEY`` routes through the hosted proxy. The caller
    decides what None means per config: ``code_scan: auto`` skips the SAST
    pass with a notice; ``code_scan: on`` treats it as a tool error (exit 2,
    fail closed).
    """
    byok = os.environ.get("ANTHROPIC_API_KEY")
    license_key = os.environ.get("LINEBREAK_LICENSE_KEY", "").strip()
    if not byok and not license_key:
        return None

    import anthropic

    if byok:
        client = anthropic.Anthropic()
    else:
        client = anthropic.Anthropic(
            base_url=license_base_url(),
            auth_token=license_key,
            # The API's Cloudflare WAF rejects default SDK User-Agents.
            default_headers={"User-Agent": user_agent()},
        )
    model = os.environ.get("LINEBREAK_GATE_MODEL") or DEFAULT_MODEL

    def ask(system: str, user: str) -> str:
        try:
            response = client.messages.create(
                model=model,
                max_tokens=_MAX_TOKENS,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIStatusError as e:
            if e.status_code == 402:
                # ScanAbort, not RuntimeError: mid-verification the scan core
                # keeps findings on ordinary verifier errors, which would bury
                # this message under unverified noise — an empty balance must
                # stop the whole scan with the cause visible.
                raise ScanAbort(
                    "out of LineBreak credits — top up at linebreakapp.com or set "
                    "ANTHROPIC_API_KEY to use your own key"
                ) from e
            raise
        # A safety-classifier decline must not read as "no findings" — raise so
        # code_scan's discovery path fails closed. Same for a truncated
        # response: a JSON array cut off mid-finding parses as [] downstream,
        # which would be a fail-open clean pass.
        stop_reason = getattr(response, "stop_reason", None)
        if stop_reason == "refusal":
            raise RuntimeError("the model declined the security-review request (refusal)")
        if stop_reason == "max_tokens":
            raise RuntimeError(
                "model response truncated at max_tokens — refusing to treat a "
                "partial security review as a clean result"
            )
        return "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )

    return ask
