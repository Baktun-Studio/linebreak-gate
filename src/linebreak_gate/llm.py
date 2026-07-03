"""The CI gate's model seam for the AI SAST pass.

The desktop routes code-scan model calls through its session/credits stack
(``app.agent.model_picker``); in CI there is no session, so the gate uses BYOK:
the official Anthropic SDK with ``ANTHROPIC_API_KEY`` from the environment.
Both surfaces feed the SAME ``ask(system, user) -> text`` contract into the
shared :mod:`linebreak_gate.code_scan` discovery/verification core.
"""

from __future__ import annotations

import os
from collections.abc import Callable

# Claude Opus — the default engine for the security review. Overridable via
# LINEBREAK_GATE_MODEL for teams that want a cheaper/faster tier.
DEFAULT_MODEL = "claude-opus-4-8"
_MAX_TOKENS = 16000

Ask = Callable[[str, str], str]


def build_ask() -> Ask | None:
    """Build the model callable, or return ``None`` when no API key is set.

    The caller decides what None means per config: ``code_scan: auto`` skips
    the SAST pass with a notice; ``code_scan: on`` treats it as a tool error
    (exit 2, fail closed).
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None

    import anthropic

    client = anthropic.Anthropic()
    model = os.environ.get("LINEBREAK_GATE_MODEL") or DEFAULT_MODEL

    def ask(system: str, user: str) -> str:
        response = client.messages.create(
            model=model,
            max_tokens=_MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
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
