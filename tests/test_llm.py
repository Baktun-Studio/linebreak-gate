"""The CI gate's BYOK model seam: credentials gating and fail-closed handling
of refusal/truncation stop reasons."""

from types import SimpleNamespace

import pytest

from linebreak_gate import llm


class _FakeMessages:
    def __init__(self, response):
        self._response = response
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return self._response


def _fake_client(monkeypatch, response):
    import anthropic

    messages = _FakeMessages(response)

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            self.messages = messages

    monkeypatch.setattr(anthropic, "Anthropic", _FakeClient)
    return messages


def test_build_ask_returns_none_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert llm.build_ask() is None


def test_ask_joins_text_blocks(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    response = SimpleNamespace(
        stop_reason="end_turn",
        content=[
            SimpleNamespace(type="text", text="[{"),
            SimpleNamespace(type="thinking", text="ignored"),
            SimpleNamespace(type="text", text="}]"),
        ],
    )
    messages = _fake_client(monkeypatch, response)
    ask = llm.build_ask()
    assert ask("system", "user") == "[{}]"
    assert messages.calls[0]["model"] == llm.DEFAULT_MODEL


def test_ask_fails_closed_on_refusal(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    _fake_client(monkeypatch, SimpleNamespace(stop_reason="refusal", content=[]))
    ask = llm.build_ask()
    with pytest.raises(RuntimeError, match="refusal"):
        ask("system", "user")


def test_ask_fails_closed_on_truncation(monkeypatch):
    # A response cut off at max_tokens would parse as an empty findings array
    # downstream — that must be an error, never a clean pass.
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    _fake_client(
        monkeypatch,
        SimpleNamespace(
            stop_reason="max_tokens",
            content=[SimpleNamespace(type="text", text='[{"title": "cut of')],
        ),
    )
    ask = llm.build_ask()
    with pytest.raises(RuntimeError, match="truncated"):
        ask("system", "user")


def test_model_env_override(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setenv("LINEBREAK_GATE_MODEL", "claude-custom-model")
    messages = _fake_client(
        monkeypatch,
        SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text="[]")]),
    )
    llm.build_ask()("s", "u")
    assert messages.calls[0]["model"] == "claude-custom-model"
    monkeypatch.delenv("LINEBREAK_GATE_MODEL")
