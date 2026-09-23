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


class _CaptureAnthropicKwargs:
    def __init__(self, store):
        self._store = store

    def __call__(self, *args, **kwargs):
        self._store.update(kwargs)

        class _Messages:
            def create(self, **kw):
                from types import SimpleNamespace

                return SimpleNamespace(
                    stop_reason="end_turn", content=[SimpleNamespace(type="text", text="[]")]
                )

        from types import SimpleNamespace

        return SimpleNamespace(messages=_Messages())


def test_license_key_routes_through_hosted_proxy(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LINEBREAK_LICENSE_KEY", "lb_live_abc")
    import anthropic

    captured = {}
    monkeypatch.setattr(anthropic, "Anthropic", _CaptureAnthropicKwargs(captured))
    ask = llm.build_ask()
    assert ask is not None
    ask("s", "u")
    assert captured["base_url"] == "https://api.linebreakapp.com"
    assert captured["auth_token"] == "lb_live_abc"
    # WAF: the SDK's default UA gets 403'd by Cloudflare — must be overridden.
    assert captured["default_headers"]["User-Agent"].startswith("linebreak-gate/")


def test_byok_takes_precedence_over_license_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-byok")
    monkeypatch.setenv("LINEBREAK_LICENSE_KEY", "lb_live_abc")
    import anthropic

    captured = {}
    monkeypatch.setattr(anthropic, "Anthropic", _CaptureAnthropicKwargs(captured))
    assert llm.build_ask() is not None
    # BYOK constructs the plain client — no proxy base_url, no bearer.
    assert "base_url" not in captured and "auth_token" not in captured


def test_no_credentials_returns_none(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("LINEBREAK_LICENSE_KEY", raising=False)
    assert llm.build_ask() is None


def test_402_aborts_the_whole_scan(monkeypatch):
    # Out-of-credits must raise ScanAbort (not a plain RuntimeError): the scan
    # core keeps findings on ordinary verifier errors, which would bury the
    # credits message under unverified noise.
    import anthropic
    import httpx

    from linebreak_gate.code_scan import ScanAbort

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("LINEBREAK_LICENSE_KEY", "lb_live_abc")

    response = httpx.Response(402, request=httpx.Request("POST", "https://api.linebreakapp.com"))
    error = anthropic.APIStatusError("payment required", response=response, body=None)

    class _Raises:
        def create(self, **kw):
            raise error

    class _Client:
        def __init__(self, *a, **kw):
            self.messages = _Raises()

    monkeypatch.setattr(anthropic, "Anthropic", _Client)
    ask = llm.build_ask()
    with pytest.raises(ScanAbort, match="out of LineBreak credits"):
        ask("s", "u")
