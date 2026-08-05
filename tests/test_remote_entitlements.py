"""The remote entitlements evaluator (LIN-32): every failure mode is a
denial — an enforcement flip must never silently fall back to open."""

import pytest

from linebreak_gate.entitlements import RemoteCiEntitlements, resolve_provider
from linebreak_gate.entitlements.remote import DEFAULT_LICENSE_BASE_URL


def _provider(monkeypatch, key="lb_live_test", responses=None, error=None):
    if key is None:
        monkeypatch.delenv("LINEBREAK_LICENSE_KEY", raising=False)
    else:
        monkeypatch.setenv("LINEBREAK_LICENSE_KEY", key)
    calls = []

    def transport(url, headers):
        calls.append((url, headers))
        if error:
            raise error
        return responses

    provider = RemoteCiEntitlements(transport=transport)
    return provider, calls


def test_missing_key_is_a_denial(monkeypatch):
    provider, calls = _provider(monkeypatch, key=None, responses=(200, {}))
    decision = provider.allow("security.ci_gate", {})
    assert not decision.allowed
    assert "LINEBREAK_LICENSE_KEY" in decision.reason
    assert calls == []  # no key -> no network call


def test_valid_pro_key_allows(monkeypatch):
    provider, calls = _provider(
        monkeypatch,
        responses=(200, {"valid": True, "plan": "pro", "gate_entitled": True, "credits": 42}),
    )
    decision = provider.allow("security.ci_gate", {})
    assert decision.allowed
    url, headers = calls[0]
    assert url == f"{DEFAULT_LICENSE_BASE_URL}/v1/ci/validate"
    assert headers["Authorization"] == "Bearer lb_live_test"
    # The WAF rejects default library agents — the UA must be ours.
    assert headers["User-Agent"].startswith("linebreak-gate/")


def test_invalid_or_revoked_key_denies(monkeypatch):
    provider, _ = _provider(monkeypatch, responses=(401, {"valid": False}))
    decision = provider.allow("security.ci_gate", {})
    assert not decision.allowed
    assert "invalid or was revoked" in decision.reason


def test_free_plan_requires_upgrade(monkeypatch):
    provider, _ = _provider(
        monkeypatch,
        responses=(200, {"valid": True, "plan": "free", "gate_entitled": False, "credits": 0}),
    )
    decision = provider.allow("security.ci_gate", {})
    assert not decision.allowed
    assert decision.upgrade_url


def test_network_failure_fails_closed(monkeypatch):
    provider, _ = _provider(monkeypatch, error=OSError("connection refused"))
    decision = provider.allow("security.ci_gate", {})
    assert not decision.allowed
    assert "fail closed" in decision.reason


def test_non_json_200_body_fails_closed_not_crash(monkeypatch):
    # A corporate proxy/challenge page answering 200 + HTML raises
    # json.JSONDecodeError (a ValueError) inside the transport — that must be
    # a denial, never an unhandled traceback (which would exit 1, the
    # "blocking findings" code).
    import json as _json

    provider, _ = _provider(monkeypatch, error=_json.JSONDecodeError("x", "<html>", 0))
    decision = provider.allow("security.ci_gate", {})
    assert not decision.allowed
    assert "fail closed" in decision.reason


def test_http_exception_fails_closed_not_crash(monkeypatch):
    import http.client

    provider, _ = _provider(monkeypatch, error=http.client.BadStatusLine("garbage"))
    decision = provider.allow("security.ci_gate", {})
    assert not decision.allowed
    assert "fail closed" in decision.reason


def test_service_5xx_is_not_blamed_on_the_key(monkeypatch):
    # An outage must never tell the operator to regenerate the key —
    # regeneration atomically revokes the old key and breaks every other
    # pipeline using it.
    provider, _ = _provider(monkeypatch, responses=(503, {}))
    decision = provider.allow("security.ci_gate", {})
    assert not decision.allowed
    assert "HTTP 503" in decision.reason
    assert "revoked" not in decision.reason
    assert "not a problem with your key" in decision.reason


def test_resolve_provider_remote_returns_real_evaluator(monkeypatch):
    monkeypatch.setenv("LINEBREAK_ENTITLEMENTS_PROVIDER", "remote")
    assert isinstance(resolve_provider(), RemoteCiEntitlements)


def test_base_url_env_override(monkeypatch):
    monkeypatch.setenv("LINEBREAK_LICENSE_BASE_URL", "https://api-staging.linebreakapp.com/")
    provider, calls = _provider(
        monkeypatch,
        responses=(200, {"valid": True, "plan": "pro", "gate_entitled": True}),
    )
    provider.allow("security.ci_gate", {})
    assert calls[0][0] == "https://api-staging.linebreakapp.com/v1/ci/validate"


@pytest.fixture(autouse=True)
def _no_base_override(monkeypatch):
    monkeypatch.delenv("LINEBREAK_LICENSE_BASE_URL", raising=False)
