"""El gestor de tickets configurado en el panel (Integraciones) llega a la
compuerta por GET /v1/gate/tickets-config con el token del pipeline, solo
cuando gate.yml no fija un bloque ``tickets:``. Lo que dice gate.yml gana;
una variable de entorno gana sobre la credencial que mandó el servicio."""

from __future__ import annotations

import pytest

from linebreak_gate import cli, tickets
from linebreak_gate.gate_config import GateConfig, TicketsConfig, resolve_config

GOV_ENV = {
    "LINEBREAK_GOVERNANCE_BASE_URL": "https://gov.example",
    "LINEBREAK_GOVERNANCE_TOKEN": "lbg_pipeline",
}

JIRA_BODY = {
    "provider": "jira",
    "project": "SEC",
    "issue_type": "Bug",
    "labels": ["linebreak", "riesgo"],
    "main_branch": "main",
    "credentials": {
        "JIRA_BASE_URL": "https://acme.atlassian.net",
        "JIRA_EMAIL": "bot@acme.test",
        "JIRA_API_TOKEN": "secret-token",
    },
}


def test_none_without_governance_variables():
    assert tickets.from_governance(env={}) is None


def test_none_when_the_service_has_no_tracker():
    assert tickets.from_governance(env=GOV_ENV, fetch=lambda u, t: (404, None)) is None


def test_jira_config_with_credentials():
    seen = {}

    def fetch(url, token):
        seen["url"], seen["token"] = url, token
        return 200, JIRA_BODY

    cfg = tickets.from_governance(env=GOV_ENV, fetch=fetch)
    assert seen == {"url": "https://gov.example/v1/gate/tickets-config", "token": "lbg_pipeline"}
    assert cfg is not None
    assert cfg.provider == "jira" and cfg.project == "SEC" and cfg.issue_type == "Bug"
    assert cfg.labels == ("linebreak", "riesgo") and cfg.source == "governance"
    assert dict(cfg.credentials)["JIRA_API_TOKEN"] == "secret-token"


def test_invalid_body_is_a_ticket_error_never_a_crash():
    with pytest.raises(tickets.TicketError, match="invalid"):
        tickets.from_governance(
            env=GOV_ENV, fetch=lambda u, t: (200, {"provider": "trello", "project": "X"})
        )
    with pytest.raises(tickets.TicketError, match="answered 500"):
        tickets.from_governance(env=GOV_ENV, fetch=lambda u, t: (500, {"error": "x"}))


def test_client_uses_service_credentials_and_env_wins(monkeypatch):
    for name in ("JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_API_TOKEN", "GITHUB_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    cfg = tickets.from_governance(env=GOV_ENV, fetch=lambda u, t: (200, JIRA_BODY))
    client = tickets.client_from_env(cfg)
    assert isinstance(client, tickets.JiraClient)
    assert client.base == "https://acme.atlassian.net"
    monkeypatch.setenv("JIRA_BASE_URL", "https://other.atlassian.net")
    assert tickets.client_from_env(cfg).base == "https://other.atlassian.net"
    github = TicketsConfig(
        provider="github", project="acme/pagos", credentials=(("GITHUB_TOKEN", "ghp_x"),)
    )
    assert isinstance(tickets.client_from_env(github), tickets.GitHubClient)
    bare = TicketsConfig(provider="github", project="acme/pagos")
    with pytest.raises(tickets.TicketError, match="GITHUB_TOKEN"):
        tickets.client_from_env(bare)


def test_gate_yml_wins_over_the_service(tmp_path, monkeypatch):
    (tmp_path / ".linebreak").mkdir()
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "tickets:\n  provider: github\n  project: acme/pagos\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        tickets, "from_governance", lambda *a, **k: pytest.fail("must not consult the service")
    )
    cfg = resolve_config(tmp_path)
    assert cli._tickets_config(cfg).provider == "github"


def test_service_is_the_fallback_and_never_blocks(monkeypatch, capsys):
    monkeypatch.setattr(
        tickets, "from_governance", lambda *a, **k: TicketsConfig(provider="jira", project="SEC")
    )
    assert cli._tickets_config(GateConfig()).project == "SEC"

    def boom(*a, **k):
        raise tickets.TicketError("network error")

    monkeypatch.setattr(tickets, "from_governance", boom)
    assert cli._tickets_config(GateConfig()) is None
    assert "the verdict is unaffected" in capsys.readouterr().err
