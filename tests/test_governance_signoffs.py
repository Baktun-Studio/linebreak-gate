"""Firmas hechas desde el panel de gobierno (sep 2026): con
LINEBREAK_GOVERNANCE_BASE_URL y _TOKEN, ``check`` consulta
GET /v1/projects/{id}/signoffs y trata cada firma como una con
identity_source governance, bajo las MISMAS reglas que las del repositorio
(hash del criterio, roles.yml). Un servicio que no responde no bloquea ni
aprueba. Sin red: el fetch se simula."""

from __future__ import annotations

import json

import pytest
from test_criteria_check import STORY, passing_runner, write_bundle

from linebreak_gate import criteria_check, signoffs
from linebreak_gate.cli import main
from linebreak_gate.spec_bundle import criterion_hash

GOV_ENV = {
    "LINEBREAK_GOVERNANCE_BASE_URL": "https://gov.example/",
    "LINEBREAK_GOVERNANCE_TOKEN": "lbg_pipeline",
    "LINEBREAK_GOV_PROJECT": "prj_1",
}

MANUAL = STORY["criteria"][3]  # S1-AC4, manual


def _remote(criterion_hash_value: str, **extra) -> dict:
    return {
        "id": "gso_1",
        "criterion_id": "S1-AC4",
        "criterion_hash": criterion_hash_value,
        "story_id": "S1",
        "by": "ana@x.test",
        "role": "ciso",
        "identity_source": "governance",
        "note": "revisado en el panel",
        "at": "2026-09-22T10:00:00Z",
        **extra,
    }


# ---------------------------------------------------------------- carga


def test_silent_without_governance_variables():
    assert signoffs.load_governance_signoffs(env={}) == ([], None)


def test_notice_when_no_project_id():
    env = {k: v for k, v in GOV_ENV.items() if k != "LINEBREAK_GOV_PROJECT"}
    records, notice = signoffs.load_governance_signoffs(env=env, fetch=lambda u, t: (200, []))
    assert records == []
    assert "no project id" in notice


def test_unreachable_service_is_a_notice_not_a_verdict():
    def boom(url, token):
        raise OSError("connection refused")

    records, notice = signoffs.load_governance_signoffs(env=GOV_ENV, fetch=boom)
    assert records == []
    assert "unreachable" in notice and "repository's sign-offs only" in notice


def test_error_status_is_a_notice():
    records, notice = signoffs.load_governance_signoffs(env=GOV_ENV, fetch=lambda u, t: (500, None))
    assert records == [] and "answered 500" in notice


def test_records_are_mapped_and_malformed_ones_skipped():
    seen = {}

    def fetch(url, token):
        seen["url"], seen["token"] = url, token
        return 200, {"signoffs": [_remote("abc"), {"criterion_id": "S1-AC4"}]}

    records, notice = signoffs.load_governance_signoffs(env=GOV_ENV, fetch=fetch)
    assert seen == {
        "url": "https://gov.example/v1/projects/prj_1/signoffs",
        "token": "lbg_pipeline",
    }
    assert len(records) == 1
    rec = records[0]
    assert rec["criterion_id"] == "S1-AC4" and rec["criterion_hash"] == "abc"
    assert rec["approver"] == "ana@x.test" and rec["note"] == "revisado en el panel"
    assert rec["signed_at"] == "2026-09-22T10:00:00Z" and rec["role"] == "ciso"
    # The service vouches for the identity: it is never downgraded to client.
    assert rec["identity_source"] == "governance"
    assert rec["identity"] == {"provider": "governance", "email": "ana@x.test"}
    assert "1 governance sign-off(s)" in notice


# ---------------------------------------------------------------- evaluación


def test_governance_signoff_satisfies_the_manual_criterion(tmp_path):
    write_bundle(tmp_path)
    remote = [signoffs.governance_record(_remote(criterion_hash(MANUAL)))]
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner, extra_signoffs=remote)
    entry = next(r for r in result["criteria"] if r["id"] == "S1-AC4")
    assert entry["result"] == "pass"
    assert entry["signoff"]["identity_source"] == "governance"
    assert entry["signoff"]["approver"] == "ana@x.test"
    assert result["passes"] is True
    assert result["governance_signoffs"] == 1


def test_stale_hash_from_the_service_satisfies_nothing(tmp_path):
    write_bundle(tmp_path)
    remote = [signoffs.governance_record(_remote("deadbeef"))]
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner, extra_signoffs=remote)
    entry = next(r for r in result["criteria"] if r["id"] == "S1-AC4")
    assert entry["result"] == "needs-signoff"
    assert result["passes"] is False


def test_roles_in_force_apply_to_service_signoffs_too(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / ".linebreak" / "roles.yml").write_text(
        "roles:\n  qa:\n    members: [luis@x.test]\n    can:\n      sign_criteria: ['*']\n"
        "policy:\n  require_roles: true\n",
        encoding="utf-8",
    )
    remote = [signoffs.governance_record(_remote(criterion_hash(MANUAL)))]  # ana, role ciso
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner, extra_signoffs=remote)
    entry = next(r for r in result["criteria"] if r["id"] == "S1-AC4")
    assert entry["result"] == "role-denied"
    assert "role_denied" in result["block_reasons"]


def test_require_verified_identity_accepts_governance_source(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / ".linebreak" / "roles.yml").write_text(
        "policy:\n  require_verified_identity: true\n", encoding="utf-8"
    )
    remote = [signoffs.governance_record(_remote(criterion_hash(MANUAL)))]
    result = criteria_check.evaluate_bundle(tmp_path, run=passing_runner, extra_signoffs=remote)
    entry = next(r for r in result["criteria"] if r["id"] == "S1-AC4")
    assert entry["result"] == "pass"


# ---------------------------------------------------------------- CLI


@pytest.fixture
def gov_env(monkeypatch):
    for k, v in GOV_ENV.items():
        monkeypatch.setenv(k, v)


def _check(tmp_path, capsys):
    code = main(["check", "--path", str(tmp_path), "--format", "json"])
    out = capsys.readouterr()
    return code, json.loads(out.out), out.err


def _manual_only_bundle(tmp_path):
    # One manual criterion and nothing to run: the CLI needs no build tooling.
    write_bundle(tmp_path, [{"id": "S1", "title": "Story", "criteria": [MANUAL]}])


def test_check_consults_the_service_and_records_the_source(tmp_path, gov_env, monkeypatch, capsys):
    _manual_only_bundle(tmp_path)
    monkeypatch.setattr(
        signoffs,
        "_default_governance_fetch",
        lambda url, token: (200, {"signoffs": [_remote(criterion_hash(MANUAL))]}),
    )
    code, payload, err = _check(tmp_path, capsys)
    assert code == 0, err
    entry = next(r for r in payload["criteria"] if r["id"] == "S1-AC4")
    assert entry["result"] == "pass"
    assert entry["signoff"]["identity_source"] == "governance"


def test_check_goes_on_when_the_service_is_down(tmp_path, gov_env, monkeypatch, capsys):
    _manual_only_bundle(tmp_path)

    def down(url, token):
        raise OSError("no route to host")

    monkeypatch.setattr(signoffs, "_default_governance_fetch", down)
    code, payload, err = _check(tmp_path, capsys)
    # The manual criterion still needs a sign-off: the outage neither blocks
    # anything else nor approves anything.
    assert code == 1
    assert "unreachable" in err
    entry = next(r for r in payload["criteria"] if r["id"] == "S1-AC4")
    assert entry["result"] == "needs-signoff"
