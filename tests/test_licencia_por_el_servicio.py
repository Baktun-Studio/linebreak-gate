"""La licencia la da la organización del servicio de gobierno
(e10-s6-licencia-por-el-servicio): con credenciales que responden y
autentican, check y scan no muestran el aviso de LineBreak Pro; sin ellas, o
con un servicio que no responde o rechaza el token, el aviso sigue."""

from __future__ import annotations

import urllib.error

import pytest

from linebreak_gate import governance_env, security_scan
from linebreak_gate.cli import main

AVISO_IA = "AI code review is a LineBreak Pro feature"
AVISO_CRITERIOS = "acceptance-criteria enforcement is a LineBreak Pro feature"


@pytest.fixture(autouse=True)
def _sin_cache(monkeypatch):
    monkeypatch.setattr(governance_env, "_LICENSED_CACHE", {})


def _fake_scan(findings):
    return lambda root, exclude_paths=None: {"findings": findings, "scanner": "fake"}


def _servicio(monkeypatch, respuesta):
    """Credenciales del servicio en el entorno y una respuesta simulada de /v1/me."""
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_BASE_URL", "https://gov.example")
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_TOKEN", "tok")
    monkeypatch.setenv("LINEBREAK_GOV_PROJECT", "prj_demo")
    llamadas = []

    def urlopen(request, timeout=None):
        llamadas.append(request.full_url)
        if isinstance(respuesta, Exception):
            raise respuesta

        class R:
            status = respuesta

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return R()

    monkeypatch.setattr("urllib.request.urlopen", urlopen)
    return llamadas


def _bundle(tmp_path):
    from test_criteria_check import write_bundle

    write_bundle(
        tmp_path,
        [
            {
                "id": "S1",
                "title": "Uno",
                "criteria": [{"id": "S1-AC1", "statement": "Algo", "check": {"type": "build"}}],
            }
        ],
    )


def test_con_servicio_que_autentica_no_hay_aviso_de_pro(tmp_path, monkeypatch, capsys):
    llamadas = _servicio(monkeypatch, 200)
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    _bundle(tmp_path)
    main(["check", "--path", str(tmp_path), "--manual", "warn"])
    err = capsys.readouterr().err
    assert AVISO_IA not in err and AVISO_CRITERIOS not in err
    # Una sola consulta a /v1/me por proceso.
    assert llamadas.count("https://gov.example/v1/me") == 1


@pytest.mark.parametrize(
    "respuesta",
    [urllib.error.HTTPError("u", 401, "no", {}, None), urllib.error.URLError("sin red")],
)
def test_si_el_servicio_rechaza_o_no_responde_el_aviso_sigue(
    tmp_path, monkeypatch, capsys, respuesta
):
    _servicio(monkeypatch, respuesta)
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    _bundle(tmp_path)
    main(["check", "--path", str(tmp_path), "--manual", "warn"])
    err = capsys.readouterr().err
    assert AVISO_IA in err and AVISO_CRITERIOS in err


def test_sin_proyecto_no_se_consulta_el_servicio(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_BASE_URL", "https://gov.example")
    monkeypatch.setenv("LINEBREAK_GOVERNANCE_TOKEN", "tok")

    def prohibido(*a, **k):
        raise AssertionError("sin proyecto no se consulta el servicio")

    monkeypatch.setattr("urllib.request.urlopen", prohibido)
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    assert AVISO_IA in capsys.readouterr().err


def test_sin_credenciales_el_aviso_sigue_y_no_hay_red(tmp_path, monkeypatch, capsys):
    def prohibido(*a, **k):
        raise AssertionError("sin credenciales no se consulta el servicio")

    monkeypatch.setattr("urllib.request.urlopen", prohibido)
    monkeypatch.setattr(security_scan, "scan_project", _fake_scan([]))
    main(["scan", "--path", str(tmp_path)])
    assert AVISO_IA in capsys.readouterr().err


def test_spec_approve_dice_que_falta_la_firma_sin_hablar_de_licencia(tmp_path, capsys):
    draft = tmp_path / "draft.yml"
    draft.write_text(
        "stories:\n  - id: S1\n    title: Uno\n    criteria:\n"
        "      - id: S1-AC1\n        statement: Algo verificable\n"
        "        check: {type: build}\n",
        encoding="utf-8",
    )
    code = main(
        [
            "spec",
            "approve",
            str(draft),
            "--path",
            str(tmp_path),
            "--approver",
            "Ana <a@b.c>",
            "--local",
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "not signed" in out and "governance instance" in out
    assert "license" not in out.lower()
