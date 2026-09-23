"""Issue #260: un criterio no pasa por un motivo distinto del que enuncia.

El caso de Katun (11 sep 2026): el criterio de F4 promete que una petición
sin firma sigue la política del comercio; su prueba comprobaba
``status >= 400``. En el comercio de demostración respondía
``400 unsupported_api_version`` (el rechazo prometido); en un inquilino nuevo
de QA, ``503 checkout_not_configured`` (el checkout ni existía), y el
criterio seguía en verde.

Un check puede declarar qué espera observar (``expect``): cadenas que deben
aparecer en la salida y el código de salida. Un rechazo por otra razón deja
de contar como el mismo rechazo.
"""

from __future__ import annotations

import pytest
from test_criteria_check import write_bundle

from linebreak_gate import cli, criteria_check, spec_bundle
from linebreak_gate.cli import main


def _historia(check):
    return {
        "id": "F4",
        "title": "Peticiones sin firma",
        "criteria": [
            {
                "id": "F4-AC1",
                "statement": "Una petición sin firma sigue la política del comercio",
                "check": check,
            }
        ],
    }


def _imprime(texto: str, salida: int = 0) -> str:
    return f"python -c \"import sys; print('{texto}'); sys.exit({salida})\""


EXPECT_RECHAZO = {"output": "400 unsupported_api_version"}


# ---------------------------------------------------------------- evaluación


def test_otro_motivo_de_rechazo_ya_no_pasa(tmp_path):
    # El inquilino desechable: el comando sale con 0 porque hubo un error,
    # pero no el error que el criterio promete.
    write_bundle(
        tmp_path,
        [
            _historia(
                {
                    "type": "command",
                    "payload": _imprime("503 checkout_not_configured"),
                    "expect": EXPECT_RECHAZO,
                }
            )
        ],
    )
    result = criteria_check.evaluate_bundle(tmp_path)
    entry = result["criteria"][0]
    assert entry["result"] == "fail"
    assert entry["detail"].startswith("expected output not observed: '400 unsupported_api_version'")
    assert result["passes"] is False
    assert result["block_reasons"] == ["tests_failed"]


def test_el_rechazo_prometido_pasa(tmp_path):
    write_bundle(
        tmp_path,
        [
            _historia(
                {
                    "type": "command",
                    "payload": _imprime("status 400 unsupported_api_version"),
                    "expect": EXPECT_RECHAZO,
                }
            )
        ],
    )
    assert criteria_check.evaluate_bundle(tmp_path)["criteria"][0]["result"] == "pass"


def test_todas_las_cadenas_deben_aparecer(tmp_path):
    write_bundle(
        tmp_path,
        [
            _historia(
                {
                    "type": "command",
                    "payload": _imprime("400 unsupported_api_version"),
                    "expect": {"output": ["400", "politica: revisar_desconocidos"]},
                }
            )
        ],
    )
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert entry["result"] == "fail"
    assert "'politica: revisar_desconocidos'" in entry["detail"]
    assert "'400'" not in entry["detail"].splitlines()[0]


def test_el_codigo_de_salida_esperado(tmp_path):
    # Un script que debe rechazar (salir con 3) pasa solo si rechaza así.
    write_bundle(
        tmp_path,
        [
            _historia(
                {
                    "type": "command",
                    "payload": _imprime("rechazado", salida=3),
                    "expect": {"exit": 3, "output": "rechazado"},
                }
            )
        ],
    )
    assert criteria_check.evaluate_bundle(tmp_path)["criteria"][0]["result"] == "pass"

    write_bundle(
        tmp_path,
        [
            _historia(
                {
                    "type": "command",
                    "payload": _imprime("rechazado", salida=0),
                    "expect": {"exit": 3},
                }
            )
        ],
    )
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert entry["result"] == "fail"
    assert entry["detail"].startswith("expected exit 3, got 0")


def test_un_corredor_sin_codigo_de_salida_nunca_cumple_un_rechazo(tmp_path):
    # Un tiempo agotado no tiene código de salida: no satisface `exit: 1`.
    write_bundle(tmp_path, [_historia({"type": "command", "payload": "x", "expect": {"exit": 1}})])

    def agotado(criterion, root):  # noqa: ARG001
        return criteria_check.RunOutcome(ok=False, detail="timed out after 1800s")

    entry = criteria_check.evaluate_bundle(tmp_path, run=agotado)["criteria"][0]
    assert entry["result"] == "fail"
    assert "expected exit 1, got no exit code" in entry["detail"]


def test_sin_expect_nada_cambia(tmp_path):
    write_bundle(
        tmp_path,
        [_historia({"type": "command", "payload": _imprime("503 checkout_not_configured")})],
    )
    assert criteria_check.evaluate_bundle(tmp_path)["criteria"][0]["result"] == "pass"


def test_el_reporte_dice_lo_que_se_espera(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_result_icons", lambda: cli._RESULT_ICONS_ASCII)
    write_bundle(
        tmp_path,
        [
            _historia(
                {
                    "type": "command",
                    "payload": _imprime("503 checkout_not_configured"),
                    "expect": EXPECT_RECHAZO,
                }
            )
        ],
    )
    assert main(["check", "--path", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "expect: '400 unsupported_api_version')" in out
    assert "      expected output not observed: '400 unsupported_api_version'" in out


# ---------------------------------------------------------------- esquema


def test_expect_se_valida():
    def errores(check):
        return spec_bundle.validate_criterion({"id": "c", "statement": "s", "check": check})

    assert errores({"type": "command", "payload": "x", "expect": {"output": "ok"}}) == []
    assert errores({"type": "tests", "payload": "x", "expect": {"exit": 0}}) == []
    assert errores({"type": "build", "expect": {"output": ["a", "b"]}}) == []
    assert "only applies" in errores({"type": "manual", "expect": {"output": "x"}})[0]
    assert "must be a mapping" in errores({"type": "command", "payload": "x", "expect": "ok"})[0]
    assert "must be a mapping" in errores({"type": "command", "payload": "x", "expect": {}})[0]
    assert (
        "unknown expect"
        in errores({"type": "command", "payload": "x", "expect": {"stdout": "ok"}})[0]
    )
    assert "non-empty" in errores({"type": "command", "payload": "x", "expect": {"output": ""}})[0]
    assert "non-empty" in errores({"type": "command", "payload": "x", "expect": {"output": []}})[0]
    for malo in (True, -1, 256, "0"):
        assert (
            "between 0 and 255"
            in errores({"type": "command", "payload": "x", "expect": {"exit": malo}})[0]
        )


def _criterio(check):
    return {"id": "c", "statement": "s", "check": check}


def test_el_hash_no_cambia_para_criterios_sin_expect():
    # Las firmas y excepciones existentes se atan al hash: agregar la clave al
    # esquema no puede envejecer ninguna. Valores calculados con el esquema
    # anterior a `expect` (origin/main del 23 sep 2026).
    assert (
        spec_bundle.criterion_hash(_criterio({"type": "command", "payload": "./smoke.sh"}))
        == "ab7c350ebe69742d1c8744030535c67f2ff41efa609de1cf6aa67651a38763c3"
    )
    assert (
        spec_bundle.criterion_hash(
            _criterio({"type": "command", "payload": "./smoke.sh", "when": "release"})
        )
        == "697ce4f31548efbc341e3a4645ba9e1dbdc6995f209260a6f745b4fbad134cc3"
    )
    story = {"id": "s", "title": "t", "criteria": [_criterio({"type": "build"})]}
    assert "expect" not in spec_bundle.dump_story_yaml(story)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ({"output": "x"}, {"output": ["x"]}),
        ({"output": "x", "exit": 0}, {"output": ["x"]}),
        ({"exit": 2, "output": "x"}, {"output": ["x"], "exit": 2}),
    ],
)
def test_dos_formas_de_escribir_la_misma_expectativa_tienen_el_mismo_hash(a, b):
    base = {"type": "command", "payload": "./f4.sh"}
    assert spec_bundle.criterion_hash(_criterio({**base, "expect": a})) == (
        spec_bundle.criterion_hash(_criterio({**base, "expect": b}))
    )


def test_cambiar_la_expectativa_cambia_el_hash():
    base = {"type": "command", "payload": "./f4.sh"}
    assert spec_bundle.criterion_hash(_criterio(base)) != spec_bundle.criterion_hash(
        _criterio({**base, "expect": {"output": "400"}})
    )
    # `exit: 0` solo es el valor implícito: no es contenido.
    assert spec_bundle.criterion_hash(_criterio(base)) == spec_bundle.criterion_hash(
        _criterio({**base, "expect": {"exit": 0}})
    )


def test_expect_viaja_en_el_paquete_escrito(tmp_path):
    check = {"type": "command", "payload": "./f4.sh", "expect": {"output": "400", "exit": 1}}
    write_bundle(tmp_path, [_historia(check)])
    bundle = spec_bundle.load_bundle(tmp_path)
    assert bundle["stories"][0]["criteria"][0]["check"]["expect"] == {"output": ["400"], "exit": 1}
