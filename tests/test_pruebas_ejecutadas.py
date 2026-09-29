"""Issue #259: un criterio de pruebas no queda verde sin ejecutar ninguna prueba.

El caso de Katun (10 y 11 sep 2026): once criterios de E6-S2 en verde con
filtros que no coincidían con nada; ``vitest -t`` sale con cero y marca todo
como omitido. La salida del corredor dice cuántas pruebas corrieron: cero
ejecutadas en un criterio ``tests`` es un fallo, siempre; en un ``command``
es un hallazgo de integridad (advertencia por defecto, bloqueo con
``criteria.integrity.zero_tests: block``). El número aparece junto a cada
criterio en el reporte.
"""

from __future__ import annotations

import pytest
from test_criteria_check import write_bundle

from linebreak_gate import cli, criteria_check
from linebreak_gate.cli import main
from linebreak_gate.runner_counts import count_tests

# ---------------------------------------------------------------- lectura de resúmenes
# Salidas reales capturadas de cada corredor (vitest 4.1, pytest 8, node 24).

VITEST_PASA = """
 RUN  v4.1.5 /repo

 Test Files  1 passed (1)
      Tests  2 passed (2)
   Start at  12:58:28
   Duration  77ms (transform 7ms, setup 0ms, import 11ms, tests 1ms, environment 0ms)
"""

# `vitest run a.test.mjs -t zzz`: sale con 0 y no ejecutó nada.
VITEST_FILTRO_SIN_COINCIDENCIAS = """
 RUN  v4.1.5 /repo

 Test Files  1 skipped (1)
      Tests  2 skipped (2)
   Start at  12:58:28
   Duration  61ms
"""

VITEST_MIXTO = """
 Test Files  1 failed | 1 passed (2)
      Tests  1 failed | 2 passed | 1 skipped | 1 todo (5)
"""

VITEST_SIN_ARCHIVOS = """
 RUN  v4.1.5 /repo

No test files found, exiting with code 0

filter: nada
"""

PYTEST_PASA = "..\n2 passed in 0.01s\n"
PYTEST_DESELECCIONADAS = (
    "collected 2 items / 2 deselected / 0 selected\n\n"
    "============================ 2 deselected in 0.00s =============================\n"
)
PYTEST_SIN_PRUEBAS = "\nno tests ran in 0.00s\n"
PYTEST_MIXTO = (
    "=========== 1 failed, 3 passed, 1 skipped, 2 warnings in 0.31s (0:00:01) ===========\n"
)

JEST_PASA = "Test Suites: 1 passed, 1 total\nTests:       1 failed, 3 passed, 4 total\n"
JEST_OMITIDAS = "Test Suites: 1 skipped, 0 of 1 total\nTests:       3 skipped, 3 total\n"
JEST_SIN_PRUEBAS = "No tests found, exiting with code 0\n"

NODE_SPEC = "✔ uno (0.25ms)\nℹ tests 2\nℹ suites 0\nℹ pass 1\nℹ fail 0\nℹ skipped 1\n"
NODE_TAP = "1..2\n# tests 2\n# pass 0\n# fail 0\n# skipped 2\n"

CARGO = (
    "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out; "
    "finished in 0.00s\n"
    "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; "
    "finished in 0.00s\n"
)
GO_SIN_PRUEBAS = (
    "ok  \texample.com/pkg\t0.01s [no tests to run]\n?   \texample.com/otro\t[no test files]\n"
)
GO_OK = "ok  \texample.com/pkg\t0.01s\n"
GO_VERBOSO = "=== RUN   TestA\n--- PASS: TestA (0.00s)\n=== RUN   TestB\n--- FAIL: TestB (0.00s)\n"


@pytest.mark.parametrize(
    ("salida", "ejecutadas"),
    [
        (VITEST_PASA, 2),
        (VITEST_FILTRO_SIN_COINCIDENCIAS, 0),
        (VITEST_MIXTO, 3),
        (VITEST_SIN_ARCHIVOS, 0),
        (PYTEST_PASA, 2),
        (PYTEST_DESELECCIONADAS, 0),
        (PYTEST_SIN_PRUEBAS, 0),
        (PYTEST_MIXTO, 4),
        (JEST_PASA, 4),
        (JEST_OMITIDAS, 0),
        (JEST_SIN_PRUEBAS, 0),
        (NODE_SPEC, 1),
        (NODE_TAP, 0),
        (CARGO, 0),
        (GO_SIN_PRUEBAS, 0),
        (GO_VERBOSO, 2),
    ],
)
def test_lee_las_pruebas_ejecutadas_de_cada_corredor(salida, ejecutadas):
    assert count_tests(salida).executed == ejecutadas


def test_un_numero_que_el_corredor_no_da_es_desconocido_nunca_cero():
    # `go test` sin -v dice "ok" sin decir cuántas: puede haber corrido pruebas.
    assert count_tests(GO_OK).executed is None
    assert count_tests(GO_OK).runners == ("go",)
    # Una salida sin resumen reconocible: nada que leer.
    assert count_tests("todo bien\n").executed is None
    assert count_tests("todo bien\n").runners == ()


def test_varias_corridas_en_una_salida_se_suman():
    # Un `pnpm -r test`: un paquete sin pruebas no esconde a los que sí tienen.
    assert count_tests(VITEST_SIN_ARCHIVOS + VITEST_PASA).executed == 2
    assert count_tests(PYTEST_PASA + VITEST_PASA).executed == 4


def test_los_colores_ansi_no_esconden_el_resumen():
    coloreado = (
        "\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m5 passed\x1b[39m\x1b[22m\x1b[90m (5)\x1b[39m\n"
    )
    assert count_tests(coloreado).executed == 5


# ---------------------------------------------------------------- criterio `tests`


def _historia(check):
    return {
        "id": "E6-S2",
        "title": "Pantallas",
        "criteria": [{"id": "E6-S2-AC1", "statement": "La bandeja filtra", "check": check}],
    }


def _corredor(salida, ok=True, exit_code=0):
    def run(criterion, root):  # noqa: ARG001 - firma fijada por el contrato
        return criteria_check.RunOutcome(
            ok=ok, detail=f"exit {exit_code}", exit_code=exit_code, output=salida
        )

    return run


def test_criterio_tests_con_cero_ejecutadas_falla_aunque_el_corredor_salga_con_cero(tmp_path):
    # El caso de Katun: `vitest run -t <filtro>` sin coincidencias sale con 0.
    write_bundle(tmp_path, [_historia({"type": "tests", "payload": "apps/panel/panel.test.ts"})])
    result = criteria_check.evaluate_bundle(
        tmp_path, run=_corredor(VITEST_FILTRO_SIN_COINCIDENCIAS)
    )
    entry = result["criteria"][0]
    assert entry["result"] == "fail"
    assert entry["tests_run"] == 0
    assert entry["detail"].startswith("0 tests ran")
    assert result["passes"] is False
    assert result["block_reasons"] == ["tests_failed"]


def test_criterio_tests_con_pruebas_ejecutadas_pasa_y_lleva_el_numero(tmp_path):
    write_bundle(tmp_path, [_historia({"type": "tests", "payload": "apps/panel/panel.test.ts"})])
    result = criteria_check.evaluate_bundle(tmp_path, run=_corredor(VITEST_PASA))
    entry = result["criteria"][0]
    assert entry["result"] == "pass"
    assert entry["tests_run"] == 2


def test_criterio_tests_sin_resumen_reconocible_pasa_con_numero_desconocido(tmp_path):
    # Nunca se inventa un cero: sin resumen, el número es desconocido y el
    # criterio se juzga por su código de salida, como antes.
    write_bundle(tmp_path, [_historia({"type": "tests", "payload": "x"})])
    result = criteria_check.evaluate_bundle(tmp_path, run=_corredor("ok\n"))
    entry = result["criteria"][0]
    assert entry["result"] == "pass"
    assert entry["tests_run"] is None


def test_pytest_real_sin_pruebas_falla_y_dice_por_que(tmp_path):
    # De punta a punta con el corredor real: pytest sin pruebas sale con 5 y
    # el detalle dice por qué (cero ejecutadas), no solo "exit 5".
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (tmp_path / "test_vacio.py").write_text("X = 1\n", encoding="utf-8")
    write_bundle(tmp_path, [_historia({"type": "tests", "payload": "test_vacio.py"})])
    result = criteria_check.evaluate_bundle(tmp_path)
    entry = result["criteria"][0]
    assert entry["result"] == "fail"
    assert entry["tests_run"] == 0
    assert "0 tests ran" in entry["detail"]


# ---------------------------------------------------------------- criterio `command`


def _comando_sin_pruebas(tmp_path):
    (tmp_path / "test_x.py").write_text("def test_a():\n    pass\n", encoding="utf-8")
    # pytest de verdad con un filtro que no coincide, envuelto para salir con
    # cero como sale `vitest -t` (y como sale cualquier `... || true`).
    payload = (
        "python -c \"import subprocess, sys; subprocess.run([sys.executable, '-m', "
        "'pytest', 'test_x.py', '-k', 'zzz', '-p', 'no:cacheprovider'])\""
    )
    write_bundle(tmp_path, [_historia({"type": "command", "payload": payload})])


def test_comando_que_corre_cero_pruebas_advierte_por_defecto(tmp_path):
    _comando_sin_pruebas(tmp_path)
    result = criteria_check.evaluate_bundle(tmp_path)
    entry = result["criteria"][0]
    assert entry["result"] == "pass"
    assert entry["tests_run"] == 0
    assert entry["integrity"] == [
        {"kind": "zero_tests", "policy": "warn", "detail": criteria_check.ZERO_TESTS_DETAIL}
    ]
    assert result["passes"] is True
    assert [f["kind"] for f in result["integrity"]["findings"]] == ["zero_tests"]


def test_comando_que_corre_cero_pruebas_bloquea_con_la_politica(tmp_path):
    _comando_sin_pruebas(tmp_path)
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "criteria:\n  integrity:\n    zero_tests: block\n", encoding="utf-8"
    )
    result = criteria_check.evaluate_bundle(tmp_path)
    entry = result["criteria"][0]
    assert entry["result"] == "fail"
    assert entry["detail"].startswith("integrity (zero_tests: block")
    assert result["passes"] is False


def test_comando_sin_corredor_reconocible_no_lleva_numero(tmp_path):
    write_bundle(tmp_path, [_historia({"type": "command", "payload": "python -c pass"})])
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert entry["result"] == "pass"
    assert "tests_run" not in entry
    assert "integrity" not in entry


# ---------------------------------------------------------------- reporte


def test_el_reporte_muestra_el_numero_junto_a_cada_criterio(tmp_path, capsys, monkeypatch):
    # Con el corredor real: un archivo sin pruebas y uno con dos.
    monkeypatch.setattr(cli, "_result_icons", lambda: cli._RESULT_ICONS_ASCII)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    (tmp_path / "test_vacio.py").write_text("X = 1\n", encoding="utf-8")
    (tmp_path / "test_dos.py").write_text(
        "def test_a():\n    pass\n\ndef test_b():\n    pass\n", encoding="utf-8"
    )
    write_bundle(
        tmp_path,
        [
            _historia({"type": "tests", "payload": "test_vacio.py"}),
            {
                "id": "E6-S3",
                "title": "Otra",
                "criteria": [
                    {
                        "id": "E6-S3-AC1",
                        "statement": "Corre",
                        "check": {"type": "tests", "payload": "test_dos.py"},
                    }
                ],
            },
        ],
    )
    code = main(["check", "--path", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 1
    assert "(tests: test_vacio.py, 0 tests)" in out
    assert "(tests: test_dos.py, 2 tests)" in out
    assert "      0 tests ran: the runner finished without executing a single test" in out
