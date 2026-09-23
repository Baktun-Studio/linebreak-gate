"""Cuántas pruebas ejecutó de verdad un corredor (issue #259).

Un criterio de pruebas que sale con cero sin haber ejecutado ninguna prueba no
comprobó nada: ``vitest run -t <filtro>`` que no coincide con ningún nombre
sale con 0 y marca todo como omitido, ``jest --passWithNoTests`` igual,
``cargo test <filtro>`` sale con 0 y "0 passed", ``go test -run`` sin
coincidencias dice ``[no tests to run]``. El código de salida no distingue
"se comprobó y pasó" de "no se comprobó nada"; el resumen del corredor sí.

Este módulo lee ese resumen en la salida capturada y devuelve cuántas pruebas
se EJECUTARON (pasadas + fallidas; las omitidas, deseleccionadas y
pendientes no cuentan). Reconoce pytest, vitest, jest, node --test (reportero
spec y TAP), cargo test y go test. Cuando varias corridas aparecen en la misma
salida (un ``pnpm -r test``, varios binarios de cargo, varios paquetes de go)
suma todas.

Devuelve ``None`` cuando no reconoce ningún resumen o cuando el corredor no
informa el número (``go test`` sin ``-v``): un número desconocido nunca se
presenta como cero, y cero nunca se presenta como éxito.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: Secuencias de color ANSI (FORCE_COLOR en CI las deja en la salida).
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

# pytest: "1 failed, 2 passed, 1 skipped in 0.12s" o "no tests ran in 0.01s",
# con o sin el marco de "=" (sin -q), con o sin la duración entre paréntesis.
_PYTEST_ITEM = r"\d+ (?:passed|failed|errors?|skipped|deselected|xfailed|xpassed|warnings?|reruns?)"
_PYTEST_SUMMARY = re.compile(
    rf"^=*\s*((?:{_PYTEST_ITEM})(?:, {_PYTEST_ITEM})*|no tests ran)"
    r" in [\d.]+s(?: \([\d:.]+\))?\s*=*\s*$",
    re.M,
)
_PYTEST_COUNT = re.compile(r"(\d+) (passed|failed|xfailed|xpassed)\b")

# vitest: "      Tests  1 failed | 2 passed | 1 skipped (4)" y el aviso de
# "No test files found, exiting with code 0|1".
_VITEST_TESTS = re.compile(r"^\s*Tests\s{2,}(.+?)\s*\(\d+\)\s*$", re.M)
_VITEST_NO_FILES = re.compile(r"^No test files found, exiting with code \d+", re.M)

# jest: "Tests:       1 failed, 2 passed, 3 total" y "No tests found, exiting with code 0".
_JEST_TESTS = re.compile(r"^Tests:\s+(.+?\d+ total)\s*$", re.M)
_JEST_NO_TESTS = re.compile(r"^No tests found, exiting with code \d+", re.M)

# node --test: reportero spec ("ℹ tests 3", "ℹ pass 2", "ℹ fail 1") y TAP ("# pass 2").
_NODE_LINE = re.compile(r"^(?:ℹ|#) (tests|pass|fail) (\d+)\s*$", re.M)

# cargo test: "test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 3 filtered out; ..."
_CARGO_RESULT = re.compile(r"^test result: \w+\. (\d+) passed; (\d+) failed;", re.M)

# go test: una línea por paquete separada por tabuladores ("ok  \tpkg\t0.01s",
# "?   \tpkg\t[no test files]"), y con -v una por prueba de primer nivel. Los
# tabuladores la distinguen de las líneas "ok 1 - nombre" de TAP.
_GO_PACKAGE = re.compile(r"^(ok|FAIL|\?)[ ]*\t\S+\t(.*)$", re.M)
_GO_TEST = re.compile(r"^--- (PASS|FAIL): ", re.M)


@dataclass(frozen=True)
class TestCount:
    """El resultado de leer una salida.

    ``executed`` es el número de pruebas ejecutadas (``None`` = desconocido).
    ``runners`` nombra los corredores reconocidos, en orden estable.
    """

    __test__ = False  # no es una clase de pruebas de pytest

    executed: int | None
    runners: tuple[str, ...]


def _pytest(text: str) -> int | None:
    found = None
    for m in _PYTEST_SUMMARY.finditer(text):
        body = m.group(1)
        n = sum(int(k) for k, _ in _PYTEST_COUNT.findall(body))
        found = (found or 0) + n
    return found


def _vitest(text: str) -> int | None:
    found = None
    for m in _VITEST_TESTS.finditer(text):
        counts = dict((w, int(n)) for n, w in re.findall(r"(\d+) (\w+)", m.group(1)))
        found = (found or 0) + counts.get("passed", 0) + counts.get("failed", 0)
    if found is None and _VITEST_NO_FILES.search(text):
        return 0
    return found


def _jest(text: str) -> int | None:
    found = None
    for m in _JEST_TESTS.finditer(text):
        counts = dict((w, int(n)) for n, w in re.findall(r"(\d+) (\w+)", m.group(1)))
        found = (found or 0) + counts.get("passed", 0) + counts.get("failed", 0)
    if found is None and _JEST_NO_TESTS.search(text):
        return 0
    return found


def _node(text: str) -> int | None:
    # Cada corrida de node --test cierra con su bloque de totales; se suman
    # los pares pass/fail que aparezcan.
    lines = _NODE_LINE.findall(text)
    if not any(k == "tests" for k, _ in lines):
        return None
    return sum(int(n) for k, n in lines if k in ("pass", "fail"))


def _cargo(text: str) -> int | None:
    results = _CARGO_RESULT.findall(text)
    if not results:
        return None
    return sum(int(p) + int(f) for p, f in results)


def _go(text: str) -> tuple[bool, int | None]:
    """(reconocido, ejecutadas). Sin ``-v`` un paquete "ok" no dice cuántas
    pruebas corrió: el número es desconocido salvo que TODOS los paquetes
    digan que no tenían pruebas o no corrieron ninguna."""
    packages = _GO_PACKAGE.findall(text)
    tests = _GO_TEST.findall(text)
    if tests:
        return True, len(tests)
    if not packages:
        return False, None
    if all("[no test files]" in rest or "[no tests to run]" in rest for _status, rest in packages):
        return True, 0
    return True, None


def count_tests(output: str) -> TestCount:
    """Pruebas ejecutadas según los resúmenes que aparezcan en ``output``."""
    text = _ANSI.sub("", output or "").replace("\r\n", "\n")
    runners: list[str] = []
    total = 0
    unknown = False
    for name, parse in (
        ("pytest", _pytest),
        ("vitest", _vitest),
        ("jest", _jest),
        ("node", _node),
        ("cargo", _cargo),
    ):
        n = parse(text)
        if n is not None:
            runners.append(name)
            total += n
    recognized, n = _go(text)
    if recognized:
        runners.append("go")
        if n is None:
            unknown = True
        else:
            total += n
    if not runners:
        return TestCount(executed=None, runners=())
    if unknown and total == 0:
        # Un paquete de go dijo "ok" sin decir cuántas: puede haber corrido
        # pruebas. Desconocido, nunca cero.
        return TestCount(executed=None, runners=tuple(runners))
    return TestCount(executed=total, runners=tuple(runners))
