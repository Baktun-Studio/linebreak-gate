"""Issue #261: el texto firmado envejece y la herramienta avisa.

El caso de Katun (11 sep 2026): ``e6-s1-politicas``, firmado el 10, decía que
la política ``rechazar`` responde 401, ``revisar`` crea una excepción y
``aceptar`` deja pasar. Al día siguiente otra historia renombró las tres a
``solo_registro``, ``revisar_desconocidos`` y ``aceptar_desconocidos``; los
nombres firmados dejaron de existir en el código y el criterio siguió verde.

Dos controles:

* ``check`` marca los criterios cuyo enunciado nombra identificadores (entre
  comillas invertidas, con guion bajo, o nombres de archivo) que ya no
  aparecen en el código, fuera de ``.linebreak/`` y de la documentación en
  Markdown. Advertencia por defecto; ``criteria.integrity.stale_statements:
  block`` hace fallar el criterio.
* ``spec approve`` muestra el antes y el después de cada frase que cambia
  respecto de la aprobación vigente.
"""

from __future__ import annotations

import subprocess

import yaml
from test_criteria_check import write_bundle

from linebreak_gate import cli, criteria_check, signoffs, spec_integrity
from linebreak_gate.cli import main

FIRMADO = (
    "Sin firma, la política `rechazar` responde 401; la política `revisar` crea una "
    "excepción en la bandeja y deja el pedido en espera; `aceptar` deja pasar y registra."
)
VIGENTE = (
    "Sin firma, `solo_registro` registra y deja pasar; revisar_desconocidos crea una "
    "excepción en la bandeja; aceptar_desconocidos deja pasar y registra."
)
CODIGO = (
    "POLITICAS = ('solo_registro', 'revisar_desconocidos', 'aceptar_desconocidos')\n"
    "def aplicar(politica):\n    return politica in POLITICAS\n"
)


def _git(root, *args):
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)


def _repo(tmp_path, statement, check=None):
    _git(tmp_path, "init", "-q")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "politicas.py").write_text(CODIGO, encoding="utf-8")
    write_bundle(
        tmp_path,
        [
            {
                "id": "e6-s1",
                "title": "Políticas sin firma",
                "criteria": [
                    {
                        "id": "e6-s1-politicas",
                        "statement": statement,
                        "check": check or {"type": "command", "payload": "python -c pass"},
                    }
                ],
            }
        ],
    )
    return tmp_path


# ---------------------------------------------------------------- identificadores


def test_identificadores_de_un_enunciado():
    ids = spec_integrity.statement_identifiers(
        "Con `require_roles` en .linebreak/roles.yml, identity_source vale vcs; "
        "GET /v1/me responde; ver docs/RUNBOOK.md y gate.yml. LINEBREAK_GOV_PROJECT."
    )
    assert ids["names"] == ["require_roles", "identity_source", "LINEBREAK_GOV_PROJECT"]
    assert ids["files"] == [".linebreak/roles.yml", "docs/RUNBOOK.md", "gate.yml"]


def test_una_palabra_comun_sin_marcas_no_es_un_identificador():
    # Los falsos positivos matan una advertencia: "rechazar" suelto es español.
    ids = spec_integrity.statement_identifiers("La política rechazar responde 401 al instante.")
    assert ids == {"names": [], "files": []}


# ---------------------------------------------------------------- check


def test_el_caso_de_katun_advierte(tmp_path):
    _repo(tmp_path, FIRMADO)
    result = criteria_check.evaluate_bundle(tmp_path)
    entry = result["criteria"][0]
    assert entry["result"] == "pass"  # advertencia, no bloqueo, por defecto
    assert [f["kind"] for f in entry["integrity"]] == ["stale_statements"]
    detail = entry["integrity"][0]["detail"]
    assert "`rechazar`, `revisar`, `aceptar`" in detail
    assert result["passes"] is True
    [finding] = result["integrity"]["findings"]
    assert finding["id"] == "e6-s1-politicas" and finding["policy"] == "warn"


def test_un_enunciado_al_dia_no_advierte(tmp_path):
    _repo(tmp_path, VIGENTE)
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert "integrity" not in entry


def test_un_nombre_que_solo_sobrevive_como_parte_de_otro_sigue_siendo_viejo(tmp_path):
    # `revisar` dentro de `revisar_desconocidos` no cuenta: se busca la palabra.
    _repo(tmp_path, "La política `revisar` crea una excepción.")
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert "`revisar`" in entry["integrity"][0]["detail"]


def test_ni_la_especificacion_ni_el_markdown_cuentan_como_codigo(tmp_path):
    _repo(tmp_path, FIRMADO)
    # El CHANGELOG recuerda los nombres viejos para siempre; el borrador los repite.
    (tmp_path / "CHANGELOG.md").write_text("rechazar revisar aceptar\n", encoding="utf-8")
    (tmp_path / ".linebreak" / "spec-draft.yml").write_text(
        "rechazar revisar aceptar\n", encoding="utf-8"
    )
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert "`rechazar`, `revisar`, `aceptar`" in entry["integrity"][0]["detail"]


def test_un_archivo_nombrado_que_ya_no_existe(tmp_path):
    _repo(tmp_path, "El runbook docs/RUNBOOK_BITBUCKET.md se cumple y src/politicas.py aplica.")
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert entry["integrity"][0]["detail"].startswith(
        "the statement names `docs/RUNBOOK_BITBUCKET.md`,"
    )


def test_con_la_politica_block_el_criterio_falla(tmp_path):
    _repo(tmp_path, FIRMADO)
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "criteria:\n  integrity:\n    stale_statements: block\n", encoding="utf-8"
    )
    result = criteria_check.evaluate_bundle(tmp_path)
    entry = result["criteria"][0]
    assert entry["result"] == "fail"
    assert entry["detail"].startswith("integrity (stale_statements: block")
    assert result["passes"] is False


def test_una_firma_sobre_un_enunciado_viejo_no_basta_con_block(tmp_path):
    _repo(tmp_path, FIRMADO, check={"type": "manual"})
    signoffs.record_signoff(
        tmp_path, criterion_id="e6-s1-politicas", approver="v@example.com", note="visto"
    )
    assert criteria_check.evaluate_bundle(tmp_path)["criteria"][0]["result"] == "pass"
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "criteria:\n  integrity: block\n", encoding="utf-8"
    )
    entry = criteria_check.evaluate_bundle(tmp_path)["criteria"][0]
    assert entry["result"] == "fail"


def test_off_no_mira(tmp_path):
    _repo(tmp_path, FIRMADO)
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        "criteria:\n  integrity:\n    stale_statements: off\n", encoding="utf-8"
    )
    result = criteria_check.evaluate_bundle(tmp_path)
    assert "integrity" not in result["criteria"][0]
    assert result["integrity"]["policy"]["stale_statements"] == "off"


def test_sin_git_no_se_mira_y_se_dice(tmp_path):
    write_bundle(
        tmp_path,
        [
            {
                "id": "s",
                "title": "t",
                "criteria": [
                    {"id": "c", "statement": FIRMADO, "check": {"type": "manual"}},
                ],
            }
        ],
    )
    result = criteria_check.evaluate_bundle(tmp_path)
    assert result["integrity"]["skipped"] == {"stale_statements": "not a git repository"}


def test_el_reporte_lo_muestra(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_result_icons", lambda: cli._RESULT_ICONS_ASCII)
    _repo(tmp_path, FIRMADO)
    assert main(["check", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "      integrity warning (stale_statements): the statement names `rechazar`" in out
    assert "  integrity: 1 warning(s), 0 blocking (criteria.integrity: shared_tests=warn" in out
    assert "1 integrity warning(s) (not blocking; criteria.integrity: block" in out


# ---------------------------------------------------------------- antes y después


def test_el_antes_y_el_despues_de_cada_frase():
    old = [
        {
            "id": "e6-s1",
            "title": "t",
            "criteria": [
                {"id": "e6-s1-politicas", "statement": FIRMADO, "check": {"type": "manual"}},
                {"id": "e6-s1-quitado", "statement": "x", "check": {"type": "manual"}},
            ],
        }
    ]
    new = [
        {
            "id": "e6-s1",
            "title": "t",
            "criteria": [
                {"id": "e6-s1-politicas", "statement": VIGENTE, "check": {"type": "manual"}},
                {
                    "id": "e6-s1-nuevo",
                    "statement": "y",
                    "check": {"type": "command", "payload": "./a.sh"},
                },
            ],
        },
        {"id": "e6-s2", "title": "t", "criteria": []},
    ]
    diff = spec_integrity.diff_stories(old, new)
    assert diff["stories_added"] == ["e6-s2"]
    assert diff["criteria_added"] == [{"id": "e6-s1-nuevo", "story": "e6-s1"}]
    assert diff["criteria_removed"] == [{"id": "e6-s1-quitado", "story": "e6-s1"}]
    [changed] = diff["criteria_changed"]
    assert changed["statement"] == {"before": FIRMADO, "after": VIGENTE}
    lines = spec_integrity.format_diff(diff)
    assert "  ~ criterion e6-s1-politicas (e6-s1): statement changed" in lines
    assert f"      before: {FIRMADO}" in lines
    assert f"      after:  {VIGENTE}" in lines


def test_spec_approve_muestra_el_antes_y_el_despues(tmp_path, capsys):
    _repo(tmp_path, FIRMADO)
    draft = tmp_path / "draft.yml"
    draft.write_text(
        yaml.safe_dump(
            {
                "stories": [
                    {
                        "id": "e6-s1",
                        "title": "Políticas sin firma",
                        "criteria": [
                            {
                                "id": "e6-s1-politicas",
                                "statement": VIGENTE,
                                "check": {"type": "command", "payload": "python -c pass"},
                            }
                        ],
                    }
                ]
            },
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    code = main(["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "v@x.com"])
    out = capsys.readouterr().out
    assert code == 0
    assert "About to approve draft.yml: 1 story(ies), 1 criterion(s)." in out
    assert "Compared with the approval in force (1 story(ies), 1 criterion(s)):" in out
    assert f"      before: {FIRMADO}" in out
    assert f"      after:  {VIGENTE}" in out
