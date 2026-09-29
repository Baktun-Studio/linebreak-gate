"""e17-s1-bloque-administrado: `linebreak-gate mcp install` registra el
servidor y deja al agente un bloque administrado, entre marcas de LineBreak,
en el archivo que su editor siempre lee, en el idioma de la especificación.
Volver a correrlo reemplaza solo ese bloque."""

from __future__ import annotations

import json
import re

import pytest
import yaml

from linebreak_gate import mcp_install
from linebreak_gate.cli import main

READ_TOOLS = ("list_stories", "get_story", "next_story", "spec_status", "check_story")
WRITE_COMMANDS = ("spec approve", "signoff", "override", "publish")

#: editor -> (archivo de instrucciones, archivo del servidor relativo al repo o None si es global)
EDITORES = {
    "claude-code": ("CLAUDE.md", ".mcp.json"),
    "codex": ("AGENTS.md", None),
    "cursor": (".cursor/rules/linebreak.mdc", ".cursor/mcp.json"),
    "copilot": (".github/copilot-instructions.md", ".vscode/mcp.json"),
}

HISTORIA_ES = """\
id: e1-s1-pago
title: El cliente paga con tarjeta
epic: e1-pagos
criteria:
- id: e1-s1-cobro
  statement: Cuando el cliente paga con una tarjeta válida, el cobro se registra y la orden
    queda pagada con su recibo.
  check:
    type: command
    payload: pytest tests/test_pago.py -q
"""

HISTORIA_EN = """\
id: e1-s1-pay
title: The customer pays by card
epic: e1-payments
criteria:
- id: e1-s1-charge
  statement: When the customer pays with a valid card, the charge is recorded and the order
    is marked as paid with its receipt.
  check:
    type: command
    payload: pytest tests/test_pay.py -q
"""


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    # Codex escribe su servidor en ~/.codex/config.toml: nunca en el perfil real.
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))
    return home_dir


def _repo(tmp_path, historia: str | None = None, *, borrador: str | None = None):
    root = tmp_path / "repo"
    root.mkdir()
    if historia is not None:
        stories = root / ".linebreak" / "spec" / "stories"
        stories.mkdir(parents=True)
        (stories / "e1-s1.yml").write_text(historia, encoding="utf-8")
    if borrador is not None:
        (root / ".linebreak").mkdir(exist_ok=True)
        draft = {"stories": [yaml.safe_load(borrador)]}
        (root / ".linebreak" / "spec-draft.yml").write_text(
            yaml.safe_dump(draft, allow_unicode=True), encoding="utf-8"
        )
    return root


def _bloque(texto: str) -> str:
    inicio = re.search(r"<!-- linebreak:(inicio|start) -->", texto)
    fin = re.search(r"<!-- linebreak:(fin|end) -->", texto)
    assert inicio and fin and inicio.start() < fin.start(), texto
    return texto[inicio.start() : fin.end()]


# ---------------------------------------------------------------- el bloque por editor


@pytest.mark.parametrize("editor", sorted(EDITORES))
def test_cada_editor_registra_el_servidor_y_escribe_el_bloque(tmp_path, home, editor):
    root = _repo(tmp_path, HISTORIA_ES)
    assert mcp_install.run_install(root, editor=editor) == 0

    instrucciones, servidor = EDITORES[editor]
    if servidor:
        assert "linebreak" in (root / servidor).read_text(encoding="utf-8")
    else:
        assert "[mcp_servers.linebreak]" in (home / ".codex" / "config.toml").read_text(
            encoding="utf-8"
        )

    texto = (root / instrucciones).read_text(encoding="utf-8")
    bloque = _bloque(texto)
    assert bloque.startswith("<!-- linebreak:inicio -->")
    assert bloque.endswith("<!-- linebreak:fin -->")
    assert "contrato firmado" in bloque
    for tool in READ_TOOLS:
        assert f"`{tool}`" in bloque
    assert "`linebreak-gate`" in bloque and "`.linebreak/`" in bloque
    for cmd in WRITE_COMMANDS:
        assert f"`{cmd}`" in bloque
    assert "salvo que una persona lo pida" in bloque
    assert "`.linebreak/spec/`" in bloque and "`.linebreak/spec-draft.yml`" in bloque
    assert "dilo en vez de cambiarlo" in bloque


def test_bloque_en_ingles_cuando_la_especificacion_esta_en_ingles(tmp_path):
    root = _repo(tmp_path, HISTORIA_EN)
    assert mcp_install.run_install(root, editor="claude-code") == 0
    bloque = _bloque((root / "CLAUDE.md").read_text(encoding="utf-8"))
    assert bloque.startswith("<!-- linebreak:start -->")
    assert "signed LineBreak contract" in bloque
    for tool in READ_TOOLS:
        assert f"`{tool}`" in bloque
    for cmd in WRITE_COMMANDS:
        assert f"`{cmd}`" in bloque
    assert "unless a person explicitly asks" in bloque
    assert "say so instead of changing it" in bloque


def test_sin_especificacion_el_bloque_va_en_ingles_y_dice_que_hacer(tmp_path):
    root = _repo(tmp_path)
    assert mcp_install.run_install(root, editor="claude-code") == 0
    bloque = _bloque((root / "CLAUDE.md").read_text(encoding="utf-8"))
    assert bloque.startswith("<!-- linebreak:start -->")
    assert "no approved specification" in bloque


def test_solo_borrador_en_espanol_da_bloque_en_espanol(tmp_path):
    root = _repo(tmp_path, borrador=HISTORIA_ES)
    assert mcp_install.spec_language(root) == "es"


def test_heuristica_de_idioma():
    assert mcp_install.text_language("El cobro se registra y la orden queda pagada.") == "es"
    assert mcp_install.text_language("The charge is recorded and the order is paid.") == "en"
    assert mcp_install.text_language("") == "en"


def test_idioma_sale_de_lo_escrito_no_de_las_claves_yaml(tmp_path):
    # Las claves (id, title, criteria, check, payload...) están en inglés en
    # todo repositorio: solo cuentan los títulos y los enunciados.
    root = _repo(tmp_path, HISTORIA_ES)
    assert mcp_install.spec_language(root) == "es"


@pytest.mark.parametrize("lang", ["es", "en"])
def test_textos_sin_em_dash_ni_emojis_ni_voseo(lang):
    bloque = mcp_install.instructions_block(lang)
    assert "—" not in bloque
    assert not re.search(r"[\U0001F300-\U0001FAFF☀-➿]", bloque)
    for voseo in ("usá", "corré", "editá", "decilo", "podés", "tenés"):
        assert voseo not in bloque


# ---------------------------------------------------------------- solo ese bloque


def test_archivo_existente_sin_bloque_se_conserva_y_el_bloque_va_al_final(tmp_path):
    root = _repo(tmp_path, HISTORIA_ES)
    previo = "# Mi proyecto\n\nReglas de la casa.\n"
    (root / "CLAUDE.md").write_text(previo, encoding="utf-8")
    assert mcp_install.run_install(root, editor="claude-code") == 0
    texto = (root / "CLAUDE.md").read_text(encoding="utf-8")
    assert texto.startswith(previo)
    assert texto.rstrip("\n").endswith("<!-- linebreak:fin -->")


@pytest.mark.parametrize("editor", sorted(EDITORES))
def test_dos_corridas_dejan_el_archivo_identico(tmp_path, editor):
    root = _repo(tmp_path, HISTORIA_ES)
    instrucciones = root / EDITORES[editor][0]
    assert mcp_install.run_install(root, editor=editor) == 0
    primera = instrucciones.read_bytes()
    assert mcp_install.run_install(root, editor=editor) == 0
    assert instrucciones.read_bytes() == primera
    assert primera.count(b"<!-- linebreak:inicio -->") == 1


def test_volver_a_correrlo_reemplaza_solo_el_bloque(tmp_path, capsys):
    root = _repo(tmp_path, HISTORIA_ES)
    antes = "# Proyecto\n\nArriba del bloque.\n\n"
    despues = "\n\n## Otra sección\n\nAbajo del bloque.\n"
    viejo = "<!-- linebreak:inicio -->\ntexto viejo que ya no aplica\n<!-- linebreak:fin -->"
    (root / "CLAUDE.md").write_text(antes + viejo + despues, encoding="utf-8")
    assert mcp_install.run_install(root, editor="claude-code") == 0
    texto = (root / "CLAUDE.md").read_text(encoding="utf-8")
    assert texto.startswith(antes) and texto.endswith(despues)
    assert "texto viejo" not in texto
    assert _bloque(texto) == mcp_install.instructions_block("es")
    assert "Replaced" in capsys.readouterr().out


def test_cambio_de_idioma_reemplaza_el_bloque_sin_duplicarlo(tmp_path):
    root = _repo(tmp_path, HISTORIA_EN)
    en = mcp_install.instructions_block("en")
    (root / "AGENTS.md").write_text("Intro\n\n" + en + "\n", encoding="utf-8")
    (root / ".linebreak" / "spec" / "stories" / "e1-s1.yml").write_text(
        HISTORIA_ES, encoding="utf-8"
    )
    assert mcp_install.run_install(root, editor="codex") == 0
    texto = (root / "AGENTS.md").read_text(encoding="utf-8")
    assert texto == "Intro\n\n" + mcp_install.instructions_block("es") + "\n"


def test_marcas_sin_pareja_no_se_tocan(tmp_path, capsys):
    root = _repo(tmp_path, HISTORIA_ES)
    roto = "Algo\n<!-- linebreak:inicio -->\nsin fin\n"
    (root / "CLAUDE.md").write_text(roto, encoding="utf-8")
    assert mcp_install.run_install(root, editor="claude-code") == 0
    assert (root / "CLAUDE.md").read_text(encoding="utf-8") == roto
    out = capsys.readouterr().out
    assert "left untouched" in out and "<!-- linebreak:inicio -->" in out


def test_fin_de_linea_crlf_se_respeta(tmp_path):
    root = _repo(tmp_path, HISTORIA_ES)
    previo = b"# Windows\r\n\r\nReglas.\r\n"
    (root / "CLAUDE.md").write_bytes(previo)
    assert mcp_install.run_install(root, editor="claude-code") == 0
    datos = (root / "CLAUDE.md").read_bytes()
    assert datos.startswith(previo)
    assert b"\n" not in datos.replace(b"\r\n", b"")  # ningún salto suelto


# ---------------------------------------------------------------- Cursor, --print y la CLI


def test_cursor_regla_mdc_con_frontmatter_que_siempre_aplica(tmp_path):
    root = _repo(tmp_path, HISTORIA_ES)
    assert mcp_install.run_install(root, editor="cursor") == 0
    texto = (root / ".cursor" / "rules" / "linebreak.mdc").read_text(encoding="utf-8")
    frontmatter = texto.split("---\n")[1]
    assert texto.startswith("---\n")
    assert "description:" in frontmatter and "alwaysApply: true" in frontmatter
    assert _bloque(texto) == mcp_install.instructions_block("es")


def test_print_no_escribe_nada_y_muestra_el_bloque(tmp_path, capsys):
    root = _repo(tmp_path, HISTORIA_ES)
    assert mcp_install.run_install(root, editor="claude-code", print_only=True) == 0
    assert not (root / "CLAUDE.md").exists() and not (root / ".mcp.json").exists()
    out = capsys.readouterr().out
    assert "CLAUDE.md" in out and mcp_install.instructions_block("es") in out


def test_la_cli_escribe_servidor_y_bloque(tmp_path):
    root = _repo(tmp_path, HISTORIA_ES)
    assert main(["mcp", "install", "--path", str(root), "--editor", "claude-code"]) == 0
    doc = json.loads((root / ".mcp.json").read_text(encoding="utf-8"))
    assert doc["mcpServers"]["linebreak"] == {"command": "linebreak-gate", "args": ["mcp"]}
    assert "<!-- linebreak:inicio -->" in (root / "CLAUDE.md").read_text(encoding="utf-8")
