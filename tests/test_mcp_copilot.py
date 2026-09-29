"""e17-s1-copilot: `linebreak-gate mcp install --editor copilot` escribe el
servidor en .vscode/mcp.json con el formato de servidores MCP de VS Code
(raíz ``servers``, cada servidor con ``type: stdio``, ``command`` y ``args``;
https://code.visualstudio.com/docs/copilot/reference/mcp-configuration) sin
pisar otros servidores del archivo."""

from __future__ import annotations

import json

from linebreak_gate import mcp_install
from linebreak_gate.cli import main

ESPERADO = {"type": "stdio", "command": "linebreak-gate", "args": ["mcp"]}


def _leer(root):
    return json.loads((root / ".vscode" / "mcp.json").read_text(encoding="utf-8"))


def test_archivo_nuevo_con_el_formato_de_vs_code(tmp_path, capsys):
    assert mcp_install.run_install(tmp_path, editor="copilot") == 0
    doc = _leer(tmp_path)
    assert doc == {"servers": {"linebreak": ESPERADO}}
    assert "mcpServers" not in doc  # ese es el formato de Claude Code y Cursor
    assert ".vscode" in capsys.readouterr().out


def test_se_fusiona_sin_pisar_otros_servidores_ni_otras_claves(tmp_path, capsys):
    previo = {
        "inputs": [{"type": "promptString", "id": "token", "description": "Token"}],
        "servers": {
            "github": {"type": "http", "url": "https://api.githubcopilot.com/mcp/"},
            "memoria": {"type": "stdio", "command": "npx", "args": ["-y", "memoria"]},
        },
    }
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(json.dumps(previo), encoding="utf-8")
    assert mcp_install.run_install(tmp_path, editor="copilot") == 0
    doc = _leer(tmp_path)
    assert doc["inputs"] == previo["inputs"]
    assert doc["servers"]["github"] == previo["servers"]["github"]
    assert doc["servers"]["memoria"] == previo["servers"]["memoria"]
    assert doc["servers"]["linebreak"] == ESPERADO
    assert "merged" in capsys.readouterr().out.lower()


def test_una_entrada_linebreak_distinta_no_se_toca(tmp_path, capsys):
    propio = {"servers": {"linebreak": {"type": "stdio", "command": "mi-fork", "args": []}}}
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text(json.dumps(propio), encoding="utf-8")
    assert mcp_install.run_install(tmp_path, editor="copilot") == 0
    assert _leer(tmp_path) == propio
    out = capsys.readouterr().out
    assert "left untouched" in out and '"type": "stdio"' in out


def test_archivo_que_no_se_puede_leer_no_se_reescribe(tmp_path, capsys):
    (tmp_path / ".vscode").mkdir()
    (tmp_path / ".vscode" / "mcp.json").write_text("{roto", encoding="utf-8")
    assert mcp_install.run_install(tmp_path, editor="copilot") == 0
    assert (tmp_path / ".vscode" / "mcp.json").read_text(encoding="utf-8") == "{roto"
    assert "could not be parsed" in capsys.readouterr().out


def test_dos_corridas_dejan_el_archivo_identico(tmp_path):
    assert mcp_install.run_install(tmp_path, editor="copilot") == 0
    primera = (tmp_path / ".vscode" / "mcp.json").read_bytes()
    assert mcp_install.run_install(tmp_path, editor="copilot") == 0
    assert (tmp_path / ".vscode" / "mcp.json").read_bytes() == primera


def test_copilot_tambien_deja_sus_instrucciones(tmp_path):
    assert mcp_install.run_install(tmp_path, editor="copilot") == 0
    texto = (tmp_path / ".github" / "copilot-instructions.md").read_text(encoding="utf-8")
    assert "<!-- linebreak:start -->" in texto and "`get_story`" in texto


def test_print_muestra_el_formato_de_vs_code_sin_escribir(tmp_path, capsys):
    assert mcp_install.run_install(tmp_path, editor="copilot", print_only=True) == 0
    assert not (tmp_path / ".vscode").exists()
    out = capsys.readouterr().out
    assert '"servers"' in out and '"type": "stdio"' in out


def test_la_cli_acepta_copilot(tmp_path):
    assert main(["mcp", "install", "--path", str(tmp_path), "--editor", "copilot"]) == 0
    assert _leer(tmp_path)["servers"]["linebreak"] == ESPERADO
