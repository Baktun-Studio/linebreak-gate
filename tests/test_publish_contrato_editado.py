"""Defecto 25: cuando la compuerta bloquea porque el contrato se editó después
de aprobarse, `publish` manda ese veredicto al panel (motivo spec_edited y el
detalle con los dos hashes), nunca un registro viejo que decía aprobada."""

from __future__ import annotations

import json

from test_bridge import _stories, _write_bundle
from test_cli_publish import ENV, _criteria_doc

from linebreak_gate import publish
from linebreak_gate.cli import main


def _clave(tmp_path) -> None:
    (tmp_path / ".linebreak" / "gate.yml").write_text(
        f"approvals:\n  public_keys:\n    - kid: {_write_bundle.kid}\n"
        f"      public_key: {_write_bundle.public_key}\n",
        encoding="utf-8",
    )


def test_contrato_editado_se_publica_bloqueado_con_el_detalle(tmp_path, capsys):
    _write_bundle(tmp_path, _stories(), signed=True, tamper=True)
    _clave(tmp_path)
    # Un registro viejo de una corrida anterior que decía que todo pasaba.
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")], stage="pr", manual="warn")
    assert main(["check", "--path", str(tmp_path), "--stage", "pr", "--manual", "warn"]) == 1
    assert "edited after it was approved" in capsys.readouterr().out
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["verdict"] == "blocked"
    assert body["block_reasons"] == ["spec_edited"]
    assert body["criteria"] == []
    assert "edited after it was approved" in body["spec"]["verification_error"]
    assert json.dumps(body)  # serializable para el servicio


def test_un_contrato_intacto_no_lleva_error(tmp_path):
    _write_bundle(tmp_path, _stories(), signed=True)
    _clave(tmp_path)
    main(["check", "--path", str(tmp_path), "--stage", "pr", "--manual", "warn"])
    body = publish.build_payload(tmp_path, env=ENV)
    assert "spec_edited" not in body["block_reasons"]
    assert "verification_error" not in (body["spec"] or {})
