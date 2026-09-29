"""e7-s2-firmas-del-proyecto-publish: cada firma del repositorio viaja al panel
con el hash del criterio, la historia y la nota de su archivo."""

from __future__ import annotations

from linebreak_gate import publish, signoffs


def _firma(tmp_path, nombre: str, texto: str) -> None:
    d = tmp_path / signoffs.SIGNOFFS_DIR
    d.mkdir(parents=True, exist_ok=True)
    (d / nombre).write_text(texto, encoding="utf-8")


def test_la_firma_del_repositorio_lleva_hash_historia_y_nota(tmp_path):
    _firma(
        tmp_path,
        "e12-s1-e2e-db2052fb.yml",
        "criterion_id: e12-s1-e2e\nstory_id: e12-s1-qa-liberacion\n"
        "criterion_hash: db2052fb00\napprover: Ana <ana@x.test>\n"
        "note: Tres compras de prueba verificadas.\nidentity_source: client\n"
        "signed_at: '2026-09-18T03:28:02Z'\n",
    )
    [firma] = publish._signoffs(tmp_path)
    assert firma["criterion_id"] == "e12-s1-e2e"
    assert firma["criterion_hash"] == "db2052fb00"
    assert firma["story_id"] == "e12-s1-qa-liberacion"
    assert firma["note"] == "Tres compras de prueba verificadas."
    assert firma["by"] == "Ana <ana@x.test>"


def test_una_firma_sin_historia_viaja_igual(tmp_path):
    _firma(
        tmp_path,
        "S1-AC1-x.yml",
        "criterion_id: S1-AC1\ncriterion_hash: abc\napprover: a@x.test\nnote: ok\n"
        "signed_at: '2026-09-10T14:23:11Z'\n",
    )
    [firma] = publish._signoffs(tmp_path)
    assert firma["story_id"] is None and firma["note"] == "ok" and firma["criterion_hash"] == "abc"
