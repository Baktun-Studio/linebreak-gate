"""Issue #258: ``spec approve`` no firma un borrador atrasado sin avisar.

El caso de Katun (11 sep 2026): el borrador con dos historias nuevas se
fusionó a main; el checkout local del aprobador iba un commit atrás; se firmó
un paquete de 28 historias en vez de 30, con fecha y aprobador correctos. Se
detectó porque alguien contó las historias después.

Ahora ``spec approve``:

* imprime antes de firmar cuántas historias y criterios va a aprobar, y qué
  historias y criterios se agregan, se quitan o cambian respecto de la
  aprobación vigente;
* trae el borrador del remoto (``git fetch``) y se NIEGA a firmar si la copia
  en disco difiere, si el borrador no está en el remoto o si no se pudo
  consultar, diciendo qué hacer; ``--local`` firma la copia en disco a
  sabiendas;
* en un repositorio sin remoto sigue, con un aviso: no hay copia que pueda ir
  adelante.
"""

from __future__ import annotations

import subprocess

import yaml

from linebreak_gate.cli import main
from linebreak_gate.spec_bundle import load_bundle

DRAFT_REL = ".linebreak/spec-draft.yml"


def _git(root, *args):
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    return proc


def _historias(n):
    return {
        "stories": [
            {
                "id": f"e{i}-s1",
                "title": f"Historia {i}",
                "criteria": [
                    {
                        "id": f"e{i}-s1-ac",
                        "statement": f"Se cumple {i}",
                        "check": {"type": "manual"},
                    }
                ],
            }
            for i in range(1, n + 1)
        ]
    }


def _clon(remote, dest):
    _git(dest.parent, "clone", "-q", str(remote), dest.name)
    _git(dest, "config", "user.email", "t@example.com")
    _git(dest, "config", "user.name", "T")
    return dest


def _publicar(repo, data, mensaje):
    draft = repo / DRAFT_REL
    draft.parent.mkdir(parents=True, exist_ok=True)
    draft.write_text(yaml.safe_dump(data), encoding="utf-8")
    _git(repo, "add", DRAFT_REL)
    _git(repo, "commit", "-q", "-m", mensaje)
    _git(repo, "push", "-q", "origin", "HEAD:main")


def _escenario(tmp_path):
    """Un remoto con el borrador de 28 historias; el aprobador lo clona; otra
    persona fusiona después el borrador de 30. El aprobador queda atrás."""
    remote = tmp_path / "remoto.git"
    _git(tmp_path, "init", "-q", "--bare", str(remote))
    # Sin `init -b` (git anteriores a 2.28): la rama por defecto del remoto es main.
    _git(remote, "symbolic-ref", "HEAD", "refs/heads/main")
    autor = _clon(remote, tmp_path / "autor")
    _git(autor, "symbolic-ref", "HEAD", "refs/heads/main")
    _publicar(autor, _historias(28), "borrador")
    aprobador = _clon(remote, tmp_path / "aprobador")
    _publicar(autor, _historias(30), "dos historias nuevas (PR 140)")
    return autor, aprobador


def _aprobar(repo, *extra):
    return main(
        ["spec", "approve", DRAFT_REL, "--path", str(repo), "--approver", "v@example.com", *extra]
    )


def test_una_copia_atrasada_no_se_firma(tmp_path, capsys):
    _, aprobador = _escenario(tmp_path)
    assert _aprobar(aprobador) == 1
    out, err = capsys.readouterr()
    # Antes de nada, lo que se iba a aprobar: el número que habría bastado.
    assert f"About to approve {DRAFT_REL}: 28 story(ies), 28 criterion(s)." in out
    assert "the draft on disk is NOT the one on origin/main; nothing approved" in err
    assert (
        "origin/main has 30 story(ies), 30 criterion(s); the copy on disk has 28 story(ies), "
        "28 criterion(s)."
    ) in err
    assert "  + story e29-s1" in err
    assert "  + story e30-s1" in err
    assert "Update the checkout (git pull) and approve again, or pass --local" in err
    assert load_bundle(aprobador) is None  # nada escrito


def test_al_dia_con_el_remoto_se_firma(tmp_path, capsys):
    _, aprobador = _escenario(tmp_path)
    _git(aprobador, "pull", "-q", "origin", "main")
    assert _aprobar(aprobador) == 0
    out = capsys.readouterr().out
    assert f"About to approve {DRAFT_REL}: 30 story(ies), 30 criterion(s)." in out
    assert "The draft matches origin/main (fetched just now)." in out
    assert len(load_bundle(aprobador)["stories"]) == 30


def test_local_firma_la_copia_en_disco_a_sabiendas(tmp_path, capsys):
    _, aprobador = _escenario(tmp_path)
    assert _aprobar(aprobador, "--local") == 0
    out = capsys.readouterr().out
    assert (
        "WARNING: --local: approving the copy on disk without confirming it against origin/main"
        in out
    )
    assert len(load_bundle(aprobador)["stories"]) == 28


def test_un_borrador_que_no_esta_en_el_remoto_no_se_firma(tmp_path, capsys):
    autor, _ = _escenario(tmp_path)
    (autor / DRAFT_REL).unlink()
    otro = autor / ".linebreak" / "otro-borrador.yml"
    otro.write_text(yaml.safe_dump(_historias(2)), encoding="utf-8")
    code = main(
        [
            "spec",
            "approve",
            ".linebreak/otro-borrador.yml",
            "--path",
            str(autor),
            "--approver",
            "v@example.com",
        ]
    )
    assert code == 1
    err = capsys.readouterr().err
    assert "the draft is not on origin/main" in err
    assert "Push the draft so the approval covers what was reviewed" in err


def test_un_remoto_inalcanzable_no_se_toma_por_al_dia(tmp_path, capsys):
    _, aprobador = _escenario(tmp_path)
    _git(aprobador, "remote", "set-url", "origin", str(tmp_path / "no-existe.git"))
    assert _aprobar(aprobador) == 1
    err = capsys.readouterr().err
    assert "could not confirm the draft against origin/main" in err
    assert "git fetch origin main failed" in err
    assert _aprobar(aprobador, "--local") == 0


def test_against_elige_la_rama_del_remoto(tmp_path, capsys):
    autor, aprobador = _escenario(tmp_path)
    # Una rama de revisión con el mismo borrador de 28 que tiene el aprobador.
    _git(autor, "push", "-q", "origin", "HEAD~1:refs/heads/revision")
    assert _aprobar(aprobador, "--against", "origin/revision") == 0
    assert "The draft matches origin/revision (fetched just now)." in capsys.readouterr().out


def test_sin_remoto_sigue_con_aviso(tmp_path, capsys):
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    draft = tmp_path / "draft.yml"
    draft.write_text(yaml.safe_dump(_historias(1)), encoding="utf-8")
    assert (
        main(["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "v@x.com"]) == 0
    )
    out = capsys.readouterr().out
    assert "No remote to compare the draft against (the repository has no remote)" in out
    assert "No approved bundle yet in .linebreak/spec/: every story is new." in out


def test_el_resumen_contra_la_aprobacion_vigente(tmp_path, capsys):
    _, aprobador = _escenario(tmp_path)
    assert _aprobar(aprobador, "--local") == 0  # la aprobación vigente: 28
    capsys.readouterr()
    _git(aprobador, "stash", "-q")
    _git(aprobador, "pull", "-q", "--rebase", "origin", "main")
    assert _aprobar(aprobador) == 0
    out = capsys.readouterr().out
    assert "Compared with the approval in force (28 story(ies), 28 criterion(s)):" in out
    assert "  + story e29-s1" in out
    assert "  + criterion e30-s1-ac (e30-s1)" in out
