"""Issue #263: un criterio no verifica, sin que se note, las pruebas de otra historia.

El caso de Katun (10 sep 2026): once criterios de la historia E6-S2 tenían
como payload rutas de otras historias, todos en verde. Una historia puede
entregarse entera sin una sola prueba propia.

Análisis estático del paquete, sin ejecutar nada: cuando dos historias corren
el mismo destino de prueba (el payload de un ``tests``, o los argumentos de
un corredor dentro de un ``command``, resueltos contra su ``cd``), cada
criterio involucrado lleva un hallazgo ``shared_tests``. Advertencia por
defecto (hay pruebas legítimamente compartidas); ``criteria.integrity.
shared_tests: block`` hace fallar los criterios. ``spec approve`` lo advierte
antes de firmar.
"""

from __future__ import annotations

import pytest
import yaml
from test_criteria_check import write_bundle

from linebreak_gate import cli, criteria_check, gate_config, spec_integrity
from linebreak_gate.cli import main
from linebreak_gate.spec_integrity import run_targets

# ---------------------------------------------------------------- destinos


@pytest.mark.parametrize(
    ("check", "destinos"),
    [
        ({"type": "tests", "payload": "apps/panel/panel.test.ts"}, ["apps/panel/panel.test.ts"]),
        ({"type": "tests", "payload": "./db/rls/"}, ["db/rls"]),
        (
            {
                "type": "command",
                "payload": "cd packages/gate && uv run --quiet pytest tests/test_roles.py -q",
            },
            ["packages/gate/tests/test_roles.py"],
        ),
        (
            {"type": "command", "payload": "pnpm -C apps/web exec vitest run src/screens/panel"},
            ["apps/web/src/screens/panel"],
        ),
        (
            {"type": "command", "payload": "npx vitest run apps/panel/panel.test.ts -t bandeja"},
            ["apps/panel/panel.test.ts (-t bandeja)"],
        ),
        (
            {"type": "command", "payload": "node --test apps/edge/a.node.test.ts"},
            ["apps/edge/a.node.test.ts"],
        ),
        (
            {"type": "command", "payload": "node scripts/qa/flujos.test.mjs --base $URL"},
            ["scripts/qa/flujos.test.mjs"],
        ),
        (
            {"type": "command", "payload": "go test ./pkg/rail -run TestCobro"},
            ["pkg/rail (-run TestCobro)"],
        ),
        ({"type": "command", "payload": "npm run lint"}, []),
        ({"type": "command", "payload": "pnpm -C apps/web typecheck"}, []),
        ({"type": "build"}, []),
        ({"type": "manual"}, []),
    ],
)
def test_destinos_de_prueba_de_un_check(check, destinos):
    assert run_targets(check) == destinos


# ---------------------------------------------------------------- hallazgos


def _criterio(cid, payload, ctype="tests"):
    return {
        "id": cid,
        "statement": f"{cid} se cumple",
        "check": {"type": ctype, "payload": payload},
    }


KATUN = [
    {
        "id": "E6-S1",
        "title": "Panel",
        "criteria": [_criterio("E6-S1-AC1", "apps/panel/panel.test.ts")],
    },
    {
        "id": "E6-S2",
        "title": "Bandeja",
        "criteria": [
            # Prestado de E6-S1: el caso del ticket.
            _criterio("E6-S2-AC1", "apps/panel/panel.test.ts"),
            # Propio.
            _criterio("E6-S2-AC2", "apps/panel/bandeja.test.ts"),
        ],
    },
]


def test_el_caso_de_katun():
    hallazgos = {(f["story"], f["id"]): f for f in spec_integrity.shared_tests(KATUN)}
    assert set(hallazgos) == {("E6-S1", "E6-S1-AC1"), ("E6-S2", "E6-S2-AC1")}
    assert hallazgos[("E6-S2", "E6-S2-AC1")]["detail"] == (
        "runs the same tests as another story: apps/panel/panel.test.ts "
        "(also run by E6-S1/E6-S1-AC1)"
    )


def test_dentro_de_una_misma_historia_no_es_hallazgo():
    historia = {
        "id": "S1",
        "title": "t",
        "criteria": [_criterio("S1-a", "tests/test_x.py"), _criterio("S1-b", "tests/test_x.py")],
    }
    assert spec_integrity.shared_tests([historia]) == []


def test_partir_un_archivo_con_filtros_distintos_no_es_compartir():
    historias = [
        {
            "id": f"S{i}",
            "title": "t",
            "criteria": [_criterio(f"S{i}-a", f"pytest tests/test_x.py -k {k}", "command")],
        }
        for i, k in ((1, "alta"), (2, "baja"))
    ]
    assert spec_integrity.shared_tests(historias) == []


def test_la_misma_ruta_relativa_en_paquetes_distintos_no_es_compartir():
    historias = [
        {
            "id": "S1",
            "title": "t",
            "criteria": [
                _criterio("S1-a", "cd packages/gate && pytest tests/test_x.py", "command")
            ],
        },
        {
            "id": "S2",
            "title": "t",
            "criteria": [
                _criterio("S2-a", "cd services/governance && pytest tests/test_x.py", "command")
            ],
        },
    ]
    assert spec_integrity.shared_tests(historias) == []


# ---------------------------------------------------------------- check


def _pasa(criterion, root):  # noqa: ARG001
    return criteria_check.RunOutcome(ok=True, detail="exit 0", exit_code=0, output="")


def test_advierte_por_defecto_sin_bloquear(tmp_path):
    write_bundle(tmp_path, KATUN)
    result = criteria_check.evaluate_bundle(tmp_path, run=_pasa)
    by_id = {r["id"]: r for r in result["criteria"]}
    assert result["passes"] is True
    assert by_id["E6-S2-AC1"]["result"] == "pass"
    assert by_id["E6-S2-AC1"]["integrity"][0]["kind"] == "shared_tests"
    assert "integrity" not in by_id["E6-S2-AC2"]
    assert {(f["id"], f["kind"]) for f in result["integrity"]["findings"]} == {
        ("E6-S1-AC1", "shared_tests"),
        ("E6-S2-AC1", "shared_tests"),
    }


def test_con_la_politica_block_fallan_los_criterios_involucrados(tmp_path):
    write_bundle(tmp_path, KATUN)
    policy = gate_config.IntegrityPolicy(shared_tests="block")
    result = criteria_check.evaluate_bundle(tmp_path, run=_pasa, integrity_policy=policy)
    by_id = {r["id"]: r for r in result["criteria"]}
    assert by_id["E6-S2-AC1"]["result"] == "fail"
    assert by_id["E6-S1-AC1"]["result"] == "fail"
    assert by_id["E6-S2-AC2"]["result"] == "pass"
    assert result["passes"] is False


def test_una_historia_en_alcance_que_toma_prestado_de_otra_fuera_de_alcance(tmp_path):
    # --story E6-S2: la historia de la que toma prestado no se evalúa, pero el
    # préstamo se ve igual.
    write_bundle(tmp_path, KATUN)
    result = criteria_check.evaluate_bundle(tmp_path, run=_pasa, story_ids={"E6-S2"})
    assert [f["id"] for f in result["integrity"]["findings"]] == ["E6-S2-AC1"]


def test_el_reporte_y_la_bitacora_lo_registran(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(cli, "_result_icons", lambda: cli._RESULT_ICONS_ASCII)
    historias = [
        {
            "id": s,
            "title": "t",
            "criteria": [_criterio(f"{s}-a", 'python -c "print(1)" test_comun.py', "command")],
        }
        for s in ("S1", "S2")
    ]
    write_bundle(tmp_path, historias)
    assert main(["check", "--path", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert (
        "      integrity warning (shared_tests): runs the same tests as another story: "
        "test_comun.py (also run by S2/S2-a)"
    ) in out
    audit = (tmp_path / ".linebreak" / "audit" / "criteria.json").read_text(encoding="utf-8")
    assert '"shared_tests"' in audit


def test_spec_approve_lo_advierte_antes_de_firmar(tmp_path, capsys):
    draft = tmp_path / "draft.yml"
    draft.write_text(yaml.safe_dump({"stories": KATUN}), encoding="utf-8")
    code = main(["spec", "approve", str(draft), "--path", str(tmp_path), "--approver", "v@x.com"])
    out = capsys.readouterr().out
    assert code == 0
    assert "Integrity warnings on this draft (2; `check` applies criteria.integrity):" in out
    assert "  shared_tests: E6-S2-AC1 (E6-S2): runs the same tests as another story" in out


# ---------------------------------------------------------------- configuración


def test_la_politica_en_gate_yml(tmp_path):
    cfg = tmp_path / ".linebreak" / "gate.yml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text("criteria:\n  integrity: block\n", encoding="utf-8")
    assert gate_config.resolve_config(tmp_path).criteria_integrity == gate_config.IntegrityPolicy(
        "block", "block", "block"
    )
    cfg.write_text("criteria:\n  integrity:\n    shared_tests: off\n", encoding="utf-8")
    policy = gate_config.resolve_config(tmp_path).criteria_integrity
    assert policy.as_dict() == {
        "shared_tests": "off",
        "stale_statements": "warn",
        "zero_tests": "warn",
    }
    assert gate_config.resolve_config(tmp_path / "nada").criteria_integrity.as_dict() == {
        "shared_tests": "warn",
        "stale_statements": "warn",
        "zero_tests": "warn",
    }
    for malo in (
        "criteria:\n  integrity: bloquear\n",
        "criteria:\n  integrity:\n    compartidas: block\n",
        "criteria:\n  integrity:\n    shared_tests: 1\n",
        "criteria:\n  integrity: [block]\n",
        "criteria:\n  integrity: true\n",
    ):
        cfg.write_text(malo, encoding="utf-8")
        with pytest.raises(gate_config.GateConfigError):
            gate_config.resolve_config(tmp_path)
