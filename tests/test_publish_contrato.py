"""e16-s2-publish: ``linebreak-gate publish`` manda con la especificación el
rol y el nombre de quien la aprobó y sus historias, cada una con su título y
sus criterios (identificador, tipo y enunciado). El panel muestra con eso el
contrato aprobado junto a la aprobación firmada."""

from __future__ import annotations

from test_cli_publish import ENV, _criteria_doc
from test_criteria_check import STORY, write_bundle

from linebreak_gate import publish
from linebreak_gate.spec_bundle import dump_manifest_yaml, dump_story_yaml

SECOND = {
    "id": "S2",
    "title": "Transferencias con límite diario",
    "criteria": [
        {
            "id": "S2-AC1",
            "statement": "Una transferencia sobre el límite se rechaza",
            "check": {"type": "tests", "payload": "tests/test_limite.py"},
        },
        {
            "id": "S2-AC2",
            "statement": "Operaciones concilió una muestra",
            "check": {"type": "manual"},
        },
    ],
}


def _bundle(root, *, approved_by: str = "Mariana Ríos <mariana@x.test>") -> None:
    spec = root / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    manifest = dump_manifest_yaml(
        generated_at="2026-08-24T00:00:00Z",
        source_phase="epics_and_stories",
        approval={
            "role": "product",
            "user_email": approved_by,
            "approved_by": approved_by,
            "approved_at": "2026-08-24T15:30:00Z",
        },
        signed_approval={
            "project_id": "p",
            "phase": "epics_and_stories",
            "artifact_hash": "h",
            "approver_email": "mariana@x.test",
            "approver_role": "owner",
            "self_approved": False,
            "approved_at": "2026-08-24T15:30:02Z",
            "bundle_version": 1,
            "instance_id": "inst",
            "kid": "kid-1",
            "signature": "s",
        },
    )
    (spec / "manifest.yml").write_text(manifest, encoding="utf-8")
    for story in (STORY, SECOND):
        (spec / "stories" / f"{story['id']}.yml").write_text(
            dump_story_yaml(story), encoding="utf-8"
        )


def _spec(root) -> dict:
    _criteria_doc(root, [("S1-AC1", "build", "pass")])
    return publish.build_payload(root, env=ENV)["spec"]


def test_spec_carries_role_and_name_of_the_approver(tmp_path):
    _bundle(tmp_path)
    spec = _spec(tmp_path)
    assert spec["signed_by"] == "mariana@x.test"
    assert spec["role"] == "owner"
    assert spec["name"] == "Mariana Ríos"
    assert spec["at"] == "2026-08-24T15:30:02Z" and spec["kid"] == "kid-1"


def test_spec_carries_every_story_with_title_and_criteria(tmp_path):
    _bundle(tmp_path)
    spec = _spec(tmp_path)
    assert spec["stories"] == 2
    items = {s["id"]: s for s in spec["items"]}
    assert set(items) == {"S1", "S2"}
    assert items["S1"]["title"] == "User can sign in"
    assert items["S2"]["title"] == "Transferencias con límite diario"
    assert items["S2"]["criteria"] == [
        {
            "id": "S2-AC1",
            "type": "tests",
            "statement": "Una transferencia sobre el límite se rechaza",
        },
        {"id": "S2-AC2", "type": "manual", "statement": "Operaciones concilió una muestra"},
    ]
    assert [c["id"] for c in items["S1"]["criteria"]] == ["S1-AC1", "S1-AC2", "S1-AC3", "S1-AC4"]
    assert {c["type"] for c in items["S1"]["criteria"]} == {"build", "tests", "command", "manual"}
    # Solo identificador, tipo y enunciado: el payload del check no viaja.
    for story in spec["items"]:
        for c in story["criteria"]:
            assert set(c) == {"id", "type", "statement"}


def test_name_is_absent_when_approved_by_is_only_an_email(tmp_path):
    _bundle(tmp_path, approved_by="mariana@x.test")
    spec = _spec(tmp_path)
    assert spec["name"] is None
    assert spec["role"] == "owner"


def test_unsigned_bundle_still_sends_its_stories_without_approver(tmp_path):
    write_bundle(tmp_path)
    spec = _spec(tmp_path)
    assert spec["signed"] is False
    assert spec["role"] is None and spec["name"] is None
    assert [s["id"] for s in spec["items"]] == ["S1"]
    assert len(spec["items"][0]["criteria"]) == 4


def test_no_bundle_sends_no_spec(tmp_path):
    assert _spec(tmp_path) is None
