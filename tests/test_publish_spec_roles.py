"""``linebreak-gate publish`` (panel de gobierno, sep 2026): cada corrida lleva
la especificación firmada (``spec``), el roster de roles (``roles``) y, por
criterio, el enunciado y el hash de contenido que una firma hecha desde el
panel debe igualar. Sin bundle ni roles.yml el cuerpo sigue siendo válido."""

from __future__ import annotations

from test_cli_publish import ENV, _criteria_doc
from test_criteria_check import STORY, write_bundle

from linebreak_gate import publish
from linebreak_gate.spec_bundle import (
    bundle_hash,
    criterion_hash,
    dump_manifest_yaml,
    dump_story_yaml,
    load_bundle,
)

ROSTER = """
roles:
  ciso:
    members: [ana@x.test]
    can:
      sign_criteria: ["*"]
      approve_overrides: ["*"]
      accept_security_risk: [critical, high]
policy:
  require_roles: true
  require_verified_identity: false
"""


def _signed_bundle(root) -> None:
    spec = root / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    manifest = dump_manifest_yaml(
        generated_at="2026-07-13T00:00:00Z",
        source_phase="epics_and_stories",
        approval={
            "role": "architect",
            "user_email": "v@x.test",
            "approved_by": "v@x.test",
            "approved_at": "2026-07-13T00:00:01Z",
        },
        signed_approval={
            "project_id": "p",
            "phase": "epics_and_stories",
            "artifact_hash": "h",
            "approver_email": "arch@x.test",
            "approver_role": "admin",
            "self_approved": True,
            "approved_at": "2026-07-13T00:00:02Z",
            "bundle_version": 1,
            "instance_id": "inst",
            "kid": "kid-1",
            "signature": "s",
        },
    )
    (spec / "manifest.yml").write_text(manifest, encoding="utf-8")
    (spec / "stories" / "S1.yml").write_text(dump_story_yaml(STORY), encoding="utf-8")


def test_spec_carries_hash_signer_kid_and_self_approval(tmp_path):
    _signed_bundle(tmp_path)
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["spec"] == {
        "hash": bundle_hash(load_bundle(tmp_path)),
        "signed": True,
        "signed_by": "arch@x.test",
        "at": "2026-07-13T00:00:02Z",
        "kid": "kid-1",
        "self_approved": True,
        "stories": 1,
    }


def test_unsigned_bundle_reports_hash_without_signature(tmp_path):
    write_bundle(tmp_path)
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["spec"]["signed"] is False
    assert body["spec"]["signed_by"] is None and body["spec"]["kid"] is None
    assert body["spec"]["hash"] == bundle_hash(load_bundle(tmp_path))


def test_criteria_carry_statement_and_content_hash(tmp_path):
    write_bundle(tmp_path)
    _criteria_doc(tmp_path, [("S1-AC4", "manual", "needs-signoff"), ("ZZ-9", "manual", "pass")])
    body = publish.build_payload(tmp_path, env=ENV)
    by_id = {c["id"]: c for c in body["criteria"]}
    assert by_id["S1-AC4"]["hash"] == criterion_hash(STORY["criteria"][3])
    assert by_id["S1-AC4"]["statement"] == "x"
    # A criterion the bundle no longer has cannot be bound: hash is None.
    assert by_id["ZZ-9"]["hash"] is None


def test_roles_summary_from_roles_yml(tmp_path):
    write_bundle(tmp_path)
    (tmp_path / ".linebreak" / "roles.yml").write_text(ROSTER, encoding="utf-8")
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["roles"] == {
        "source": "file",
        "require_roles": True,
        "require_verified_identity": False,
        "roles": [
            {
                "name": "ciso",
                "members": ["ana@x.test"],
                "sign_criteria": ["*"],
                "approve_overrides": ["*"],
                "accept_security_risk": ["critical", "high"],
            }
        ],
    }


def test_without_bundle_or_roster_the_body_is_still_valid(tmp_path):
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["spec"] is None
    assert body["roles"] == {
        "source": "absent",
        "require_roles": False,
        "require_verified_identity": False,
        "roles": [],
    }
    assert body["criteria"][0]["hash"] is None
