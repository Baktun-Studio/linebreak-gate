"""``linebreak-gate publish``: builds the panel body from the recorded run and
NEVER blocks (exit 0 on every failure). No network: the transport is faked."""

from __future__ import annotations

import json

import pytest
from test_criteria_check import STORY, write_bundle

from linebreak_gate import publish, signoffs
from linebreak_gate import security_artifact as sa
from linebreak_gate.cli import AUDIT_DIR, main
from linebreak_gate.spec_bundle import criterion_hash, dump_manifest_yaml

ENV = {
    "GITHUB_REPOSITORY": "acme/pagos",
    "GITHUB_REF": "refs/pull/12/head",
    "GITHUB_SHA": "abc123",
    "GITHUB_RUN_ID": "777",
    "GITHUB_RUN_ATTEMPT": "1",
}


def _criteria_doc(root, results, *, stage="release", overrides=()):
    doc = sa.new_artifact(
        "criteria_check",
        id="criteria",
        findings=[
            {
                "id": cid,
                "story": "S1",
                "statement": "x",
                "check": {"type": ctype},
                "result": result,
                "detail": "d",
            }
            for cid, ctype, result in results
        ],
        summary="test",
        scanner="linebreak-gate check",
    )
    doc["scope"] = {"mode": "all", "stage": stage, "manual": "block", "release_only": []}
    doc["bundle"] = {"signature": "unsigned"}
    sa.write_artifact(root, "criteria", doc, base_dir=AUDIT_DIR)
    for cid, reason, approver in overrides:
        sa.append_approval(
            root,
            "criteria",
            approval_id=f"ov-{cid}",
            role="approver",
            decision="override",
            user_email=approver,
            notes=reason,
            finding={"criterion_id": cid, "criterion_hash": "h"},
            identity_source="client",
            base_dir=AUDIT_DIR,
        )


def _security_doc(root, findings, *, accepted=()):
    doc = sa.new_artifact(
        "cve_scan", id="security", findings=findings, summary="t", scanner="osv-scanner"
    )
    sa.write_artifact(root, "security", doc, base_dir=AUDIT_DIR)
    for finding_id, approver in accepted:
        sa.append_approval(
            root,
            "security",
            approval_id=f"acc-{finding_id}",
            role="approver",
            decision="override",
            user_email=approver,
            notes="accepted risk",
            finding={"id": finding_id},
            identity_source="client",
            base_dir=AUDIT_DIR,
        )


def _finding(cve, severity, kev=False, package="lodash", version="4.17.20"):
    return {
        "cve_id": cve,
        "severity": severity,
        "cvss": 9.8 if severity == "critical" else 5.0,
        "kev": kev,
        "package": package,
        "ecosystem": "npm",
        "installed_version": version,
        "fixed_version": "9.9.9",
    }


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in ("LINEBREAK_GOV_TOKEN", "LINEBREAK_GOV_PROJECT", "LINEBREAK_RUN_ID"):
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------- payload


def test_payload_for_a_passing_run(tmp_path):
    write_bundle(tmp_path)
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass"), ("S1-AC4", "manual", "pass")])
    _security_doc(tmp_path, [_finding("CVE-2024-0001", "low")])
    signoffs.record_signoff(tmp_path, criterion_id="S1-AC4", approver="qa@x.test", note="ok")
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["verdict"] == "pass"
    assert body["block_reasons"] == []
    assert body["repo"] == "acme/pagos" and body["commit"] == "abc123"
    assert body["stage"] == "release"
    hashes = {c["id"]: criterion_hash(c) for c in STORY["criteria"]}
    assert body["criteria"] == [
        {
            "id": "S1-AC1",
            "story": "S1",
            "type": "build",
            "result": "pass",
            "detail": "d",
            "statement": "x",
            "hash": hashes["S1-AC1"],
        },
        {
            "id": "S1-AC4",
            "story": "S1",
            "type": "manual",
            "result": "pass",
            "detail": "d",
            "statement": "x",
            "hash": hashes["S1-AC4"],
        },
    ]
    assert body["findings"][0]["id"] == "CVE-2024-0001"
    assert "accepted" not in body["findings"][0]
    assert body["signoffs"][0]["criterion_id"] == "S1-AC4"
    assert body["signoffs"][0]["by"] == "qa@x.test"
    assert body["signoffs"][0]["identity_source"] == "client"
    assert body["attestation"] == {"present": False, "commit": None, "signed_by": None, "at": None}
    # Deterministic id under GitHub Actions: a re-run of the step is idempotent.
    assert body["run_id"] == publish.build_payload(tmp_path, env=ENV)["run_id"]
    assert (
        body["run_id"]
        != publish.build_payload(tmp_path, env={**ENV, "GITHUB_RUN_ATTEMPT": "2"})["run_id"]
    )


def test_payload_for_a_blocked_run_maps_reasons(tmp_path):
    write_bundle(tmp_path)
    _criteria_doc(
        tmp_path,
        [
            ("S1-AC2", "tests", "fail"),
            ("S1-AC3", "command", "error"),
            ("S1-AC4", "manual", "needs-signoff"),
            ("S1-AC1", "build", "overridden"),
        ],
        stage="pr",
        overrides=[("S1-AC1", "known flake", "lead@x.test")],
    )
    _security_doc(
        tmp_path,
        [
            _finding("CVE-2024-0002", "critical", kev=True),
            _finding("CVE-2024-0003", "critical", package="yaml"),
        ],
        accepted=[("dep:yaml@4.17.20:CVE-2024-0003", "ciso@x.test")],
    )
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["verdict"] == "blocked"
    assert body["block_reasons"] == [
        "command_failed",
        "kev",
        "tests_failed",
        "unsigned_manual",
        "vulnerability",
    ]
    assert body["stage"] == "pr"
    by_id = {c["id"]: c["result"] for c in body["criteria"]}
    assert by_id == {"S1-AC2": "fail", "S1-AC3": "fail", "S1-AC4": "pending", "S1-AC1": "pass"}
    findings = {f["id"]: f for f in body["findings"]}
    assert findings["CVE-2024-0002"]["kev"] is True and "accepted" not in findings["CVE-2024-0002"]
    assert findings["CVE-2024-0003"]["accepted"]["by"] == "ciso@x.test"
    assert body["overrides"] == [
        {
            "target": "S1-AC1",
            "by": "lead@x.test",
            "role": "approver",
            "at": body["overrides"][0]["at"],
            "expires": None,
            "reason": "known flake",
            "ticket": None,
        }
    ]


def test_accepted_finding_does_not_block_and_expired_acceptance_is_flagged(tmp_path):
    _security_doc(
        tmp_path,
        [_finding("CVE-2024-0003", "critical", package="yaml")],
        accepted=[("dep:yaml@4.17.20:CVE-2024-0003", "ciso@x.test")],
    )
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["verdict"] == "pass"
    # An acceptance with a past `expires` (recorded by a newer gate) reports expired_risk.
    doc = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)
    doc["approvals"][0]["expires"] = "2020-01-01T00:00:00Z"
    sa.write_artifact(tmp_path, "security", doc, base_dir=AUDIT_DIR)
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["verdict"] == "blocked" and body["block_reasons"] == ["expired_risk"]


def test_signed_bundle_reports_attestation(tmp_path):
    spec = tmp_path / ".linebreak" / "spec"
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
            "approver_role": "architect",
            "self_approved": False,
            "approved_at": "2026-07-13T00:00:02Z",
            "bundle_version": 1,
            "instance_id": "inst",
            "kid": "k",
            "signature": "s",
        },
    )
    (spec / "manifest.yml").write_text(manifest, encoding="utf-8")
    from linebreak_gate.spec_bundle import dump_story_yaml

    (spec / "stories" / "S1.yml").write_text(dump_story_yaml(STORY), encoding="utf-8")
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    body = publish.build_payload(tmp_path, env=ENV)
    assert body["attestation"] == {
        "present": True,
        "commit": "abc123",
        "signed_by": "arch@x.test",
        "at": "2026-07-13T00:00:02Z",
    }


def test_nothing_recorded_is_an_error(tmp_path):
    with pytest.raises(publish.PublishError):
        publish.build_payload(tmp_path, env=ENV)


# ---------------------------------------------------------------- CLI: never blocks


def test_publish_sends_with_bearer_and_exits_zero(tmp_path, monkeypatch, capsys):
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    monkeypatch.setenv("LINEBREAK_GOV_TOKEN", "lbg_secret")
    sent = {}

    def transport(url, body, headers):
        sent.update(url=url, body=body, headers=headers)
        return 201, '{"stored": true}'

    monkeypatch.setattr(publish, "_default_transport", transport)
    rc = main(
        ["publish", "--to", "https://gov.example/", "--project", "prj_1", "--path", str(tmp_path)]
    )
    assert rc == 0
    assert sent["url"] == "https://gov.example/v1/projects/prj_1/gate-runs"
    assert sent["headers"]["Authorization"] == "Bearer lbg_secret"
    assert sent["body"]["verdict"] == "pass"
    assert "published run" in capsys.readouterr().out


def test_publish_project_from_env_and_run_id_override(tmp_path, monkeypatch):
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    monkeypatch.setenv("LINEBREAK_GOV_TOKEN", "t")
    monkeypatch.setenv("LINEBREAK_GOV_PROJECT", "prj_env")
    sent = {}
    monkeypatch.setattr(
        publish, "_default_transport", lambda u, b, h: sent.update(url=u, body=b) or (201, "")
    )
    assert (
        main(
            [
                "publish",
                "--to",
                "https://gov.example",
                "--path",
                str(tmp_path),
                "--run-id",
                "fixed-id",
            ]
        )
        == 0
    )
    assert sent["url"].endswith("/v1/projects/prj_env/gate-runs")
    assert sent["body"]["run_id"] == "fixed-id"


@pytest.mark.parametrize(
    "setup",
    ["no_records", "no_token", "no_project", "server_500", "unreachable", "corrupt_record"],
)
def test_publish_never_blocks(tmp_path, monkeypatch, capsys, setup):
    if setup != "no_records":
        _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])
    if setup != "no_token":
        monkeypatch.setenv("LINEBREAK_GOV_TOKEN", "t")
    argv = ["publish", "--to", "https://gov.example", "--path", str(tmp_path)]
    if setup != "no_project":
        argv += ["--project", "prj_1"]
    if setup == "server_500":
        monkeypatch.setattr(publish, "_default_transport", lambda u, b, h: (500, "boom"))
    elif setup == "unreachable":

        def down(u, b, h):
            raise OSError("connection refused")

        monkeypatch.setattr(publish, "_default_transport", down)
    elif setup == "corrupt_record":
        # A malformed spec bundle would be exit 2 for `check`; for publish it is a warning.
        (tmp_path / ".linebreak" / "spec").mkdir(parents=True)
        monkeypatch.setattr(publish, "_default_transport", lambda u, b, h: (201, ""))
    else:
        monkeypatch.setattr(publish, "_default_transport", lambda u, b, h: (201, ""))
    assert main(argv) == 0
    err = capsys.readouterr().err
    assert "publish skipped" in err and "never blocks" in err


def test_dry_run_prints_body_and_sends_nothing(tmp_path, monkeypatch, capsys):
    _criteria_doc(tmp_path, [("S1-AC1", "build", "pass")])

    def never(u, b, h):
        raise AssertionError("must not send")

    monkeypatch.setattr(publish, "_default_transport", never)
    assert (
        main(["publish", "--to", "https://gov.example", "--path", str(tmp_path), "--dry-run"]) == 0
    )
    body = json.loads(capsys.readouterr().out)
    assert body["verdict"] == "pass" and body["criteria"][0]["id"] == "S1-AC1"
