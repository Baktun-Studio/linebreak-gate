"""The shared artifact module parameterized for the CI audit dir
(.linebreak/audit) while keeping the desktop default (_bmad-output/security)
byte-identical."""

import json

from linebreak_gate import security_artifact as sa

AUDIT_DIR = ".linebreak/audit"


def _doc(findings=None):
    return sa.new_artifact(
        "cve_scan",
        id="security",
        findings=findings or [],
        summary="test",
        scanner="osv-scanner",
    )


def test_default_base_dir_unchanged(tmp_path):
    # Desktop path must stay exactly _bmad-output/security/<name>.json.
    sa.write_artifact(tmp_path, "security", _doc())
    assert (tmp_path / "_bmad-output" / "security" / "security.json").exists()


def test_write_and_read_in_audit_dir(tmp_path):
    sa.write_artifact(tmp_path, "security", _doc(), base_dir=AUDIT_DIR)
    file = tmp_path / ".linebreak" / "audit" / "security.json"
    assert file.exists()
    doc = sa.read_artifact(tmp_path, "security", base_dir=AUDIT_DIR)
    assert doc["kind"] == "cve_scan"
    assert doc["generated_at"]
    # The two locations are independent surfaces.
    assert sa.read_artifact(tmp_path, "security")["kind"] is None


def test_append_approval_records_finding_tuple(tmp_path):
    sa.write_artifact(tmp_path, "security", _doc(), base_dir=AUDIT_DIR)
    finding = {
        "id": "dep:lodash@4.17.20:CVE-2024-0001",
        "package": "lodash",
        "installed_version": "4.17.20",
        "cve_id": "CVE-2024-0001",
    }
    doc = sa.append_approval(
        tmp_path,
        "security",
        approval_id="abc123",
        role="approver",
        decision="override",
        user_email="sec-lead@example.com",
        notes="accepted risk; upstream fix pending",
        finding=finding,
        base_dir=AUDIT_DIR,
    )
    entry = doc["approvals"][-1]
    assert entry["decision"] == "override"
    assert entry["user_email"] == "sec-lead@example.com"
    assert entry["notes"] == "accepted risk; upstream fix pending"
    assert entry["finding"] == finding
    assert entry["at"]

    # And it survives on disk in the committed JSON.
    raw = json.loads((tmp_path / ".linebreak" / "audit" / "security.json").read_text())
    assert raw["approvals"][-1]["finding"]["cve_id"] == "CVE-2024-0001"


def test_append_approval_without_finding_is_unchanged_shape(tmp_path):
    # The desktop's existing call sites don't pass `finding`; the entry shape
    # must stay exactly as before (no new key).
    sa.write_artifact(tmp_path, "security", _doc())
    doc = sa.append_approval(
        tmp_path,
        "security",
        approval_id="xyz",
        role="architect",
        decision="override",
        notes="ship it",
    )
    assert "finding" not in doc["approvals"][-1]
