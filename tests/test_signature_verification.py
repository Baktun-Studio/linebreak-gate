"""Offline signed-approval verification at the gate (LIN-51, Deliverable 2).

The gate verifies an Ed25519 signature over the spec bundle BEFORE enforcing
criteria, entirely OFFLINE (no call to the governance service). These tests pin:

* valid signature + configured key -> proceed (exit 0), and it works with the
  network disabled;
* a bundle edited after signing (hash mismatch) -> fail closed (exit 1);
* a signature stripped while a key is configured -> fail closed (exit 1) — the
  downgrade-to-unsigned attack is foreclosed;
* no key configured -> today's unsigned behavior, honest output;
* an untrusted signing key -> fail closed;
* a malformed public key in gate.yml -> config error (exit 2);
* an expired license does NOT block verification (the gate never phones home).
"""

from __future__ import annotations

import socket

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from linebreak_gate import approval_sig, cli, criteria_check, signoffs
from linebreak_gate.gate_config import GateConfigError, resolve_config
from linebreak_gate.spec_bundle import bundle_hash, dump_manifest_yaml, dump_story_yaml, load_bundle

GEN_AT = "2026-07-15T00:00:00Z"
SOURCE_PHASE = "epics_and_stories"

# A single `manual` criterion so a recorded sign-off makes criteria PASS with no
# subprocess/toolchain — exit codes then reflect SIGNATURE status, not criteria.
STORY = {
    "id": "S1",
    "title": "Sign in",
    "epic": "Auth",
    "criteria": [{"id": "S1-AC1", "statement": "Design approved", "check": {"type": "manual"}}],
}


def _keypair() -> tuple[Ed25519PrivateKey, str, str]:
    priv = Ed25519PrivateKey.generate()
    pub_b64 = approval_sig.public_key_to_b64(priv.public_key())
    kid = approval_sig.kid_for_public_key(priv.public_key())
    return priv, kid, pub_b64


def _write_signed_bundle(root, *, priv, kid, stories=None, phase=SOURCE_PHASE, self_approved=False):
    """Write a real signed bundle: stories + manifest, then sign the loaded
    bundle's hash and rewrite the manifest with the signed_approval envelope —
    exactly the governance service's sign-after-write flow."""
    stories = stories or [STORY]
    spec = root / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    for s in stories:
        (spec / "stories" / f"{s['id']}.yml").write_text(dump_story_yaml(s), encoding="utf-8")
    approval = {
        "role": "architect",
        "user_email": "arch@example.com",
        "approved_by": "arch@example.com",
    }
    (spec / "manifest.yml").write_text(
        dump_manifest_yaml(generated_at=GEN_AT, source_phase=phase, approval=approval),
        encoding="utf-8",
    )
    art_hash = bundle_hash(load_bundle(root))
    fields = {
        "project_id": "proj_1",
        "phase": phase,
        "artifact_hash": art_hash,
        "approver_email": "arch@example.com",
        "approver_role": "architect",
        "self_approved": self_approved,
        "approved_at": "2026-07-15T00:00:01Z",
        "bundle_version": 1,
        "instance_id": "inst_1",
    }
    envelope = approval_sig.sign(fields, priv, kid=kid)
    (spec / "manifest.yml").write_text(
        dump_manifest_yaml(
            generated_at=GEN_AT, source_phase=phase, approval=approval, signed_approval=envelope
        ),
        encoding="utf-8",
    )
    return art_hash, envelope


def _write_gate_yml(root, entries):
    (root / ".linebreak" / "gate.yml").write_text(
        yaml.safe_dump({"approvals": {"public_keys": entries}}), encoding="utf-8"
    )


def _signoff_manual(root):
    signoffs.record_signoff(
        root, criterion_id="S1-AC1", approver="arch@example.com", note="design approved"
    )


def _run_check(root):
    return cli.main(["check", "--path", str(root), "--format", "json"])


# --------------------------------------------------------------------------
# Happy path + offline guarantee
# --------------------------------------------------------------------------


def test_valid_signature_passes(tmp_path, capsys):
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    _write_gate_yml(tmp_path, [{"kid": kid, "public_key": pub}])
    _signoff_manual(tmp_path)
    assert _run_check(tmp_path) == 0
    assert '"signature": "verified"' in capsys.readouterr().out


def test_self_approved_is_surfaced_in_gate_output(tmp_path, capsys):
    """A solo self-approval is signed AND visibly flagged to the CI auditor."""
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid, self_approved=True)
    _write_gate_yml(tmp_path, [{"kid": kid, "public_key": pub}])
    _signoff_manual(tmp_path)
    assert cli.main(["check", "--path", str(tmp_path), "--format", "summary"]) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "SELF-APPROVED" in out


def test_verification_is_offline(tmp_path, monkeypatch):
    """The entire check runs to a verdict with all sockets disabled — the gate
    never contacts the governance service."""
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    _write_gate_yml(tmp_path, [{"kid": kid, "public_key": pub}])
    _signoff_manual(tmp_path)

    def _no_sockets(*a, **k):
        raise AssertionError("the gate must not open a socket during `check`")

    monkeypatch.setattr(socket, "socket", _no_sockets)
    monkeypatch.setattr(socket, "create_connection", _no_sockets)
    assert _run_check(tmp_path) == 0


# --------------------------------------------------------------------------
# Fail-closed paths
# --------------------------------------------------------------------------


def test_tampered_bundle_fails_closed(tmp_path, capsys):
    """Editing the bundle after signing (here: a story title, which changes the
    bundle hash) makes the signed artifact_hash no longer match -> BLOCKED."""
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    _write_gate_yml(tmp_path, [{"kid": kid, "public_key": pub}])
    _signoff_manual(tmp_path)
    story_path = tmp_path / ".linebreak" / "spec" / "stories" / "S1.yml"
    edited = story_path.read_text().replace("Sign in", "Sign in (edited)")
    story_path.write_text(edited, encoding="utf-8")
    assert _run_check(tmp_path) == 1
    assert "edited after it was approved" in capsys.readouterr().out


def test_signature_stripped_while_key_configured_fails_closed(tmp_path, capsys):
    """Downgrade foreclosure: removing the signed_approval block while a key is
    configured does NOT fall back to unsigned — it BLOCKS."""
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    _write_gate_yml(tmp_path, [{"kid": kid, "public_key": pub}])
    _signoff_manual(tmp_path)
    # Rewrite the manifest WITHOUT the signed_approval envelope.
    spec = tmp_path / ".linebreak" / "spec"
    (spec / "manifest.yml").write_text(
        dump_manifest_yaml(
            generated_at=GEN_AT,
            source_phase=SOURCE_PHASE,
            approval={"role": "architect", "approved_by": "arch@example.com"},
        ),
        encoding="utf-8",
    )
    assert _run_check(tmp_path) == 1
    assert "no signed_approval block" in capsys.readouterr().out


def test_untrusted_key_fails_closed(tmp_path):
    """A bundle signed by a key that is NOT the configured one -> BLOCKED."""
    signer, signer_kid, _ = _keypair()
    _, trusted_kid, trusted_pub = _keypair()  # a different key is the trusted one
    _write_signed_bundle(tmp_path, priv=signer, kid=signer_kid)
    _write_gate_yml(tmp_path, [{"kid": trusted_kid, "public_key": trusted_pub}])
    _signoff_manual(tmp_path)
    assert _run_check(tmp_path) == 1


def test_malformed_public_key_is_config_error(tmp_path):
    """A broken public key in gate.yml is exit 2 (config), not a silent skip."""
    priv, kid, _ = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    _write_gate_yml(tmp_path, [{"kid": kid, "public_key": "not-a-real-key"}])
    assert _run_check(tmp_path) == 2


def test_mislabeled_kid_is_config_error(tmp_path):
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    _write_gate_yml(tmp_path, [{"kid": "wrong-kid-label", "public_key": pub}])
    with pytest.raises(GateConfigError, match="does not match its public key"):
        resolve_config(tmp_path)


# --------------------------------------------------------------------------
# Unsigned mode (no key configured) stays honest and unchanged
# --------------------------------------------------------------------------


def test_no_key_configured_is_unsigned_and_passes(tmp_path, capsys):
    priv, kid, _ = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)  # a signature is present...
    _signoff_manual(tmp_path)
    # ...but NO approvals.public_keys in gate.yml -> unsigned mode, honest output.
    assert _run_check(tmp_path) == 0
    assert '"signature": "unsigned"' in capsys.readouterr().out


def test_unsigned_bundle_with_no_key_configured_passes(tmp_path):
    """A bundle with no signature at all + no configured key = today's behavior."""
    spec = tmp_path / ".linebreak" / "spec"
    (spec / "stories").mkdir(parents=True)
    (spec / "stories" / "S1.yml").write_text(dump_story_yaml(STORY), encoding="utf-8")
    (spec / "manifest.yml").write_text(
        dump_manifest_yaml(
            generated_at=GEN_AT,
            source_phase=SOURCE_PHASE,
            approval={"role": "architect", "approved_by": "arch@example.com"},
        ),
        encoding="utf-8",
    )
    _signoff_manual(tmp_path)
    assert _run_check(tmp_path) == 0


# --------------------------------------------------------------------------
# License independence (the gate never phones home)
# --------------------------------------------------------------------------


def test_expired_license_does_not_block_verification(tmp_path, monkeypatch):
    """An expired/opaque license key present in the environment must NOT block a
    validly signed bundle — verification is offline and license-independent."""
    monkeypatch.setenv("LINEBREAK_LICENSE_KEY", "lb_live_expired_deadbeef")
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    _write_gate_yml(tmp_path, [{"kid": kid, "public_key": pub}])
    _signoff_manual(tmp_path)
    assert _run_check(tmp_path) == 0


# --------------------------------------------------------------------------
# Unit-level verify_bundle_signature
# --------------------------------------------------------------------------


def test_verify_bundle_signature_unsigned_mode_returns_none(tmp_path):
    priv, kid, _ = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    bundle = load_bundle(tmp_path)
    assert criteria_check.verify_bundle_signature(bundle, ()) is None


def test_verify_bundle_signature_returns_payload(tmp_path):
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    bundle = load_bundle(tmp_path)
    payload = criteria_check.verify_bundle_signature(bundle, ((kid, pub),))
    assert payload["approver_role"] == "architect"
    assert payload["kid"] == kid


def test_verify_bundle_signature_phase_mismatch_blocks(tmp_path):
    """Defense-in-depth behind the hash: an envelope whose phase disagrees with
    the manifest source_phase (while the artifact_hash still matches) blocks."""
    priv, kid, pub = _keypair()
    _write_signed_bundle(tmp_path, priv=priv, kid=kid)
    bundle = load_bundle(tmp_path)
    art_hash = bundle_hash(bundle)
    fields = {
        "project_id": "proj_1",
        "phase": "prd",  # disagrees with source_phase (epics_and_stories)
        "artifact_hash": art_hash,  # but the hash matches
        "approver_email": "arch@example.com",
        "approver_role": "architect",
        "self_approved": False,
        "approved_at": "2026-07-15T00:00:01Z",
        "bundle_version": 1,
        "instance_id": "inst_1",
    }
    bundle["manifest"]["signed_approval"] = approval_sig.sign(fields, priv, kid=kid)
    with pytest.raises(criteria_check.BundleSignatureError, match="phase"):
        criteria_check.verify_bundle_signature(bundle, ((kid, pub),))
