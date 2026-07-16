"""Ed25519 signed-approval primitives (LIN-51).

These tests pin the canonical serialization and the sign/verify contract, and
assert the packaged golden conformance vector so the byte form cannot drift on
either side of the package boundary (gate verifier vs governance-service signer).
"""

from __future__ import annotations

import base64
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from linebreak_gate import approval_sig as a

FIELDS = {
    "project_id": "proj_1",
    "phase": "prd",
    "artifact_hash": "deadbeef" * 8,
    "approver_email": "arch@example.com",
    "approver_role": "architect",
    "approved_at": "2026-07-15T00:00:00Z",
    "bundle_version": 1,
    "instance_id": "inst_1",
}


def _keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = a.private_key_from_seed_b64(base64.b64encode(bytes(range(32, 64))).decode())
    kid = a.kid_for_public_key(priv.public_key())
    return priv, kid


# --------------------------------------------------------------------------
# Canonical payload
# --------------------------------------------------------------------------


def test_canonical_payload_is_sorted_compact_json():
    payload = a.canonical_payload(FIELDS)
    # sorted keys, no whitespace — key order in the input can't change the bytes.
    assert payload.startswith(b'{"approved_at":')
    assert b", " not in payload and b": " not in payload


def test_canonical_payload_is_order_independent():
    shuffled = {k: FIELDS[k] for k in reversed(list(FIELDS))}
    assert a.canonical_payload(shuffled) == a.canonical_payload(FIELDS)


def test_canonical_payload_ignores_extra_keys():
    # kid/signature on an envelope must not enter the signed bytes.
    enveloped = {**FIELDS, "kid": "x", "signature": "y"}
    assert a.canonical_payload(enveloped) == a.canonical_payload(FIELDS)


def test_canonical_payload_missing_field_fails_closed():
    incomplete = {k: v for k, v in FIELDS.items() if k != "instance_id"}
    with pytest.raises(a.ApprovalSignatureError, match="missing field"):
        a.canonical_payload(incomplete)


# --------------------------------------------------------------------------
# Sign / verify
# --------------------------------------------------------------------------


def test_sign_then_verify_roundtrips():
    priv, kid = _keypair()
    env = a.sign(FIELDS, priv, kid=kid)
    assert env["kid"] == kid
    assert set(env) == set(a.ENVELOPE_KEYS)
    verified = a.verify_envelope(env, {kid: priv.public_key()})
    assert verified == FIELDS


def test_signature_is_deterministic():
    priv, kid = _keypair()
    assert a.sign(FIELDS, priv, kid=kid) == a.sign(FIELDS, priv, kid=kid)


def test_tampered_field_fails_verification():
    priv, kid = _keypair()
    env = a.sign(FIELDS, priv, kid=kid)
    env = copy.deepcopy(env)
    env["approver_role"] = "developer"  # forge a weaker role
    with pytest.raises(a.ApprovalSignatureError, match="does not verify"):
        a.verify_envelope(env, {kid: priv.public_key()})


def test_unknown_kid_fails_closed():
    priv, kid = _keypair()
    env = a.sign(FIELDS, priv, kid=kid)
    with pytest.raises(a.ApprovalSignatureError, match="no configured public key"):
        a.verify_envelope(env, {"some-other-kid": priv.public_key()})


def test_foreign_key_signature_rejected():
    # An attacker signs with their own key and sets kid to a trusted one.
    priv, kid = _keypair()
    attacker = Ed25519PrivateKey.generate()
    env = a.sign(FIELDS, attacker, kid=kid)
    with pytest.raises(a.ApprovalSignatureError, match="does not verify"):
        a.verify_envelope(env, {kid: priv.public_key()})


@pytest.mark.parametrize("missing", ["kid", "signature"])
def test_missing_envelope_fields_fail_closed(missing):
    priv, kid = _keypair()
    env = a.sign(FIELDS, priv, kid=kid)
    env.pop(missing)
    with pytest.raises(a.ApprovalSignatureError, match=f"missing a '{missing}'"):
        a.verify_envelope(env, {kid: priv.public_key()})


def test_bad_base64_signature_fails_closed():
    priv, kid = _keypair()
    env = a.sign(FIELDS, priv, kid=kid)
    env["signature"] = "not!base64!"
    with pytest.raises(a.ApprovalSignatureError):
        a.verify_envelope(env, {kid: priv.public_key()})


# --------------------------------------------------------------------------
# Key encoding / kid
# --------------------------------------------------------------------------


def test_public_key_b64_roundtrip():
    priv, _ = _keypair()
    b64 = a.public_key_to_b64(priv.public_key())
    restored = a.public_key_from_b64(b64)
    assert a.public_key_to_b64(restored) == b64


def test_kid_is_stable_and_short():
    priv, _ = _keypair()
    kid1 = a.kid_for_public_key(priv.public_key())
    kid2 = a.kid_for_public_key(a.public_key_from_b64(a.public_key_to_b64(priv.public_key())))
    assert kid1 == kid2
    assert len(kid1) == 16


def test_public_key_from_bad_b64_fails_closed():
    with pytest.raises(a.ApprovalSignatureError):
        a.public_key_from_b64("!!!")


# --------------------------------------------------------------------------
# Golden conformance vector (shared across the package boundary)
# --------------------------------------------------------------------------


def test_golden_vector_matches_serialization():
    v = a.golden_vector()
    priv = a.private_key_from_seed_b64(v["seed_b64"])
    # Canonical bytes reproduce exactly.
    payload = a.canonical_payload(v["fields"])
    assert payload.decode("utf-8") == v["canonical_payload_utf8"]
    assert base64.b64encode(payload).decode() == v["canonical_payload_b64"]
    # Signature reproduces exactly (Ed25519 is deterministic).
    env = a.sign(v["fields"], priv, kid=v["kid"])
    assert env["signature"] == v["signature_b64"]
    assert env == v["envelope"]


def test_golden_vector_verifies():
    v = a.golden_vector()
    pub = a.public_key_from_b64(v["public_key_b64"])
    assert a.kid_for_public_key(pub) == v["kid"]
    assert a.verify_envelope(v["envelope"], {v["kid"]: pub}) == v["fields"]
