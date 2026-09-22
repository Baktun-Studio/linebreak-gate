"""Ed25519-signed approval envelopes (LIN-51).

The signature over the canonical payload **is** the authorization proof. The
governance service refuses to sign an approval whose approver role is wrong for
the phase, so a valid signature over the canonical payload is itself proof the
server's role check passed. The gate verifies OFFLINE and re-derives nothing
about roles — it holds only public keys.

This module is the ONE implementation of the canonical serialization and the
sign/verify primitives. The governance service (signer) and the CI gate
(verifier) both import it, so they can never drift. A packaged golden vector
(:func:`golden_vector`) pins the byte form and signature on both sides — a
change to the serializer on either side fails a test.

Serialization convention (identical to entitlement signing,
``apps/desktop/backend/app/entitlements/remote.py``): JSON with sorted keys, no
whitespace, unicode preserved. Key order and whitespace can never change the
signed bytes. ``kid`` and ``signature`` travel in the envelope OUTSIDE the
signed bytes — a signature cannot cover its own value, and ``kid`` only selects
the verifying key.
"""

from __future__ import annotations

import base64
import hashlib
import json
from importlib import resources
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

#: The fixed, ordered set of fields the signature covers. No extras — an unknown
#: key would change the signed bytes and could smuggle unverified data; a
#: missing key fails closed.
PAYLOAD_FIELDS = (
    "project_id",
    "phase",
    "artifact_hash",
    "approver_email",
    "approver_role",
    # Whether the approver is also the requester. Carried in EVERY signed approval
    # (true/false), cryptographically bound, so a self-approval is STATED, never
    # inferred by absence — an auditor can see whether an independent party
    # checked it. Only ever true in a solo (single-user) org; a team org forbids
    # self-approval outright.
    "self_approved",
    "approved_at",
    "bundle_version",
    "instance_id",
)

#: Envelope key order for on-disk serialization (manifest ``signed_approval``
#: block). Deterministic so re-approval diffs stay surgical.
ENVELOPE_KEYS = (*PAYLOAD_FIELDS, "kid", "signature")


class ApprovalSignatureError(Exception):
    """A signed approval envelope is malformed or fails verification.

    Every failure path — missing field, unknown ``kid``, bad base64, signature
    that does not verify — raises this. The gate maps it to a fail-closed
    verdict; there is no partial-trust path.
    """


def canonical_payload(fields: dict[str, Any]) -> bytes:
    """Deterministic bytes the Ed25519 signature covers.

    Exactly :data:`PAYLOAD_FIELDS`, no extras, none missing. Extra keys in
    ``fields`` (e.g. ``kid``/``signature`` on an envelope) are ignored — they
    never enter the signed bytes.
    """
    missing = [k for k in PAYLOAD_FIELDS if k not in fields]
    if missing:
        raise ApprovalSignatureError(f"approval payload missing field(s): {missing}")
    obj = {k: fields[k] for k in PAYLOAD_FIELDS}
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


# --------------------------------------------------------------------------
# Key encoding / identity
# --------------------------------------------------------------------------


def public_key_raw(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    """Standard base64 of the 32-byte raw public key — the copyable value for
    ``.linebreak/gate.yml`` and the service's ``/v1/keys`` endpoint."""
    return base64.b64encode(public_key_raw(public_key)).decode("ascii")


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as e:
        raise ApprovalSignatureError(f"public key is not valid base64: {e}") from e
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except ValueError as e:
        raise ApprovalSignatureError(f"not a valid Ed25519 public key: {e}") from e


def kid_for_public_key(public_key: Ed25519PublicKey) -> str:
    """Stable, self-describing key id: ``base64url(sha256(raw_pubkey))[:16]``.

    Travels in every envelope; ``gate.yml`` pins ``{kid -> public_key}`` so old
    and new keys both verify across a rotation.
    """
    digest = hashlib.sha256(public_key_raw(public_key)).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")[:16]


# --------------------------------------------------------------------------
# Sign / verify
# --------------------------------------------------------------------------


def sign(fields: dict[str, Any], private_key: Ed25519PrivateKey, *, kid: str) -> dict[str, Any]:
    """Sign the canonical payload and return the on-disk envelope: the payload
    fields plus ``kid`` and a base64 ``signature``. Ed25519 is deterministic,
    so the same inputs always yield the same signature."""
    payload = canonical_payload(fields)
    signature = private_key.sign(payload)
    envelope = {k: fields[k] for k in PAYLOAD_FIELDS}
    envelope["kid"] = kid
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    return envelope


def verify_envelope(
    envelope: dict[str, Any], public_keys: dict[str, Ed25519PublicKey]
) -> dict[str, Any]:
    """Verify a signed approval envelope against a mapping ``{kid: public_key}``.

    Returns the verified payload (the :data:`PAYLOAD_FIELDS` subset) on success.
    Raises :class:`ApprovalSignatureError` on ANY failure — a missing/empty
    ``kid`` or ``signature``, an unknown ``kid`` (the key is not configured in
    ``gate.yml``), malformed base64, or a signature that does not verify. There
    is no path that returns without a cryptographic check.
    """
    kid = envelope.get("kid")
    signature_b64 = envelope.get("signature")
    if not isinstance(kid, str) or not kid:
        raise ApprovalSignatureError("signed approval envelope is missing a 'kid'")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise ApprovalSignatureError("signed approval envelope is missing a 'signature'")
    public_key = public_keys.get(kid)
    if public_key is None:
        raise ApprovalSignatureError(
            f"no configured public key for kid {kid!r} — the approval was signed by a key "
            "this gate does not trust"
        )
    payload = canonical_payload(envelope)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as e:
        raise ApprovalSignatureError(f"signature is not valid base64: {e}") from e
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as e:
        raise ApprovalSignatureError("approval signature does not verify") from e
    return {k: envelope[k] for k in PAYLOAD_FIELDS}


# --------------------------------------------------------------------------
# Golden conformance vector (packaged; shared by every consumer's tests)
# --------------------------------------------------------------------------


def golden_vector() -> dict[str, Any]:
    """The packaged Ed25519 conformance vector.

    Shipped in the wheel so every consumer — the gate's own suite AND the
    governance service that pip-installs this package — verifies against the
    IDENTICAL bytes and signature across the package boundary. Any drift in the
    canonical serialization on either side fails against this fixed vector.
    """
    data = resources.files(__package__).joinpath("golden/approval_vector.json").read_text("utf-8")
    return json.loads(data)


def private_key_from_seed_b64(seed_b64: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a base64 32-byte seed (the ``EnvSecretStore``
    / test-vector representation)."""
    try:
        seed = base64.b64decode(seed_b64, validate=True)
    except (ValueError, TypeError) as e:
        raise ApprovalSignatureError(f"private key seed is not valid base64: {e}") from e
    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError as e:
        raise ApprovalSignatureError(f"not a valid Ed25519 seed: {e}") from e
