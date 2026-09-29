"""Registros de evidencia firmados por la instancia de gobierno (e16-s3).

La aprobación de la especificación ya viaja firmada (``approval_sig``). Este
módulo extiende la misma firma Ed25519, con la misma serialización canónica
(``approval_sig.canonical_json``: claves ordenadas, sin espacios, UTF-8), a la
evidencia de cada corrida:

* ``gate_run``: el expediente normalizado de la corrida, al recibirlo.
* ``override``: cada excepción de esa corrida, al recibirla.
* ``panel_signoff``: cada firma hecha desde el panel, al registrarla.

Un registro firmado cubre exactamente :data:`SIGNED_FIELDS`. ``kid`` y
``signature`` viajan fuera de los bytes firmados, igual que en las
aprobaciones. El servicio guarda el texto canónico exacto que firmó
(``signed_canonical``) y el archivo descargable lo lleva tal cual, así que la
verificación nunca depende de volver a serializar números o fechas.

El servicio (firmante) y ``linebreak-gate verify`` (verificador sin red)
importan este mismo módulo, así que no pueden divergir.
"""

from __future__ import annotations

import base64
import json
import math
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .approval_sig import canonical_json, public_key_from_b64

#: Versión del formato del archivo descargable.
FORMAT = "linebreak-evidence/v1"
KINDS = ("gate_run", "override", "panel_signoff")
#: Lo que cubre la firma. Nada más: un campo extra no entra en los bytes.
SIGNED_FIELDS = ("kind", "object_id", "payload", "signed_at", "instance_id")
UNSIGNED_NOTE = "sin firma de la instancia"

#: Salidas de ``linebreak-gate verify``.
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_UNREADABLE = 2
EXIT_UNSIGNED = 3


class EvidenceSignatureError(Exception):
    """Un registro de evidencia está mal formado o su firma no verifica."""


class EvidenceFileError(Exception):
    """El archivo de evidencia no se puede leer o su formato no es conocido."""


def _check_json_value(value: Any, path: str) -> None:
    """Solo tipos JSON y números finitos: un NaN o un objeto que ``json`` no
    serializa igual en todos lados no puede entrar a lo firmado."""
    if value is None or isinstance(value, (bool, str, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise EvidenceSignatureError(f"número no finito en {path}")
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _check_json_value(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, item in value.items():
            if not isinstance(k, str):
                raise EvidenceSignatureError(f"clave no textual en {path}")
            _check_json_value(item, f"{path}.{k}")
        return
    raise EvidenceSignatureError(f"tipo no JSON en {path}: {type(value).__name__}")


def signed_fields(record: dict[str, Any]) -> dict[str, Any]:
    """El subconjunto firmado de un registro. Falla cerrado si falta algo o si
    el tipo no es uno de :data:`KINDS`."""
    missing = [k for k in SIGNED_FIELDS if k not in record]
    if missing:
        raise EvidenceSignatureError(f"al registro le falta: {missing}")
    if record["kind"] not in KINDS:
        raise EvidenceSignatureError(f"tipo de registro desconocido: {record['kind']!r}")
    for key in ("object_id", "signed_at", "instance_id"):
        if not isinstance(record[key], str) or not record[key]:
            raise EvidenceSignatureError(f"'{key}' debe ser texto no vacío")
    if not isinstance(record["payload"], dict):
        raise EvidenceSignatureError("'payload' debe ser un objeto")
    fields = {k: record[k] for k in SIGNED_FIELDS}
    _check_json_value(fields, "registro")
    return fields


def canonical_record(record: dict[str, Any]) -> bytes:
    """Los bytes que cubre la firma: :data:`SIGNED_FIELDS` en JSON canónico."""
    return canonical_json(signed_fields(record))


def sign_record(
    record: dict[str, Any], private_key: Ed25519PrivateKey, *, kid: str
) -> dict[str, Any]:
    """Firma el registro. Devuelve los campos firmados más ``signed_canonical``
    (el texto exacto firmado, para guardarlo tal cual), ``kid`` y ``signature``
    (base64)."""
    canonical = canonical_record(record)
    signature = private_key.sign(canonical)
    # Los campos devueltos salen del texto firmado, no del objeto de entrada:
    # el registro es exactamente lo firmado y no comparte referencias.
    return {
        **json.loads(canonical),
        "signed_canonical": canonical.decode("utf-8"),
        "kid": kid,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_canonical(
    canonical: str, kid: str | None, signature_b64: str | None, public_key: Ed25519PublicKey
) -> None:
    """Verifica una firma sobre el texto canónico tal cual se guardó."""
    if not kid or not signature_b64:
        raise EvidenceSignatureError("el registro no trae kid o firma")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError) as e:
        raise EvidenceSignatureError(f"la firma no es base64 válido: {e}") from e
    try:
        public_key.verify(signature, canonical.encode("utf-8"))
    except InvalidSignature as e:
        raise EvidenceSignatureError("la firma no verifica") from e


def verify_record(
    record: dict[str, Any], public_keys: dict[str, Ed25519PublicKey]
) -> dict[str, Any]:
    """Verifica un registro firmado contra ``{kid: llave pública}``.

    Dos comprobaciones, las dos obligatorias: la firma verifica sobre el texto
    canónico que trae el registro (``signed_canonical``, o el recalculado si no
    lo trae), y ese texto es exactamente el canónico de los campos que el
    registro muestra. Así un carácter cambiado en el contenido visible o en el
    texto firmado falla igual. Devuelve los campos firmados."""
    kid = record.get("kid")
    signature_b64 = record.get("signature")
    if not isinstance(kid, str) or not kid:
        raise EvidenceSignatureError("el registro no trae kid")
    if not isinstance(signature_b64, str) or not signature_b64:
        raise EvidenceSignatureError("el registro no trae firma")
    public_key = public_keys.get(kid)
    if public_key is None:
        raise EvidenceSignatureError(f"el kid {kid!r} no es de confianza")
    expected = canonical_record(record).decode("utf-8")
    canonical = record.get("signed_canonical", expected)
    if not isinstance(canonical, str):
        raise EvidenceSignatureError("'signed_canonical' debe ser texto")
    verify_canonical(canonical, kid, signature_b64, public_key)
    if canonical != expected:
        raise EvidenceSignatureError("el contenido del registro no es el que se firmó")
    return signed_fields(record)


# --------------------------------------------------------------------------
# Archivo descargable
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class RecordResult:
    kind: str
    object_id: str
    status: str  # verified | failed | unsigned
    kid: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class FileResult:
    records: tuple[RecordResult, ...]
    exit_code: int


def load_evidence_file(raw: str | bytes) -> dict[str, Any]:
    """Lee y valida la forma del archivo. :class:`EvidenceFileError` si no es
    JSON, si el formato no es :data:`FORMAT` o si no trae registros."""
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as e:
        raise EvidenceFileError(f"el archivo no es JSON válido: {e}") from e
    if not isinstance(doc, dict):
        raise EvidenceFileError("el archivo no es un objeto JSON")
    if doc.get("format") != FORMAT:
        raise EvidenceFileError(
            f"formato desconocido {doc.get('format')!r}; se esperaba {FORMAT!r}"
        )
    records = doc.get("records")
    if not isinstance(records, list) or not records:
        raise EvidenceFileError("el archivo no trae registros")
    if not all(isinstance(r, dict) for r in records):
        raise EvidenceFileError("cada registro debe ser un objeto")
    return doc


def file_public_keys(doc: dict[str, Any]) -> dict[str, str]:
    """Las llaves públicas que trae el propio archivo (``instance.public_keys``)."""
    instance = doc.get("instance") if isinstance(doc.get("instance"), dict) else {}
    out: dict[str, str] = {}
    for entry in instance.get("public_keys") or []:
        if isinstance(entry, dict):
            kid, key = entry.get("kid"), entry.get("public_key")
            if isinstance(kid, str) and isinstance(key, str):
                out[kid] = key
    return out


def parse_public_keys(pairs: dict[str, str]) -> dict[str, Ed25519PublicKey]:
    """``{kid: base64}`` -> ``{kid: llave}``. Una llave mal formada es error."""
    try:
        return {kid: public_key_from_b64(value) for kid, value in pairs.items()}
    except Exception as e:  # ApprovalSignatureError u otro error de decodificación
        raise EvidenceSignatureError(f"llave pública inválida: {e}") from e


def verify_evidence(doc: dict[str, Any], public_keys: dict[str, Ed25519PublicKey]) -> FileResult:
    """Verifica cada registro del archivo. Salida: 0 todo firmado y verifica;
    1 alguna firma no verifica o su kid no es de confianza; 3 todo lo firmado
    verifica pero hay registros sin firma de la instancia."""
    results: list[RecordResult] = []
    for record in doc["records"]:
        kind = str(record.get("kind") or "?")
        object_id = str(record.get("object_id") or "?")
        if record.get("signed") is False and not record.get("signature"):
            results.append(RecordResult(kind, object_id, "unsigned", detail=UNSIGNED_NOTE))
            continue
        kid = record.get("kid") if isinstance(record.get("kid"), str) else None
        try:
            verify_record(record, public_keys)
        except EvidenceSignatureError as e:
            results.append(RecordResult(kind, object_id, "failed", kid=kid, detail=str(e)))
            continue
        results.append(RecordResult(kind, object_id, "verified", kid=kid))
    statuses = {r.status for r in results}
    if "failed" in statuses:
        code = EXIT_FAILED
    elif "unsigned" in statuses:
        code = EXIT_UNSIGNED
    else:
        code = EXIT_OK
    return FileResult(tuple(results), code)
