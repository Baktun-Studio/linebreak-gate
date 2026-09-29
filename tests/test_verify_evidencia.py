"""e16-s3-verify: ``linebreak-gate verify ARCHIVO`` comprueba sin red cada firma
del archivo descargado contra las llaves de ``.linebreak/gate.yml`` o las dadas
con ``--key kid=llave`` (la llave que trae el propio archivo solo con
``--key-from-file``, y lo advierte); sale 0 si todo está firmado y verifica, 1 si
una firma no verifica o su kid no es de confianza (basta cambiar un carácter del
contenido), 3 si todo lo firmado verifica pero hay registros sin firma de la
instancia, y 2 si el archivo no se puede leer."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from linebreak_gate import approval_sig, evidence_sig
from linebreak_gate.cli import main

INSTANCE = "inst_prueba"


def _key():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, approval_sig.kid_for_public_key(pub), approval_sig.public_key_to_b64(pub)


PRIV, KID, PUB = _key()
OTHER_PRIV, OTHER_KID, OTHER_PUB = _key()


def _signed(kind: str, object_id: str, payload: dict, priv=PRIV, kid=KID) -> dict:
    record = evidence_sig.sign_record(
        {
            "kind": kind,
            "object_id": object_id,
            "payload": payload,
            "signed_at": "2026-09-28T15:00:00+00:00",
            "instance_id": INSTANCE,
        },
        priv,
        kid=kid,
    )
    return {**record, "signed": True}


def _unsigned(kind: str, object_id: str, payload: dict) -> dict:
    return {
        "kind": kind,
        "object_id": object_id,
        "payload": payload,
        "signed": False,
        "note": evidence_sig.UNSIGNED_NOTE,
    }


RUN = {
    "run_id": "run-1",
    "verdict": "blocked",
    "findings": [{"id": "CVE-2026-0002", "cvss": 9.8, "epss": 0.4000000059604645}],
    "note": "Revisión: año fiscal",
}
OVERRIDE = {"id": "gov_1", "target": "S2-AC3", "reason": "flaky en CI", "expires": None}
SIGNOFF = {"id": "gso_1", "criterion_id": "S2-AC2", "note": "Diseño revisado", "by": "a@b.test"}


def _doc(records: list[dict], keys=((KID, PUB),)) -> dict:
    return {
        "format": evidence_sig.FORMAT,
        "exported_at": "2026-09-28T15:01:00+00:00",
        "project": {"id": "prj_1", "name": "Pagos"},
        "run_id": "run-1",
        "instance": {
            "instance_id": INSTANCE,
            "public_keys": [{"kid": k, "public_key": v, "status": "active"} for k, v in keys],
        },
        "records": records,
    }


def _all_signed() -> dict:
    return _doc(
        [
            _signed("gate_run", "run-1", RUN),
            _signed("override", "gov_1", OVERRIDE),
            _signed("panel_signoff", "gso_1", SIGNOFF),
        ]
    )


def _write(tmp_path: Path, doc) -> str:
    path = tmp_path / "evidencia.json"
    text = doc if isinstance(doc, str) else json.dumps(doc, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")
    return str(path)


def _gate_yml(root: Path, pairs) -> None:
    (root / ".linebreak").mkdir(exist_ok=True)
    lines = ["approvals:", "  public_keys:"]
    for kid, pub in pairs:
        lines += [f"    - kid: {kid}", f"      public_key: {pub}"]
    (root / ".linebreak" / "gate.yml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run(tmp_path, doc, *extra) -> int:
    return main(["verify", _write(tmp_path, doc), "--path", str(tmp_path), *extra])


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Sin red: cualquier intento de conexión falla la prueba."""

    def refuse(*_a, **_k):
        raise AssertionError("verify intentó usar la red")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


# ----------------------------------------------------------------- salida 0


def test_all_signed_and_verified_with_a_key_flag_exits_0(tmp_path, capsys):
    assert _run(tmp_path, _all_signed(), f"--key={KID}={PUB}") == 0
    out = capsys.readouterr().out
    assert out.count(f"firmado y verificado · kid {KID}") == 3
    assert "expediente" in out and "excepción" in out and "firma del panel" in out
    assert "run-1" in out and "gov_1" in out and "gso_1" in out


def test_keys_from_gate_yml_are_trusted(tmp_path):
    _gate_yml(tmp_path, [(KID, PUB)])
    assert _run(tmp_path, _all_signed()) == 0


def test_the_file_key_only_with_key_from_file_and_it_warns(tmp_path, capsys):
    assert _run(tmp_path, _all_signed()) == 1
    capsys.readouterr()
    assert _run(tmp_path, _all_signed(), "--key-from-file") == 0
    err = capsys.readouterr().err
    assert "confírmala por otro canal" in err and "/v1/keys" in err and "gate.yml" in err


# ----------------------------------------------------------------- salida 1


@pytest.mark.parametrize("index", [0, 1, 2])
def test_one_changed_character_in_the_content_exits_1(tmp_path, capsys, index):
    doc = _all_signed()
    record = doc["records"][index]
    field = {0: "note", 1: "reason", 2: "note"}[index]
    record["payload"][field] = record["payload"][field][:-1] + "X"
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 1
    assert "FALLA" in capsys.readouterr().out


def test_one_changed_character_in_the_signed_text_exits_1(tmp_path):
    doc = _all_signed()
    doc["records"][0]["signed_canonical"] = doc["records"][0]["signed_canonical"].replace(
        "blocked", "blockeD"
    )
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 1


def test_a_changed_number_exits_1(tmp_path):
    doc = _all_signed()
    doc["records"][0]["payload"]["findings"][0]["cvss"] = 9.9
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 1


def test_a_changed_signature_exits_1(tmp_path):
    doc = _all_signed()
    sig = doc["records"][1]["signature"]
    doc["records"][1]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 1


def test_an_untrusted_kid_exits_1(tmp_path, capsys):
    doc = _doc([_signed("gate_run", "run-1", RUN, priv=OTHER_PRIV, kid=OTHER_KID)])
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 1
    assert "no es de confianza" in capsys.readouterr().out


def test_a_key_under_a_trusted_kid_that_is_not_the_signer_exits_1(tmp_path):
    doc = _doc([_signed("gate_run", "run-1", RUN, priv=OTHER_PRIV, kid=KID)])
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 1


def test_a_failure_wins_over_unsigned(tmp_path):
    doc = _all_signed()
    doc["records"][0]["payload"]["note"] = "cambiado"
    doc["records"].append(_unsigned("override", "gov_viejo", OVERRIDE))
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 1


# ----------------------------------------------------------------- salida 3


def test_signed_ok_but_some_unsigned_exits_3(tmp_path, capsys):
    doc = _all_signed()
    doc["records"].append(_unsigned("override", "gov_viejo", OVERRIDE))
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 3
    out = capsys.readouterr().out
    assert "gov_viejo" in out and "sin firma de la instancia" in out
    assert out.count("firmado y verificado") == 3


def test_all_unsigned_exits_3(tmp_path):
    doc = _doc([_unsigned("gate_run", "run-1", RUN)])
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 3


# ----------------------------------------------------------------- salida 2


def test_missing_file_exits_2(tmp_path):
    assert main(["verify", str(tmp_path / "no-existe.json"), "--path", str(tmp_path)]) == 2


def test_not_json_exits_2(tmp_path):
    assert _run(tmp_path, "esto no es json {") == 2


def test_unknown_format_exits_2(tmp_path):
    doc = _all_signed()
    doc["format"] = "linebreak-evidence/v9"
    assert _run(tmp_path, doc, f"--key={KID}={PUB}") == 2


def test_no_records_exits_2(tmp_path):
    assert _run(tmp_path, _doc([])) == 2


def test_a_malformed_key_flag_exits_2(tmp_path):
    assert _run(tmp_path, _all_signed(), "--key=sin-igual") == 2
    assert _run(tmp_path, _all_signed(), f"--key={KID}=no-es-base64!") == 2


# ----------------------------------------------------------------- primitiva


def test_the_signed_bytes_are_the_shared_canonical_json():
    record = _signed("gate_run", "run-1", RUN)
    fields = {k: record[k] for k in evidence_sig.SIGNED_FIELDS}
    assert record["signed_canonical"].encode("utf-8") == approval_sig.canonical_json(fields)
    assert "Revisión: año fiscal" in record["signed_canonical"]
    assert " " not in record["signed_canonical"].replace("Revisión: año fiscal", "").replace(
        "flaky en CI", ""
    )
    # kid y firma quedan fuera de lo firmado.
    assert "kid" not in json.loads(record["signed_canonical"])


def test_non_finite_numbers_are_refused():
    with pytest.raises(evidence_sig.EvidenceSignatureError):
        evidence_sig.sign_record(
            {
                "kind": "gate_run",
                "object_id": "r",
                "payload": {"cvss": float("nan")},
                "signed_at": "t",
                "instance_id": INSTANCE,
            },
            PRIV,
            kid=KID,
        )


def test_an_unknown_kind_is_refused():
    with pytest.raises(evidence_sig.EvidenceSignatureError):
        evidence_sig.canonical_record(
            {"kind": "otro", "object_id": "r", "payload": {}, "signed_at": "t", "instance_id": "i"}
        )
