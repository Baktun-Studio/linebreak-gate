"""Config-as-code for the CI gate: ``.linebreak/gate.yml``.

The gate's strictness is a governance setting, so it lives in the REPO, not in
local app state — changing the threshold is itself a PR (visible, reviewable,
attributable in git history). Precedence: explicit CLI flag > ``gate.yml`` >
built-in default (fail on critical, matching the in-app gate's posture).

An invalid or unparseable config is a :class:`GateConfigError`, which the CLI
maps to exit 2 — a governance file that's wrong must never silently fall back
to a default threshold (fail closed).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from . import approval_sig
from .verdict import FLOOR_RANK

CONFIG_RELPATH = Path(".linebreak") / "gate.yml"

# Blocking floors the gate accepts — derived from the verdict table that
# consumes them, so config validation can never accept a floor the verdict
# would KeyError on.
FAIL_ON_LEVELS = tuple(FLOOR_RANK)

# AI SAST modes: auto = run when LLM credentials are available, skip with a
# notice otherwise; on = required (missing credentials is a tool error, exit
# 2); off = dependency scan only.
CODE_SCAN_MODES = ("auto", "on", "off")

DEFAULT_FAIL_ON = "critical"


class GateConfigError(ValueError):
    """The gate config (file or flag) is invalid — the CLI exits 2."""


@dataclass(frozen=True)
class GateConfig:
    fail_on: str = DEFAULT_FAIL_ON
    fail_on_source: str = "default"  # default | file | flag
    exclude_paths: tuple[str, ...] = ()
    code_scan: str = "auto"
    # Acceptance-criteria enforcement (LIN-37). Default TRUE when a bundle
    # exists — the approved spec is binding by default; relaxing it is an
    # explicit `criteria: {enforce: false}` in gate.yml, itself a visible PR.
    criteria_enforce: bool = True
    criteria_source: str = "default"  # default | file
    # Signed-approval verification (LIN-51). Each entry is (kid, public_key_b64).
    # The PRESENCE of a non-empty list is the ONLY switch that flips the gate
    # from "unsigned OK" to "signature required" — it keys off config here, never
    # off whether the manifest happens to carry a signature (which would let an
    # attacker strip the signature to downgrade to honest-unsigned). Absent/empty
    # => today's behavior. Keys are validated (decode + kid consistency) here, so
    # a malformed key is a config error (exit 2), not a silent verification miss.
    approval_public_keys: tuple[tuple[str, str], ...] = ()


def _norm_code_scan(value: object) -> str:
    # YAML 1.1 parses bare `on`/`off` as booleans — normalize them back so the
    # natural spelling in gate.yml works.
    if value is True:
        return "on"
    if value is False:
        return "off"
    return str(value).strip().lower()


def resolve_config(project_root: Path | str, cli_fail_on: str | None = None) -> GateConfig:
    """Resolve the effective gate config for ``project_root``.

    Raises :class:`GateConfigError` on a malformed file or invalid values —
    never silently defaults past a broken governance file.
    """
    file = Path(project_root) / CONFIG_RELPATH
    data: dict = {}
    if file.exists():
        try:
            parsed = yaml.safe_load(file.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as e:
            raise GateConfigError(f"{CONFIG_RELPATH} is not valid YAML: {e}") from e
        if parsed is None:
            parsed = {}
        if not isinstance(parsed, dict):
            raise GateConfigError(
                f"{CONFIG_RELPATH} must be a mapping, got {type(parsed).__name__}"
            )
        data = parsed

    # Precedence: flag > file > default — then one shared validation.
    if cli_fail_on is not None:
        raw_fail_on, fail_on_source, described = cli_fail_on, "flag", f"--fail-on {cli_fail_on!r}"
    elif data.get("fail_on") is not None:
        raw_fail_on, fail_on_source = data["fail_on"], "file"
        described = f"fail_on {data['fail_on']!r} in {CONFIG_RELPATH}"
    else:
        raw_fail_on, fail_on_source, described = DEFAULT_FAIL_ON, "default", "default fail_on"
    fail_on = str(raw_fail_on).strip().lower()
    if fail_on not in FAIL_ON_LEVELS:
        raise GateConfigError(f"invalid {described}; expected one of {', '.join(FAIL_ON_LEVELS)}")

    raw_excludes = data.get("exclude_paths") or []
    if not isinstance(raw_excludes, list) or not all(isinstance(p, str) for p in raw_excludes):
        raise GateConfigError(f"exclude_paths in {CONFIG_RELPATH} must be a list of strings")

    code_scan = _norm_code_scan(data.get("code_scan", "auto"))
    if code_scan not in CODE_SCAN_MODES:
        raise GateConfigError(
            f"invalid code_scan {data.get('code_scan')!r} in {CONFIG_RELPATH}; "
            f"expected one of {', '.join(CODE_SCAN_MODES)}"
        )

    criteria_enforce, criteria_source = True, "default"
    raw_criteria = data.get("criteria")
    if raw_criteria is not None:
        if not isinstance(raw_criteria, dict):
            raise GateConfigError(f"criteria in {CONFIG_RELPATH} must be a mapping")
        raw_enforce = raw_criteria.get("enforce")
        if raw_enforce is not None:
            if not isinstance(raw_enforce, bool):
                raise GateConfigError(
                    f"invalid criteria.enforce {raw_enforce!r} in {CONFIG_RELPATH}; "
                    "expected true or false"
                )
            criteria_enforce, criteria_source = raw_enforce, "file"
        unknown = set(raw_criteria) - {"enforce"}
        if unknown:
            raise GateConfigError(f"unknown criteria key(s) {sorted(unknown)} in {CONFIG_RELPATH}")

    approval_public_keys = _parse_approval_public_keys(data.get("approvals"))

    return GateConfig(
        fail_on=fail_on,
        fail_on_source=fail_on_source,
        exclude_paths=tuple(raw_excludes),
        code_scan=code_scan,
        criteria_enforce=criteria_enforce,
        criteria_source=criteria_source,
        approval_public_keys=approval_public_keys,
    )


def _parse_approval_public_keys(raw_approvals: object) -> tuple[tuple[str, str], ...]:
    """Parse + validate ``approvals: {public_keys: [{kid, public_key}, ...]}``.

    Every failure is a :class:`GateConfigError` (exit 2): a broken governance
    file must never silently disable signature checking. Validates that each
    public key decodes to a real Ed25519 key AND that the declared ``kid``
    matches the key, so a mislabeled key is caught here, not as a silent
    verification miss later.
    """
    if raw_approvals is None:
        return ()
    if not isinstance(raw_approvals, dict):
        raise GateConfigError(f"approvals in {CONFIG_RELPATH} must be a mapping")
    unknown = set(raw_approvals) - {"public_keys"}
    if unknown:
        raise GateConfigError(f"unknown approvals key(s) {sorted(unknown)} in {CONFIG_RELPATH}")
    raw_keys = raw_approvals.get("public_keys")
    if raw_keys is None:
        return ()
    if not isinstance(raw_keys, list):
        raise GateConfigError(f"approvals.public_keys in {CONFIG_RELPATH} must be a list")
    parsed: list[tuple[str, str]] = []
    seen: set[str] = set()
    for entry in raw_keys:
        if not isinstance(entry, dict) or (set(entry) - {"kid", "public_key"}):
            raise GateConfigError(
                f"each approvals.public_keys entry in {CONFIG_RELPATH} must be a mapping with "
                "'kid' and 'public_key'"
            )
        kid = entry.get("kid")
        pub = entry.get("public_key")
        if not isinstance(kid, str) or not kid.strip():
            raise GateConfigError(
                f"an approvals.public_keys entry in {CONFIG_RELPATH} is missing a string 'kid'"
            )
        if not isinstance(pub, str) or not pub.strip():
            raise GateConfigError(
                f"approvals.public_keys[{kid}] in {CONFIG_RELPATH} is missing a string 'public_key'"
            )
        try:
            public_key = approval_sig.public_key_from_b64(pub)
        except approval_sig.ApprovalSignatureError as e:
            raise GateConfigError(
                f"approvals.public_keys[{kid}] in {CONFIG_RELPATH} is not a valid Ed25519 "
                f"public key: {e}"
            ) from e
        derived = approval_sig.kid_for_public_key(public_key)
        if derived != kid:
            raise GateConfigError(
                f"approvals.public_keys[{kid}] in {CONFIG_RELPATH} has a kid that does not match "
                f"its public key (expected {derived!r})"
            )
        if kid in seen:
            raise GateConfigError(
                f"duplicate kid {kid!r} in approvals.public_keys in {CONFIG_RELPATH}"
            )
        seen.add(kid)
        parsed.append((kid, pub))
    return tuple(parsed)
