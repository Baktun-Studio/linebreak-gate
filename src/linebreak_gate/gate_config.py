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

    return GateConfig(
        fail_on=fail_on,
        fail_on_source=fail_on_source,
        exclude_paths=tuple(raw_excludes),
        code_scan=code_scan,
        criteria_enforce=criteria_enforce,
        criteria_source=criteria_source,
    )
