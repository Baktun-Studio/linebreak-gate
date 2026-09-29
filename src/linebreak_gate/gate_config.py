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

# Ticket providers the gate can mirror accepted risks into.
TICKET_PROVIDERS = ("jira", "github")
DEFAULT_TICKET_LABELS = ("linebreak",)
DEFAULT_MAIN_BRANCH = "main"
DEFAULT_JIRA_ISSUE_TYPE = "Task"

# Exploitation policy defaults (the `security:` mapping). KEV blocks by default:
# CISA lists a CVE only with confirmed in-the-wild exploitation, so letting one
# through because its CVSS label reads "medium" is exactly the miss a bank's
# auditor asks about. The EPSS threshold is an appetite decision, so it is off
# until the repo sets it. Neither changes anything when no intel is available.
DEFAULT_BLOCK_KEV = True
DEFAULT_EPSS_THRESHOLD: float | None = None
DEFAULT_INTEL_MAX_AGE_HOURS = 24.0
SECURITY_KEYS = frozenset(
    {"fail_on", "block_kev", "epss_threshold", "intel", "intel_max_age_hours"}
)


class GateConfigError(ValueError):
    """The gate config (file or flag) is invalid — the CLI exits 2."""


#: Integrity findings about the approved criteria themselves (issues #259,
#: #261, #263), each with its own policy under ``criteria.integrity``:
#:
#: * ``shared_tests``: two stories run the same test path (#263).
#: * ``stale_statements``: a statement names an identifier that no longer
#:   appears in the code (#261).
#: * ``zero_tests``: a ``command`` criterion ran a test runner that executed
#:   zero tests (#259; a ``tests`` criterion with zero tests ALWAYS fails).
INTEGRITY_KINDS = ("shared_tests", "stale_statements", "zero_tests")
#: ``warn`` (default) reports without blocking; ``block`` turns the finding
#: into a failed criterion; ``off`` does not look.
INTEGRITY_POLICIES = ("off", "warn", "block")
DEFAULT_INTEGRITY_POLICY = "warn"


@dataclass(frozen=True)
class IntegrityPolicy:
    """The ``criteria.integrity`` policy, one value per finding kind."""

    shared_tests: str = DEFAULT_INTEGRITY_POLICY
    stale_statements: str = DEFAULT_INTEGRITY_POLICY
    zero_tests: str = DEFAULT_INTEGRITY_POLICY

    def of(self, kind: str) -> str:
        return str(getattr(self, kind))

    def as_dict(self) -> dict[str, str]:
        return {kind: self.of(kind) for kind in INTEGRITY_KINDS}


@dataclass(frozen=True)
class TicketsConfig:
    """``tickets:`` block: where accepted risks and criterion exceptions are
    mirrored so traceability lives in the team's own tracker too."""

    provider: str
    project: str
    labels: tuple[str, ...] = DEFAULT_TICKET_LABELS
    # Branch whose scans open attention tickets for NEW findings (released code).
    main_branch: str = DEFAULT_MAIN_BRANCH
    # Jira only: the issue type created for each ticket.
    issue_type: str = DEFAULT_JIRA_ISSUE_TYPE
    # Where the block came from: ``file`` (gate.yml) or ``governance`` (the
    # service's Integrations screen, read with the pipeline token when the
    # repository fixes nothing). gate.yml always wins.
    source: str = "file"
    # Credentials handed over by the governance service, keyed by the SAME
    # environment variable names the pipeline would set (JIRA_BASE_URL,
    # JIRA_EMAIL, JIRA_API_TOKEN, GITHUB_TOKEN). An environment variable that
    # is set still wins over these.
    credentials: tuple[tuple[str, str], ...] = ()


def tickets_config_from_mapping(raw: object, *, source: str = "file") -> TicketsConfig | None:
    """Validate a ``tickets`` block that did not come from gate.yml (the
    governance service's copy) with exactly the rules gate.yml gets."""
    cfg = _parse_tickets(raw)
    if cfg is None:
        return None
    return TicketsConfig(
        provider=cfg.provider,
        project=cfg.project,
        labels=cfg.labels,
        main_branch=cfg.main_branch,
        issue_type=cfg.issue_type,
        source=source,
    )


@dataclass(frozen=True)
class GateConfig:
    fail_on: str = DEFAULT_FAIL_ON
    fail_on_source: str = "default"  # default | file | flag
    exclude_paths: tuple[str, ...] = ()
    code_scan: str = "auto"
    # Exploitation policy (security: mapping in gate.yml).
    block_kev: bool = DEFAULT_BLOCK_KEV
    epss_threshold: float | None = DEFAULT_EPSS_THRESHOLD
    # Enrichment with EPSS/KEV: on by default; `security.intel: false` turns
    # the lookups (network + cache) off entirely for air-gapped pipelines.
    intel: bool = True
    intel_max_age_hours: float = DEFAULT_INTEL_MAX_AGE_HOURS
    # Acceptance-criteria enforcement (LIN-37). Default TRUE when a bundle
    # exists — the approved spec is binding by default; relaxing it is an
    # explicit `criteria: {enforce: false}` in gate.yml, itself a visible PR.
    criteria_enforce: bool = True
    criteria_source: str = "default"  # default | file
    # Integrity of the approved criteria (`criteria.integrity`): a single
    # policy string for every kind, or a mapping per kind. Default warn.
    criteria_integrity: IntegrityPolicy = IntegrityPolicy()
    # Signed-approval verification (LIN-51). Each entry is (kid, public_key_b64).
    # The PRESENCE of a non-empty list is the ONLY switch that flips the gate
    # from "unsigned OK" to "signature required" — it keys off config here, never
    # off whether the manifest happens to carry a signature (which would let an
    # attacker strip the signature to downgrade to honest-unsigned). Absent/empty
    # => today's behavior. Keys are validated (decode + kid consistency) here, so
    # a malformed key is a config error (exit 2), not a silent verification miss.
    approval_public_keys: tuple[tuple[str, str], ...] = ()
    # Risk-acceptance policy: `risk_acceptance: {max_days, required}`. When
    # `required` is true an override without an expiry is refused; `max_days`
    # caps how far out an expiry may be set. Absent => open-ended acceptances
    # (today's behavior) and no cap.
    risk_max_days: int | None = None
    risk_required: bool = False
    # Ticket mirroring (`tickets:` block). None => no tracker integration.
    tickets: TicketsConfig | None = None


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

    security = _parse_security(data.get("security"))
    file_fail_on = data.get("fail_on")
    if file_fail_on is not None and security.get("fail_on") is not None:
        raise GateConfigError(
            f"{CONFIG_RELPATH} sets fail_on both at the top level and under security:; keep one"
        )
    if file_fail_on is None:
        file_fail_on = security.get("fail_on")

    # Precedence: flag > file > default — then one shared validation.
    if cli_fail_on is not None:
        raw_fail_on, fail_on_source, described = cli_fail_on, "flag", f"--fail-on {cli_fail_on!r}"
    elif file_fail_on is not None:
        raw_fail_on, fail_on_source = file_fail_on, "file"
        described = f"fail_on {file_fail_on!r} in {CONFIG_RELPATH}"
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
    criteria_integrity = IntegrityPolicy()
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
        criteria_integrity = _parse_integrity(raw_criteria.get("integrity"))
        unknown = set(raw_criteria) - {"enforce", "integrity"}
        if unknown:
            raise GateConfigError(f"unknown criteria key(s) {sorted(unknown)} in {CONFIG_RELPATH}")

    approval_public_keys = _parse_approval_public_keys(data.get("approvals"))
    risk_max_days, risk_required = _parse_risk_acceptance(data.get("risk_acceptance"))
    tickets = _parse_tickets(data.get("tickets"))

    return GateConfig(
        fail_on=fail_on,
        fail_on_source=fail_on_source,
        exclude_paths=tuple(raw_excludes),
        code_scan=code_scan,
        block_kev=security["block_kev"],
        epss_threshold=security["epss_threshold"],
        intel=security["intel"],
        intel_max_age_hours=security["intel_max_age_hours"],
        criteria_enforce=criteria_enforce,
        criteria_source=criteria_source,
        criteria_integrity=criteria_integrity,
        approval_public_keys=approval_public_keys,
        risk_max_days=risk_max_days,
        risk_required=risk_required,
        tickets=tickets,
    )


def _parse_integrity(raw: object) -> IntegrityPolicy:
    """Parse ``criteria.integrity``: ``warn`` / ``block`` / ``off`` for every
    kind, or ``{shared_tests: block, stale_statements: warn, zero_tests: block}``
    (kinds left out keep the default). A value the gate does not know is a
    GateConfigError: a typo must never silently leave a check relaxed."""
    if raw is None:
        return IntegrityPolicy()
    allowed = ", ".join(INTEGRITY_POLICIES)
    if isinstance(raw, bool):
        # YAML 1.1 reads a bare `off` as False; accept that spelling.
        raw = "off" if raw is False else raw
    if isinstance(raw, str):
        value = raw.strip().lower()
        if value not in INTEGRITY_POLICIES:
            raise GateConfigError(
                f"invalid criteria.integrity {raw!r} in {CONFIG_RELPATH}; expected one of "
                f"{allowed}, or a mapping of {', '.join(INTEGRITY_KINDS)}"
            )
        return IntegrityPolicy(**{kind: value for kind in INTEGRITY_KINDS})
    if not isinstance(raw, dict):
        raise GateConfigError(
            f"criteria.integrity in {CONFIG_RELPATH} must be one of {allowed} or a mapping"
        )
    unknown = set(raw) - set(INTEGRITY_KINDS)
    if unknown:
        raise GateConfigError(
            f"unknown criteria.integrity key(s) {sorted(unknown)} in {CONFIG_RELPATH}; "
            f"expected {', '.join(INTEGRITY_KINDS)}"
        )
    values: dict[str, str] = {}
    for kind, value in raw.items():
        if value is False:
            value = "off"
        if not isinstance(value, str) or value.strip().lower() not in INTEGRITY_POLICIES:
            raise GateConfigError(
                f"invalid criteria.integrity.{kind} {value!r} in {CONFIG_RELPATH}; "
                f"expected one of {allowed}"
            )
        values[kind] = value.strip().lower()
    return IntegrityPolicy(**values)


def _parse_risk_acceptance(raw: object) -> tuple[int | None, bool]:
    """Parse ``risk_acceptance: {max_days: 90, required: true}``. Every failure
    is a GateConfigError: a broken policy must never silently become "no
    expiry needed"."""
    if raw is None:
        return None, False
    if not isinstance(raw, dict):
        raise GateConfigError(f"risk_acceptance in {CONFIG_RELPATH} must be a mapping")
    unknown = set(raw) - {"max_days", "required"}
    if unknown:
        raise GateConfigError(
            f"unknown risk_acceptance key(s) {sorted(unknown)} in {CONFIG_RELPATH}"
        )
    max_days = raw.get("max_days")
    if max_days is not None and (
        isinstance(max_days, bool) or not isinstance(max_days, int) or max_days < 1
    ):
        raise GateConfigError(
            f"invalid risk_acceptance.max_days {max_days!r} in {CONFIG_RELPATH}; "
            "expected a positive integer number of days"
        )
    required = raw.get("required", False)
    if not isinstance(required, bool):
        raise GateConfigError(
            f"invalid risk_acceptance.required {required!r} in {CONFIG_RELPATH}; "
            "expected true or false"
        )
    return max_days, required


def _parse_tickets(raw: object) -> TicketsConfig | None:
    """Parse ``tickets: {provider, project, labels, main_branch, issue_type}``."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise GateConfigError(f"tickets in {CONFIG_RELPATH} must be a mapping")
    allowed = {"provider", "project", "labels", "main_branch", "issue_type"}
    unknown = set(raw) - allowed
    if unknown:
        raise GateConfigError(f"unknown tickets key(s) {sorted(unknown)} in {CONFIG_RELPATH}")
    provider = str(raw.get("provider") or "").strip().lower()
    if provider not in TICKET_PROVIDERS:
        raise GateConfigError(
            f"invalid tickets.provider {raw.get('provider')!r} in {CONFIG_RELPATH}; "
            f"expected one of {', '.join(TICKET_PROVIDERS)}"
        )
    project = raw.get("project")
    if not isinstance(project, str) or not project.strip():
        raise GateConfigError(
            f"tickets.project in {CONFIG_RELPATH} is required (Jira project key, or "
            "'owner/repo' for GitHub Issues)"
        )
    project = project.strip()
    if provider == "github" and project.count("/") != 1:
        raise GateConfigError(
            f"tickets.project {project!r} in {CONFIG_RELPATH} must be 'owner/repo' for GitHub"
        )
    raw_labels = raw.get("labels")
    if raw_labels is None:
        labels: tuple[str, ...] = DEFAULT_TICKET_LABELS
    elif isinstance(raw_labels, list) and all(isinstance(x, str) and x.strip() for x in raw_labels):
        labels = tuple(x.strip() for x in raw_labels)
    else:
        raise GateConfigError(
            f"tickets.labels in {CONFIG_RELPATH} must be a list of non-empty strings"
        )
    main_branch = raw.get("main_branch", DEFAULT_MAIN_BRANCH)
    if not isinstance(main_branch, str) or not main_branch.strip():
        raise GateConfigError(f"tickets.main_branch in {CONFIG_RELPATH} must be a branch name")
    issue_type = raw.get("issue_type", DEFAULT_JIRA_ISSUE_TYPE)
    if not isinstance(issue_type, str) or not issue_type.strip():
        raise GateConfigError(f"tickets.issue_type in {CONFIG_RELPATH} must be a string")
    return TicketsConfig(
        provider=provider,
        project=project,
        labels=labels,
        main_branch=main_branch.strip(),
        issue_type=issue_type.strip(),
    )


def _parse_security(raw: object) -> dict:
    """Parse + validate the ``security:`` mapping (exploitation policy).

    Returns the effective values (defaults filled in) plus ``fail_on`` as
    written (or None) for the caller's precedence logic. Every malformed value
    is a :class:`GateConfigError`: a policy file that is wrong must never
    silently run with the defaults.
    """
    out: dict = {
        "fail_on": None,
        "block_kev": DEFAULT_BLOCK_KEV,
        "epss_threshold": DEFAULT_EPSS_THRESHOLD,
        "intel": True,
        "intel_max_age_hours": DEFAULT_INTEL_MAX_AGE_HOURS,
    }
    if raw is None:
        return out
    if not isinstance(raw, dict):
        raise GateConfigError(f"security in {CONFIG_RELPATH} must be a mapping")
    unknown = set(raw) - SECURITY_KEYS
    if unknown:
        raise GateConfigError(f"unknown security key(s) {sorted(unknown)} in {CONFIG_RELPATH}")
    out["fail_on"] = raw.get("fail_on")

    for key in ("block_kev", "intel"):
        value = raw.get(key)
        if value is not None:
            if not isinstance(value, bool):
                raise GateConfigError(
                    f"invalid security.{key} {value!r} in {CONFIG_RELPATH}; expected true or false"
                )
            out[key] = value

    threshold = raw.get("epss_threshold")
    if threshold is not None:
        if isinstance(threshold, bool) or not isinstance(threshold, int | float):
            raise GateConfigError(
                f"invalid security.epss_threshold {threshold!r} in {CONFIG_RELPATH}; "
                "expected a number between 0 and 1 (a probability)"
            )
        if not 0.0 <= float(threshold) <= 1.0:
            raise GateConfigError(
                f"invalid security.epss_threshold {threshold!r} in {CONFIG_RELPATH}; "
                "expected a number between 0 and 1 (a probability)"
            )
        out["epss_threshold"] = float(threshold)

    max_age = raw.get("intel_max_age_hours")
    if max_age is not None:
        if isinstance(max_age, bool) or not isinstance(max_age, int | float) or max_age <= 0:
            raise GateConfigError(
                f"invalid security.intel_max_age_hours {max_age!r} in {CONFIG_RELPATH}; "
                "expected a positive number of hours"
            )
        out["intel_max_age_hours"] = float(max_age)
    return out


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
