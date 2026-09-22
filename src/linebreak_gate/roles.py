"""Roles and permissions for the humans who sign, override, and accept risk.

Today anyone can run ``linebreak-gate signoff`` or ``override`` and the name on
the record is whatever the person typed. This module adds a roster the gate
enforces: ``.linebreak/roles.yml`` in the client's repository, committed like
``gate.yml`` so a change of who may sign is itself a reviewed PR::

    roles:
      ciso:
        members: [ana@example.com]
        can:
          sign_criteria: ["*"]          # patterns over criterion, story, epic ids
          approve_overrides: ["*"]
          accept_security_risk: [critical, high, medium, low]
      qa:
        members: [luis@example.com, "github:luis-qa"]
        can:
          sign_criteria: ["e12-*"]
          approve_overrides: []
          accept_security_risk: [low, medium]
    policy:
      require_roles: true               # a record without an authorized role is rejected
      require_verified_identity: false  # identity_source: client records do not count

A dedicated file (not a ``roles:`` block in ``gate.yml``) because the roster is
people data that changes on its own cadence and can carry its own CODEOWNERS
line; it is parsed with the same fail-closed discipline as ``gate.yml`` (a
broken file is a :class:`RolesConfigError`, exit 2, never a silent bypass).

Two moments of enforcement share one rule table:

* **recording** (``signoff`` / ``override``): :func:`authorize` picks the role
  the record is made under (``--role``, or inferred when exactly one of the
  person's roles allows the action) and refuses with a message naming the
  roles that would be needed.
* **checking** (``check`` / ``scan`` / ``report``): :func:`verify_record`
  re-evaluates every recorded sign-off and override against the roles IN
  FORCE NOW. A record whose role was removed, whose member left, or whose
  identity is only declared under ``require_verified_identity`` is rejected
  with a ``role_denied`` / ``identity_unverified`` reason. Nothing is deleted:
  the record stays on disk as audit; it just satisfies nothing.

With no file, or ``require_roles: false`` and ``require_verified_identity:
false``, nothing is denied and every command behaves as before.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from .gate_config import GateConfigError
from .verdict import FLOOR_RANK

ROLES_RELPATH = PurePosixPath(".linebreak/roles.yml")

#: The actions a role can be granted.
ACTIONS = ("sign_criteria", "approve_overrides", "accept_security_risk")
SEVERITIES = tuple(FLOOR_RANK)  # critical, high, medium, low

#: Where the name on a record came from. ``client`` is human-typed and
#: unverified; ``vcs`` is the CI provider's actor; ``governance`` is the
#: identity behind a governance-service token.
IDENTITY_SOURCES = ("client", "vcs", "governance")
VERIFIED_SOURCES = frozenset({"vcs", "governance"})

_ROLE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_EMAIL_IN_BRACKETS = re.compile(r"<([^<>@\s]+@[^<>@\s]+)>")


class RolesConfigError(GateConfigError):
    """``roles.yml`` is malformed: exit 2, never a silent fallback."""


class RoleDenied(Exception):
    """A person, or a recorded approval, is not authorized under the roles in
    force. ``reason`` is the machine motive (``role_denied`` or
    ``identity_unverified``); ``str(exc)`` is the readable line."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(frozen=True)
class Role:
    name: str
    members: tuple[str, ...]
    sign_criteria: tuple[str, ...] = ()
    approve_overrides: tuple[str, ...] = ()
    accept_security_risk: tuple[str, ...] = ()

    def has_member(self, keys: frozenset[str]) -> bool:
        return any(m in keys for m in self.members)

    def allows(
        self, action: str, *, targets: tuple[str, ...] = (), severity: str | None = None
    ) -> bool:
        """Whether this role may perform ``action`` on the target ids (a
        criterion id, its story id, its epic) or on a finding of ``severity``."""
        if action == "accept_security_risk":
            if severity is None:
                return False
            return "*" in self.accept_security_risk or severity in self.accept_security_risk
        patterns = getattr(self, action)
        return any(
            fnmatch.fnmatchcase(t, p) for p in patterns for t in targets if isinstance(t, str)
        )


@dataclass(frozen=True)
class RolesPolicy:
    roles: tuple[Role, ...] = ()
    require_roles: bool = False
    require_verified_identity: bool = False
    source: str = "absent"  # absent | file

    @property
    def enforcing(self) -> bool:
        return self.require_roles or self.require_verified_identity

    def role(self, name: str) -> Role | None:
        return next((r for r in self.roles if r.name == name), None)

    def roles_of(self, keys: frozenset[str]) -> list[Role]:
        return [r for r in self.roles if r.has_member(keys)]

    def roles_allowing(
        self, action: str, *, targets: tuple[str, ...] = (), severity: str | None = None
    ) -> list[str]:
        return [r.name for r in self.roles if r.allows(action, targets=targets, severity=severity)]


#: The policy with no file on disk: nothing is enforced, nothing is denied.
EMPTY_POLICY = RolesPolicy()


# ---------------------------------------------------------------- identity keys


def identity_keys(*values: str | None) -> frozenset[str]:
    """The lowercase strings a roster entry can match against for one person:
    every value as typed, plus any ``<email>`` found inside angle brackets
    (``Ana Lopez <ana@example.com>`` matches a member ``ana@example.com``)."""
    keys: set[str] = set()
    for v in values:
        if not isinstance(v, str) or not v.strip():
            continue
        s = v.strip().lower()
        keys.add(s)
        for email in _EMAIL_IN_BRACKETS.findall(s):
            keys.add(email)
    return frozenset(keys)


def record_keys(record: dict[str, Any], *subject_fields: str) -> frozenset[str]:
    """Keys for a stored sign-off/override entry: its subject field(s) plus the
    nested ``identity`` block written by newer versions (email, login, and
    ``provider:login`` so a roster can list ``github:ana-lopez``)."""
    values: list[str | None] = [record.get(f) for f in subject_fields]
    ident = record.get("identity")
    if isinstance(ident, dict):
        values.extend([ident.get("email"), ident.get("login")])
        provider, login = ident.get("provider"), ident.get("login")
        if isinstance(provider, str) and isinstance(login, str):
            values.append(f"{provider}:{login}")
    return identity_keys(*values)


# ---------------------------------------------------------------- loading


def load_roles(project_root: Path | str) -> RolesPolicy:
    """Parse and validate ``.linebreak/roles.yml``. Absent file: the empty
    policy (nothing enforced). Any malformation: :class:`RolesConfigError`."""
    file = Path(project_root) / ROLES_RELPATH
    if not file.exists():
        return EMPTY_POLICY
    try:
        parsed = yaml.safe_load(file.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as e:
        raise RolesConfigError(f"{ROLES_RELPATH} is not valid YAML: {e}") from e
    if parsed is None:
        parsed = {}
    if not isinstance(parsed, dict):
        raise RolesConfigError(f"{ROLES_RELPATH} must be a mapping, got {type(parsed).__name__}")
    unknown = set(parsed) - {"roles", "policy"}
    if unknown:
        raise RolesConfigError(f"unknown top-level key(s) {sorted(unknown)} in {ROLES_RELPATH}")

    roles = _parse_roles(parsed.get("roles"))
    require_roles, require_verified = _parse_policy(parsed.get("policy"))
    return RolesPolicy(
        roles=roles,
        require_roles=require_roles,
        require_verified_identity=require_verified,
        source="file",
    )


def _string_list(value: object, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v.strip() for v in value):
        raise RolesConfigError(f"{where} in {ROLES_RELPATH} must be a list of non-empty strings")
    return tuple(v.strip() for v in value)


def _parse_roles(raw: object) -> tuple[Role, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, dict):
        raise RolesConfigError(f"roles in {ROLES_RELPATH} must be a mapping of role name to spec")
    out: list[Role] = []
    for name, spec in raw.items():
        if not isinstance(name, str) or not _ROLE_NAME_RE.match(name):
            raise RolesConfigError(
                f"role name {name!r} in {ROLES_RELPATH} must match {_ROLE_NAME_RE.pattern}"
            )
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise RolesConfigError(f"roles.{name} in {ROLES_RELPATH} must be a mapping")
        unknown = set(spec) - {"members", "can"}
        if unknown:
            raise RolesConfigError(
                f"unknown key(s) {sorted(unknown)} in roles.{name} in {ROLES_RELPATH}"
            )
        members = tuple(
            m.lower() for m in _string_list(spec.get("members"), f"roles.{name}.members")
        )
        can = spec.get("can") or {}
        if not isinstance(can, dict):
            raise RolesConfigError(f"roles.{name}.can in {ROLES_RELPATH} must be a mapping")
        unknown_can = set(can) - set(ACTIONS)
        if unknown_can:
            raise RolesConfigError(
                f"unknown action(s) {sorted(unknown_can)} in roles.{name}.can in {ROLES_RELPATH}; "
                f"expected {', '.join(ACTIONS)}"
            )
        severities = tuple(
            s.lower()
            for s in _string_list(
                can.get("accept_security_risk"), f"roles.{name}.can.accept_security_risk"
            )
        )
        bad = [s for s in severities if s != "*" and s not in SEVERITIES]
        if bad:
            raise RolesConfigError(
                f"roles.{name}.can.accept_security_risk in {ROLES_RELPATH} has unknown "
                f"severity(ies) {bad}; expected {', '.join(SEVERITIES)} or '*'"
            )
        out.append(
            Role(
                name=name,
                members=members,
                sign_criteria=_string_list(
                    can.get("sign_criteria"), f"roles.{name}.can.sign_criteria"
                ),
                approve_overrides=_string_list(
                    can.get("approve_overrides"), f"roles.{name}.can.approve_overrides"
                ),
                accept_security_risk=severities,
            )
        )
    return tuple(out)


def _parse_policy(raw: object) -> tuple[bool, bool]:
    if raw is None:
        return False, False
    if not isinstance(raw, dict):
        raise RolesConfigError(f"policy in {ROLES_RELPATH} must be a mapping")
    known = {"require_roles", "require_verified_identity"}
    unknown = set(raw) - known
    if unknown:
        raise RolesConfigError(f"unknown policy key(s) {sorted(unknown)} in {ROLES_RELPATH}")
    values: list[bool] = []
    for key in ("require_roles", "require_verified_identity"):
        value = raw.get(key, False)
        if not isinstance(value, bool):
            raise RolesConfigError(
                f"invalid policy.{key} {value!r} in {ROLES_RELPATH}; expected true or false"
            )
        values.append(value)
    return values[0], values[1]


# ---------------------------------------------------------------- decisions


def describe(action: str, *, targets: tuple[str, ...] = (), severity: str | None = None) -> str:
    """One readable phrase per action, used by every denial message."""
    target = next((t for t in targets if isinstance(t, str) and t), "?")
    if action == "sign_criteria":
        return f"sign criterion {target}"
    if action == "approve_overrides":
        return f"override criterion {target}"
    return f"accept a {severity or 'unknown'}-severity security risk ({target})"


def authorize(
    policy: RolesPolicy,
    *,
    subject: str,
    keys: frozenset[str],
    action: str,
    targets: tuple[str, ...] = (),
    severity: str | None = None,
    role: str | None = None,
) -> str | None:
    """Decide which role a NEW record is made under.

    ``role`` given: it must exist, include the person, and allow the action.
    ``role`` absent: inferred when exactly one of the person's roles allows the
    action; several candidates ask for ``--role``. No candidate is a
    :class:`RoleDenied` under ``require_roles``, or ``None`` (recorded without a
    role, exactly as before) when roles are not required.
    """
    what = describe(action, targets=targets, severity=severity)
    if role is not None:
        if policy.source == "absent":
            raise RoleDenied(
                "role_denied",
                f"--role {role!r} cannot be checked: there is no {ROLES_RELPATH} in this repository",
            )
        found = policy.role(role)
        if found is None:
            raise RoleDenied(
                "role_denied",
                f"role {role!r} is not defined in {ROLES_RELPATH} (defined: "
                f"{', '.join(r.name for r in policy.roles) or 'none'})",
            )
        if not found.has_member(keys):
            raise RoleDenied(
                "role_denied", f"{subject} is not a member of role {role!r} in {ROLES_RELPATH}"
            )
        if not found.allows(action, targets=targets, severity=severity):
            raise RoleDenied(
                "role_denied",
                f"role {role!r} may not {what}; roles that may: "
                f"{_names(policy.roles_allowing(action, targets=targets, severity=severity))}",
            )
        return role

    able = [
        r for r in policy.roles_of(keys) if r.allows(action, targets=targets, severity=severity)
    ]
    if len(able) == 1:
        return able[0].name
    if len(able) > 1:
        raise RoleDenied(
            "role_denied",
            f"{subject} holds more than one role that may {what} "
            f"({', '.join(r.name for r in able)}); pass --role to say which one signs",
        )
    if not policy.require_roles:
        return None
    raise RoleDenied(
        "role_denied",
        f"{subject} holds no role that may {what}; roles that may: "
        f"{_names(policy.roles_allowing(action, targets=targets, severity=severity))} "
        f"(policy.require_roles is on in {ROLES_RELPATH})",
    )


def verify_record(
    policy: RolesPolicy,
    *,
    kind: str,
    subject: str,
    keys: frozenset[str],
    action: str,
    targets: tuple[str, ...] = (),
    severity: str | None = None,
    role: str | None,
    identity_source: str | None,
) -> RoleDenied | None:
    """Re-check a RECORDED sign-off or override against the roles in force.
    Returns ``None`` when it still counts, else the :class:`RoleDenied` that
    says why (the caller reports it; nothing raises so one bad record never
    hides the others)."""
    if not policy.enforcing:
        return None
    if policy.require_verified_identity and identity_source not in VERIFIED_SOURCES:
        return RoleDenied(
            "identity_unverified",
            f"{kind} by {subject} carries a declared identity (identity_source: "
            f"{identity_source or 'client'}), not a verified one; "
            f"policy.require_verified_identity is on in {ROLES_RELPATH}",
        )
    if not policy.require_roles:
        return None
    what = describe(action, targets=targets, severity=severity)
    if role is None:
        return RoleDenied(
            "role_denied",
            f"{kind} by {subject} carries no role; policy.require_roles is on in "
            f"{ROLES_RELPATH} (record it again with --role)",
        )
    found = policy.role(role)
    if found is None:
        return RoleDenied(
            "role_denied",
            f"{kind} by {subject} was made as role {role!r}, which is no longer defined in "
            f"{ROLES_RELPATH}",
        )
    if not found.has_member(keys):
        return RoleDenied(
            "role_denied",
            f"{kind} by {subject} was made as role {role!r}, but {subject} is no longer a "
            f"member of it in {ROLES_RELPATH}",
        )
    if not found.allows(action, targets=targets, severity=severity):
        return RoleDenied(
            "role_denied",
            f"{kind} by {subject} was made as role {role!r}, which may not {what}; roles that "
            f"may: {_names(policy.roles_allowing(action, targets=targets, severity=severity))}",
        )
    return None


def denial_record(denial: RoleDenied, *, kind: str, by: str, role: str | None) -> dict[str, Any]:
    """The JSON shape a rejected approval takes in check output and evidence."""
    return {"kind": kind, "by": by, "role": role, "reason": denial.reason, "detail": denial.message}


def criterion_targets(story: dict[str, Any], criterion: dict[str, Any]) -> tuple[str, ...]:
    """The ids a ``sign_criteria`` / ``approve_overrides`` pattern is matched
    against: the criterion id, its story id, and the story's epic."""
    return tuple(t for t in (criterion.get("id"), story.get("id"), story.get("epic")) if t)


def severity_name(rank: int) -> str:
    """The severity name for a verdict rank (a rank-0 finding, which never
    blocks, is treated as ``low`` so an override on it needs the least)."""
    for name, r in FLOOR_RANK.items():
        if r == rank:
            return name
    return "low"


def _names(names: list[str]) -> str:
    return ", ".join(names) if names else "none defined"
