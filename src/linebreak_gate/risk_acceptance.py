"""Expiry of accepted risks.

An override (a security finding acknowledged, or a failed criterion excused)
used to be forever: the person who accepted the risk leaves, the risk stays.
This module bounds acceptances in time:

* ``resolve_expiry`` turns ``--expires YYYY-MM-DD`` / ``--days N`` into a date
  under the repo policy (``risk_acceptance: {max_days, required}`` in
  ``.linebreak/gate.yml``): a required-but-missing expiry is an error, a date
  past ``max_days`` is an error.
* ``acceptance_state`` classifies one recorded acceptance for today:
  ``open`` (no expiry), ``active``, ``expiring`` (less than :data:`WARN_DAYS`
  left, reported as a warning) or ``expired`` (blocks again as
  ``expired_risk``).
* ``latest_by_target`` picks the EFFECTIVE acceptance per target: a renewal is
  a new record with a later ``at``; the earlier record stays in the trail as
  history. Nothing is ever rewritten.

Dates are calendar days in UTC; an acceptance is valid THROUGH its expiry
date and expired the day after.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import Callable, Iterable
from typing import Any

#: Days before expiry at which the gate starts warning (without blocking).
WARN_DAYS = 14

STATES = ("open", "active", "expiring", "expired")


class RiskAcceptanceError(ValueError):
    """An expiry could not be resolved under the policy (exit-2 material)."""


def today() -> _dt.date:
    """Today's UTC date. Module-level so tests can pin the calendar."""
    return _dt.datetime.now(tz=_dt.UTC).date()


def parse_date(text: str) -> _dt.date:
    try:
        return _dt.date.fromisoformat(str(text).strip())
    except ValueError as e:
        raise RiskAcceptanceError(f"invalid date {text!r}; expected YYYY-MM-DD") from e


def resolve_expiry(
    *,
    expires: str | None,
    days: int | None,
    max_days: int | None,
    required: bool,
    now: _dt.date | None = None,
) -> str | None:
    """The expiry date (``YYYY-MM-DD``) for a new acceptance, or None when the
    policy allows an open-ended one and none was given.

    Raises :class:`RiskAcceptanceError` when both forms are given, the date is
    unparseable or not in the future, ``days`` is not positive, the policy
    requires an expiry and none was given, or the expiry exceeds ``max_days``.
    """
    now = now or today()
    if expires is not None and days is not None:
        raise RiskAcceptanceError("pass either --expires or --days, not both")
    if days is not None:
        if isinstance(days, bool) or days < 1:
            raise RiskAcceptanceError(f"--days must be a positive number of days, got {days!r}")
        date = now + _dt.timedelta(days=days)
    elif expires is not None:
        date = parse_date(expires)
        if date <= now:
            raise RiskAcceptanceError(
                f"--expires {date.isoformat()} is not in the future (today is {now.isoformat()})"
            )
    else:
        if required:
            raise RiskAcceptanceError(
                "this repo requires an expiry on every accepted risk "
                "(risk_acceptance.required: true in .linebreak/gate.yml): pass "
                "--expires YYYY-MM-DD or --days N"
            )
        return None
    if max_days is not None and (date - now).days > max_days:
        raise RiskAcceptanceError(
            f"expiry {date.isoformat()} is more than {max_days} day(s) out, the maximum "
            "this repo allows (risk_acceptance.max_days in .linebreak/gate.yml)"
        )
    return date.isoformat()


def acceptance_state(entry: dict[str, Any], now: _dt.date | None = None) -> dict[str, Any]:
    """Classify one recorded acceptance: ``{"state", "expires", "days_left"}``.

    An unparseable ``expires`` counts as ``expired`` (fail closed: a bound we
    cannot read is not a bound we can trust)."""
    now = now or today()
    expires = entry.get("expires")
    if not expires:
        return {"state": "open", "expires": None, "days_left": None}
    try:
        date = parse_date(str(expires))
    except RiskAcceptanceError:
        return {"state": "expired", "expires": str(expires), "days_left": None}
    days_left = (date - now).days
    if days_left < 0:
        state = "expired"
    elif days_left < WARN_DAYS:
        state = "expiring"
    else:
        state = "active"
    return {"state": state, "expires": date.isoformat(), "days_left": days_left}


def latest_by_target(
    entries: Iterable[dict[str, Any]], key: Callable[[dict[str, Any]], str | None]
) -> dict[str, dict[str, Any]]:
    """The effective override per target: the entry with the latest ``at``.

    ``key`` maps an entry to its target id (a finding id, a criterion id) or
    None to skip it. Only ``decision == "override"`` entries take part."""
    latest: dict[str, dict[str, Any]] = {}
    for entry in entries or []:
        if not isinstance(entry, dict) or entry.get("decision") != "override":
            continue
        target = key(entry)
        if not target:
            continue
        current = latest.get(target)
        if current is None or str(entry.get("at") or "") >= str(current.get("at") or ""):
            latest[target] = entry
    return latest


def describe(entry: dict[str, Any], state: dict[str, Any]) -> dict[str, Any]:
    """The acceptance block reports and tickets render: who, when, until when,
    the recorded reason and the mirrored ticket (when any)."""
    return {
        "by": entry.get("user_email"),
        "role": entry.get("role"),
        "at": entry.get("at"),
        "reason": entry.get("notes"),
        "expires": state["expires"],
        "state": state["state"],
        "days_left": state["days_left"],
        "ticket": entry.get("ticket"),
        "approval_id": entry.get("id"),
    }
