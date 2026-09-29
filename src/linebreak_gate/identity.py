"""Who is signing: the identity behind a sign-off or override.

Three sources, resolved in this order (the first that applies wins):

* ``governance``: ``LINEBREAK_GOVERNANCE_BASE_URL`` + ``LINEBREAK_GOVERNANCE_TOKEN``
  are set (the same variables the desktop uses). The gate asks the service
  ``GET /v1/me`` and uses the email behind the token. A configured token that
  fails (401, unreachable) is an :class:`IdentityError`: the command refuses
  rather than silently downgrading to a typed name.
* ``vcs``: the command runs in CI and the provider says who triggered it:
  GitHub Actions (``GITHUB_ACTOR``, plus the ``users.noreply.github.com``
  address when ``GITHUB_ACTOR_ID`` is present), GitLab CI (``GITLAB_USER_EMAIL``
  / ``GITLAB_USER_LOGIN``), Bitbucket Pipelines (``BITBUCKET_STEP_TRIGGERER_UUID``)
  and Azure Pipelines (``BUILD_REQUESTEDFOREMAIL``).
* ``client``: whatever ``--approver`` said. Human-typed, unverified; this is
  what every record carried before this module existed.

The record stores the source so an auditor can tell a verified identity from a
declared one, and ``policy.require_verified_identity`` in ``roles.yml`` makes
the difference binding (see :mod:`roles`).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from . import governance_env
from .roles import VERIFIED_SOURCES, identity_keys

GOVERNANCE_BASE_ENV = "LINEBREAK_GOVERNANCE_BASE_URL"
GOVERNANCE_TOKEN_ENV = "LINEBREAK_GOVERNANCE_TOKEN"
_TIMEOUT_SECONDS = 15

_EMAIL_RE = re.compile(r"[^<>@\s]+@[^<>@\s]+")


class IdentityError(Exception):
    """No usable identity, or a configured governance token that does not
    work. The CLI exits 2: a record must never be attributed by guesswork."""


@dataclass(frozen=True)
class Identity:
    subject: str
    source: str  # client | vcs | governance
    provider: str | None = None  # github | gitlab | bitbucket | azure_devops | governance
    email: str | None = None
    login: str | None = None
    roles: tuple[str, ...] = ()  # roles the governance service reports (informational)
    declared: str | None = None  # what --approver said, when it differs from the subject

    @property
    def verified(self) -> bool:
        return self.source in VERIFIED_SOURCES

    def keys(self) -> frozenset[str]:
        """Everything a ``roles.yml`` member entry can match for this person."""
        values: list[str | None] = [self.subject, self.email, self.login]
        if self.provider and self.login:
            values.append(f"{self.provider}:{self.login}")
        return identity_keys(*values)

    def record(self) -> dict[str, Any] | None:
        """The nested ``identity`` block written to evidence, or ``None`` for a
        ``client`` record (the typed name IS the whole identity; repeating the
        email parsed out of it would only dress it up as verified data)."""
        if self.source == "client":
            return None
        block = {
            k: v
            for k, v in (
                ("provider", self.provider),
                ("email", self.email),
                ("login", self.login),
            )
            if v
        }
        return block or None


# ---------------------------------------------------------------- governance


def _default_fetch_me(base_url: str, token: str) -> tuple[int, dict[str, Any]]:
    """``GET /v1/me`` with the bearer token. Returns (status, body); raises
    :class:`IdentityError` on transport failure."""
    from . import __version__

    request = urllib.request.Request(
        f"{base_url}/v1/me",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": f"linebreak-gate/{__version__}",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
            return response.status, json.loads(response.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8") or "{}")
        except (ValueError, OSError):
            body = {}
        return e.code, body if isinstance(body, dict) else {}
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise IdentityError(f"governance service unreachable at {base_url}: {e}") from e


def from_governance(
    env: Mapping[str, str],
    fetch_me: Callable[[str, str], tuple[int, dict[str, Any]]] | None = None,
) -> Identity | None:
    base = (env.get(GOVERNANCE_BASE_ENV) or "").strip().rstrip("/")
    token = (env.get(GOVERNANCE_TOKEN_ENV) or "").strip()
    if not base or not token:
        return None
    status, body = (fetch_me or _default_fetch_me)(base, token)
    if status == 401:
        raise IdentityError(
            f"the governance token in {GOVERNANCE_TOKEN_ENV} was rejected (401) by {base}; "
            "refusing to fall back to a typed name"
        )
    if status != 200:
        raise IdentityError(f"governance service {base} answered {status} to GET /v1/me")
    email = body.get("email")
    if not isinstance(email, str) or not email.strip():
        raise IdentityError(f"governance service {base} returned no email for this token")
    roles = body.get("roles")
    return Identity(
        subject=email.strip(),
        source="governance",
        provider="governance",
        email=email.strip(),
        roles=tuple(r for r in roles if isinstance(r, str)) if isinstance(roles, list) else (),
    )


# ---------------------------------------------------------------- vcs


def from_vcs(env: Mapping[str, str]) -> Identity | None:
    """The CI provider's actor, or ``None`` outside CI. Each provider is
    recognized by its own marker variable, never by the generic ``CI=true``
    (which says nothing about who triggered the job)."""
    actor = (env.get("GITHUB_ACTOR") or "").strip()
    if env.get("GITHUB_ACTIONS") == "true" and actor:
        actor_id = (env.get("GITHUB_ACTOR_ID") or "").strip()
        # GitHub exposes no email for the actor; the documented noreply address
        # is derivable from the numeric id and is what commits carry.
        email = f"{actor_id}+{actor}@users.noreply.github.com" if actor_id else None
        return Identity(
            subject=f"github:{actor}", source="vcs", provider="github", email=email, login=actor
        )

    if env.get("GITLAB_CI") == "true":
        email = (env.get("GITLAB_USER_EMAIL") or "").strip() or None
        login = (env.get("GITLAB_USER_LOGIN") or "").strip() or None
        if email or login:
            return Identity(
                subject=email or f"gitlab:{login}",
                source="vcs",
                provider="gitlab",
                email=email,
                login=login,
            )

    uuid = (env.get("BITBUCKET_STEP_TRIGGERER_UUID") or "").strip()
    if uuid:
        # Pipelines exposes only the triggerer's account UUID; a roster lists it
        # as ``bitbucket:{uuid}`` (braces included, exactly as Bitbucket prints it).
        return Identity(subject=f"bitbucket:{uuid}", source="vcs", provider="bitbucket", login=uuid)

    if env.get("TF_BUILD", "").lower() == "true":
        email = (env.get("BUILD_REQUESTEDFOREMAIL") or "").strip() or None
        name = (env.get("BUILD_REQUESTEDFOR") or "").strip() or None
        if email:
            return Identity(
                subject=email, source="vcs", provider="azure_devops", email=email, login=name
            )
    return None


# ---------------------------------------------------------------- resolve


def resolve(
    declared: str | None,
    *,
    env: Mapping[str, str] | None = None,
    fetch_me: Callable[[str, str], tuple[int, dict[str, Any]]] | None = None,
) -> Identity:
    """The identity a new record is attributed to.

    A verified identity (governance, then vcs) wins over ``declared``; when the
    two differ the typed name is kept as ``declared`` on the record so nothing
    is lost. With no verified identity, ``declared`` becomes a ``client``
    identity; when it is empty too, :class:`IdentityError`.
    """
    # Environment first, then the credential files (governance_env): one
    # lookup for every command that talks to the service.
    env = governance_env.merged() if env is None else env
    declared = (declared or "").strip() or None
    ident = from_governance(env, fetch_me) or from_vcs(env)
    if ident is None:
        if declared is None:
            raise IdentityError(
                "a non-empty --approver (name/email) is required: no CI identity "
                "(GitHub, GitLab, Bitbucket, Azure Pipelines) and no governance token "
                f"({GOVERNANCE_BASE_ENV} + {GOVERNANCE_TOKEN_ENV}) is available here"
            )
        return Identity(subject=declared, source="client", email=_email_in(declared))
    if declared and identity_keys(declared).isdisjoint(ident.keys()):
        ident = replace(ident, declared=declared)
    return ident


def client(declared: str) -> Identity:
    """A ``client`` identity for a typed name (the pre-existing behavior)."""
    declared = declared.strip()
    if not declared:
        raise IdentityError("a non-empty --approver (name/email) is required")
    return Identity(subject=declared, source="client", email=_email_in(declared))


def _email_in(text: str) -> str | None:
    match = _EMAIL_RE.search(text)
    return match.group(0).lower() if match else None
