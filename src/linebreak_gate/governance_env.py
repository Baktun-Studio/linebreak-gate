"""Where the governance service credentials come from: one lookup for every
command that talks to the service (``check`` for panel sign-offs and the
tracker configuration, ``signoff`` / ``override`` for the verified identity,
``publish``, ``report --from-governance``).

Order, the first that applies wins (documented in the README):

1. Environment variables (``LINEBREAK_GOVERNANCE_BASE_URL``,
   ``LINEBREAK_GOVERNANCE_TOKEN``, ``LINEBREAK_GOV_TOKEN``,
   ``LINEBREAK_GOVERNANCE_PROJECT``, ``LINEBREAK_GOV_PROJECT``). A variable
   that is set always wins over a file, key by key.
2. ``~/.config/linebreak/governance.env`` (``$XDG_CONFIG_HOME/linebreak/``
   when that variable is set).
3. ``~/.config/linebreak/governance-local.env`` (a local instance).
4. ``~/.linebreak/env``, kept for compatibility with the desktop app, which
   wrote its credentials there.

Files are ``KEY=value`` lines (``export`` and quotes allowed, ``#`` comments).
Only the FIRST file that carries a token is used, whole: a base URL from one
file is never paired with a token from another (that would send a production
token to a local instance, or the other way round). ``LINEBREAK_GOV_CREDENTIALS=off``
turns the file lookup off; the environment alone counts then.

Nothing here talks to the network; it only answers "which values, and from
where", so a message can say where a token came from.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

BASE_URL = "LINEBREAK_GOVERNANCE_BASE_URL"
TOKEN = "LINEBREAK_GOVERNANCE_TOKEN"
#: The pipeline token ``publish`` has always read; same service, same bearer.
PIPELINE_TOKEN = "LINEBREAK_GOV_TOKEN"
PROJECT = "LINEBREAK_GOVERNANCE_PROJECT"
PROJECT_ALIAS = "LINEBREAK_GOV_PROJECT"

KEYS = (BASE_URL, TOKEN, PIPELINE_TOKEN, PROJECT, PROJECT_ALIAS)
_TOKEN_KEYS = (TOKEN, PIPELINE_TOKEN)

#: ``off`` (or ``0``/``false``/``no``) disables the file lookup.
DISABLE_ENV = "LINEBREAK_GOV_CREDENTIALS"

ENVIRONMENT = "environment"


def _home() -> Path:
    """The home directory the files are looked up in (a seam for tests)."""
    return Path.home()


def candidate_files(env: Mapping[str, str] | None = None, home: Path | None = None) -> list[Path]:
    """The credential files, in lookup order."""
    env = os.environ if env is None else env
    home = _home() if home is None else home
    xdg = (env.get("XDG_CONFIG_HOME") or "").strip()
    config = Path(xdg) if xdg else home / ".config"
    return [
        config / "linebreak" / "governance.env",
        config / "linebreak" / "governance-local.env",
        home / ".linebreak" / "env",
    ]


def parse_env_file(path: Path) -> dict[str, str]:
    """``KEY=value`` lines of one file. An unreadable file is empty: a missing
    credential is reported by the command that needed it, not here."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {}
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if key:
            out[key] = value
    return out


def _file_lookup_enabled(env: Mapping[str, str]) -> bool:
    return (env.get(DISABLE_ENV) or "").strip().lower() not in ("off", "0", "false", "no")


@dataclass(frozen=True)
class Credentials:
    base_url: str | None
    #: ``LINEBREAK_GOVERNANCE_TOKEN``, else ``LINEBREAK_GOV_TOKEN``.
    token: str | None
    project: str | None
    #: Where the file-provided values came from (a path), or ``environment``
    #: when every value came from variables; ``None`` when nothing was found.
    source: str | None

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.token)


def _first_file(env: Mapping[str, str], home: Path | None) -> tuple[Path | None, dict[str, str]]:
    if not _file_lookup_enabled(env):
        return None, {}
    for path in candidate_files(env, home):
        values = parse_env_file(path)
        if any((values.get(k) or "").strip() for k in _TOKEN_KEYS):
            return path, {k: values[k].strip() for k in KEYS if (values.get(k) or "").strip()}
    return None, {}


def merged(env: Mapping[str, str] | None = None, home: Path | None = None) -> dict[str, str]:
    """A copy of ``env`` with the governance keys it lacks filled from the
    first credential file that carries a token. A set variable always wins.
    Callers that already take an ``env`` mapping use this unchanged."""
    env = os.environ if env is None else env
    out = dict(env)
    _, values = _first_file(env, home)
    for key, value in values.items():
        if not (out.get(key) or "").strip():
            out[key] = value
    return out


def resolve(env: Mapping[str, str] | None = None, home: Path | None = None) -> Credentials:
    """The credentials in force and where they came from."""
    env = os.environ if env is None else env
    path, values = _first_file(env, home)

    def pick(*keys: str) -> tuple[str | None, bool]:
        for key in keys:
            value = (env.get(key) or "").strip()
            if value:
                return value, False
        for key in keys:
            if values.get(key):
                return values[key], True
        return None, False

    base, base_from_file = pick(BASE_URL)
    token, token_from_file = pick(TOKEN, PIPELINE_TOKEN)
    project, project_from_file = pick(PROJECT, PROJECT_ALIAS)
    if base_from_file or token_from_file or project_from_file:
        source = str(path)
    elif base or token or project:
        source = ENVIRONMENT
    else:
        source = None
    return Credentials(
        base_url=base.rstrip("/") if base else None,
        token=token,
        project=project,
        source=source,
    )


def describe_source(creds: Credentials) -> str:
    """``environment variables`` or the file, with ``~`` for the home."""
    if creds.source in (None, ENVIRONMENT):
        return "environment variables"
    try:
        return "~/" + Path(creds.source).relative_to(_home()).as_posix()
    except ValueError:
        return creds.source
