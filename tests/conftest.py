"""Suite-wide guards."""

from __future__ import annotations

import pytest

from linebreak_gate import exploit_intel, governance_env

#: The variables that make `signoff` / `override` resolve a verified identity
#: (identity.py). The suite itself runs on GitHub Actions, where GITHUB_ACTOR
#: is set: without clearing these, every test that records an approval under
#: a typed --approver would instead sign as `github:<actor>` in CI and pass or
#: fail depending on where it runs. Tests that want a CI identity set the
#: variables explicitly.
_IDENTITY_ENV = (
    "GITHUB_ACTIONS",
    "GITHUB_ACTOR",
    "GITHUB_ACTOR_ID",
    "GITLAB_CI",
    "GITLAB_USER_EMAIL",
    "GITLAB_USER_LOGIN",
    "BITBUCKET_STEP_TRIGGERER_UUID",
    "TF_BUILD",
    "BUILD_REQUESTEDFOREMAIL",
    "BUILD_REQUESTEDFOR",
    "LINEBREAK_GOVERNANCE_BASE_URL",
    "LINEBREAK_GOVERNANCE_TOKEN",
    "LINEBREAK_GOV_TOKEN",
    "LINEBREAK_GOVERNANCE_PROJECT",
    "LINEBREAK_GOV_PROJECT",
    "LINEBREAK_GOV_CREDENTIALS",
    "XDG_CONFIG_HOME",
)


@pytest.fixture(autouse=True)
def _no_ambient_identity(monkeypatch):
    for name in _IDENTITY_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_home_credentials(monkeypatch, tmp_path_factory):
    """The governance credentials are also looked up in files under the home
    directory (governance_env). The suite never reads the developer's real
    ones: the lookup points at an empty directory; tests that exercise the
    files write their own and pass ``home`` explicitly."""
    empty = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(governance_env, "_home", lambda: empty)


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """The suite never touches FIRST or CISA: every scan runs as if offline.
    Tests that simulate the feeds clear this and inject a fake ``fetch``."""
    monkeypatch.setenv(exploit_intel.OFFLINE_ENV, "1")
