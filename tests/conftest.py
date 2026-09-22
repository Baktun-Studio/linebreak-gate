"""Shared fixtures for the gate suite."""

from __future__ import annotations

import pytest

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
)


@pytest.fixture(autouse=True)
def _no_ambient_identity(monkeypatch):
    for name in _IDENTITY_ENV:
        monkeypatch.delenv(name, raising=False)
