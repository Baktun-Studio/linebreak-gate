"""Identity resolution for sign-offs and overrides: governance token, then
the CI provider, then the typed name (client). A configured token that fails
never falls back silently."""

from __future__ import annotations

import pytest

from linebreak_gate import identity


def test_typed_name_is_a_client_identity():
    ident = identity.resolve("Ana Lopez <Ana@Example.com>", env={})
    assert ident.source == "client"
    assert ident.verified is False
    assert ident.subject == "Ana Lopez <Ana@Example.com>"
    assert ident.email == "ana@example.com"
    assert ident.record() is None  # a typed name carries no verified block


def test_no_identity_at_all_is_an_error():
    with pytest.raises(identity.IdentityError, match="--approver"):
        identity.resolve("  ", env={})


def test_github_actions_actor():
    env = {"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "ana-lopez", "GITHUB_ACTOR_ID": "12345"}
    ident = identity.resolve("ana@example.com", env=env)
    assert ident.source == "vcs" and ident.provider == "github"
    assert ident.subject == "github:ana-lopez"
    assert ident.login == "ana-lopez"
    assert ident.email == "12345+ana-lopez@users.noreply.github.com"
    assert ident.declared == "ana@example.com"  # the typed name is kept, not lost
    assert "github:ana-lopez" in ident.keys()
    assert ident.record() == {
        "provider": "github",
        "email": "12345+ana-lopez@users.noreply.github.com",
        "login": "ana-lopez",
    }


def test_github_actions_without_actor_id_has_no_email():
    env = {"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "ana-lopez"}
    ident = identity.from_vcs(env)
    assert ident.email is None and ident.subject == "github:ana-lopez"


def test_generic_ci_flag_alone_is_not_an_identity():
    assert identity.from_vcs({"CI": "true", "GITHUB_ACTOR": "ana"}) is None


def test_gitlab_ci_user():
    env = {"GITLAB_CI": "true", "GITLAB_USER_EMAIL": "ana@example.com", "GITLAB_USER_LOGIN": "ana"}
    ident = identity.from_vcs(env)
    assert ident.provider == "gitlab" and ident.subject == "ana@example.com"
    assert "gitlab:ana" in ident.keys()


def test_bitbucket_pipelines_triggerer():
    env = {"BITBUCKET_STEP_TRIGGERER_UUID": "{abc-123}"}
    ident = identity.from_vcs(env)
    assert ident.provider == "bitbucket" and ident.subject == "bitbucket:{abc-123}"


def test_azure_pipelines_requester():
    env = {
        "TF_BUILD": "True",
        "BUILD_REQUESTEDFOREMAIL": "ana@example.com",
        "BUILD_REQUESTEDFOR": "Ana",
    }
    ident = identity.from_vcs(env)
    assert ident.provider == "azure_devops" and ident.subject == "ana@example.com"


def test_declared_name_matching_the_verified_identity_is_not_repeated():
    env = {"GITLAB_CI": "true", "GITLAB_USER_EMAIL": "ana@example.com"}
    ident = identity.resolve("Ana <ana@example.com>", env=env)
    assert ident.declared is None


GOV_ENV = {
    "LINEBREAK_GOVERNANCE_BASE_URL": "https://gov.example/",
    "LINEBREAK_GOVERNANCE_TOKEN": "lbg_test",
}


def test_governance_identity_comes_from_v1_me():
    calls = []

    def fetch(base, token):
        calls.append((base, token))
        return 200, {"email": "ana@example.com", "roles": ["approver", "architect"]}

    ident = identity.resolve("typed", env=GOV_ENV, fetch_me=fetch)
    assert calls == [("https://gov.example", "lbg_test")]
    assert ident.source == "governance" and ident.verified
    assert ident.subject == "ana@example.com"
    assert ident.roles == ("approver", "architect")
    assert ident.declared == "typed"


def test_governance_wins_over_ci_identity():
    env = {**GOV_ENV, "GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "ana"}
    ident = identity.resolve(None, env=env, fetch_me=lambda b, t: (200, {"email": "g@x.com"}))
    assert ident.source == "governance"


def test_rejected_governance_token_never_falls_back():
    with pytest.raises(identity.IdentityError, match="401"):
        identity.resolve("typed", env=GOV_ENV, fetch_me=lambda b, t: (401, {}))


def test_unreachable_governance_service_never_falls_back():
    def fetch(base, token):
        raise identity.IdentityError("governance service unreachable")

    with pytest.raises(identity.IdentityError, match="unreachable"):
        identity.resolve("typed", env=GOV_ENV, fetch_me=fetch)


def test_governance_answer_without_email_is_an_error():
    with pytest.raises(identity.IdentityError, match="no email"):
        identity.resolve("typed", env=GOV_ENV, fetch_me=lambda b, t: (200, {"roles": []}))
