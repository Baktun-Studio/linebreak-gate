"""One reader for every CI provider: GitHub Actions, GitLab CI, Bitbucket
Pipelines, Azure Pipelines, and the local shell."""

import json

import pytest

from linebreak_gate import ci_env

# ---------------------------------------------------------------- GitHub


def test_github_pull_request():
    env = ci_env.detect(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "acme/backend",
            "GITHUB_SHA": "abc123",
            "GITHUB_REF": "refs/pull/42/merge",
            "GITHUB_REF_NAME": "42/merge",
            "GITHUB_HEAD_REF": "feat/S1-login",
            "GITHUB_BASE_REF": "main",
            "GITHUB_ACTOR": "ana",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_RUN_ID": "77",
        }
    )
    assert env.provider == "github"
    assert env.repo == "acme/backend"
    assert env.commit == "abc123"
    assert env.branch == "feat/S1-login"
    assert env.target_branch == "main"
    assert env.pr_number == 42
    assert env.is_pr is True
    assert env.stage == "pr"
    assert env.actor == "ana"
    assert env.build_url == "https://github.com/acme/backend/actions/runs/77"
    assert env.is_default_branch is False


def test_github_push_reads_default_branch_from_event_payload(tmp_path):
    payload = tmp_path / "event.json"
    payload.write_text(json.dumps({"repository": {"default_branch": "develop"}}))
    env = ci_env.detect(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "acme/backend",
            "GITHUB_REF": "refs/heads/develop",
            "GITHUB_REF_NAME": "develop",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_EVENT_PATH": str(payload),
        }
    )
    assert env.pr_number is None
    assert env.branch == "develop"
    assert env.default_branch == "develop"
    assert env.is_default_branch is True
    assert env.stage == "release"


def test_github_pull_request_target_takes_number_from_payload(tmp_path):
    payload = tmp_path / "event.json"
    payload.write_text(json.dumps({"pull_request": {"number": 9}}))
    env = ci_env.detect(
        {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_EVENT_PATH": str(payload),
        }
    )
    assert env.pr_number == 9


def test_github_unreadable_payload_is_not_an_error(tmp_path):
    env = ci_env.detect(
        {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_PATH": str(tmp_path / "missing.json")}
    )
    assert env.provider == "github"
    assert env.default_branch is None


# ---------------------------------------------------------------- GitLab


def test_gitlab_merge_request():
    env = ci_env.detect(
        {
            "GITLAB_CI": "true",
            "CI_PROJECT_PATH": "acme/backend",
            "CI_COMMIT_SHA": "def456",
            "CI_COMMIT_REF_NAME": "feat/S2",
            "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME": "feat/S2",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main",
            "CI_MERGE_REQUEST_IID": "7",
            "CI_DEFAULT_BRANCH": "main",
            "GITLAB_USER_LOGIN": "ana",
            "CI_SERVER_URL": "https://gitlab.example.com",
            "CI_JOB_URL": "https://gitlab.example.com/acme/backend/-/jobs/1",
        }
    )
    assert env.provider == "gitlab"
    assert (env.repo, env.commit, env.branch, env.target_branch) == (
        "acme/backend",
        "def456",
        "feat/S2",
        "main",
    )
    assert env.pr_number == 7
    assert env.actor == "ana"
    assert env.default_branch == "main"


def test_gitlab_default_branch_push():
    env = ci_env.detect(
        {
            "GITLAB_CI": "true",
            "CI_COMMIT_BRANCH": "main",
            "CI_COMMIT_REF_NAME": "main",
            "CI_DEFAULT_BRANCH": "main",
            "CI_COMMIT_AUTHOR": "Ana <ana@example.com>",
        }
    )
    assert env.is_pr is False
    assert env.is_default_branch is True
    assert env.actor == "Ana <ana@example.com>"


# ---------------------------------------------------------------- Bitbucket


BITBUCKET_PR = {
    "BITBUCKET_BUILD_NUMBER": "12",
    "BITBUCKET_REPO_FULL_NAME": "acme-ws/backend",
    "BITBUCKET_WORKSPACE": "acme-ws",
    "BITBUCKET_REPO_SLUG": "backend",
    "BITBUCKET_COMMIT": "0123456789abcdef",
    "BITBUCKET_BRANCH": "feat/S1",
    "BITBUCKET_PR_ID": "5",
    "BITBUCKET_PR_DESTINATION_BRANCH": "main",
    "BITBUCKET_STEP_TRIGGERER_UUID": "{aaaa-bbbb}",
    "BITBUCKET_PIPELINE_UUID": "{pipe}",
    "BITBUCKET_STEP_UUID": "{step}",
}


def test_bitbucket_pull_request():
    env = ci_env.detect(BITBUCKET_PR)
    assert env.provider == "bitbucket"
    assert env.repo == "acme-ws/backend"
    assert env.commit == "0123456789abcdef"
    assert env.branch == "feat/S1"
    assert env.target_branch == "main"
    assert env.pr_number == 5
    assert env.is_pr is True
    assert env.actor == "{aaaa-bbbb}"
    assert env.server_url == "https://api.bitbucket.org/2.0"
    assert env.build_url == "https://bitbucket.org/acme-ws/backend/pipelines/results/12"
    assert env.details["workspace"] == "acme-ws"
    assert env.details["repo_slug"] == "backend"
    assert env.details["triggerer_uuid"] == "{aaaa-bbbb}"
    # Bitbucket names no default branch: unknown, never guessed.
    assert env.default_branch is None


def test_bitbucket_branch_push_has_no_pr_and_unknown_default_branch():
    e = dict(BITBUCKET_PR)
    del e["BITBUCKET_PR_ID"]
    del e["BITBUCKET_PR_DESTINATION_BRANCH"]
    e["BITBUCKET_BRANCH"] = "main"
    env = ci_env.detect(e)
    assert env.is_pr is False
    assert env.stage == "release"
    assert env.is_default_branch is None


def test_bitbucket_workspace_and_slug_derived_from_full_name():
    env = ci_env.detect(
        {"BITBUCKET_COMMIT": "abc", "BITBUCKET_REPO_FULL_NAME": "ws/repo", "BITBUCKET_PR_ID": "1"}
    )
    assert env.details["workspace"] == "ws"
    assert env.details["repo_slug"] == "repo"


def test_bitbucket_api_url_override():
    env = ci_env.detect({**BITBUCKET_PR, "BITBUCKET_API_URL": "http://localhost:8080/2.0/"})
    assert env.server_url == "http://localhost:8080/2.0"


# ---------------------------------------------------------------- Azure DevOps


AZURE_PR = {
    "TF_BUILD": "True",
    "SYSTEM_PULLREQUEST_PULLREQUESTID": "31",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH": "refs/heads/feat/S1",
    "SYSTEM_PULLREQUEST_TARGETBRANCH": "refs/heads/main",
    "SYSTEM_PULLREQUEST_SOURCECOMMITID": "headsha",
    "BUILD_SOURCEVERSION": "mergesha",
    "BUILD_SOURCEBRANCH": "refs/pull/31/merge",
    "BUILD_SOURCEBRANCHNAME": "merge",
    "BUILD_REPOSITORY_NAME": "backend",
    "BUILD_REPOSITORY_ID": "repo-guid",
    "BUILD_REPOSITORY_PROVIDER": "TfsGit",
    "SYSTEM_TEAMPROJECT": "Core Banking",
    "SYSTEM_COLLECTIONURI": "https://dev.azure.com/acme/",
    "BUILD_REQUESTEDFOREMAIL": "ana@example.com",
    "BUILD_REQUESTEDFOR": "Ana",
    "BUILD_BUILDID": "900",
}


def test_azure_pull_request():
    env = ci_env.detect(AZURE_PR)
    assert env.provider == "azure"
    assert env.repo == "backend"
    assert env.commit == "mergesha"
    assert env.branch == "feat/S1"
    assert env.target_branch == "main"
    assert env.pr_number == 31
    assert env.is_pr is True
    assert env.actor == "ana@example.com"
    assert env.server_url == "https://dev.azure.com/acme"
    assert env.build_url == "https://dev.azure.com/acme/Core%20Banking/_build/results?buildId=900"
    assert env.details["project"] == "Core Banking"
    assert env.details["repository_id"] == "repo-guid"
    assert env.details["source_commit"] == "headsha"
    assert env.details["repository_provider"] == "TfsGit"


def test_azure_branch_build_strips_refs_heads():
    e = {
        "TF_BUILD": "true",
        "BUILD_SOURCEBRANCH": "refs/heads/release/2026.09",
        "BUILD_SOURCEVERSION": "sha",
        "BUILD_REPOSITORY_NAME": "backend",
        "BUILD_REQUESTEDFOR": "Ana",
    }
    env = ci_env.detect(e)
    assert env.branch == "release/2026.09"
    assert env.pr_number is None
    assert env.actor == "Ana"
    assert env.build_url is None


def test_azure_github_sourced_pr_number():
    env = ci_env.detect({"TF_BUILD": "True", "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER": "8"})
    assert env.pr_number == 8


# ---------------------------------------------------------------- local + actor


def test_local_when_no_provider_marker():
    env = ci_env.detect({"USER": "vlad", "PATH": "/bin"})
    assert env.provider == "local"
    assert env.actor == "vlad"
    assert env.is_pr is False
    assert env.is_default_branch is None
    assert "local" in env.label


def test_provider_markers_are_exclusive_in_order():
    # A shell with leftover GITHUB_ACTIONS wins over Bitbucket variables; the
    # marker decides, never the presence of another provider's names.
    env = ci_env.detect({"GITHUB_ACTIONS": "true", **BITBUCKET_PR})
    assert env.provider == "github"


@pytest.mark.parametrize(
    "environ, expected",
    [
        ({"GITHUB_ACTIONS": "true", "GITHUB_ACTOR": "gh-ana", "USER": "shell"}, "gh-ana"),
        ({"GITLAB_CI": "true", "GITLAB_USER_LOGIN": "gl-ana"}, "gl-ana"),
        ({**BITBUCKET_PR}, "{aaaa-bbbb}"),
        ({**AZURE_PR}, "ana@example.com"),
        ({"USERNAME": "win-ana"}, "win-ana"),
    ],
)
def test_actor_prefers_the_provider_then_the_shell(environ, expected):
    assert ci_env.actor(environ) == expected


def test_actor_never_raises_without_any_hint(monkeypatch):
    monkeypatch.setattr(ci_env.getpass, "getuser", lambda: (_ for _ in ()).throw(OSError()))
    assert ci_env.actor({}) == "unknown"


def test_non_numeric_pr_ids_are_ignored():
    assert ci_env.detect({"BITBUCKET_COMMIT": "a", "BITBUCKET_PR_ID": "n/a"}).pr_number is None
