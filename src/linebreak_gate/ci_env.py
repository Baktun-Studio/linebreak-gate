"""Where is the gate running? One reader for every CI provider's environment.

GitHub Actions, GitLab CI, Bitbucket Pipelines and Azure Pipelines each
describe a build with their own variables. Everything in the gate that needs
the repository, the commit, the branch, the pull request number or the acting
user goes through :func:`detect`, never through loose ``os.environ`` lookups,
so supporting a new provider is one function here and nothing anywhere else.

Detection keys on the provider's own marker variable (``GITHUB_ACTIONS``,
``GITLAB_CI``, ``BITBUCKET_BUILD_NUMBER``, ``TF_BUILD``); a shell with none of
them is ``local``. Values are read as given and never validated over the
network: this module has no side effects and no I/O beyond the optional GitHub
event payload file.
"""

from __future__ import annotations

import getpass
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

PROVIDERS = ("github", "gitlab", "bitbucket", "azure", "local")

#: Human labels for messages.
PROVIDER_LABELS = {
    "github": "GitHub Actions",
    "gitlab": "GitLab CI",
    "bitbucket": "Bitbucket Pipelines",
    "azure": "Azure Pipelines",
    "local": "local shell (no CI provider detected)",
}

BITBUCKET_API_URL = "https://api.bitbucket.org/2.0"


@dataclass(frozen=True)
class CiEnv:
    """What the CI provider told us about this build. ``None`` means the
    provider did not say (a tag build has no branch, a push has no PR)."""

    provider: str
    repo: str | None = None
    commit: str | None = None
    branch: str | None = None
    target_branch: str | None = None
    default_branch: str | None = None
    pr_number: int | None = None
    actor: str | None = None
    server_url: str | None = None
    build_url: str | None = None
    #: Provider-specific identifiers the reporters need (Bitbucket workspace
    #: and slug, Azure project and repository id, ...). Strings only.
    details: Mapping[str, str] = field(default_factory=dict)

    @property
    def is_pr(self) -> bool:
        return self.pr_number is not None

    @property
    def is_default_branch(self) -> bool | None:
        """True on a non-PR build of the default branch, False on any other
        non-PR build, None when the provider does not name a default branch
        (Bitbucket and Azure do not; GitHub only via the event payload)."""
        if self.is_pr:
            return False
        if self.default_branch is None or self.branch is None:
            return None
        return self.branch == self.default_branch

    @property
    def stage(self) -> str:
        """The check stage this build naturally is: ``pr`` on a pull request,
        ``release`` on everything else (a branch push, a tag)."""
        return "pr" if self.is_pr else "release"

    @property
    def label(self) -> str:
        return PROVIDER_LABELS.get(self.provider, self.provider)


# ---------------------------------------------------------------- helpers


def _get(env: Mapping[str, str], *names: str) -> str | None:
    for name in names:
        value = env.get(name)
        if value is not None and value.strip():
            return value.strip()
    return None


def _int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _strip_ref(ref: str | None) -> str | None:
    """``refs/heads/feat/x`` -> ``feat/x``; ``refs/tags/v1`` -> ``v1``; a bare
    name is returned as is. ``refs/pull/N/merge`` is left alone (it is not a
    branch and the caller prefers the PR source branch anyway)."""
    if ref is None:
        return None
    for prefix in ("refs/heads/", "refs/tags/"):
        if ref.startswith(prefix):
            return ref[len(prefix) :]
    return ref


def _read_github_event(path: str | None) -> dict:
    """The GitHub event payload, or {} when absent or unreadable: the payload
    is a convenience for the default branch and the PR number, never a
    requirement."""
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------- providers


def _github(env: Mapping[str, str]) -> CiEnv:
    ref = _get(env, "GITHUB_REF") or ""
    m = re.match(r"refs/pull/(\d+)/", ref)
    pr = int(m.group(1)) if m else None
    event = _read_github_event(env.get("GITHUB_EVENT_PATH"))
    if pr is None:
        pull = event.get("pull_request")
        if isinstance(pull, dict):
            pr = _int(str(pull.get("number"))) if pull.get("number") is not None else None
    repository = event.get("repository")
    default = None
    if isinstance(repository, dict) and repository.get("default_branch"):
        default = str(repository["default_branch"])
    server = _get(env, "GITHUB_SERVER_URL") or "https://github.com"
    repo = _get(env, "GITHUB_REPOSITORY")
    run_id = _get(env, "GITHUB_RUN_ID")
    build_url = f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else None
    return CiEnv(
        provider="github",
        repo=repo,
        commit=_get(env, "GITHUB_SHA"),
        branch=_get(env, "GITHUB_HEAD_REF") or _get(env, "GITHUB_REF_NAME"),
        target_branch=_get(env, "GITHUB_BASE_REF"),
        default_branch=default,
        pr_number=pr,
        actor=_get(env, "GITHUB_ACTOR"),
        server_url=server,
        build_url=build_url,
        details={
            k: v
            for k, v in {
                "event_name": _get(env, "GITHUB_EVENT_NAME"),
                "run_id": run_id,
                "api_url": _get(env, "GITHUB_API_URL"),
            }.items()
            if v
        },
    )


def _gitlab(env: Mapping[str, str]) -> CiEnv:
    return CiEnv(
        provider="gitlab",
        repo=_get(env, "CI_PROJECT_PATH"),
        commit=_get(env, "CI_COMMIT_SHA"),
        branch=_get(env, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
        or _get(env, "CI_COMMIT_BRANCH", "CI_COMMIT_REF_NAME"),
        target_branch=_get(env, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME"),
        default_branch=_get(env, "CI_DEFAULT_BRANCH"),
        pr_number=_int(_get(env, "CI_MERGE_REQUEST_IID")),
        actor=_get(env, "GITLAB_USER_LOGIN", "GITLAB_USER_EMAIL", "CI_COMMIT_AUTHOR"),
        server_url=_get(env, "CI_SERVER_URL"),
        build_url=_get(env, "CI_JOB_URL"),
        details={
            k: v
            for k, v in {
                "project_id": _get(env, "CI_PROJECT_ID"),
                "api_url": _get(env, "CI_API_V4_URL"),
            }.items()
            if v
        },
    )


def _bitbucket(env: Mapping[str, str]) -> CiEnv:
    workspace = _get(env, "BITBUCKET_WORKSPACE")
    slug = _get(env, "BITBUCKET_REPO_SLUG")
    repo = _get(env, "BITBUCKET_REPO_FULL_NAME")
    if repo is None and workspace and slug:
        repo = f"{workspace}/{slug}"
    if repo and (workspace is None or slug is None) and "/" in repo:
        workspace, slug = repo.split("/", 1)
    build_number = _get(env, "BITBUCKET_BUILD_NUMBER")
    build_url = (
        f"https://bitbucket.org/{repo}/pipelines/results/{build_number}"
        if repo and build_number
        else None
    )
    details = {
        k: v
        for k, v in {
            "workspace": workspace,
            "repo_slug": slug,
            "build_number": build_number,
            "pipeline_uuid": _get(env, "BITBUCKET_PIPELINE_UUID"),
            "step_uuid": _get(env, "BITBUCKET_STEP_UUID"),
            "repo_uuid": _get(env, "BITBUCKET_REPO_UUID"),
            "triggerer_uuid": _get(env, "BITBUCKET_STEP_TRIGGERER_UUID"),
        }.items()
        if v
    }
    return CiEnv(
        provider="bitbucket",
        repo=repo,
        commit=_get(env, "BITBUCKET_COMMIT"),
        branch=_get(env, "BITBUCKET_BRANCH"),
        target_branch=_get(env, "BITBUCKET_PR_DESTINATION_BRANCH"),
        default_branch=None,
        pr_number=_int(_get(env, "BITBUCKET_PR_ID")),
        # Pipelines exposes the triggering user as a UUID only (no login).
        actor=_get(env, "BITBUCKET_STEP_TRIGGERER_UUID"),
        server_url=(_get(env, "BITBUCKET_API_URL") or BITBUCKET_API_URL).rstrip("/"),
        build_url=build_url,
        details=details,
    )


def _azure(env: Mapping[str, str]) -> CiEnv:
    collection = _get(env, "SYSTEM_COLLECTIONURI")
    project = _get(env, "SYSTEM_TEAMPROJECT")
    build_id = _get(env, "BUILD_BUILDID")
    build_url = (
        f"{collection.rstrip('/')}/{quote(project, safe='')}/_build/results?buildId={build_id}"
        if collection and project and build_id
        else None
    )
    # On a PR build BUILD_SOURCEVERSION is the merge commit the agent built
    # (what the gate scanned); the PR head is kept in details.source_commit.
    details = {
        k: v
        for k, v in {
            "project": project,
            "project_id": _get(env, "SYSTEM_TEAMPROJECTID"),
            "repository_id": _get(env, "BUILD_REPOSITORY_ID"),
            "repository_provider": _get(env, "BUILD_REPOSITORY_PROVIDER"),
            "collection_uri": collection,
            "build_id": build_id,
            "source_commit": _get(env, "SYSTEM_PULLREQUEST_SOURCECOMMITID"),
            "requested_for": _get(env, "BUILD_REQUESTEDFOR"),
        }.items()
        if v
    }
    return CiEnv(
        provider="azure",
        repo=_get(env, "BUILD_REPOSITORY_NAME"),
        commit=_get(env, "BUILD_SOURCEVERSION"),
        branch=_strip_ref(_get(env, "SYSTEM_PULLREQUEST_SOURCEBRANCH"))
        or _strip_ref(_get(env, "BUILD_SOURCEBRANCH")),
        target_branch=_strip_ref(_get(env, "SYSTEM_PULLREQUEST_TARGETBRANCH")),
        default_branch=None,
        pr_number=_int(
            _get(env, "SYSTEM_PULLREQUEST_PULLREQUESTID", "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")
        ),
        actor=_get(env, "BUILD_REQUESTEDFOREMAIL", "BUILD_REQUESTEDFOR"),
        server_url=collection.rstrip("/") if collection else None,
        build_url=build_url,
        details=details,
    )


def _local(env: Mapping[str, str]) -> CiEnv:
    return CiEnv(provider="local", actor=_get(env, "USER", "USERNAME"))


def _is_true(value: str | None) -> bool:
    return (value or "").strip().lower() in ("true", "1", "yes")


def detect(env: Mapping[str, str] | None = None) -> CiEnv:
    """Read the CI provider's environment (``os.environ`` by default). Never
    raises: an unknown or empty environment is ``provider="local"``."""
    e = os.environ if env is None else env
    if _is_true(e.get("GITHUB_ACTIONS")):
        return _github(e)
    if _is_true(e.get("GITLAB_CI")):
        return _gitlab(e)
    if _get(e, "BITBUCKET_BUILD_NUMBER", "BITBUCKET_COMMIT", "BITBUCKET_REPO_FULL_NAME"):
        return _bitbucket(e)
    if _is_true(e.get("TF_BUILD")):
        return _azure(e)
    return _local(e)


def actor(env: Mapping[str, str] | None = None) -> str:
    """The acting user for audit records: the provider's actor, else the
    shell's user, else ``unknown``. Never raises."""
    e = os.environ if env is None else env
    found = detect(e).actor or _get(e, "USER", "USERNAME")
    if found:
        return found
    try:
        return getpass.getuser()
    except (OSError, ImportError, KeyError):
        return "unknown"
