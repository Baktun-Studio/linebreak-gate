"""`linebreak-gate init` — one command produces the whole client setup:
workflow file, optional gate.yml, secrets via gh, branch-protection offer."""

from pathlib import Path

import pytest

from linebreak_gate import init_cmd
from linebreak_gate.cli import main
from linebreak_gate.gate_config import resolve_config

WORKFLOW_RELPATH = Path(".github/workflows/security-gate.yml")


class _Recorder:
    """Fake subprocess.run capturing invocations."""

    def __init__(self, responses=None):
        self.calls = []
        self._responses = responses or {}

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))

        class P:
            returncode = 0
            stdout = ""
            stderr = ""

        proc = P()
        for prefix, (code, out) in self._responses.items():
            if " ".join(cmd).startswith(prefix):
                proc.returncode = code
                proc.stdout = out
        return proc


def _git_repo(tmp_path, origin="git@github.com:acme/backend.git"):
    responses = (
        {"git config --get": (0, origin + "\n")} if origin else {"git config --get": (1, "")}
    )
    return _Recorder(responses)


def test_init_writes_workflow_file(tmp_path):
    rc = init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path), which=lambda n: None, interactive=False
    )
    assert rc == 0
    content = (tmp_path / WORKFLOW_RELPATH).read_text()
    assert "Baktun-Studio/linebreak-gate@v1" in content
    assert "pull-requests: write" in content
    assert "ANTHROPIC_API_KEY" in content
    assert "@main" not in content


def test_init_is_idempotent_without_force(tmp_path, capsys):
    init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path), which=lambda n: None, interactive=False
    )
    (tmp_path / WORKFLOW_RELPATH).write_text("CUSTOMIZED BY CLIENT\n")
    rc = init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path), which=lambda n: None, interactive=False
    )
    assert rc == 0
    # Never clobber a client's customized workflow.
    assert (tmp_path / WORKFLOW_RELPATH).read_text() == "CUSTOMIZED BY CLIENT\n"
    assert "already exists" in capsys.readouterr().out


def test_init_force_overwrites(tmp_path):
    init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path), which=lambda n: None, interactive=False
    )
    (tmp_path / WORKFLOW_RELPATH).write_text("OLD\n")
    init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path), which=lambda n: None, interactive=False, force=True
    )
    assert "linebreak-gate@v1" in (tmp_path / WORKFLOW_RELPATH).read_text()


def test_init_fail_on_writes_gate_yml(tmp_path):
    init_cmd.run_init(
        path=tmp_path,
        run=_git_repo(tmp_path),
        which=lambda n: None,
        interactive=False,
        fail_on="high",
    )
    assert resolve_config(tmp_path).fail_on == "high"


@pytest.mark.parametrize(
    "origin",
    [
        "git@github.com:acme/backend.git",
        "https://github.com/acme/backend.git",
        "https://github.com/acme/backend",
        "ssh://git@github.com/acme/backend.git",
    ],
)
def test_parse_github_remote(origin):
    assert init_cmd._parse_github_remote(origin) == ("acme", "backend")


def test_next_steps_suggest_the_readme_badge(tmp_path, capsys):
    init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path), which=lambda n: None, interactive=False
    )
    assert "linebreak-gate badge" in capsys.readouterr().out


def test_deep_links_printed_without_gh(tmp_path, capsys):
    init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path), which=lambda n: None, interactive=False
    )
    out = capsys.readouterr().out
    assert "https://github.com/acme/backend/settings/secrets/actions" in out
    assert "https://github.com/acme/backend/settings/branches" in out


def test_secrets_set_via_gh_when_interactive(tmp_path):
    run = _git_repo(tmp_path)
    prompts = iter(["sk-ant-test-key", ""])  # anthropic key given, license key skipped
    confirms = iter(["n"])  # decline branch protection
    rc = init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: next(prompts),
        confirm_fn=lambda msg: next(confirms) == "y",
    )
    assert rc == 0
    secret_calls = [c for c, _ in run.calls if c[:3] == ["gh", "secret", "set"]]
    assert len(secret_calls) == 1
    assert "ANTHROPIC_API_KEY" in secret_calls[0]
    assert "--repo" in secret_calls[0] and "acme/backend" in secret_calls[0]
    # The secret value goes via stdin, never argv.
    kwargs = [k for c, k in run.calls if c[:3] == ["gh", "secret", "set"]][0]
    assert kwargs.get("input") == "sk-ant-test-key"


def test_branch_protection_offer_accepted(tmp_path):
    run = _git_repo(tmp_path)
    rc = init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: "",
        confirm_fn=lambda msg: True,
    )
    assert rc == 0
    api_calls = [c for c, _ in run.calls if c[:2] == ["gh", "api"]]
    assert any("required_status_checks/contexts" in " ".join(c) for c in api_calls)


def test_branch_protection_failure_falls_back_to_link(tmp_path, capsys):
    run = _Recorder(
        {
            "git config --get": (0, "git@github.com:acme/backend.git\n"),
            "gh api": (1, ""),  # no protection rule yet -> API fails
        }
    )
    rc = init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: "",
        confirm_fn=lambda msg: True,
    )
    assert rc == 0  # a protection hiccup must not fail the setup
    assert "settings/branches" in capsys.readouterr().out


def test_no_remote_still_writes_files(tmp_path, capsys):
    rc = init_cmd.run_init(
        path=tmp_path, run=_git_repo(tmp_path, origin=None), which=lambda n: None, interactive=False
    )
    assert rc == 0
    assert (tmp_path / WORKFLOW_RELPATH).exists()
    assert "could not detect" in capsys.readouterr().out.lower()


def test_cli_routes_init(tmp_path, monkeypatch):
    called = {}

    def fake_run_init(**kwargs):
        called.update(kwargs)
        return 0

    monkeypatch.setattr(init_cmd, "run_init", fake_run_init)
    assert main(["init", "--path", str(tmp_path), "--fail-on", "high"]) == 0
    assert called["fail_on"] == "high"


def test_workflow_template_matches_readme_quickstart():
    """The snippet init writes and the README quickstart must be ONE snippet —
    drift here means new clients scaffold a different workflow than the docs
    show."""
    readme = (Path(__file__).parent.parent / "README.md").read_text()
    fence = "```yaml\n# .github/workflows/security-gate.yml\n"
    start = readme.index(fence) + len(fence)
    end = readme.index("```", start)
    assert readme[start:end] == init_cmd.WORKFLOW_TEMPLATE


def test_run_init_validates_fail_on():
    with pytest.raises(Exception, match="fail"):
        init_cmd.run_init(
            path=".", fail_on="hgih", interactive=False, run=_Recorder(), which=lambda n: None
        )


def test_token_embedded_https_remote_parses():
    # The URL every CI checkout leaves on origin.
    assert init_cmd._parse_github_remote(
        "https://x-access-token:ghs_abc123@github.com/acme/backend.git"
    ) == ("acme", "backend")
    assert init_cmd._parse_github_remote("git@github.com:Acme/Backend.GIT") == ("Acme", "Backend")
    assert init_cmd._parse_github_remote("ssh://git@github.com:22/acme/backend.git") == (
        "acme",
        "backend",
    )


def test_protection_targets_default_branch(tmp_path):
    run = _Recorder(
        {
            "git config --get": (0, "git@github.com:acme/backend.git\n"),
            "gh api repos/acme/backend --jq": (0, "develop\n"),
        }
    )
    init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: "",
        confirm_fn=lambda msg: True,
    )
    protection_calls = [
        " ".join(c) for c, _ in run.calls if "required_status_checks/contexts" in " ".join(c)
    ]
    assert protection_calls and "branches/develop/" in protection_calls[0]


def test_cli_routes_init_forwards_all_flags(tmp_path, monkeypatch):
    called = {}
    monkeypatch.setattr(init_cmd, "run_init", lambda **kw: called.update(kw) or 0)
    assert (
        main(["init", "--path", str(tmp_path), "--fail-on", "high", "--force", "--non-interactive"])
        == 0
    )
    assert called["path"] == str(tmp_path)
    assert called["fail_on"] == "high"
    assert called["force"] is True
    assert called["interactive"] is False


def test_non_admin_gets_owner_handoff_instead_of_prompts(tmp_path, capsys):
    """A write-but-not-admin account must be told UP FRONT that steps 2-3 will
    404 for them, with a ready-to-send message for the repo owner — never
    walked into prompts that can only fail."""
    run = _Recorder(
        {
            "git config --get": (0, "git@github.com:acme/backend.git\n"),
            "gh api repos/acme/backend --jq": (0, "false true\n"),
        }
    )
    rc = init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: pytest.fail("must not prompt a non-admin"),
        confirm_fn=lambda msg: pytest.fail("must not prompt a non-admin"),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "NOT the admin role" in out
    assert "settings/secrets/actions" in out and "settings/branches" in out
    # The workflow file still gets written — step 1 only needs write access.
    assert (tmp_path / WORKFLOW_RELPATH).exists()


def test_read_only_account_gets_accurate_wording(tmp_path, capsys):
    run = _Recorder(
        {
            "git config --get": (0, "git@github.com:acme/backend.git\n"),
            "gh api repos/acme/backend --jq": (0, "false false\n"),
        }
    )
    rc = init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: pytest.fail("must not prompt"),
        confirm_fn=lambda msg: pytest.fail("must not prompt"),
    )
    assert rc == 0
    assert "read-only access" in capsys.readouterr().out


def test_admin_account_flows_normally(tmp_path):
    run = _Recorder(
        {
            "git config --get": (0, "git@github.com:acme/backend.git\n"),
            "gh api repos/acme/backend --jq": (0, "true true\n"),
        }
    )
    prompts = iter(["", ""])
    rc = init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: next(prompts),
        confirm_fn=lambda msg: False,
    )
    assert rc == 0


def test_permission_check_failure_does_not_block(tmp_path):
    # Offline / weird gh output -> proceed as before, never a false lockout.
    run = _Recorder({"git config --get": (0, "git@github.com:acme/backend.git\n")})
    prompts = iter(["", ""])
    rc = init_cmd.run_init(
        path=tmp_path,
        run=run,
        which=lambda n: "/usr/bin/gh" if n == "gh" else None,
        interactive=True,
        prompt_fn=lambda msg: next(prompts),
        confirm_fn=lambda msg: False,
    )
    assert rc == 0


# ---------------------------------------------------------------- Bitbucket + Azure (1.13)


@pytest.mark.parametrize(
    "origin",
    [
        "git@bitbucket.org:acme-ws/backend.git",
        "https://ana@bitbucket.org/acme-ws/backend.git",
        "https://bitbucket.org/acme-ws/backend",
        "ssh://git@bitbucket.org/acme-ws/backend.git",
    ],
)
def test_parse_bitbucket_remote(origin):
    remote = init_cmd.parse_remote(origin)
    assert remote == init_cmd.Remote("bitbucket", "acme-ws", "backend")
    assert remote.slug == "acme-ws/backend"


@pytest.mark.parametrize(
    "origin",
    [
        "https://acme@dev.azure.com/acme/Core/_git/backend",
        "https://dev.azure.com/acme/Core/_git/backend",
        "git@ssh.dev.azure.com:v3/acme/Core/backend",
        "https://acme.visualstudio.com/Core/_git/backend",
        "https://acme.visualstudio.com/DefaultCollection/Core/_git/backend",
    ],
)
def test_parse_azure_remote(origin):
    assert init_cmd.parse_remote(origin) == init_cmd.Remote("azure", "acme", "backend", "Core")


def test_parse_remote_github_and_unknown():
    assert init_cmd.parse_remote("git@github.com:acme/backend.git") == init_cmd.Remote(
        "github", "acme", "backend"
    )
    assert init_cmd.parse_remote("git@git.example.com:acme/backend.git") is None
    assert init_cmd.parse_remote("") is None


def test_bitbucket_remote_writes_only_the_pipelines_file_with_deep_links(tmp_path, capsys):
    rc = init_cmd.run_init(
        path=tmp_path,
        run=_git_repo(tmp_path, origin="git@bitbucket.org:acme-ws/backend.git"),
        which=lambda n: None,
        interactive=False,
    )
    assert rc == 0
    assert (tmp_path / "bitbucket-pipelines.yml").exists()
    assert not (tmp_path / WORKFLOW_RELPATH).exists()
    assert not (tmp_path / "azure-pipelines.yml").exists()
    out = capsys.readouterr().out
    assert "https://bitbucket.org/acme-ws/backend/admin/pipelines/repository-variables" in out
    assert "https://bitbucket.org/acme-ws/backend/admin/branch-restrictions" in out
    assert "BITBUCKET_ACCESS_TOKEN" in out
    assert "Premium" in out  # merge checks need the Premium plan; say so up front


def test_azure_remote_writes_only_the_pipelines_file_with_deep_links(tmp_path, capsys):
    rc = init_cmd.run_init(
        path=tmp_path,
        run=_git_repo(tmp_path, origin="https://acme@dev.azure.com/acme/Core/_git/backend"),
        which=lambda n: None,
        interactive=False,
    )
    assert rc == 0
    assert (tmp_path / "azure-pipelines.yml").exists()
    assert not (tmp_path / WORKFLOW_RELPATH).exists()
    out = capsys.readouterr().out
    assert "https://dev.azure.com/acme/Core/_git/backend/branches" in out
    assert "Contribute to pull requests" in out
    assert "Build validation" in out


def test_provider_all_writes_the_three_files(tmp_path):
    init_cmd.run_init(
        path=tmp_path,
        run=_git_repo(tmp_path),
        which=lambda n: None,
        interactive=False,
        provider="all",
    )
    assert (tmp_path / WORKFLOW_RELPATH).exists()
    assert (tmp_path / "bitbucket-pipelines.yml").exists()
    assert (tmp_path / "azure-pipelines.yml").exists()


def test_explicit_provider_wins_over_the_remote(tmp_path, capsys):
    init_cmd.run_init(
        path=tmp_path,
        run=_git_repo(tmp_path),  # a GitHub remote
        which=lambda n: None,
        interactive=False,
        provider="azure",
    )
    assert (tmp_path / "azure-pipelines.yml").exists()
    assert not (tmp_path / WORKFLOW_RELPATH).exists()
    # No Azure remote known: placeholders, never a GitHub link dressed as Azure.
    assert "https://dev.azure.com/<org>/<project>" in capsys.readouterr().out


def test_unknown_remote_defaults_to_github_and_says_how_to_get_the_others(tmp_path, capsys):
    init_cmd.run_init(
        path=tmp_path,
        run=_git_repo(tmp_path, origin="git@git.example.com:acme/backend.git"),
        which=lambda n: None,
        interactive=False,
    )
    assert (tmp_path / WORKFLOW_RELPATH).exists()
    assert "--provider bitbucket|azure|all" in capsys.readouterr().out


def test_pipeline_templates_are_idempotent_without_force(tmp_path, capsys):
    kwargs = dict(run=_git_repo(tmp_path), which=lambda n: None, interactive=False)
    init_cmd.run_init(path=tmp_path, provider="bitbucket", **kwargs)
    (tmp_path / "bitbucket-pipelines.yml").write_text("CUSTOM\n")
    init_cmd.run_init(path=tmp_path, provider="bitbucket", **kwargs)
    assert (tmp_path / "bitbucket-pipelines.yml").read_text() == "CUSTOM\n"
    init_cmd.run_init(path=tmp_path, provider="bitbucket", force=True, **kwargs)
    assert "linebreak-gate ci" in (tmp_path / "bitbucket-pipelines.yml").read_text()


def test_bitbucket_template_contents():
    t = init_cmd.BITBUCKET_PIPELINES_TEMPLATE
    assert "linebreak-gate ci" in t
    assert "osv-scanner" in t
    assert "pull-requests:" in t
    assert ".linebreak/ci-out/**" in t
    assert "BITBUCKET_ACCESS_TOKEN" in t
    assert "\t" not in t


def test_azure_template_contents():
    t = init_cmd.AZURE_PIPELINES_TEMPLATE
    assert "linebreak-gate ci" in t
    assert "SYSTEM_ACCESSTOKEN: $(System.AccessToken)" in t
    assert "LINEBREAK_OSV_SCANNER_BIN" in t
    assert "PublishBuildArtifacts@1" in t
    assert "pathToPublish: .linebreak/ci-out" in t
    assert "\t" not in t


@pytest.mark.parametrize(
    "header, template",
    [
        ("# bitbucket-pipelines.yml\n", init_cmd.BITBUCKET_PIPELINES_TEMPLATE),
        ("# azure-pipelines.yml\n", init_cmd.AZURE_PIPELINES_TEMPLATE),
    ],
)
def test_pipeline_templates_match_the_readme(header, template):
    """The file init writes and the README snippet must be ONE snippet."""
    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    fence = "```yaml\n" + header
    start = readme.index(fence) + len(fence)
    end = readme.index("```", start)
    assert readme[start:end] == template


def test_cli_forwards_provider(tmp_path, monkeypatch):
    called = {}
    monkeypatch.setattr(init_cmd, "run_init", lambda **kw: called.update(kw) or 0)
    assert main(["init", "--path", str(tmp_path), "--provider", "bitbucket"]) == 0
    assert called["provider"] == "bitbucket"


def test_cli_rejects_unknown_provider(tmp_path):
    with pytest.raises(SystemExit):
        main(["init", "--path", str(tmp_path), "--provider", "svn"])
