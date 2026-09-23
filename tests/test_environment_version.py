"""What a check against a deployed environment measured (issue #264).

A criterion that declares ``check.environment`` gets the deployed version
recorded next to its verdict, compared with the evaluated commit and with the
main branch; anything but ``current`` is a warning (never a block) in the
summary, the JSON, the audit record and the published run.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from test_criteria_check import write_bundle

from linebreak_gate import criteria_check, environment, publish, spec_bundle
from linebreak_gate.cli import main

SPEC = {"name": "staging", "version_url": "${STAGING_URL}/version"}


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, capture_output=True, text=True, check=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    """A repository with three commits on main; returns (root, [c1, c2, c3])."""
    _git(tmp_path, "init", "-q")
    # Named explicitly: `init -b` needs git 2.28+, and some runners are older.
    _git(tmp_path, "symbolic-ref", "HEAD", "refs/heads/main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    _git(tmp_path, "config", "commit.gpgsign", "false")
    commits = []
    for i in range(3):
        (tmp_path / f"f{i}.txt").write_text(str(i), encoding="utf-8")
        _git(tmp_path, "add", ".")
        _git(tmp_path, "commit", "-q", "-m", f"c{i}")
        commits.append(_git(tmp_path, "rev-parse", "HEAD"))
    return tmp_path, commits


def _story(env_spec: dict | None = SPEC) -> list[dict]:
    check: dict = {"type": "command", "payload": "e2e.sh"}
    if env_spec is not None:
        check["environment"] = env_spec
    return [
        {
            "id": "S1",
            "title": "Checkout",
            "criteria": [{"id": "f1-e2e", "statement": "flow one", "check": check}],
        }
    ]


def _ok(criterion, root):  # noqa: ARG001
    return criteria_check.RunOutcome(ok=True, detail="exit 0")


def _serving(*versions: str):
    """A fake environment answering each version in turn (the last repeats)."""
    seen: list[str] = []

    def fetch(url: str) -> tuple[int, str]:
        seen.append(url)
        v = versions[min(len(seen) - 1, len(versions) - 1)]
        return 200, json.dumps({"commit": v, "deployed_at": "x"})

    fetch.seen = seen  # type: ignore[attr-defined]
    return fetch


# ---------------------------------------------------------------- parsing


def test_version_from_json_field_default_keys_or_text():
    assert environment.parse_version('{"version": "1.4.2"}') == "1.4.2"
    assert environment.parse_version('{"commit": "abc1234", "version": "1"}') == "abc1234"
    assert environment.parse_version('{"build": {"sha": "def5678"}}', "build.sha") == "def5678"
    assert environment.parse_version('{"build": {}}', "build.sha") is None
    assert environment.parse_version("abc1234\nbuilt today\n") == "abc1234"
    assert environment.parse_version("") is None


def test_url_variables_expand_and_a_missing_one_is_reported():
    url, missing = environment.expand("${BASE}/version?x=$Q", {"BASE": "https://s", "Q": "1"})
    assert (url, missing) == ("https://s/version?x=1", [])
    probe = environment.probe(SPEC, {}, fetch=_serving("abc"))
    assert probe["error"] == "STAGING_URL not set"


def test_environment_schema():
    assert spec_bundle.validate_story(_story()[0]) == []
    bad = _story({"version_url": "ftp://x", "extra": 1})[0]
    errors = " ".join(spec_bundle.validate_story(bad))
    assert "unknown environment key" in errors and "http(s)" in errors
    no_url = _story({"name": "staging"})[0]
    assert any("version_url" in e for e in spec_bundle.validate_story(no_url))


# ---------------------------------------------------------------- relate to git


def test_relate_current_behind_short_sha_and_unknown(repo):
    root, (c1, c2, c3) = repo
    assert environment.relate(root, c3, c3, "main")["status"] == "current"
    assert environment.relate(root, c3[:8], c3, "main")["status"] == "current"
    behind = environment.relate(root, c1, c3, "main")
    assert behind["status"] == "behind" and behind["behind"] == 2
    assert environment.relate(root, "not-a-commit", c3, "main")["status"] == "unknown"


def test_relate_counts_how_far_behind_main_on_a_branch(repo):
    root, (c1, _c2, c3) = repo
    _git(root, "checkout", "-q", "-b", "feat/x", c1)
    (root / "branch.txt").write_text("b", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "branch")
    head = _git(root, "rev-parse", "HEAD")
    out = environment.relate(root, c1, head, "main")
    assert out["status"] == "behind" and out["behind"] == 1
    assert out["behind_main"] == 2 and out["main"] == "main"
    assert environment.relate(root, c3, head, "main")["status"] == "diverged"


# ---------------------------------------------------------------- evaluation


def test_a_current_environment_is_recorded_without_warning(repo):
    root, (_c1, _c2, c3) = repo
    write_bundle(root, _story())
    fetch = _serving(c3)
    payload = criteria_check.evaluate_bundle(
        root, run=_ok, environ={"STAGING_URL": "https://stg"}, env_fetch=fetch
    )
    env = payload["criteria"][0]["environment"]
    assert env["status"] == "current" and env["version"] == c3 and env["name"] == "staging"
    assert fetch.seen == ["https://stg/version", "https://stg/version"]  # before and after
    assert payload["environment_warnings"] == []


def test_an_environment_behind_the_commit_warns_but_does_not_block(repo, capsys):
    root, (c1, _c2, c3) = repo
    write_bundle(root, _story())
    payload = criteria_check.evaluate_bundle(
        root,
        run=_ok,
        environ={"STAGING_URL": "https://stg"},
        env_fetch=_serving(c1),
        write_artifact=True,
    )
    assert payload["passes"] is True
    (warning,) = payload["environment_warnings"]
    assert warning["status"] == "behind"
    assert "2 commit(s) behind the evaluated commit" in warning["message"]
    audit = json.loads((root / ".linebreak/audit/criteria.json").read_text(encoding="utf-8"))
    assert audit["findings"][0]["environment"]["version"] == c1
    assert audit["environment_warnings"][0]["status"] == "behind"


def test_a_version_that_moves_during_the_run_is_changed(repo):
    root, (c1, c2, _c3) = repo
    write_bundle(root, _story())
    payload = criteria_check.evaluate_bundle(
        root, run=_ok, environ={"STAGING_URL": "https://stg"}, env_fetch=_serving(c1, c2)
    )
    env = payload["criteria"][0]["environment"]
    assert env["status"] == "changed" and env["version_after"] == c2
    assert "mixes two deployments" in payload["environment_warnings"][0]["message"]


def test_an_unreachable_environment_is_said(repo):
    root, _ = repo
    write_bundle(root, _story())

    def down(url):
        raise OSError("connection refused")

    payload = criteria_check.evaluate_bundle(
        root, run=_ok, environ={"STAGING_URL": "https://stg"}, env_fetch=down
    )
    env = payload["criteria"][0]["environment"]
    assert env["status"] == "unreachable" and "connection refused" in env["note"]
    assert payload["passes"] is True


def test_a_criterion_without_environment_probes_nothing(repo):
    root, _ = repo
    write_bundle(root, _story(None))
    fetch = _serving("x")
    payload = criteria_check.evaluate_bundle(root, run=_ok, env_fetch=fetch)
    assert "environment" not in payload["criteria"][0]
    assert fetch.seen == []


def test_cli_and_publish_show_what_was_measured(repo, capsys, monkeypatch):
    root, (c1, _c2, _c3) = repo
    monkeypatch.setattr(environment, "_default_fetch", _serving(c1))
    story = _story(dict(SPEC, version_url="https://stg/version"))
    story[0]["criteria"][0]["check"]["payload"] = 'python -c "import sys; sys.exit(0)"'
    write_bundle(root, story)
    assert main(["check", "--path", str(root)]) == 0
    out = capsys.readouterr().out
    assert (
        f"measured staging at {c1} (behind, 2 commit(s) behind the evaluated commit, 2 behind main)"
    ) in out
    assert "environment warning: f1-e2e measured staging at" in out
    body = publish.build_payload(root, env={})
    (criterion,) = body["criteria"]
    assert criterion["detail"].startswith(f"[measured staging at {c1}: behind]")
    assert criterion["environment"]["status"] == "behind"
