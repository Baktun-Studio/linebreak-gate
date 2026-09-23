"""Governance service credentials in one place (governance_env).

Order: environment variables, then ~/.config/linebreak/governance.env, then
~/.config/linebreak/governance-local.env, then ~/.linebreak/env (the desktop
app's file, kept for compatibility). The first FILE carrying a token is used
whole (a URL from one file is never paired with a token from another); a set
variable wins key by key. Every command that talks to the service uses it:
the sign-offs `check` consults, the verified identity of `signoff`, the
tracker configuration, `publish` and `report --from-governance`.
"""

from __future__ import annotations

from pathlib import Path

from linebreak_gate import governance_env, identity, publish, signoffs
from linebreak_gate.cli import main


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(governance_env, "_home", lambda: home)
    return home


def test_lookup_order_is_documented_and_stable(tmp_path):
    home = tmp_path
    files = governance_env.candidate_files({}, home)
    assert files == [
        home / ".config" / "linebreak" / "governance.env",
        home / ".config" / "linebreak" / "governance-local.env",
        home / ".linebreak" / "env",
    ]
    xdg = governance_env.candidate_files({"XDG_CONFIG_HOME": str(tmp_path / "x")}, home)
    assert xdg[0] == tmp_path / "x" / "linebreak" / "governance.env"


def test_file_syntax_export_quotes_and_comments(tmp_path):
    f = _write(
        tmp_path / "g.env",
        "# comment\nexport LINEBREAK_GOVERNANCE_BASE_URL='https://gov.example'\n"
        'LINEBREAK_GOVERNANCE_TOKEN="lbg_x"\n\nnot a line\n',
    )
    assert governance_env.parse_env_file(f) == {
        "LINEBREAK_GOVERNANCE_BASE_URL": "https://gov.example",
        "LINEBREAK_GOVERNANCE_TOKEN": "lbg_x",
    }


def test_first_file_with_a_token_wins_whole(tmp_path):
    home = tmp_path
    # governance.env has a URL but no token: skipped whole, so its URL is
    # never paired with the local file's token.
    _write(
        home / ".config/linebreak/governance.env", "LINEBREAK_GOVERNANCE_BASE_URL=https://prod\n"
    )
    local = _write(
        home / ".config/linebreak/governance-local.env",
        "LINEBREAK_GOVERNANCE_BASE_URL=http://localhost:8080\nLINEBREAK_GOVERNANCE_TOKEN=lbg_local\n",
    )
    _write(
        home / ".linebreak/env",
        "LINEBREAK_GOVERNANCE_BASE_URL=https://old\nLINEBREAK_GOVERNANCE_TOKEN=lbg_old\n",
    )
    creds = governance_env.resolve({}, home)
    assert (creds.base_url, creds.token, creds.source) == (
        "http://localhost:8080",
        "lbg_local",
        str(local),
    )


def test_desktop_file_is_the_last_resort(tmp_path):
    home = tmp_path
    _write(
        home / ".linebreak/env",
        "LINEBREAK_GOVERNANCE_TOKEN=lbg_old\nLINEBREAK_GOVERNANCE_BASE_URL=https://old\n",
    )
    assert governance_env.resolve({}, home).token == "lbg_old"


def test_environment_wins_key_by_key(tmp_path):
    home = tmp_path
    _write(
        home / ".config/linebreak/governance.env",
        "LINEBREAK_GOVERNANCE_BASE_URL=https://prod\nLINEBREAK_GOVERNANCE_TOKEN=lbg_file\n"
        "LINEBREAK_GOV_PROJECT=prj_file\n",
    )
    env = {"LINEBREAK_GOVERNANCE_TOKEN": "lbg_env", "LINEBREAK_GOV_PROJECT": "prj_env"}
    creds = governance_env.resolve(env, home)
    assert (creds.base_url, creds.token, creds.project) == ("https://prod", "lbg_env", "prj_env")
    merged = governance_env.merged(env, home)
    assert merged["LINEBREAK_GOVERNANCE_TOKEN"] == "lbg_env"
    assert merged["LINEBREAK_GOVERNANCE_BASE_URL"] == "https://prod"


def test_only_environment_when_the_files_are_off(tmp_path):
    home = tmp_path
    _write(home / ".config/linebreak/governance.env", "LINEBREAK_GOVERNANCE_TOKEN=lbg_file\n")
    creds = governance_env.resolve({"LINEBREAK_GOV_CREDENTIALS": "off"}, home)
    assert creds.token is None and creds.source is None


def test_signoff_lookup_and_identity_read_the_file(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    _write(
        home / ".config/linebreak/governance.env",
        "LINEBREAK_GOVERNANCE_BASE_URL=https://gov.example\nLINEBREAK_GOVERNANCE_TOKEN=lbg_f\n"
        "LINEBREAK_GOV_PROJECT=prj_1\n",
    )
    calls = []

    def fetch(url, token):
        calls.append((url, token))
        return 200, {"signoffs": []}

    records, notice = signoffs.load_governance_signoffs(fetch=fetch)
    assert (records, notice) == ([], None)
    assert calls == [("https://gov.example/v1/projects/prj_1/signoffs", "lbg_f")]

    ident = identity.resolve(
        "Ana", fetch_me=lambda base, token: (200, {"email": "ana@example.com", "roles": []})
    )
    assert (ident.source, ident.subject) == ("governance", "ana@example.com")


def test_publish_reads_url_token_and_project_from_the_file(tmp_path, monkeypatch, capsys):
    home = _home(tmp_path, monkeypatch)
    _write(
        home / ".config/linebreak/governance.env",
        "LINEBREAK_GOVERNANCE_BASE_URL=https://gov.example\nLINEBREAK_GOVERNANCE_TOKEN=lbg_f\n"
        "LINEBREAK_GOV_PROJECT=prj_1\n",
    )
    sent = {}
    monkeypatch.setattr(
        publish, "build_payload", lambda *a, **k: {"run_id": "r1", "verdict": "pass"}
    )
    monkeypatch.setattr(publish, "send", lambda payload, **kw: sent.update(kw))
    assert main(["publish", "--path", str(tmp_path)]) == 0
    assert sent == {"url": "https://gov.example", "project_id": "prj_1", "token": "lbg_f"}
    assert (
        "published run r1 (pass) to https://gov.example for project prj_1"
        in capsys.readouterr().out
    )


def test_publish_pipeline_token_still_wins(tmp_path, monkeypatch):
    home = _home(tmp_path, monkeypatch)
    _write(home / ".config/linebreak/governance.env", "LINEBREAK_GOVERNANCE_TOKEN=lbg_f\n")
    monkeypatch.setenv("LINEBREAK_GOV_TOKEN", "lbg_pipeline")
    sent = {}
    monkeypatch.setattr(
        publish, "build_payload", lambda *a, **k: {"run_id": "r1", "verdict": "pass"}
    )
    monkeypatch.setattr(publish, "send", lambda payload, **kw: sent.update(kw))
    main(["publish", "--path", str(tmp_path), "--to", "https://x", "--project", "p"])
    assert sent["token"] == "lbg_pipeline"
