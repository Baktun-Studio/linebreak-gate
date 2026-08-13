"""``linebreak-gate badge`` — ready-to-paste README badge.

No network calls: the shields.io STATIC badge is fully encoded in its URL.
The snippet goes to stdout and the hint to stderr, so piping stays clean
(``linebreak-gate badge >> README.md`` appends only the badge)."""

from linebreak_gate.cli import BADGE_HINT, main

SHIELDS_URL = "https://img.shields.io/badge/gated%20by-LineBreak-14120F?labelColor=FAF8F4"
GATE_URL = "https://www.linebreakapp.com/en/gate"


def test_badge_default_is_markdown(capsys):
    assert main(["badge"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == f"[![gated by LineBreak]({SHIELDS_URL})]({GATE_URL})"


def test_badge_hint_goes_to_stderr_not_stdout(capsys):
    assert main(["badge"]) == 0
    captured = capsys.readouterr()
    assert BADGE_HINT in captured.err
    assert BADGE_HINT not in captured.out


def test_badge_html_variant(capsys):
    assert main(["badge", "--format", "html"]) == 0
    out = capsys.readouterr().out.strip()
    assert out == (f'<a href="{GATE_URL}"><img src="{SHIELDS_URL}" alt="gated by LineBreak" /></a>')


def test_badge_url_variant_is_bare_shields_url(capsys):
    assert main(["badge", "--format", "url"]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == SHIELDS_URL
    assert GATE_URL not in captured.out
