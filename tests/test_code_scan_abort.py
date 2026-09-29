"""ScanAbort: a scan-wide failure raised mid-verification (e.g. hosted credits
exhausted) must fail the scan closed WITH its message — not be swallowed by the
keep-on-verifier-error rule, which would report unverified noise and hide the
actual cause."""

from linebreak_gate.code_scan import ScanAbort, scan_code

_RAW = [
    {"title": "sql injection", "severity": "high", "file": "a.py"},
    {"title": "xss", "severity": "medium", "file": "b.py"},
]


def test_scan_abort_mid_verification_fails_closed_with_message():
    def verify(_finding):
        raise ScanAbort("out of LineBreak credits — top up at linebreakapp.com")

    result = scan_code("/tmp/x", discover=lambda _r: _RAW, verify=verify)
    assert result["findings"] == []
    assert "out of LineBreak credits" in result["error"]


def test_ordinary_verifier_error_still_keeps_the_finding():
    def verify(_finding):
        raise TimeoutError("flaky network")

    result = scan_code("/tmp/x", discover=lambda _r: _RAW, verify=verify)
    assert len(result["findings"]) == 2
    assert result["error"] is None


def test_scan_abort_during_discovery_fails_closed():
    def discover(_root):
        raise ScanAbort("out of LineBreak credits")

    result = scan_code("/tmp/x", discover=discover, verify=lambda _f: True)
    assert result["findings"] == []
    assert "out of LineBreak credits" in result["error"]
