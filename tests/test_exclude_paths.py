"""exclude_paths threading: osv results and SAST file gathering honor the
repo-configured exclusions; defaults stay byte-identical to today."""

import json

from linebreak_gate.code_scan import _gather_changeset
from linebreak_gate.security_scan import parse_osv_scanner, scan_project


def _osv_payload(root, rel_lockfiles):
    return {
        "results": [
            {
                "source": {"path": f"{root}/{rel}"},
                "packages": [
                    {
                        "package": {"name": f"pkg-{i}", "ecosystem": "npm", "version": "1.0.0"},
                        "groups": [{"ids": [f"GHSA-x-{i}"], "max_severity": "9.8"}],
                        "vulnerabilities": [
                            {
                                "id": f"GHSA-x-{i}",
                                "aliases": [f"CVE-2024-000{i}"],
                                "summary": "boom",
                                "database_specific": {"severity": "CRITICAL"},
                            }
                        ],
                    }
                ],
            }
            for i, rel in enumerate(rel_lockfiles)
        ]
    }


def test_parse_osv_scanner_excludes_matching_paths(tmp_path):
    data = _osv_payload(tmp_path, ["package-lock.json", "fixtures/vuln/package-lock.json"])
    all_findings = parse_osv_scanner(data, tmp_path)
    assert len(all_findings) == 2

    filtered = parse_osv_scanner(data, tmp_path, exclude_paths=["fixtures"])
    assert [f["package"] for f in filtered] == ["pkg-0"]

    globbed = parse_osv_scanner(data, tmp_path, exclude_paths=["fixtures/*"])
    assert [f["package"] for f in globbed] == ["pkg-0"]


def test_scan_project_threads_exclude_paths(tmp_path):
    data = _osv_payload(tmp_path, ["legacy/package-lock.json", "package-lock.json"])

    def fake_run(cmd, **kwargs):
        class P:
            returncode = 1
            stdout = json.dumps(data)
            stderr = ""

        return P()

    result = scan_project(
        tmp_path,
        run=fake_run,
        which=lambda name: "/usr/bin/osv-scanner" if "osv" in name else None,
        exclude_paths=["legacy"],
    )
    assert result["error"] is None
    assert [f["package"] for f in result["findings"]] == ["pkg-1"]


def test_gather_changeset_excludes_paths(tmp_path):
    (tmp_path / "app.py").write_text("print('hi')\n")
    (tmp_path / "fixtures").mkdir()
    (tmp_path / "fixtures" / "vuln.py").write_text("import os\n")
    files = _gather_changeset(str(tmp_path))
    assert {rel for rel, _ in files} == {"app.py", "fixtures/vuln.py"}
    filtered = _gather_changeset(str(tmp_path), exclude_paths=["fixtures"])
    assert {rel for rel, _ in filtered} == {"app.py"}


def test_npm_audit_honors_exclude_globs_like_osv(tmp_path):
    """The npm-audit fallback must honor the same exclusions as the osv path —
    including `dir/*` globs and file-shaped patterns — so the verdict doesn't
    depend on which scanner engine happened to be installed."""
    (tmp_path / "package-lock.json").write_text("{}")
    (tmp_path / "sandbox").mkdir()
    (tmp_path / "sandbox" / "package-lock.json").write_text("{}")

    vuln_audit = json.dumps(
        {
            "vulnerabilities": {
                "minimist": {
                    "name": "minimist",
                    "severity": "critical",
                    "via": [
                        {
                            "name": "minimist",
                            "severity": "critical",
                            "cve": "CVE-2021-44906",
                            "url": "https://example.com/adv",
                            "title": "t",
                        }
                    ],
                }
            }
        }
    )
    clean_audit = json.dumps({"vulnerabilities": {}})

    def fake_run(cmd, **kwargs):
        class P:
            returncode = 0
            stderr = ""
            stdout = vuln_audit if "sandbox" in str(kwargs.get("cwd", "")) else clean_audit

        return P()

    def npm_only(name):
        return "/usr/bin/npm" if name == "npm" else None

    unfiltered = scan_project(tmp_path, run=fake_run, which=npm_only)
    assert [f["package"] for f in unfiltered["findings"]] == ["minimist"]

    for pattern in ("sandbox", "sandbox/*", "sandbox/package-lock.json"):
        result = scan_project(tmp_path, run=fake_run, which=npm_only, exclude_paths=[pattern])
        assert result["error"] is None, pattern
        assert result["findings"] == [], pattern
