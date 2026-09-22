"""Blocking verdict + tuple-scoped override acknowledgment for the CI gate."""

from linebreak_gate.verdict import evaluate, finding_id, finding_rank


def _dep(severity="critical", cve="CVE-2024-0001", package="lodash", version="4.17.20", **kw):
    f = {
        "cve_id": cve,
        "severity": severity,
        "cvss": kw.pop("cvss", None),
        "package": package,
        "ecosystem": "npm",
        "installed_version": version,
        "fixed_version": None,
        "advisory_url": kw.pop("advisory_url", f"https://osv.dev/vulnerability/{cve}"),
        "title": kw.pop("title", "test advisory"),
    }
    f.update(kw)
    return f


def test_rank_from_severity_string():
    assert finding_rank(_dep(severity="critical")) == 4
    assert finding_rank(_dep(severity="high")) == 3
    assert finding_rank(_dep(severity="moderate")) == 2  # npm vocab alias
    assert finding_rank(_dep(severity="low")) == 1
    assert finding_rank(_dep(severity="bogus")) == 0


def test_rank_falls_back_to_cvss_band():
    # Mirrors lib/security-artifact.js _findingRank: a cvss-only finding must
    # not rank 0 (that would fail open).
    assert finding_rank(_dep(severity="unknown", cvss=9.8)) == 4
    assert finding_rank(_dep(severity="unknown", cvss=7.5)) == 3
    assert finding_rank(_dep(severity="unknown", cvss="5.0")) == 2  # string cvss coerced
    assert finding_rank(_dep(severity="unknown", cvss=0.1)) == 1


def test_finding_id_is_stable_and_tuple_scoped():
    a = finding_id(_dep())
    assert a == finding_id(_dep())  # deterministic
    assert a != finding_id(_dep(cve="CVE-2024-0002"))  # different CVE
    assert a != finding_id(_dep(version="4.17.21"))  # different version
    assert a != finding_id(_dep(package="underscore"))  # different package


def test_finding_id_without_cve_uses_advisory_identity():
    f = _dep(cve=None, advisory_url="https://example.com/adv/1")
    assert finding_id(f) == finding_id(dict(f))
    assert finding_id(f) != finding_id(_dep(cve=None, advisory_url="https://example.com/adv/2"))


def test_default_floor_blocks_only_critical():
    findings = [_dep(severity="critical"), _dep(severity="high", cve="CVE-2024-0002")]
    result = evaluate(findings, fail_on="critical", override_ids=set())
    assert [f["cve_id"] for f in result["blocking"]] == ["CVE-2024-0001"]
    assert result["passes"] is False


def test_high_floor_blocks_high_and_above():
    findings = [
        _dep(severity="medium", cve="CVE-2024-0003"),
        _dep(severity="high", cve="CVE-2024-0002"),
    ]
    result = evaluate(findings, fail_on="high", override_ids=set())
    assert [f["cve_id"] for f in result["blocking"]] == ["CVE-2024-0002"]


def test_clean_passes():
    assert evaluate([], fail_on="critical", override_ids=set())["passes"] is True


def test_override_acknowledges_exact_tuple_only():
    f1 = _dep(severity="critical", cve="CVE-2024-0001")
    f2 = _dep(severity="critical", cve="CVE-2024-0002")
    ids = {finding_id(f1)}
    result = evaluate([f1, f2], fail_on="critical", override_ids=ids)
    # f1 acknowledged (non-blocking); f2 — a DIFFERENT CVE — still blocks.
    assert [f["cve_id"] for f in result["blocking"]] == ["CVE-2024-0002"]
    assert [f["cve_id"] for f in result["acknowledged"]] == ["CVE-2024-0001"]
    assert result["passes"] is False

    result2 = evaluate([f1], fail_on="critical", override_ids=ids)
    assert result2["passes"] is True
    assert result2["blocking"] == []


def test_override_does_not_hide_new_version_of_same_cve():
    overridden = _dep(severity="critical", version="4.17.20")
    bumped = _dep(severity="critical", version="4.17.21")
    ids = {finding_id(overridden)}
    result = evaluate([bumped], fail_on="critical", override_ids=ids)
    assert result["passes"] is False  # exact package+version+CVE tuple only


def test_detector_namespaces_are_disjoint():
    """Override ids are unioned across both artifacts in the CLI, so the
    dep:/code: prefixes are the load-bearing guard against a code-finding
    override acknowledging a dependency finding (or vice versa). Pin it."""
    dep = _dep()
    code = {"file": "app.py", "line": 10, "title": "SQLi", "category": "injection"}
    assert finding_id(dep, detector="dep").startswith("dep:")
    assert finding_id(code, detector="code").startswith("code:")


def test_evaluate_annotates_findings_with_id_and_status():
    f1 = _dep(severity="critical", cve="CVE-2024-0001")
    f2 = _dep(severity="low", cve="CVE-2024-0003")
    result = evaluate([f1, f2], fail_on="critical", override_ids=set())
    statuses = {f["cve_id"]: f["status"] for f in result["findings"]}
    assert statuses == {"CVE-2024-0001": "blocking", "CVE-2024-0003": "below_floor"}
    assert all("id" in f for f in result["findings"])
