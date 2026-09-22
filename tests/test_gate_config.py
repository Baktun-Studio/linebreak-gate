"""Config-as-code: .linebreak/gate.yml + precedence (flag > file > default)."""

import pytest

from linebreak_gate.gate_config import GateConfigError, resolve_config


def _write_gate_yml(root, text):
    d = root / ".linebreak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "gate.yml").write_text(text, encoding="utf-8")


def test_defaults_when_no_config_file(tmp_path):
    cfg = resolve_config(tmp_path)
    assert cfg.fail_on == "critical"
    assert cfg.exclude_paths == ()
    assert cfg.code_scan == "auto"
    assert cfg.fail_on_source == "default"


def test_file_fail_on_high(tmp_path):
    _write_gate_yml(tmp_path, "fail_on: high\n")
    cfg = resolve_config(tmp_path)
    assert cfg.fail_on == "high"
    assert cfg.fail_on_source == "file"


def test_cli_flag_overrides_file(tmp_path):
    _write_gate_yml(tmp_path, "fail_on: high\n")
    cfg = resolve_config(tmp_path, cli_fail_on="critical")
    assert cfg.fail_on == "critical"
    assert cfg.fail_on_source == "flag"


def test_exclude_paths_parsed(tmp_path):
    _write_gate_yml(
        tmp_path, "fail_on: medium\nexclude_paths:\n  - vendor-tests\n  - 'fixtures/*'\n"
    )
    cfg = resolve_config(tmp_path)
    assert cfg.exclude_paths == ("vendor-tests", "fixtures/*")


def test_code_scan_setting(tmp_path):
    _write_gate_yml(tmp_path, "code_scan: off\n")
    assert resolve_config(tmp_path).code_scan == "off"
    _write_gate_yml(tmp_path, "code_scan: on\n")
    assert resolve_config(tmp_path).code_scan == "on"


def test_invalid_fail_on_is_a_config_error(tmp_path):
    # A governance file that's wrong must never silently fall back to a
    # default threshold — fail closed (exit 2 at the CLI layer).
    _write_gate_yml(tmp_path, "fail_on: severe\n")
    with pytest.raises(GateConfigError):
        resolve_config(tmp_path)


def test_invalid_cli_fail_on_is_a_config_error(tmp_path):
    with pytest.raises(GateConfigError):
        resolve_config(tmp_path, cli_fail_on="everything")


def test_malformed_yaml_is_a_config_error(tmp_path):
    _write_gate_yml(tmp_path, "fail_on: [unclosed\n")
    with pytest.raises(GateConfigError):
        resolve_config(tmp_path)


def test_non_mapping_yaml_is_a_config_error(tmp_path):
    _write_gate_yml(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(GateConfigError):
        resolve_config(tmp_path)


def test_invalid_code_scan_is_a_config_error(tmp_path):
    _write_gate_yml(tmp_path, "code_scan: maybe\n")
    with pytest.raises(GateConfigError):
        resolve_config(tmp_path)
