"""Roles and permissions (.linebreak/roles.yml): parsing fails closed, the
authorization table at recording time, and the re-check of stored records
against the roles in force."""

from __future__ import annotations

import pytest

from linebreak_gate import roles
from linebreak_gate.roles import RoleDenied, RolesConfigError

ROSTER = """\
roles:
  ciso:
    members: [ana@example.com]
    can:
      sign_criteria: ["*"]
      approve_overrides: ["*"]
      accept_security_risk: [critical, high, medium, low]
  qa:
    members: [luis@example.com, "github:luis-qa"]
    can:
      sign_criteria: ["e12-*"]
      approve_overrides: []
      accept_security_risk: [low, medium]
policy:
  require_roles: true
"""


def _write(root, text=ROSTER):
    d = root / ".linebreak"
    d.mkdir(parents=True, exist_ok=True)
    (d / "roles.yml").write_text(text, encoding="utf-8")


def _keys(*values):
    return roles.identity_keys(*values)


# ---------------------------------------------------------------- loading


def test_absent_file_is_the_empty_policy(tmp_path):
    policy = roles.load_roles(tmp_path)
    assert policy is roles.EMPTY_POLICY
    assert policy.enforcing is False


def test_roster_parses_members_lowercased_and_permissions(tmp_path):
    _write(tmp_path)
    policy = roles.load_roles(tmp_path)
    assert policy.require_roles is True
    assert policy.require_verified_identity is False
    assert policy.source == "file"
    qa = policy.role("qa")
    assert qa.members == ("luis@example.com", "github:luis-qa")
    assert qa.sign_criteria == ("e12-*",)
    assert qa.approve_overrides == ()
    assert qa.accept_security_risk == ("low", "medium")


@pytest.mark.parametrize(
    "text",
    [
        ": not yaml [",
        "- a list\n",
        "roles: []\n",
        "roles:\n  ciso:\n    members: ana@example.com\n",
        "roles:\n  ciso:\n    can:\n      sign_things: ['*']\n",
        "roles:\n  ciso:\n    can:\n      accept_security_risk: [severe]\n",
        "roles:\n  'bad/name':\n    members: []\n",
        "policy:\n  require_roles: sometimes\n",
        "policy:\n  other: true\n",
        "extra: 1\n",
    ],
)
def test_malformed_roster_fails_closed(tmp_path, text):
    _write(tmp_path, text)
    with pytest.raises(RolesConfigError):
        roles.load_roles(tmp_path)


def test_identity_keys_extract_bracketed_email():
    keys = roles.identity_keys("Ana Lopez <Ana@Example.com>")
    assert "ana@example.com" in keys
    assert "ana lopez <ana@example.com>" in keys


# ---------------------------------------------------------------- authorize (recording)


def test_role_is_inferred_when_exactly_one_allows(tmp_path):
    _write(tmp_path)
    policy = roles.load_roles(tmp_path)
    role = roles.authorize(
        policy,
        subject="luis@example.com",
        keys=_keys("luis@example.com"),
        action="sign_criteria",
        targets=("e12-ac1", "e12-story"),
    )
    assert role == "qa"


def test_pattern_matches_story_and_epic_ids_too(tmp_path):
    _write(tmp_path)
    policy = roles.load_roles(tmp_path)
    # Criterion id does not match, but the epic does.
    assert (
        roles.authorize(
            policy,
            subject="luis@example.com",
            keys=_keys("luis@example.com"),
            action="sign_criteria",
            targets=("ac-9", "story-3", "e12-payments"),
        )
        == "qa"
    )


def test_denial_names_the_roles_that_would_be_needed(tmp_path):
    _write(tmp_path)
    policy = roles.load_roles(tmp_path)
    with pytest.raises(RoleDenied) as exc:
        roles.authorize(
            policy,
            subject="luis@example.com",
            keys=_keys("luis@example.com"),
            action="sign_criteria",
            targets=("e13-ac1",),
        )
    assert exc.value.reason == "role_denied"
    assert "roles that may: ciso" in str(exc.value)


def test_stranger_is_denied_under_require_roles(tmp_path):
    _write(tmp_path)
    policy = roles.load_roles(tmp_path)
    with pytest.raises(RoleDenied) as exc:
        roles.authorize(
            policy,
            subject="nobody@example.com",
            keys=_keys("nobody@example.com"),
            action="approve_overrides",
            targets=("e12-ac1",),
        )
    assert "roles that may: ciso" in str(exc.value)


def test_stranger_records_without_role_when_roles_not_required(tmp_path):
    _write(tmp_path, ROSTER.replace("require_roles: true", "require_roles: false"))
    policy = roles.load_roles(tmp_path)
    assert (
        roles.authorize(
            policy,
            subject="nobody@example.com",
            keys=_keys("nobody@example.com"),
            action="sign_criteria",
            targets=("x",),
        )
        is None
    )


def test_explicit_role_must_exist_include_the_person_and_allow_the_action(tmp_path):
    _write(tmp_path)
    policy = roles.load_roles(tmp_path)
    common = {"keys": _keys("luis@example.com"), "action": "sign_criteria", "targets": ("e12-a",)}
    with pytest.raises(RoleDenied, match="not defined"):
        roles.authorize(policy, subject="luis", role="cto", **common)
    with pytest.raises(RoleDenied, match="not a member"):
        roles.authorize(policy, subject="luis", role="ciso", **common)
    with pytest.raises(RoleDenied, match="may not override"):
        roles.authorize(
            policy,
            subject="luis",
            role="qa",
            keys=_keys("luis@example.com"),
            action="approve_overrides",
            targets=("e12-a",),
        )
    assert roles.authorize(policy, subject="luis", role="qa", **common) == "qa"


def test_explicit_role_without_a_roster_is_refused():
    with pytest.raises(RoleDenied, match="no .linebreak/roles.yml"):
        roles.authorize(
            roles.EMPTY_POLICY,
            subject="a",
            keys=_keys("a"),
            action="sign_criteria",
            targets=("x",),
            role="qa",
        )


def test_ambiguous_roles_ask_for_role_flag(tmp_path):
    _write(
        tmp_path,
        ROSTER.replace(
            "members: [ana@example.com]", "members: [ana@example.com, luis@example.com]"
        ),
    )
    policy = roles.load_roles(tmp_path)
    with pytest.raises(RoleDenied, match="pass --role"):
        roles.authorize(
            policy,
            subject="luis@example.com",
            keys=_keys("luis@example.com"),
            action="sign_criteria",
            targets=("e12-a",),
        )


def test_security_risk_is_gated_by_severity(tmp_path):
    _write(tmp_path)
    policy = roles.load_roles(tmp_path)
    ok = roles.authorize(
        policy,
        subject="luis@example.com",
        keys=_keys("luis@example.com"),
        action="accept_security_risk",
        targets=("dep:x@1:CVE-1",),
        severity="medium",
    )
    assert ok == "qa"
    with pytest.raises(RoleDenied) as exc:
        roles.authorize(
            policy,
            subject="luis@example.com",
            keys=_keys("luis@example.com"),
            action="accept_security_risk",
            targets=("dep:x@1:CVE-1",),
            severity="critical",
        )
    assert "critical-severity" in str(exc.value) and "roles that may: ciso" in str(exc.value)


# ---------------------------------------------------------------- verify_record (checking)


def _verify(policy, **overrides):
    base = {
        "kind": "sign-off",
        "subject": "luis@example.com",
        "keys": _keys("luis@example.com"),
        "action": "sign_criteria",
        "targets": ("e12-ac1",),
        "role": "qa",
        "identity_source": "client",
    }
    base.update(overrides)
    return roles.verify_record(policy, **base)


def test_record_still_counts_under_the_roles_in_force(tmp_path):
    _write(tmp_path)
    assert _verify(roles.load_roles(tmp_path)) is None


def test_record_without_role_is_denied_under_require_roles(tmp_path):
    _write(tmp_path)
    denial = _verify(roles.load_roles(tmp_path), role=None)
    assert denial.reason == "role_denied" and "carries no role" in str(denial)


def test_record_whose_role_was_removed_is_denied(tmp_path):
    _write(tmp_path, ROSTER.replace("  qa:\n", "  qa-old:\n"))
    denial = _verify(roles.load_roles(tmp_path))
    assert denial.reason == "role_denied" and "no longer defined" in str(denial)


def test_record_whose_member_left_is_denied(tmp_path):
    _write(tmp_path, ROSTER.replace("luis@example.com, ", ""))
    denial = _verify(roles.load_roles(tmp_path))
    assert "no longer a member" in str(denial)


def test_record_whose_role_lost_the_pattern_is_denied(tmp_path):
    _write(tmp_path, ROSTER.replace('sign_criteria: ["e12-*"]', 'sign_criteria: ["e99-*"]'))
    denial = _verify(roles.load_roles(tmp_path))
    assert "may not sign criterion e12-ac1" in str(denial)
    assert "roles that may: ciso" in str(denial)


def test_declared_identity_is_denied_under_require_verified_identity(tmp_path):
    _write(tmp_path, ROSTER + "  require_verified_identity: true\n")
    policy = roles.load_roles(tmp_path)
    denial = _verify(policy, identity_source="client")
    assert denial.reason == "identity_unverified"
    assert _verify(policy, identity_source="vcs") is None
    assert _verify(policy, identity_source="governance") is None


def test_nothing_is_denied_when_nothing_is_required(tmp_path):
    _write(tmp_path, ROSTER.replace("require_roles: true", "require_roles: false"))
    policy = roles.load_roles(tmp_path)
    assert _verify(policy, role=None, keys=_keys("stranger")) is None
    assert _verify(roles.EMPTY_POLICY, role=None) is None


def test_record_keys_include_provider_login_form():
    record = {"approver": "github:luis-qa", "identity": {"provider": "github", "login": "luis-qa"}}
    keys = roles.record_keys(record, "approver")
    assert "github:luis-qa" in keys and "luis-qa" in keys
