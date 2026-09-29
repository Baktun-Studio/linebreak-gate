"""Checks against a shared resource (issue #262): a red that is a clash over
the resource is said, not painted red.

* ``check.resource`` is part of the spec schema (a slug, not on ``manual``)
  and a criterion without it hashes exactly as before.
* Every check naming the same resource holds an OS lock (resource_lock), so
  two checks on one machine never overlap; a lock held too long is a tool
  error naming who holds it.
* A failed exclusive check is re-run once, alone, after every other check:
  passing alone makes it ``collision`` (not blocking, listed); failing again
  keeps ``fail`` and says it was reproduced alone.
"""

from __future__ import annotations

import json
import threading

import pytest
from test_criteria_check import write_bundle

from linebreak_gate import criteria_check, resource_lock, spec_bundle
from linebreak_gate.cli import main


@pytest.fixture(autouse=True)
def _locks_here(tmp_path, monkeypatch):
    monkeypatch.setenv(resource_lock.LOCK_DIR_ENV, str(tmp_path / "locks"))


def _e2e(cid: str, resource: str | None = "staging-merchant", payload: str = "e2e.sh") -> dict:
    check: dict = {"type": "command", "payload": payload}
    if resource:
        check["resource"] = resource
    return {"id": cid, "statement": f"{cid} end to end", "check": check}


def _story(*criteria: dict) -> list[dict]:
    return [{"id": "S1", "title": "Checkout", "criteria": list(criteria)}]


class _Flaky:
    """Fails the first N calls per payload, then passes."""

    def __init__(self, fails: int) -> None:
        self.fails = fails
        self.calls: dict[str, int] = {}

    def __call__(self, criterion, root):  # noqa: ARG002
        key = criterion["check"]["payload"]
        self.calls[key] = self.calls.get(key, 0) + 1
        ok = self.calls[key] > self.fails
        return criteria_check.RunOutcome(ok=ok, detail="exit 0" if ok else "exit 1\nmerchant busy")


# ---------------------------------------------------------------- schema


def test_resource_is_a_slug_and_only_for_checks_that_run():
    ok = _story(_e2e("A"))[0]
    assert spec_bundle.validate_story(ok) == []
    bad_slug = _story(_e2e("A", resource="../etc"))[0]
    assert any("resource" in e for e in spec_bundle.validate_story(bad_slug))
    manual = {
        "id": "S1",
        "title": "t",
        "criteria": [{"id": "M", "statement": "m", "check": {"type": "manual", "resource": "x"}}],
    }
    assert any("runs nothing" in e for e in spec_bundle.validate_story(manual))


def test_a_criterion_without_the_new_keys_hashes_as_before():
    plain = _e2e("A", resource=None)
    # The canonical form (what the hash covers) carries no new key when the
    # criterion declares none: every existing sign-off stays valid.
    dumped = spec_bundle.dump_story_yaml(_story(plain)[0])
    assert "resource" not in dumped and "environment" not in dumped
    assert spec_bundle.criterion_hash(plain) != spec_bundle.criterion_hash(_e2e("A"))


# ---------------------------------------------------------------- collision


def test_fail_then_pass_alone_is_a_collision_not_a_defect(tmp_path):
    write_bundle(tmp_path, _story(_e2e("A")))
    runner = _Flaky(fails=1)
    payload = criteria_check.evaluate_bundle(tmp_path, run=runner)
    (entry,) = payload["criteria"]
    assert entry["result"] == "collision"
    assert entry["collision"]["resource"] == "staging-merchant"
    assert "merchant busy" in entry["collision"]["first_detail"]
    assert "not a defect" in entry["detail"]
    assert payload["passes"] is True
    assert payload["collisions"] == [
        {
            "id": "A",
            "story": "S1",
            "resource": "staging-merchant",
            "first_detail": "exit 1 merchant busy",
        }
    ]
    assert runner.calls == {"e2e.sh": 2}


def test_failing_again_alone_is_a_real_failure_and_says_so(tmp_path):
    write_bundle(tmp_path, _story(_e2e("A")))
    runner = _Flaky(fails=99)
    payload = criteria_check.evaluate_bundle(tmp_path, run=runner)
    (entry,) = payload["criteria"]
    assert entry["result"] == "fail"
    assert entry["retried_alone"] == "fail"
    assert entry["detail"].startswith("reproduced when re-run alone on resource staging-merchant")
    assert payload["passes"] is False
    assert payload["collisions"] == []


def test_a_check_without_a_resource_is_never_retried(tmp_path):
    write_bundle(tmp_path, _story(_e2e("A", resource=None)))
    runner = _Flaky(fails=1)
    payload = criteria_check.evaluate_bundle(tmp_path, run=runner)
    assert payload["criteria"][0]["result"] == "fail"
    assert runner.calls == {"e2e.sh": 1}


def test_identical_exclusive_checks_are_retried_once(tmp_path):
    # Two criteria running the same script against the same merchant (the
    # Katun case: the gate stepped on itself) run once and retry once.
    write_bundle(tmp_path, _story(_e2e("A"), _e2e("B")))
    runner = _Flaky(fails=1)
    payload = criteria_check.evaluate_bundle(tmp_path, run=runner)
    assert [r["result"] for r in payload["criteria"]] == ["collision", "collision"]
    assert runner.calls == {"e2e.sh": 2}


def test_the_retry_runs_after_every_other_check(tmp_path):
    order: list[str] = []

    def runner(criterion, root):  # noqa: ARG001
        order.append(criterion["id"])
        ok = criterion["id"] != "A" or order.count("A") > 1
        return criteria_check.RunOutcome(ok=ok, detail="exit 0" if ok else "exit 1")

    write_bundle(tmp_path, _story(_e2e("A", payload="a.sh"), _e2e("B", payload="b.sh")))
    criteria_check.evaluate_bundle(tmp_path, run=runner)
    assert order == ["A", "B", "A"]


def test_the_run_records_the_resource_it_held(tmp_path):
    write_bundle(tmp_path, _story(_e2e("A")))
    payload = criteria_check.evaluate_bundle(tmp_path, run=_Flaky(fails=0), write_artifact=True)
    entry = payload["criteria"][0]
    assert entry["result"] == "pass"
    assert entry["resource"]["name"] == "staging-merchant"
    audit = json.loads((tmp_path / ".linebreak/audit/criteria.json").read_text(encoding="utf-8"))
    assert audit["findings"][0]["resource"]["name"] == "staging-merchant"


# ---------------------------------------------------------------- the lock


def test_the_lock_serializes_and_names_the_holder(tmp_path):
    with (
        resource_lock.hold("merchant", holder="f1-e2e", timeout_s=5),
        pytest.raises(resource_lock.ResourceBusy, match="f1-e2e"),
        resource_lock.hold("merchant", holder="f2-e2e", timeout_s=0.6),
    ):
        pass  # pragma: no cover - the second hold never gets the lock


def test_a_waiting_check_gets_the_lock_when_it_is_released(tmp_path):
    released = threading.Event()

    def hold_briefly():
        with resource_lock.hold("merchant", holder="f1-e2e", timeout_s=5):
            released.wait(5)

    t = threading.Thread(target=hold_briefly)
    t.start()
    try:
        # Wait until the first holder has it.
        for _ in range(50):
            if (resource_lock.lock_dir() / "merchant.holder.json").exists():
                break
            threading.Event().wait(0.05)
        threading.Timer(0.3, released.set).start()
        with resource_lock.hold("merchant", holder="f2-e2e", timeout_s=5) as info:
            assert info["waited_s"] > 0
            assert info["waited_for"]["holder"] == "f1-e2e"
    finally:
        released.set()
        t.join()


def test_a_resource_held_too_long_is_a_tool_error(tmp_path):
    write_bundle(tmp_path, _story(_e2e("A")))
    with resource_lock.hold("staging-merchant", holder="someone-else", timeout_s=5):
        payload = criteria_check.evaluate_bundle(tmp_path, run=_Flaky(fails=0), lock_timeout_s=0.6)
    entry = payload["criteria"][0]
    assert entry["result"] == "error"
    assert "someone-else" in entry["detail"]
    assert payload["tool_error"] is True


# ---------------------------------------------------------------- CLI


def test_cli_reports_the_collision_and_does_not_block(tmp_path, capsys):
    flag = tmp_path / "second-run"
    # Fails the first time (creates the flag), passes the second.
    script = (
        "python -c \"import pathlib,sys; p=pathlib.Path('second-run'); "
        "sys.exit(0) if p.exists() else (p.write_text('x'), sys.exit(1))\""
    )
    write_bundle(tmp_path, _story(_e2e("A", payload=script)))
    code = main(["check", "--path", str(tmp_path)])
    out = capsys.readouterr().out
    assert flag.exists()
    assert code == 0
    assert "[collision] S1/A" in out
    assert "collision: A (S1) on resource staging-merchant" in out


# ---------------------------------------------------------------- with expect (#260)


class _ExitsZero:
    """Always exits 0; prints the expected line only from call ``from_call`` on."""

    def __init__(self, from_call: int) -> None:
        self.from_call = from_call
        self.calls = 0

    def __call__(self, criterion, root):  # noqa: ARG002
        self.calls += 1
        out = "payment captured" if self.calls >= self.from_call else "nothing to do"
        return criteria_check.RunOutcome(ok=True, detail=out, exit_code=0, output=out)


def _e2e_expecting(cid: str) -> dict:
    criterion = _e2e(cid)
    criterion["check"]["expect"] = {"output": "payment captured"}
    return criterion


def test_a_resource_check_that_exits_zero_without_its_expect_is_retried_alone(tmp_path):
    # Exit 0 is not a pass when the expected output is missing, so the re-run
    # alone applies; observing it alone makes the red a collision.
    write_bundle(tmp_path, _story(_e2e_expecting("A")))
    runner = _ExitsZero(from_call=2)
    payload = criteria_check.evaluate_bundle(tmp_path, run=runner)
    (entry,) = payload["criteria"]
    assert entry["result"] == "collision"
    assert runner.calls == 2


def test_a_resource_check_whose_expect_is_missing_alone_too_stays_failed(tmp_path):
    write_bundle(tmp_path, _story(_e2e_expecting("A")))
    runner = _ExitsZero(from_call=99)
    payload = criteria_check.evaluate_bundle(tmp_path, run=runner)
    (entry,) = payload["criteria"]
    assert entry["result"] == "fail"
    assert entry["retried_alone"] == "fail"
    assert "expected output not observed" in entry["detail"]
    assert payload["passes"] is False
