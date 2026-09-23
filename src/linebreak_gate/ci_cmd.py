"""``linebreak-gate ci``: the whole gate run in one command, for CI providers
without a native Action (Bitbucket Pipelines, Azure Pipelines, any other).

It does what the GitHub Action's steps do, in the same order and with the
same fail-closed rules:

1. ``scan`` (dependencies + AI review), output captured as evidence;
2. ``check`` with the scope resolved like ``scripts/check-scope.sh`` does
   (per story on pull requests, the full bundle at release);
3. the JSON report and the audit records copied to an output directory the
   pipeline can publish as an artifact;
4. the PR summary comment and the build status, posted through the
   provider's API when credentials exist (never blocking, never silent);
5. exit with the worse of the two codes (0 pass / 1 blocking / 2 tool error).

The provider, repository, commit, branch and PR number all come from
:mod:`linebreak_gate.ci_env`; nothing here reads a provider variable directly.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import traceback
from collections.abc import Callable, Mapping
from pathlib import Path

from . import ci_env, ci_report

#: Where the run leaves its evidence, relative to the project root. Pipelines
#: declare it as an artifact; it is never committed (add it to .gitignore).
OUT_DIR_REL = Path(".linebreak") / "ci-out"
AUDIT_DIR_REL = Path(".linebreak") / "audit"

STORY_MODES = ("all", "auto")
MANUAL_MODES = ("auto", "warn", "block")
STAGE_MODES = ("auto", "release", "pr")

#: Credentials a pipeline maps from secret variables. Azure Pipelines leaves
#: an UNDEFINED ``$(NAME)`` macro as literal text, which would look like a
#: real key (and turn the AI review into a tool error); such values are
#: dropped before anything reads them.
_CREDENTIAL_VARS = (
    "LINEBREAK_LICENSE_KEY",
    "ANTHROPIC_API_KEY",
    "SYSTEM_ACCESSTOKEN",
    "AZURE_DEVOPS_PAT",
    "BITBUCKET_ACCESS_TOKEN",
    "BITBUCKET_USERNAME",
    "BITBUCKET_APP_PASSWORD",
    "BITBUCKET_API_TOKEN",
)
_MACRO_RE = re.compile(r"^\$\([A-Za-z0-9_.]+\)$")
_STORY_BRANCH_RE = re.compile(r"^(feat|story)/([A-Za-z0-9][A-Za-z0-9._-]*)$")


class _Buffer(io.StringIO):
    # The CLI picks its result glyphs from sys.stdout.encoding; a plain
    # StringIO reports None and would degrade the captured report to ASCII.
    encoding = "utf-8"


def _capture(run_cli: Callable[[list[str]], int], argv: list[str]) -> tuple[int, str]:
    """Run one CLI invocation with stdout+stderr captured, like the Action's
    ``2>&1 | tee``. Any escape (argparse's SystemExit, an unexpected
    exception) is a tool error (2) with the traceback in the evidence: the
    gate never turns its own crash into a pass."""
    buf = _Buffer()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        try:
            code = int(run_cli(argv) or 0)
        except SystemExit as e:  # argparse usage errors
            code = e.code if isinstance(e.code, int) else 2
        except Exception:  # noqa: BLE001 - fail closed on anything
            buf.write("linebreak-gate: unexpected error (gate stays closed)\n")
            buf.write(traceback.format_exc())
            code = 2
    return code, buf.getvalue()


def scrub_unexpanded_macros(environ: dict[str, str] | os._Environ[str]) -> list[str]:
    """Drop credential variables whose value is an unexpanded ``$(NAME)``
    macro. Returns the names dropped (for the log)."""
    dropped = []
    for name in _CREDENTIAL_VARS:
        value = environ.get(name)
        if value is not None and _MACRO_RE.match(value.strip()):
            del environ[name]
            dropped.append(name)
    return dropped


# ---------------------------------------------------------------- check scope


def _approved(root: Path, story_id: str) -> bool:
    """Same rule as check-scope.sh's ``approved()``: ``spec show`` exits 0 for
    an approved story AND when no spec exists at all (the check is a no-op
    either way)."""
    from . import bridge

    out = bridge.get_story(root, story_id)
    return bool(out.get("ok")) or out.get("error") == "no-spec"


def infer_story(root: Path, branch: str | None) -> str | None:
    """The story id in a ``feat/<id>`` or ``story/<id>`` branch, trying the
    segment and then progressively without its trailing ``-slug`` parts
    (``feat/E1-S1-add-login`` tries E1-S1-add-login, E1-S1-add, E1-S1)."""
    if not branch:
        return None
    m = _STORY_BRANCH_RE.match(branch)
    if not m:
        return None
    candidate = m.group(2)
    while candidate:
        if _approved(root, candidate):
            return candidate
        if "-" not in candidate:
            break
        candidate = candidate.rsplit("-", 1)[0]
    return None


def resolve_check_scope(
    root: Path, *, env: ci_env.CiEnv, story: str, manual: str, stage: str
) -> tuple[list[str] | None, str, str, str]:
    """Turn the ``story``/``manual``/``stage`` inputs into ``check`` flags.
    Returns (flags or None when an input is invalid, scope note, manual,
    stage). ``auto`` for manual and stage follows the build: ``warn`` and
    ``pr`` on a pull request, ``block`` and ``release`` elsewhere."""
    if manual in ("auto", ""):
        manual = "warn" if env.is_pr else "block"
    if manual not in ("warn", "block"):
        return (
            None,
            f"invalid 'manual' input '{manual}' (expected warn or block); gate stays closed",
            manual,
            stage,
        )
    if stage in ("auto", ""):
        stage = env.stage
    if stage not in ("release", "pr"):
        return (
            None,
            f"invalid 'stage' input '{stage}' (expected release or pr); gate stays closed",
            manual,
            stage,
        )
    flags = ["--manual", manual, "--stage", stage]
    if story == "all":
        scope = "scope: all stories (story: all)"
    elif story == "auto":
        inferred = infer_story(root, env.branch)
        if inferred:
            flags += ["--story", inferred]
            scope = f"scope: story {inferred} inferred from branch {env.branch} (story: auto)"
        else:
            flags.append("--started-only")
            scope = (
                "scope: started stories only; no approved story id in branch "
                f"'{env.branch or ''}' (story: auto)"
            )
    elif not story.strip():
        return (
            None,
            "invalid 'story' input (empty; expected all, auto, or a story id); gate stays closed",
            manual,
            stage,
        )
    else:
        flags += ["--story", story]
        scope = f"scope: story {story} (story input)"
    return flags, f"{scope}; manual criteria: {manual}; stage: {stage}", manual, stage


# ---------------------------------------------------------------- the command


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _json_block_reasons(report_json: str) -> list[str] | None:
    """``block_reasons`` from ``report --format json``; None when the report
    did not parse or carries no such list (older records, no scan)."""
    try:
        data = json.loads(report_json)
    except ValueError:
        return None
    reasons = data.get("block_reasons") if isinstance(data, dict) else None
    if not isinstance(reasons, list):
        return None
    return [str(r) for r in reasons]


def run_ci(
    *,
    path: str | Path = ".",
    fail_on: str | None = None,
    story: str = "all",
    manual: str = "auto",
    stage: str = "auto",
    comment: bool = True,
    status: bool = True,
    out_dir: str | Path | None = None,
    environ: Mapping[str, str] | None = None,
    run_cli: Callable[[list[str]], int] | None = None,
    transport: ci_report.Transport | None = None,
) -> int:
    """Run the whole gate and report. Returns the exit code."""
    if run_cli is None:
        from .cli import main as run_cli
    env_map = os.environ if environ is None else environ
    root = Path(path).resolve()
    out = Path(out_dir).resolve() if out_dir else root / OUT_DIR_REL

    if environ is None:
        dropped = scrub_unexpanded_macros(os.environ)
        for name in dropped:
            print(
                f"linebreak-gate ci: {name} holds an unexpanded $(...) pipeline macro "
                "(the variable is not defined); treated as unset"
            )
    env = ci_env.detect(env_map)
    where = f"PR #{env.pr_number}" if env.is_pr else "not a pull request"
    print(
        f"linebreak-gate ci: {env.label}; repo {env.repo or '?'}; commit "
        f"{(env.commit or '?')[:12]}; branch {env.branch or '?'}; {where}"
    )

    # 1. scan
    scan_argv = ["scan", "--path", str(root)]
    if fail_on:
        scan_argv += ["--fail-on", fail_on]
    scan_code, scan_text = _capture(run_cli, scan_argv)
    print(scan_text, end="" if scan_text.endswith("\n") else "\n")

    # 2. check, scoped
    flags, note, manual, stage = resolve_check_scope(
        root, env=env, story=story, manual=manual, stage=stage
    )
    criteria_text = f"linebreak-gate ci: {note}\n"
    if flags is None:
        check_code = 2
    else:
        check_code, check_text = _capture(run_cli, ["check", "--path", str(root), *flags])
        criteria_text += check_text
    print(criteria_text, end="" if criteria_text.endswith("\n") else "\n")

    # 3. evidence for the artifact
    _write(out / "report.txt", scan_text)
    _write(out / "criteria.txt", criteria_text)
    report_argv = ["report", "--path", str(root), "--format", "json"]
    if fail_on:
        report_argv += ["--fail-on", fail_on]
    _, report_json = _capture(run_cli, report_argv)
    _write(out / "report.json", report_json)
    audit = root / AUDIT_DIR_REL
    if audit.is_dir():
        for record in sorted(audit.glob("*.json")):
            try:
                shutil.copyfile(record, out / record.name)
            except OSError:
                pass

    # 4. the PR comment and the build status. Block reasons (kev, vulnerability,
    # expired_risk) come from the JSON report when it parses, else from the
    # summary; the check's reasons and role denials come from its summary.
    reasons = ci_report.parse_block_reasons(scan_text, criteria_text)
    scan_reasons = _json_block_reasons(report_json)
    if scan_reasons is None:
        scan_reasons = reasons["scan_reasons"]
    body = ci_report.render_comment(
        scan_text, scan_code, criteria_text, check_code, scan_reasons=scan_reasons
    )
    _write(out / "comment.md", body)
    state, description = ci_report.verdict(
        scan_code,
        check_code,
        scan_reasons=scan_reasons,
        check_reasons=reasons["check_reasons"],
    )
    for line in ci_report.report_to_pr(
        env,
        body,
        state,
        description,
        environ=env_map,
        transport=transport,
        comment=comment,
        status=status,
    ):
        print(f"linebreak-gate ci: {line}")

    # 5. enforce: the worse code wins (a tool error is never downgraded)
    code = max(scan_code, check_code)
    print(
        f"linebreak-gate ci: scan exited {scan_code}, check exited {check_code} "
        f"(0 pass / 1 blocking / 2 tool error); evidence in {out}"
    )
    return code
