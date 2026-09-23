"""Integridad de la especificación: que lo firmado siga diciendo la verdad.

La compuerta verifica que los criterios pasen; este módulo mira si los
criterios dicen la verdad. Todo es análisis estático del paquete (y, para los
enunciados, del código del repositorio): nada aquí ejecuta un criterio.

* :func:`shared_tests` (issue #263): dos historias que corren las mismas
  pruebas. Una historia puede entregarse entera con pruebas prestadas de otra.
* :func:`stale_statements` (issue #261): un enunciado que nombra
  identificadores que ya no aparecen en el código. La frase firmada dejó de
  describir el sistema aunque las pruebas sigan en verde.
* :func:`diff_stories` (issues #258 y #261): qué cambia entre la aprobación
  anterior y la que se va a firmar, con el antes y el después de cada frase.
* :func:`draft_freshness` (issue #258): si el borrador que se va a firmar es
  el mismo que está en el remoto, o una copia local atrasada.

Cada hallazgo es un ``dict`` con ``kind``, ``id`` (criterio), ``story`` y
``detail``; la política (``off | warn | block``) la aplica quien lo consume
(``criteria_check``), según ``criteria.integrity`` en ``gate.yml``.
"""

from __future__ import annotations

import os
import posixpath
import re
import shlex
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_GIT_TIMEOUT_S = 60

# --------------------------------------------------------------------------
# Pruebas compartidas entre historias (#263)
# --------------------------------------------------------------------------

#: Palabras que arrancan un corredor de pruebas dentro de un comando. Lo que
#: sigue (sin banderas) son los destinos: archivos, carpetas, filtros de ruta.
_RUNNERS = {"pytest", "py.test", "vitest", "jest", "mocha", "ava", "tap", "--test"}
#: Subcomandos del corredor que no son destinos.
_RUNNER_WORDS = {"run", "watch", "related", "test", "exec"}
#: Banderas cuyo valor es un filtro de NOMBRE: forman parte de la identidad
#: del destino (dos historias que parten el mismo archivo con filtros
#: distintos no comparten pruebas).
_NAME_FILTERS = {"-k", "-t", "--testNamePattern", "--test-name-pattern", "-run", "--grep", "-g"}
#: Banderas que consumen un valor que no es un destino.
_VALUED_FLAGS = {
    "-m",
    "-p",
    "-c",
    "-o",
    "--config",
    "--reporter",
    "--project",
    "--rootdir",
    "--dir",
    "--root",
    "--environment",
    "--pool",
}
#: Separadores de comandos en una línea de shell.
_SEPARATORS = {"&&", "||", ";", "|"}
#: Nombres de archivo de prueba en cualquier ecosistema.
_TEST_FILE = re.compile(
    r"(?:^|/)(?:test_[^/]*\.py|[^/]*_test\.py|[^/]*\.(?:test|spec)\.[cm]?[jt]sx?|[^/]*_test\.go)"
    r"(?:::.*)?$"
)


def _split_command(payload: str) -> list[str]:
    try:
        lexer = shlex.shlex(payload, posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return payload.split()


def _norm_path(cwd: str, token: str) -> str:
    path, sep, rest = token.partition("::")
    if not path.startswith("/"):
        path = posixpath.join(cwd, path) if cwd else path
    path = posixpath.normpath(path).rstrip("/") or "."
    return path + (sep + rest if sep else "")


def run_targets(check: dict[str, Any]) -> list[str]:
    """Los destinos de prueba de un check, normalizados para comparar.

    ``tests``: el payload mismo (una ruta o patrón). ``command``: los
    argumentos de un corredor conocido (``pytest``, ``vitest``, ``jest``,
    ``node --test``...) y cualquier archivo con nombre de prueba, resueltos
    contra el ``cd <dir>`` o ``-C <dir>`` que los precede. Un filtro de nombre
    (``-k``, ``-t``) se agrega al destino: partir un archivo entre historias
    con filtros distintos es legítimo.
    """
    ctype = check.get("type")
    payload = check.get("payload")
    if not isinstance(payload, str) or not payload.strip():
        return []
    if ctype == "tests":
        return [_norm_path("", payload.strip())]
    if ctype != "command":
        return []
    targets: list[str] = []
    cwd = ""
    for segment in _segments(_split_command(payload)):
        if len(segment) >= 2 and segment[0] == "cd":
            cwd = _norm_path(cwd, segment[1]) if not segment[1].startswith("$") else cwd
            continue
        seg_cwd = cwd
        found: list[str] = []
        name_filter = ""
        in_runner = False
        skip_next = False
        for i, tok in enumerate(segment):
            if skip_next:
                skip_next = False
                continue
            if tok in ("-C", "--prefix", "--cwd") and i + 1 < len(segment):
                seg_cwd = _norm_path(seg_cwd, segment[i + 1])
                skip_next = True
                continue
            if tok in _NAME_FILTERS and i + 1 < len(segment):
                name_filter = f" ({tok} {segment[i + 1]})"
                skip_next = True
                continue
            if tok in _VALUED_FLAGS:
                skip_next = True
                continue
            base = posixpath.basename(tok)
            if base in _RUNNERS or tok in _RUNNERS:
                in_runner = True
                continue
            if tok == "test" and i > 0 and posixpath.basename(segment[i - 1]) in ("go", "cargo"):
                in_runner = True
                continue
            if tok.startswith("-") or "$" in tok or "=" in tok:
                continue
            if in_runner and tok not in _RUNNER_WORDS:
                found.append(tok)
            elif _TEST_FILE.search(tok):
                found.append(tok)
        targets.extend(_norm_path(seg_cwd, t) + name_filter for t in found)
    # Orden estable y sin repetidos.
    return list(dict.fromkeys(targets))


def _segments(tokens: list[str]) -> list[list[str]]:
    out: list[list[str]] = [[]]
    for tok in tokens:
        if tok in _SEPARATORS or set(tok) <= {"&", "|", ";"}:
            out.append([])
        else:
            out[-1].append(tok)
    return [s for s in out if s]


def shared_tests(stories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Un hallazgo ``shared_tests`` por criterio que corre un destino de
    prueba que también corre OTRA historia. No siempre es un error (hay
    pruebas legítimamente compartidas), pero casi siempre merece una mirada."""
    owners: dict[str, list[tuple[str, str]]] = {}
    for story in stories:
        for c in story.get("criteria") or []:
            for target in run_targets(c.get("check") or {}):
                owners.setdefault(target, []).append((story["id"], c["id"]))
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    for target, users in owners.items():
        if len({sid for sid, _ in users}) < 2:
            continue
        for sid, cid in users:
            others = [f"{o_sid}/{o_cid}" for o_sid, o_cid in users if o_sid != sid]
            entry = findings.setdefault(
                (sid, cid),
                {"kind": "shared_tests", "id": cid, "story": sid, "targets": [], "detail": ""},
            )
            entry["targets"].append({"target": target, "also_in": others})
    for entry in findings.values():
        parts = [f"{t['target']} (also run by {', '.join(t['also_in'])})" for t in entry["targets"]]
        entry["detail"] = "runs the same tests as another story: " + "; ".join(parts)
    return list(findings.values())


# --------------------------------------------------------------------------
# Enunciados que envejecen (#261)
# --------------------------------------------------------------------------

_BACKTICK = re.compile(r"`([^`\n]+)`")
_SNAKE = re.compile(r"(?<![\w/.\-$])([A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+)(?![\w]|\.\w|/)")
_FILE_EXTS = "ya?ml|json|toml|py|tsx?|jsx?|mjs|cjs|md|sh|go|rs|sql|txt|ini|cfg|lock"
_FILE = re.compile(rf"(?<![\w/.\-])((?:[\w.\-]+/)*[\w\-]+\.(?:{_FILE_EXTS}))(?![\w/])")
#: Tope de identificadores por paquete: un enunciado no es un volcado de código.
_MAX_IDENTIFIERS = 400


def statement_identifiers(statement: str) -> dict[str, list[str]]:
    """Los identificadores de código que nombra un enunciado.

    ``names``: lo que va entre comillas invertidas (siempre, es la forma
    explícita de decir "esto es un nombre del código") y las palabras con
    guion bajo (``solo_registro``, ``LINEBREAK_GOVERNANCE_TOKEN``). ``files``:
    nombres de archivo con extensión conocida (``gate.yml``,
    ``docs/RUNBOOK.md``). Una palabra común sin marcas no se toma por
    identificador: los falsos positivos matan una advertencia.
    """
    names: list[str] = []
    files: list[str] = []
    rest = statement
    for m in _BACKTICK.finditer(statement):
        token = m.group(1).strip()
        if not token:
            continue
        if _FILE.fullmatch(token):
            files.append(token)
        else:
            names.append(token)
    rest = _BACKTICK.sub(" ", statement)
    for m in _FILE.finditer(rest):
        files.append(m.group(1))
    for m in _SNAKE.finditer(_FILE.sub(" ", rest)):
        names.append(m.group(1))
    return {"names": list(dict.fromkeys(names)), "files": list(dict.fromkeys(files))}


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        # git entrega los archivos tal cual (UTF-8 en la especificación); la
        # codificación local de Windows (cp1252) los desfiguraría y un
        # borrador con acentos parecería distinto del remoto.
        encoding="utf-8",
        errors="replace",
        timeout=_GIT_TIMEOUT_S,
        env=env,
        check=False,
    )


#: Dónde NO se busca un identificador: la especificación misma (siempre lo
#: contiene) y la documentación en Markdown (un CHANGELOG recuerda los nombres
#: viejos para siempre y escondería justo el desfase que se busca).
_SEARCH_PATHSPEC = (".", ":(exclude).linebreak", ":(exclude,glob)**/*.md")


def _grep_found(root: Path, tokens: list[str], *, word: bool) -> set[str]:
    """Los ``tokens`` que aparecen en el código. Una pasada con todos, y una
    búsqueda individual para los que no salieron (``-o`` puede reportar solo
    el más largo de dos patrones que se solapan)."""
    if not tokens:
        return set()
    flags = ["grep", "-I", "-F", "--untracked", "--no-color"] + (["-w"] if word else [])
    patterns = [a for t in tokens for a in ("-e", t)]
    proc = _git(root, *flags, "-o", "-h", *patterns, "--", *_SEARCH_PATHSPEC)
    if proc.returncode not in (0, 1):
        raise OSError(proc.stderr.strip() or f"git grep exited {proc.returncode}")
    found = {line for line in proc.stdout.splitlines() if line in tokens}
    for token in tokens:
        if token in found:
            continue
        one = _git(root, *flags, "-q", "-e", token, "--", *_SEARCH_PATHSPEC)
        if one.returncode == 0:
            found.add(token)
        elif one.returncode != 1:
            raise OSError(one.stderr.strip() or f"git grep exited {one.returncode}")
    return found


def _tracked_files(root: Path) -> list[str]:
    proc = _git(root, "ls-files", "--cached", "--others", "--exclude-standard")
    if proc.returncode != 0:
        raise OSError(proc.stderr.strip() or "git ls-files failed")
    return proc.stdout.splitlines()


def _file_present(token: str, files: list[str], root: Path) -> bool:
    token = token.removeprefix("./")
    if (root / token).exists():
        return True
    return any(f == token or f.endswith("/" + token) for f in files)


@dataclass
class StaleReport:
    """Resultado de :func:`stale_statements`: hallazgos, o por qué no se miró."""

    findings: list[dict[str, Any]] = field(default_factory=list)
    skipped: str | None = None


def stale_statements(root: Path | str, stories: list[dict[str, Any]]) -> StaleReport:
    """Criterios cuyo enunciado nombra identificadores o archivos que ya no
    aparecen en el repositorio. No decide si el criterio está mal: señala
    dónde mirar. Sin git (o con un git que no responde) no se mira, y el
    informe dice por qué: nunca se presenta como "todo al día"."""
    root = Path(root)
    per_criterion: list[tuple[str, str, dict[str, list[str]]]] = []
    for story in stories:
        for c in story.get("criteria") or []:
            idents = statement_identifiers(str(c.get("statement") or ""))
            if idents["names"] or idents["files"]:
                per_criterion.append((story["id"], c["id"], idents))
    if not per_criterion:
        # Ningún enunciado nombra un identificador: no hay nada que buscar.
        return StaleReport()
    probe = None
    try:
        probe = _git(root, "rev-parse", "--is-inside-work-tree")
    except (OSError, subprocess.TimeoutExpired):
        pass
    if probe is None or probe.returncode != 0 or probe.stdout.strip() != "true":
        return StaleReport(skipped="not a git repository")
    names = list(dict.fromkeys(n for _, _, i in per_criterion for n in i["names"]))
    if len(names) > _MAX_IDENTIFIERS:
        names = names[:_MAX_IDENTIFIERS]
    words = [n for n in names if re.fullmatch(r"\w+", n)]
    others = [n for n in names if n not in words]
    try:
        found = _grep_found(root, words, word=True) | _grep_found(root, others, word=False)
        files = _tracked_files(root)
    except (OSError, subprocess.TimeoutExpired) as e:
        return StaleReport(skipped=f"could not search the code ({e})")
    report = StaleReport()
    for sid, cid, idents in per_criterion:
        missing = [n for n in idents["names"] if n in names and n not in found]
        missing += [f for f in idents["files"] if not _file_present(f, files, root)]
        if missing:
            report.findings.append(
                {
                    "kind": "stale_statements",
                    "id": cid,
                    "story": sid,
                    "missing": missing,
                    "detail": "the statement names "
                    + ", ".join(f"`{m}`" for m in missing)
                    + ", no longer found in the code (outside .linebreak/ and Markdown): "
                    "the signed text may describe a system that changed",
                }
            )
    return report


# --------------------------------------------------------------------------
# Qué cambia entre dos aprobaciones (#258, #261)
# --------------------------------------------------------------------------


def _criteria_index(stories: list[dict[str, Any]]) -> dict[str, tuple[str, dict[str, Any]]]:
    return {
        c["id"]: (s["id"], c)
        for s in stories
        if isinstance(s, dict)
        for c in s.get("criteria") or []
        if isinstance(c, dict) and isinstance(c.get("id"), str)
    }


def _check_text(check: Any) -> str:
    if not isinstance(check, dict):
        return "?"
    text = str(check.get("type"))
    if check.get("payload"):
        text += f": {check['payload']}"
    if check.get("when") and check.get("when") != "always":
        text += f", when: {check['when']}"
    if check.get("expect"):
        text += f", expect: {check['expect']}"
    return text


def diff_stories(old: list[dict[str, Any]], new: list[dict[str, Any]]) -> dict[str, Any]:
    """Diferencia entre dos listas de historias (aprobación anterior y
    borrador): historias y criterios agregados y quitados, y para cada
    criterio que sigue, el antes y el después de su enunciado y de su check."""
    old_ids = [s["id"] for s in old if isinstance(s, dict)]
    new_ids = [s["id"] for s in new if isinstance(s, dict)]
    old_c = _criteria_index(old)
    new_c = _criteria_index(new)
    changed: list[dict[str, Any]] = []
    for cid, (sid, c) in new_c.items():
        if cid not in old_c:
            continue
        o_sid, o = old_c[cid]
        entry: dict[str, Any] = {"id": cid, "story": sid}
        if o_sid != sid:
            entry["moved_from"] = o_sid
        if str(o.get("statement")) != str(c.get("statement")):
            entry["statement"] = {"before": o.get("statement"), "after": c.get("statement")}
        if _check_text(o.get("check")) != _check_text(c.get("check")):
            entry["check"] = {
                "before": _check_text(o.get("check")),
                "after": _check_text(c.get("check")),
            }
        if len(entry) > 2:
            changed.append(entry)
    return {
        "stories_added": [s for s in new_ids if s not in old_ids],
        "stories_removed": [s for s in old_ids if s not in new_ids],
        "criteria_added": [
            {"id": cid, "story": sid} for cid, (sid, _) in new_c.items() if cid not in old_c
        ],
        "criteria_removed": [
            {"id": cid, "story": sid} for cid, (sid, _) in old_c.items() if cid not in new_c
        ],
        "criteria_changed": changed,
    }


def diff_is_empty(diff: dict[str, Any]) -> bool:
    return not any(diff[k] for k in diff)


def format_diff(diff: dict[str, Any]) -> list[str]:
    """Las líneas (en inglés, como toda la salida de la CLI) de una diferencia."""
    lines: list[str] = []
    for sid in diff["stories_added"]:
        lines.append(f"  + story {sid}")
    for sid in diff["stories_removed"]:
        lines.append(f"  - story {sid}")
    for c in diff["criteria_added"]:
        lines.append(f"  + criterion {c['id']} ({c['story']})")
    for c in diff["criteria_removed"]:
        lines.append(f"  - criterion {c['id']} ({c['story']})")
    for c in diff["criteria_changed"]:
        what = [k for k in ("statement", "check") if k in c]
        moved = f", moved from {c['moved_from']}" if c.get("moved_from") else ""
        lines.append(
            f"  ~ criterion {c['id']} ({c['story']}){moved}: {' and '.join(what) or 'moved'} changed"
        )
        if "statement" in c:
            lines.append(f"      before: {_one_line(c['statement']['before'])}")
            lines.append(f"      after:  {_one_line(c['statement']['after'])}")
        if "check" in c:
            lines.append(f"      check before: {_one_line(c['check']['before'])}")
            lines.append(f"      check after:  {_one_line(c['check']['after'])}")
    return lines


def _one_line(text: Any) -> str:
    return " ".join(str(text if text is not None else "").split())


def count_criteria(stories: list[dict[str, Any]]) -> int:
    return sum(len(s.get("criteria") or []) for s in stories if isinstance(s, dict))


# --------------------------------------------------------------------------
# ¿El borrador en disco es el del remoto? (#258)
# --------------------------------------------------------------------------

#: Estados de :func:`draft_freshness`. ``fresh``: el borrador en disco es el
#: del remoto. ``no-remote``: el repositorio no tiene remoto (o no es un
#: repositorio): no hay copia que pueda ir adelante. ``stale``: el remoto
#: tiene otro contenido. ``missing``: el borrador no está en el remoto.
#: ``unreachable``: no se pudo consultar el remoto. ``outside``: el borrador
#: está fuera del repositorio.
FRESHNESS_STATES = ("fresh", "no-remote", "stale", "missing", "unreachable", "outside")


@dataclass
class Freshness:
    status: str
    ref: str | None = None
    detail: str = ""
    remote_stories: list[dict[str, Any]] | None = None


def _remote_and_branch(root: Path, against: str | None) -> tuple[str, str] | None:
    remotes = [r for r in _git(root, "remote").stdout.split() if r]
    if not remotes:
        return None
    if against:
        # "<remote>/<rama>": el remoto es el prefijo más largo que exista.
        for remote in sorted(remotes, key=len, reverse=True):
            if against.startswith(remote + "/"):
                return remote, against[len(remote) + 1 :]
        remote = remotes[0] if len(remotes) == 1 else "origin"
        return remote, against
    current = _git(root, "symbolic-ref", "--quiet", "--short", "HEAD").stdout.strip()
    if current:
        remote = _git(root, "config", f"branch.{current}.remote").stdout.strip()
        merge = _git(root, "config", f"branch.{current}.merge").stdout.strip()
        if remote and remote != "." and merge.startswith("refs/heads/"):
            return remote, merge[len("refs/heads/") :]
    remote = "origin" if "origin" in remotes else remotes[0]
    head = _git(root, "symbolic-ref", "--quiet", f"refs/remotes/{remote}/HEAD").stdout.strip()
    prefix = f"refs/remotes/{remote}/"
    if head.startswith(prefix):
        return remote, head[len(prefix) :]
    for branch in ("main", "master"):
        if _git(root, "rev-parse", "--verify", "--quiet", f"{prefix}{branch}").returncode == 0:
            return remote, branch
    return remote, "main"


def draft_freshness(
    root: Path | str, draft_path: Path, data: Any, *, against: str | None = None
) -> Freshness:
    """Compara el borrador que se va a firmar (``data``, ya leído del disco)
    con su versión en el remoto, trayéndola en el momento (``git fetch``).

    El remoto contra el que se compara es ``against`` (``<remoto>/<rama>``)
    si se da; si no, la rama que sigue la rama actual; si no hay, la rama por
    defecto del remoto. La comparación es sobre el contenido leído (YAML o
    JSON), no sobre los bytes: un cambio de espacios no es un borrador
    distinto, una historia de más sí.
    """
    root = Path(root).resolve()
    try:
        top_proc = _git(root, "rev-parse", "--show-toplevel")
    except (OSError, subprocess.TimeoutExpired) as e:
        return Freshness("no-remote", detail=f"git is not available ({e})")
    if top_proc.returncode != 0:
        return Freshness("no-remote", detail="not a git repository")
    top = Path(top_proc.stdout.strip()).resolve()
    target = _remote_and_branch(root, against)
    if target is None:
        return Freshness("no-remote", detail="the repository has no remote")
    remote, branch = target
    ref = f"{remote}/{branch}"
    try:
        rel = draft_path.resolve().relative_to(top).as_posix()
    except ValueError:
        return Freshness("outside", ref=ref, detail=f"{draft_path} is outside the repository")
    try:
        fetch = _git(root, "fetch", "--quiet", "--no-tags", remote, branch)
    except subprocess.TimeoutExpired:
        return Freshness("unreachable", ref=ref, detail=f"git fetch {remote} {branch} timed out")
    if fetch.returncode != 0:
        why = (fetch.stderr or fetch.stdout).strip().splitlines()
        return Freshness(
            "unreachable",
            ref=ref,
            detail=f"git fetch {remote} {branch} failed: {why[-1] if why else 'no output'}",
        )
    shown = _git(root, "show", f"FETCH_HEAD:{rel}")
    if shown.returncode != 0:
        return Freshness("missing", ref=ref, detail=f"{rel} does not exist on {ref}")
    try:
        remote_data = yaml.safe_load(shown.stdout)
    except yaml.YAMLError:
        return Freshness("stale", ref=ref, detail=f"{rel} on {ref} does not parse")
    remote_stories = (remote_data.get("stories") if isinstance(remote_data, dict) else None) or []
    if remote_data == data:
        return Freshness("fresh", ref=ref, remote_stories=remote_stories)
    return Freshness(
        "stale",
        ref=ref,
        detail=f"{rel} on disk differs from {ref}",
        remote_stories=[s for s in remote_stories if isinstance(s, dict) and "id" in s],
    )
