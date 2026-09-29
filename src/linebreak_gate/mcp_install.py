"""LIN-55 ``linebreak-gate mcp install``: editor configuration for the bridge.

Writes (or, with ``--print``, prints) the MCP server config so the developer's
editor launches ``linebreak-gate mcp`` in the repo. Supported directly:
Claude Code (``.mcp.json``), Cursor (``.cursor/mcp.json``), Codex
(``~/.codex/config.toml``), GitHub Copilot in VS Code (``.vscode/mcp.json``);
anything else that speaks MCP takes the generic stdio config.

The hard rule: **never silently overwrite an existing config.** A fresh file is
written; a parseable file without our entry is merged (and says so); a file
that already carries a ``linebreak`` entry — or that we cannot parse — is left
byte-for-byte untouched and the desired config is printed for the human to
apply. Config in the repo uses no absolute paths, so it works for every clone
and teammate.

e17-s1: registering the server is not enough. An agent that was never told
the criteria live behind the MCP tools answers "what are the criteria of
story X?" by shelling out to the CLI and git. So install also writes a short
MANAGED block, between LineBreak markers, into the file the editor's agent
always reads (``CLAUDE.md``, ``AGENTS.md``, ``.cursor/rules/linebreak.mdc``,
``.github/copilot-instructions.md``), in the language of the repo's spec.
Only that block is ever replaced; the rest of the file is never touched.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

EDITORS = ("claude-code", "cursor", "codex", "copilot")

#: The stdio server every editor launches. Relative invocation on purpose —
#: the editor runs it with the workspace as cwd, so the config is portable
#: across clones and machines.
SERVER_ENTRY = {"command": "linebreak-gate", "args": ["mcp"]}

#: VS Code (GitHub Copilot) reads ``.vscode/mcp.json`` with a ``servers`` map
#: and an explicit transport ``type``; a stdio server's cwd defaults to the
#: workspace folder, so the entry stays repo-relative too.
#: https://code.visualstudio.com/docs/copilot/reference/mcp-configuration
VSCODE_SERVER_ENTRY = {"type": "stdio", "command": "linebreak-gate", "args": ["mcp"]}

#: Where each editor's agent reads its standing instructions (repo-relative).
INSTRUCTION_FILES = {
    "claude-code": "CLAUDE.md",
    "codex": "AGENTS.md",
    "cursor": ".cursor/rules/linebreak.mdc",
    "copilot": ".github/copilot-instructions.md",
}

#: Marker pairs per language. Both pairs are RECOGNIZED on read, so a repo
#: whose spec changed language gets its block replaced, not duplicated.
_MARKERS = {
    "es": ("<!-- linebreak:inicio -->", "<!-- linebreak:fin -->"),
    "en": ("<!-- linebreak:start -->", "<!-- linebreak:end -->"),
}
_START_RE = re.compile(r"<!-- linebreak:(?:inicio|start) -->")
_END_RE = re.compile(r"<!-- linebreak:(?:fin|end) -->")

_BLOCK_LINES = {
    "es": [
        "## Contrato de LineBreak",
        "",
        "Este bloque lo escribe `linebreak-gate mcp install`; al volver a correrlo se reemplaza.",
        "",
        "- Los criterios de aceptación de este repositorio son el contrato firmado de LineBreak.",
        "- Para leer historias, criterios y el estado del contrato usa las herramientas MCP de"
        " LineBreak: `list_stories`, `get_story`, `next_story`, `spec_status` y `check_story`."
        " No uses la CLI `linebreak-gate` ni leas `.linebreak/` directamente.",
        "- Nunca corras comandos de escritura de la CLI (`spec approve`, `signoff`, `override`,"
        " `publish`) salvo que una persona lo pida explícitamente.",
        "- No edites la especificación (`.linebreak/spec/`) ni el borrador"
        " (`.linebreak/spec-draft.yml`).",
        "- Si un criterio no se puede cumplir, dilo en vez de cambiarlo.",
        "- Si `spec_status` dice que no hay especificación aprobada, dilo así; no la crees ni"
        " la apruebes por tu cuenta.",
    ],
    "en": [
        "## LineBreak contract",
        "",
        "This block is written by `linebreak-gate mcp install`; running it again replaces it.",
        "",
        "- The acceptance criteria of this repository are the signed LineBreak contract.",
        "- To read stories, criteria and the contract status, use the LineBreak MCP tools:"
        " `list_stories`, `get_story`, `next_story`, `spec_status` and `check_story`."
        " Do not use the `linebreak-gate` CLI or read `.linebreak/` directly.",
        "- Never run CLI write commands (`spec approve`, `signoff`, `override`, `publish`)"
        " unless a person explicitly asks for it.",
        "- Do not edit the specification (`.linebreak/spec/`) or the draft"
        " (`.linebreak/spec-draft.yml`).",
        "- If a criterion cannot be met, say so instead of changing it.",
        "- If `spec_status` reports that there is no approved specification, say so; do not"
        " create or approve one on your own.",
    ],
}

#: Cursor only applies a project rule on every request when its frontmatter
#: says ``alwaysApply: true``; ``description`` is what the rules UI shows.
#: https://cursor.com/docs/context/rules
_MDC_FRONTMATTER = {
    "es": [
        "---",
        "description: Contrato de LineBreak, cómo leer los criterios",
        "alwaysApply: true",
        "---",
    ],
    "en": [
        "---",
        "description: LineBreak contract, how to read the criteria",
        "alwaysApply: true",
        "---",
    ],
}

#: Spanish vs English, by frequent function words. Deliberately words that
#: exist in only one of the two languages ("a", "no" are left out).
_ES_WORDS = frozenset(
    "el la los las de del que en con por para una un se es y sin su al lo como más cuando".split()
)
_EN_WORDS = frozenset(
    "the and of to is with for that in an be on are it by or when from this as".split()
)
_WORD_RE = re.compile(r"[a-záéíóúüñ]+")
_ACCENT_RE = re.compile(r"[áéíóúñ¿¡]")

_CODEX_SECTION = (
    "\n# LineBreak spec bridge — the approved stories/criteria for the repo you're in\n"
    "[mcp_servers.linebreak]\n"
    'command = "linebreak-gate"\n'
    'args = ["mcp"]\n'
)


def _generic_json(root_key: str = "mcpServers", entry: dict | None = None) -> str:
    return json.dumps({root_key: {"linebreak": entry or SERVER_ENTRY}}, indent=2)


def _install_json(
    path: Path, *, print_only: bool, root_key: str = "mcpServers", entry: dict | None = None
) -> int:
    """Claude Code / Cursor: a JSON file with an ``mcpServers`` map. VS Code
    (Copilot): the same shape under ``servers`` with a ``type`` per server."""
    entry = entry or SERVER_ENTRY
    wanted = _generic_json(root_key, entry)
    if print_only:
        print(f"Add to {path}:")
        print(wanted)
        return 0
    if path.exists():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(doc, dict):
                raise ValueError("top level is not an object")
        except (ValueError, OSError) as e:
            print(f"{path} could not be parsed ({e}) — left untouched. Add this yourself:")
            print(wanted)
            return 0
        servers = doc.get(root_key)
        if root_key in doc and not isinstance(servers, dict):
            # A hand-edited/foreign shape we don't understand — replacing it
            # would silently destroy the user's value. Leave it, print ours.
            print(
                f"{path} has a {root_key} entry that is not an object — left untouched. "
                "Add this yourself:"
            )
            print(wanted)
            return 0
        servers = servers if isinstance(servers, dict) else {}
        if "linebreak" in servers:
            if servers["linebreak"] == entry:
                print(f"{path} already configures the linebreak server — nothing to do.")
                return 0
            print(
                f"{path} already has a DIFFERENT 'linebreak' entry — left untouched. "
                "The standard entry, if you want to switch:"
            )
            print(wanted)
            return 0
        servers["linebreak"] = entry
        doc[root_key] = servers
        path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"Merged the linebreak server into the existing {path}.")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(wanted + "\n", encoding="utf-8")
    print(f"Wrote {path}.")
    return 0


# ---------------------------------------------------------------- instructions block


def _spec_texts(node: object) -> list[str]:
    """Every ``title`` / ``statement`` string anywhere in a parsed spec file:
    the prose a human wrote, never the English YAML keys around it."""
    out: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("title", "statement") and isinstance(value, str):
                out.append(value)
            else:
                out.extend(_spec_texts(value))
    elif isinstance(node, list):
        for item in node:
            out.extend(_spec_texts(item))
    return out


def _load_texts(paths: list[Path]) -> list[str]:
    texts: list[str] = []
    for path in paths:
        try:
            texts.extend(_spec_texts(yaml.safe_load(path.read_text(encoding="utf-8"))))
        except (yaml.YAMLError, OSError, UnicodeDecodeError):
            continue  # a broken file says nothing about the language
    return texts


def text_language(text: str) -> str:
    """``"es"`` when the text reads as Spanish, ``"en"`` otherwise."""
    words = _WORD_RE.findall(text.lower())
    es = sum(w in _ES_WORDS for w in words) + len(_ACCENT_RE.findall(text.lower()))
    en = sum(w in _EN_WORDS for w in words)
    return "es" if es > en else "en"


def spec_language(repo_root: Path | str) -> str:
    """The language of the repo's specification: the APPROVED stories in
    ``.linebreak/spec/``, else the draft ``.linebreak/spec-draft.yml``, else
    English (no spec yet)."""
    root = Path(repo_root)
    stories_dir = root / ".linebreak" / "spec" / "stories"
    approved = sorted(stories_dir.glob("*.yml")) if stories_dir.is_dir() else []
    texts = _load_texts(approved)
    if not texts:
        texts = _load_texts([root / ".linebreak" / "spec-draft.yml"])
    return text_language("\n".join(texts)) if texts else "en"


def instructions_block(lang: str, newline: str = "\n") -> str:
    """The managed block, markers included, without a trailing newline. Blank
    lines around the body keep it stable under Markdown formatters (Prettier
    separates an HTML comment from a heading), so a formatted file does not
    read as a stale block on the next install."""
    start, end = _MARKERS[lang]
    return newline.join([start, "", *_BLOCK_LINES[lang], "", end])


def write_instructions(path: Path, lang: str, *, frontmatter: list[str] | None = None) -> str:
    """Create, append or replace the managed block in ``path``; never touch
    anything outside it. Returns ``created`` | ``appended`` | ``replaced`` |
    ``unchanged`` | ``untouched`` (markers we cannot pair safely).

    Bytes in, bytes out: the file's own line endings are kept, so a CRLF file
    on Windows is not rewritten line by line."""
    if not path.exists():
        body = instructions_block(lang) + "\n"
        if frontmatter:
            body = "\n".join(frontmatter) + "\n" + body
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body.encode("utf-8"))
        return "created"
    text = path.read_bytes().decode("utf-8")
    nl = "\r\n" if "\r\n" in text else "\n"
    block = instructions_block(lang, nl)
    starts = list(_START_RE.finditer(text))
    ends = list(_END_RE.finditer(text))
    if not starts and not ends:
        if text and not text.endswith(("\n", "\r")):
            text += nl
        new = text + (nl if text else "") + block + nl
        path.write_bytes(new.encode("utf-8"))
        return "appended"
    if len(starts) != 1 or len(ends) != 1 or ends[0].start() < starts[0].end():
        return "untouched"
    new = text[: starts[0].start()] + block + text[ends[0].end() :]
    if new == text:
        return "unchanged"
    path.write_bytes(new.encode("utf-8"))
    return "replaced"


def _install_instructions(root: Path, editor: str, *, print_only: bool) -> int:
    rel = INSTRUCTION_FILES[editor]
    path = root / rel
    lang = spec_language(root)
    frontmatter = _MDC_FRONTMATTER[lang] if rel.endswith(".mdc") else None
    if print_only:
        print(f"Add to {path} (the LineBreak block, markers included):")
        if frontmatter and not path.exists():
            print("\n".join(frontmatter))
        print(instructions_block(lang))
        return 0
    try:
        outcome = write_instructions(path, lang, frontmatter=frontmatter)
    except (OSError, UnicodeDecodeError) as e:
        print(f"{path} could not be updated ({e}); left untouched. Add this block yourself:")
        print(instructions_block(lang))
        return 0
    messages = {
        "created": f"Wrote the LineBreak instructions for the agent in {path}.",
        "appended": f"Added the LineBreak instructions block at the end of {path}.",
        "replaced": f"Replaced the LineBreak block in {path}; the rest of the file is untouched.",
        "unchanged": f"{path} already has the current LineBreak block; nothing to do.",
    }
    if outcome == "untouched":
        print(
            f"{path} has LineBreak markers that do not pair up (one start, one end); "
            "left untouched. The block, if you want to fix it by hand:"
        )
        print(instructions_block(lang))
        return 0
    print(messages[outcome])
    return 0


def _install_codex(*, print_only: bool) -> int:
    """Codex keeps MCP servers in the GLOBAL ``~/.codex/config.toml``; it runs
    them with the session's working directory, so the entry stays repo-relative."""
    path = Path.home() / ".codex" / "config.toml"
    if print_only:
        print(f"Add to {path}:")
        print(_CODEX_SECTION.strip())
        return 0
    if path.exists():
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as e:
            print(f"{path} could not be read ({e}) — left untouched. Add this yourself:")
            print(_CODEX_SECTION.strip())
            return 0
        if "[mcp_servers.linebreak]" in text:
            print(
                f"{path} already has an [mcp_servers.linebreak] section — left untouched. "
                "The standard entry, if you want to switch:"
            )
            print(_CODEX_SECTION.strip())
            return 0
        # Append-only merge: TOML has no safe in-place rewrite without a writer
        # dependency, and appending a new table never alters existing content.
        path.write_text(text + _CODEX_SECTION, encoding="utf-8")
        print(f"Appended the linebreak server to the existing {path}.")
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_CODEX_SECTION.lstrip("\n"), encoding="utf-8")
    print(f"Wrote {path}.")
    return 0


def run_install(repo_root: Path | str, *, editor: str | None = None, print_only: bool = False):
    """Entry point for ``linebreak-gate mcp install``. Returns an exit code."""
    root = Path(repo_root)
    if editor in ("claude-code", "cursor", "copilot"):
        if editor == "copilot":
            rc = _install_json(
                root / ".vscode" / "mcp.json",
                print_only=print_only,
                root_key="servers",
                entry=VSCODE_SERVER_ENTRY,
            )
        else:
            target = (
                root / ".mcp.json" if editor == "claude-code" else root / ".cursor" / "mcp.json"
            )
            rc = _install_json(target, print_only=print_only)
        rc = rc or _install_instructions(root, editor, print_only=print_only)
        # Editors hold a repo-provided MCP server DISCONNECTED until the human
        # enables it once (their prompt-injection guard). Say so, or the first
        # session silently falls back to file searching.
        print(
            "Note: enable the 'linebreak' server once in your editor "
            "(Cursor: Settings → MCP; Claude Code: approve the project-server prompt; "
            "VS Code: start it from the MCP servers list and trust it)."
        )
        return rc
    if editor == "codex":
        rc = _install_codex(print_only=print_only)
        return rc or _install_instructions(root, editor, print_only=print_only)
    if editor is not None:
        print(f"unknown editor {editor!r}; expected one of {', '.join(EDITORS)}")
        return 2
    # No editor named: the generic stdio config plus one line per editor.
    print("Generic MCP (stdio) config — any MCP client can use this:")
    print(_generic_json())
    print()
    print("Or write it for your editor:")
    print(
        "  claude-code  linebreak-gate mcp install --editor claude-code   (.mcp.json + CLAUDE.md)"
    )
    print(
        "  cursor       linebreak-gate mcp install --editor cursor        "
        "(.cursor/mcp.json + .cursor/rules/linebreak.mdc)"
    )
    print(
        "  codex        linebreak-gate mcp install --editor codex         "
        "(~/.codex/config.toml + AGENTS.md)"
    )
    print(
        "  copilot      linebreak-gate mcp install --editor copilot       "
        "(.vscode/mcp.json + .github/copilot-instructions.md)"
    )
    print(
        "Each one also writes a short LineBreak block (between markers) in the file the "
        "agent reads: the criteria are read over MCP, never rewritten."
    )
    return 0
