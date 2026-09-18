"""Parse agent memory into `MemoryEntry`s.

v0.1 target: Claude Code local markdown memory — a file, or a dir of `.md`
(CLAUDE.md, MEMORY.md, and the auto-memory dir). Later targets (MCP memory-server
JSON, RAG dumps, compaction summaries) plug in as new loaders behind `load_entries`.
Pure read — memory is data, never executed.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import MemoryEntry

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
_BULLET = re.compile(r"^\s*(?:[-*+]|\d+\.)\s+")
_HEADING = re.compile(r"^\s*#{1,6}\s")


def _entries_from_text(text: str, rel: str) -> list[MemoryEntry]:
    out: list[MemoryEntry] = []
    in_frontmatter = False
    in_code = False
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if i == 1 and stripped == "---":
            in_frontmatter = True
            continue
        if in_frontmatter:
            if stripped == "---":
                in_frontmatter = False
            continue
        if stripped.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not stripped or _HEADING.match(line):
            continue
        # a memory entry: strip the bullet marker, keep the content
        content = _BULLET.sub("", line).strip()
        if content:
            out.append(MemoryEntry(file=rel, line=i, text=content))
    return out


def load_entries(target: str | Path) -> list[MemoryEntry]:
    p = Path(target)
    if not p.exists():
        raise FileNotFoundError(f"no such path: {target}")
    if p.is_file():
        return _entries_from_text(p.read_text(encoding="utf-8", errors="replace"), p.name)
    entries: list[MemoryEntry] = []
    for f in sorted(p.rglob("*.md")):
        if any(part in _SKIP_DIRS for part in f.parts):
            continue
        rel = f.relative_to(p).as_posix()
        entries.extend(
            _entries_from_text(f.read_text(encoding="utf-8", errors="replace"), rel)
        )
    return entries


def claude_memory_paths() -> list[Path]:
    """Best-effort default locations of Claude Code local memory (for docs/CLI hints)."""
    home = Path.home()
    out = [home / ".claude" / "CLAUDE.md", Path("CLAUDE.md")]
    projects = home / ".claude" / "projects"
    if projects.is_dir():
        out += sorted(projects.glob("*/memory"))
    return [p for p in out if p.exists()]
