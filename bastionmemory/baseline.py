"""Baseline snapshot + diff — the temporal core.

Memory is legit-by-default; the signal is what's *new* since you last vetted it. A
baseline is the set of entry ids (content-addressed) you accepted. On a later scan,
any risky entry whose id is absent from the baseline is `new` — the stealth /
delayed-execution catch a snapshot scanner can't make.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .models import MemoryEntry


def default_baseline_path(target: str | Path) -> Path:
    key = hashlib.sha256(str(Path(target).resolve()).encode("utf-8")).hexdigest()[:16]
    return Path.home() / ".bastionmemory" / "baseline" / f"{key}.jsonl"


def write_baseline(entries: list[MemoryEntry], path: str | Path) -> int:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    seen: set[str] = set()
    with open(p, "w", encoding="utf-8") as fh:
        for e in entries:
            if e.id in seen:
                continue
            seen.add(e.id)
            fh.write(json.dumps({"id": e.id, "file": e.file, "text": e.text},
                                ensure_ascii=False) + "\n")
    return len(seen)


def load_baseline_ids(path: str | Path) -> set[str]:
    p = Path(path)
    if not p.is_file():
        return set()
    ids: set[str] = set()
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ids.add(json.loads(line)["id"])
        except (json.JSONDecodeError, KeyError):
            continue  # tolerate a corrupt line
    return ids
