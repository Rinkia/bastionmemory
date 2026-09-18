"""Immutable data model for memory-poisoning scanning.

A `MemoryEntry` is one meaningful line of agent memory. Checks classify it and emit
`Finding`s; a `ScanReport` collects them and computes a verdict.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

SEVERITIES = ("critical", "high", "medium", "low")
_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# A finding's kind drives the verdict. A memory entry is a `fact` (declarative,
# allowed) unless it is a `directive` (an imperative aimed at future behavior) or,
# worse, `malice` (a high-risk directive: autonomy-bypass, override, exfil).
KINDS = ("directive", "malice")

VERDICTS = ("block", "review", "allow")
_VRANK = {v: i for i, v in enumerate(VERDICTS)}

_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Lowercase + collapse whitespace — the identity used for baseline diffing."""
    return _WS.sub(" ", text.strip().lower())


def entry_id(text: str) -> str:
    """Content-addressed id. A directive edited into a former fact gets a new id,
    so the diff reads it as newly-appeared."""
    return hashlib.sha256(normalize(text).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class MemoryEntry:
    file: str      # relative path
    line: int
    text: str

    @property
    def id(self) -> str:
        return entry_id(self.text)


@dataclass(frozen=True)
class Finding:
    check: str            # e.g. "autonomy-bypass"
    severity: str
    kind: str             # one of KINDS
    file: str
    line: int
    message: str
    evidence: str = ""
    temporal: str = ""    # "", "new" (absent from baseline), or "changed"

    def __post_init__(self) -> None:
        if self.severity not in _RANK:
            raise ValueError(f"bad severity {self.severity!r}")
        if self.kind not in KINDS:
            raise ValueError(f"bad kind {self.kind!r}")


@dataclass(frozen=True)
class ScanReport:
    target: str
    entry_count: int
    findings: tuple[Finding, ...] = ()
    baseline_used: bool = False

    @property
    def verdict(self) -> str:
        """block if any high-risk directive; review if any directive; else allow."""
        if any(f.kind == "malice" for f in self.findings):
            return "block"
        if self.findings:
            return "review"
        return "allow"

    @property
    def ok(self) -> bool:
        return self.verdict == "allow"

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            out[f.severity] += 1
        return out

    def sorted_findings(self) -> tuple[Finding, ...]:
        return tuple(sorted(self.findings, key=lambda f: (_RANK[f.severity], f.file, f.line)))
