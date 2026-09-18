"""Scan memory entries into a verdict.

Snapshot mode classifies every entry. Baseline mode marks each finding `new` when its
entry is absent from the baseline; `--since-baseline` then keeps only the new ones —
"what risky thing appeared since I last vetted this memory?".
"""

from __future__ import annotations

from dataclasses import replace

from .checks import classify
from .models import Finding, MemoryEntry, ScanReport


def scan(entries: list[MemoryEntry]) -> list[Finding]:
    """All findings for a snapshot (no baseline). Public API."""
    out: list[Finding] = []
    for e in entries:
        out.extend(classify(e))
    return out


def scan_report(
    target: str,
    entries: list[MemoryEntry],
    baseline_ids: set[str] | None = None,
    since_baseline: bool = False,
) -> ScanReport:
    findings: list[Finding] = []
    for e in entries:
        is_new = baseline_ids is not None and e.id not in baseline_ids
        for f in classify(e):
            if baseline_ids is not None:
                f = replace(f, temporal="new" if is_new else "")
            if since_baseline and not is_new:
                continue  # diff view: only what appeared since the baseline
            findings.append(f)
    return ScanReport(
        target=target,
        entry_count=len(entries),
        findings=tuple(findings),
        baseline_used=baseline_ids is not None,
    )
