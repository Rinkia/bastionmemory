"""Render a `ScanReport` as text or JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .models import MemoryEntry, ScanReport

MANIFEST_SCHEMA = "bastionmemory.manifest/1"
_MARK = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW "}


def to_text(rep: ScanReport) -> str:
    lines = [f"memory: {rep.target}  entries: {rep.entry_count}  VERDICT: {rep.verdict.upper()}"
             + ("  (since baseline)" if rep.baseline_used else "")]
    lines.append("-" * len(lines[0]))
    findings = rep.sorted_findings()
    if not findings:
        lines.append("allow: no poisoning signals — memory reads as facts."
                     if not rep.baseline_used else
                     "allow: nothing risky appeared since the baseline.")
        return "\n".join(lines)

    lines.append(f"why {rep.verdict}:")
    for f in findings:
        tag = f" [{f.temporal}]" if f.temporal else ""
        lines.append(f"  ! [{f.kind}] {f.check}{tag}  {f.file}:{f.line}")
        lines.append(f"        {f.message}")
        if f.evidence:
            lines.append(f"        > {f.evidence}")
    return "\n".join(lines)


def to_json(rep: ScanReport) -> str:
    return json.dumps({
        "target": rep.target,
        "entry_count": rep.entry_count,
        "baseline_used": rep.baseline_used,
        "verdict": rep.verdict,
        "ok": rep.ok,
        "counts": rep.counts(),
        "findings": [
            {"check": f.check, "kind": f.kind, "severity": f.severity,
             "file": f.file, "line": f.line, "temporal": f.temporal,
             "message": f.message, "evidence": f.evidence}
            for f in rep.sorted_findings()
        ],
    }, indent=2, ensure_ascii=False)


def to_manifest(rep: ScanReport, entries: list[MemoryEntry], tool_version: str) -> dict:
    """Stable, signable record of one scan (per-entry ids for a registry/sink later)."""
    return {
        "schema": MANIFEST_SCHEMA,
        "tool_version": tool_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": rep.target,
        "verdict": rep.verdict,
        "baseline_used": rep.baseline_used,
        "counts": rep.counts(),
        "entry_ids": sorted({e.id for e in entries}),
        "findings": json.loads(to_json(rep))["findings"],
    }
