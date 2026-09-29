"""bastionmemory — detect memory poisoning in what an AI agent remembers.

Agent memory auto-loads every session as trusted instructions. bastionmemory reads
that memory (Claude Code local markdown in v0.1) and flags injected *directives
disguised as facts* — and, the core, tracks memory against a baseline so a rule that
quietly appears across sessions is caught, not just a static snapshot.

Maps to OWASP Agentic ASI06 (memory poisoning): persistence, disguised-as-fact,
stealth, delayed execution.
"""

from __future__ import annotations

__version__ = "0.2.0"

from .models import Finding, MemoryEntry, ScanReport
from .scanner import scan

__all__ = ["Finding", "MemoryEntry", "ScanReport", "scan", "__version__"]
