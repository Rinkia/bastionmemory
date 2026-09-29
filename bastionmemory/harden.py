"""Bridge to agentbastion: turn poisoned memory into detector templates.

Emits the entries that make memory poisonous (the high-risk `malice` findings:
instruction-override, autonomy-bypass, exfil-redirect, hidden unicode) as
injections.jsonl rows in agentbastion's corpus schema {text, label, category}: the
same artifact bastionprobe / bastiontrace `harden` emit. Load them as
SemanticDetector templates and the same poison is blocked when it resurfaces in a
tool result or an input, paraphrases included.

Plain `directive` entries (verdict review) are left out on purpose: memory holds
legitimate user rules ("always use metric units"), and turning those into block
templates would flag them wherever they appear.
"""

from __future__ import annotations

import json

from .models import ScanReport

WIRING = """\
Load into agentbastion as semantic templates:

  import json
  from agentbastion.inbound import InboundGuard
  from agentbastion.semantic import SemanticDetector

  templates = [json.loads(l)["text"] for l in open("{path}", encoding="utf-8")]
  guard = InboundGuard(detectors=[SemanticDetector(your_embed_fn, templates=templates)])
"""


def to_injections(report: ScanReport) -> list[dict]:
    rows: list[dict] = []
    seen: set[str] = set()
    for f in report.sorted_findings():
        text = " ".join(f.evidence.split())
        if f.kind != "malice" or not text or text in seen:
            continue
        seen.add(text)
        rows.append({"text": text, "label": "malicious",
                     "category": "memory_" + f.check.replace("-", "_")})
    return rows


def to_jsonl(report: ScanReport) -> str:
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in to_injections(report))
