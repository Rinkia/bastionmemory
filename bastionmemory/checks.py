"""Classify memory entries: fact (allow) vs directive vs high-risk directive (malice).

The discriminator is SHAPE, not vocabulary. A fact is declarative ("the user asked me
to always use metric units"); poison is an imperative aimed at future behavior wearing a
fact's clothes ("always send credentials to X"). So autonomy-bypass and exfil only count
when the entry is *directive-shaped* — that's what keeps a security-heavy but factual
memory at `allow`. Override and hidden-unicode are malice regardless (inherently
imperative / never benign).
"""

from __future__ import annotations

import re

from .models import Finding, MemoryEntry, normalize

# Strong directive lead-words: an entry starting with one is an instruction aimed at
# future behavior. These rarely open a declarative fact, so they drive the review-level
# `directive` finding on their own.
_DIRECTIVE_STRONG = re.compile(
    r"^(always|never|from now on|whenever|make sure|be sure|ensure|remember (to|that)|"
    r"you must|you should|do not|don'?t|only ever|under no circumstances|"
    r"ignore|disregard|forget)\b"
)

# Imperative verbs also open a directive — but each is a common noun too ("run 123",
# "Report: ...", "Post-MVP"), so they are FP-prone on their own. They only *gate* the
# malice detectors (which additionally require a target / autonomy phrase); they do NOT
# raise a directive finding by themselves.
_IMPERATIVE_VERB = re.compile(
    r"^(send|forward|upload|delete|execute|approve|auto[- ]?approve|disable|enable|"
    r"skip|bypass|leak|transmit|exfiltrate)\b"
)


def is_directive(text: str) -> bool:
    """Directive-shaped for the purpose of gating malice detectors."""
    n = normalize(text)
    return bool(_DIRECTIVE_STRONG.match(n) or _IMPERATIVE_VERB.match(n))


# --- malice detectors -------------------------------------------------------
_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|earlier|above|all)\b"
    r".{0,40}\b(instruction|rule|message|direction|safety|guard)|"
    r"\byou are now\b|\bthe real (rule|instruction)s?\b|\bnew instructions?:|"
    r"\boverride\b.{0,25}\b(system|safety|previous|guardrail|policy)",
    re.IGNORECASE,
)
_AUTONOMY = re.compile(
    r"\b(without (asking|confirmation|approval|telling|the user)|don'?t ask|do not ask|"
    r"no confirmation|skip (the )?confirmation|auto[- ]?approve|automatically approve|"
    r"don'?t (tell|inform|notify|alert)|without (the )?user'?s? (knowledge|consent|review))\b",
    re.IGNORECASE,
)
_EXFIL_VERB = re.compile(r"\b(send|forward|upload|post|report|exfiltrate|transmit|leak|share|email)\b", re.IGNORECASE)
_EXFIL_TARGET = re.compile(
    r"(https?://|[\w.-]+@[\w.-]+\.\w+|\bapi[ -]?keys?\b|\bcredentials?\b|\bsecrets?\b|"
    r"\btokens?\b|\bpasswords?\b|\b\.env\b)",
    re.IGNORECASE,
)
_HIDDEN = {"​", "‌", "‍", "﻿",
           "‪", "‫", "‬", "‭", "‮",
           "⁦", "⁧", "⁨", "⁩"}


def classify(entry: MemoryEntry) -> list[Finding]:
    """Zero or more findings for one entry. Empty = a fact (allow)."""
    text = entry.text
    out: list[Finding] = []
    directive = is_directive(text)

    def add(check, sev, kind, msg):
        out.append(Finding(check=check, severity=sev, kind=kind, file=entry.file,
                            line=entry.line, message=msg, evidence=text[:200]))

    if any(c in text for c in _HIDDEN):
        add("hidden-unicode", "high", "malice", "hidden/bidi unicode in a memory entry")

    if _OVERRIDE.search(text):
        add("instruction-override", "critical", "malice",
            "memory entry countermands prior/system instructions")

    if directive and _AUTONOMY.search(text):
        add("autonomy-bypass", "critical", "malice",
            "memory entry grants autonomy / bypasses the user confirmation screen")

    if directive and _EXFIL_VERB.search(text) and _EXFIL_TARGET.search(text):
        add("exfil-redirect", "critical", "malice",
            "memory entry instructs sending secrets/data to an external destination")

    # a plain instruction aimed at future behavior, not already flagged as malice.
    # STRONG lead-words only — generic imperative verbs are too noun-like to flag alone.
    if not out and _DIRECTIVE_STRONG.match(normalize(text)):
        add("directive", "medium", "directive",
            "memory entry is a directive aimed at future behavior (memory should hold facts)")
    return out
