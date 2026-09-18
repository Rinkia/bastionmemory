# Changelog

## 0.1.0 (unreleased)

First cut. Memory-poisoning scanner for Claude Code local markdown memory (OWASP ASI06).

- Parse memory (file or dir of `.md`) into entries; skip headings/frontmatter/code.
- Classifier: fact vs directive by **shape**, not vocabulary. Malice detectors —
  instruction-override, autonomy-bypass, exfil-redirect (verb+target, directive-gated),
  hidden-unicode. Plain directives → review.
- **Baseline/diff** (the core): snapshot entry ids; `--since-baseline` reports only what
  appeared since — catches stealth / delayed execution a snapshot can't.
- Verdicts allow / review / block; `--fail-on block|review|none` (default review).
- `harden` emits an agentbastion/bastiongate memory-quarantine policy.
- Signable `--report` manifest. Zero required dependencies.
