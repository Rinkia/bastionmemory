# Changelog

## 0.2.0

- **`harden` emits `injections.jsonl`, not a policy.yaml.** The old output (a
  `memory: quarantine_entries` block) was labelled an agentbastion/bastiongate policy,
  but no consumer reads that block. `harden` now writes the high-risk (`malice`)
  entries as agentbastion corpus rows `{text, label, category}`, which agentbastion
  loads as `SemanticDetector` templates: the same artifact bastionprobe and
  bastiontrace `harden` emit. Plain directives are left out (they would become false
  positives). `-o` still picks the file; stdout is the default.

## 0.1.0

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
