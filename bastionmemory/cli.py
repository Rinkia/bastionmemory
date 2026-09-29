"""bastionmemory command line.

    bastionmemory scan ./memory                       # snapshot verdict
    bastionmemory scan ./memory --record              # accept current memory as baseline
    bastionmemory scan ./memory --since-baseline      # only what appeared since baseline
    bastionmemory scan ./memory --baseline b.jsonl --since-baseline
    bastionmemory scan ./memory --json | --report out.json
    bastionmemory harden ./memory -o memory-policy.yaml
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__, harden, report
from .baseline import default_baseline_path, load_baseline_ids, write_baseline
from .loader import load_entries
from .models import VERDICTS
from .scanner import scan_report

_VRANK = {v: i for i, v in enumerate(VERDICTS)}


def _unicode_safe() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def _fails(verdict: str, threshold: str) -> bool:
    if threshold == "none":
        return False
    return _VRANK[verdict] <= _VRANK[threshold]


def main(argv=None) -> int:
    _unicode_safe()
    ap = argparse.ArgumentParser(prog="bastionmemory", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"bastionmemory {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="scan agent memory for poisoning")
    ps.add_argument("target", help="a memory file or a dir of .md memory")
    ps.add_argument("--baseline", help="baseline path (default: ~/.bastionmemory/baseline/<target>)")
    ps.add_argument("--record", action="store_true", help="write current memory as the baseline")
    ps.add_argument("--since-baseline", action="store_true", help="report only entries new since baseline")
    ps.add_argument("--json", action="store_true", help="emit JSON")
    ps.add_argument("--report", help="write a signable manifest to this path")
    ps.add_argument("--fail-on", default="review", choices=["block", "review", "none"],
                    help="exit non-zero at this verdict or worse (default: review)")

    ph = sub.add_parser("harden", help="emit poisoned entries as agentbastion injections.jsonl")
    ph.add_argument("target")
    ph.add_argument("--baseline")
    ph.add_argument("-o", "--out", help="write injections.jsonl here (default: stdout)")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return _cmd_scan(args)
    if args.cmd == "harden":
        return _cmd_harden(args)
    return 2


def _resolve_baseline(args):
    if args.baseline:
        return Path(args.baseline)
    return default_baseline_path(args.target)


def _cmd_scan(args) -> int:
    entries = load_entries(args.target)
    bpath = _resolve_baseline(args)

    if args.record:
        n = write_baseline(entries, bpath)
        print(f"recorded baseline: {n} entries -> {bpath}", file=sys.stderr)

    baseline_ids = None
    if args.since_baseline or (bpath.is_file() and not args.record):
        baseline_ids = load_baseline_ids(bpath)
        if args.since_baseline and not baseline_ids:
            print(f"bastionmemory: no baseline at {bpath} — run with --record first",
                  file=sys.stderr)
            return 2

    rep = scan_report(args.target, entries, baseline_ids=baseline_ids,
                      since_baseline=args.since_baseline)
    print(report.to_json(rep) if args.json else report.to_text(rep))
    if args.report:
        Path(args.report).write_text(
            json.dumps(report.to_manifest(rep, entries, __version__), indent=2,
                       ensure_ascii=False), encoding="utf-8")
        print(f"wrote report -> {args.report}", file=sys.stderr)
    return 1 if _fails(rep.verdict, args.fail_on) else 0


def _cmd_harden(args) -> int:
    entries = load_entries(args.target)
    bpath = _resolve_baseline(args)
    baseline_ids = load_baseline_ids(bpath) if bpath.is_file() else None
    rep = scan_report(args.target, entries, baseline_ids=baseline_ids)
    jsonl = harden.to_jsonl(rep)
    if args.out:
        Path(args.out).write_text(jsonl, encoding="utf-8")
        n = jsonl.count("\n")
        print(f"wrote {n} injection template(s) -> {args.out}", file=sys.stderr)
        if n:
            print(harden.WIRING.format(path=Path(args.out).as_posix()), file=sys.stderr)
    else:
        sys.stdout.write(jsonl)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
