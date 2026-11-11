import argparse
import sys

from . import __version__
from .core import load_trace, analyze, to_json, to_text, to_md, SEV_ORDER

KINDS = ("hearsay", "rumor", "acted-on-hearsay", "acted-on-rumor")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="hearsay",
        description="Flag facts in multi-agent traces that an agent repeats without ever observing them.")
    p.add_argument("trace", help="JSONL trace file, or - for stdin")
    p.add_argument("--format", choices=("text", "json", "md"), default="text")
    p.add_argument("--shared-results", action="store_true",
                   help="treat every tool result as visible to every agent")
    p.add_argument("--min-number", type=int, default=11,
                   help="ignore bare integers below this (default 11)")
    p.add_argument("--min-severity", choices=tuple(SEV_ORDER), default="low")
    p.add_argument("--fail-on", default="",
                   help="comma list of kinds or severities that make the exit code 1, e.g. acted-on-rumor,high")
    p.add_argument("--version", action="version", version=f"hearsay {__version__}")
    a = p.parse_args(argv)

    fh = sys.stdin if a.trace == "-" else open(a.trace, encoding="utf-8")
    with fh:
        events = load_trace(fh)
    findings = [f for f in analyze(events, a.shared_results, a.min_number)
                if SEV_ORDER[f.severity] >= SEV_ORDER[a.min_severity]]
    out = {"json": to_json, "md": to_md, "text": to_text}[a.format](findings)
    sys.stdout.write(out)

    gates = {g.strip() for g in a.fail_on.split(",") if g.strip()}
    bad = [g for g in gates if g not in KINDS and g not in SEV_ORDER]
    if bad:
        p.error(f"unknown --fail-on value(s): {', '.join(bad)}")
    for f in findings:
        if f.kind in gates or f.severity in gates:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
