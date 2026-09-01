#!/usr/bin/env python3
"""sol-audit command line.

Standard library only, like the rest of this repository. `python cli.py --help` is meant to be
enough on its own: if you have to read the source to work out what a flag does, that is a bug.
"""
import argparse
import json
import os
import sys

import scanner

EXIT_CLEAN = 0     # ran, nothing at or above the failure threshold
EXIT_FINDINGS = 1  # ran, found something
EXIT_USAGE = 2     # could not run: bad path, unknown rule, unreadable input

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

_COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
          "LOW": "\033[36m", "INFO": "\033[37m"}
_RESET = "\033[0m"


def _use_colour(mode):
    if mode == "always":
        return True
    if mode == "never":
        return False
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def build_parser():
    p = argparse.ArgumentParser(
        prog="sol-audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Static security scanner for Solana / Anchor programs.\n"
            "Point it at a directory of Rust sources, or at one .rs file.\n"
        ),
        epilog="""\
what the exit code means
  0   ran successfully, nothing at or above --fail-on
  1   ran successfully, found something at or above --fail-on
  2   could not run: bad path, unknown rule or category, unreadable input
  Use `--fail-on none` if you want findings reported but the exit code always 0.

how much to trust a finding
  Rules come in three kinds, and you can select them with --profile:
    guarded    the construct is present AND the check that would make it safe is absent.
               These are the ones that can tell a bug from its fix.
    shape      the construct itself is the defect, so there is no check to look for.
               Correct, but blind to context. Most of the noise lives here.
    heuristic  often wrong, sometimes right. Off unless you ask for it.
  --profile strict  = guarded only        THE DEFAULT, and the quietest
  --profile broad   = guarded + shape     adds lint-grade rules: arithmetic, unwrap, unsafe
  --profile all     = everything          adds the heuristics, roughly doubles the output
  strict and all reach the same measured recall on the teaching corpus, and strict produces
  about half the findings on third-party code. That is why strict is the default.

measured effectiveness
  This scanner's recall and its false-positive rate are both measured and published in
  README.md, including the classes it does not detect at all. Read that before you trust
  a clean report from it.

examples
  python cli.py ./programs
  python cli.py ./programs --profile broad --format json --out findings.json
  python cli.py ./programs --category authorization,cpi --min-severity HIGH
  python cli.py ./programs --exclude-rule SOL-004,SOL-009
  python cli.py --list-rules
""")
    p.add_argument("path", nargs="?",
                   help="directory to scan recursively, or a single .rs file")
    p.add_argument("--profile", default="strict", choices=sorted(scanner.PROFILES),
                   help="which kinds of rule to run (default: strict)")
    p.add_argument("--category", metavar="A,B",
                   help="run only these categories: " + ", ".join(scanner.CATEGORIES))
    p.add_argument("--exclude-category", metavar="A,B",
                   help="skip these categories")
    p.add_argument("--rule", metavar="SOL-001,SOL-002",
                   help="run only these rule ids; overrides --profile")
    p.add_argument("--exclude-rule", metavar="SOL-004,...",
                   help="skip these rule ids")
    p.add_argument("--min-severity", default="INFO", choices=SEVERITIES,
                   help="hide findings below this severity (default: INFO, i.e. show all)")
    p.add_argument("--fail-on", default="LOW", choices=list(SEVERITIES) + ["none"],
                   help="exit 1 if anything at or above this severity remains (default: LOW)")
    p.add_argument("--format", default="text", choices=("text", "json", "sarif"),
                   help="output format (default: text)")
    p.add_argument("--out", metavar="FILE",
                   help="write the report here instead of stdout")
    p.add_argument("--log", metavar="FILE",
                   help="write one JSON line per file analysed, so a later reader can tell "
                        "'analysed and found nothing' from 'never looked at it'")
    p.add_argument("--color", default="auto", choices=("auto", "always", "never"),
                   help="colourise text output (default: auto)")
    p.add_argument("--quiet", action="store_true",
                   help="text format: findings only, no summary")
    p.add_argument("--list-rules", action="store_true",
                   help="print every rule with its id, category, kind and severity, then exit")
    p.add_argument("--version", action="version", version="sol-audit 3.0")
    return p


def _split(value):
    return [x.strip() for x in value.split(",") if x.strip()] if value else None


def list_rules(stream):
    stream.write("%-9s %-14s %-10s %-9s %s\n"
                 % ("RULE", "CATEGORY", "KIND", "SEVERITY", "TITLE"))
    for rid, title, sev, _cwe, _fix, _fn in scanner.RULES:
        cat, kind = scanner.META.get(rid, ("hygiene", "shape"))
        stream.write("%-9s %-14s %-10s %-9s %s\n" % (rid, cat, kind, sev, title))
    stream.write("\nprofiles: %s\n"
                 % "  ".join("%s=%s" % (k, "+".join(v)) for k, v in scanner.PROFILES.items()))


def render_text(report, colour, quiet):
    out = []
    findings = report["findings"]
    for f in findings:
        head = "%s:%d" % (f["file"], f["line"])
        sev = f["severity"]
        tag = "%s%s%s" % (_COLOR.get(sev, ""), sev, _RESET) if colour else sev
        out.append("%s: %s %s  %s" % (head, tag, f["rule_id"], f["title"]))
        if f["snippet"]:
            out.append("    %s" % f["snippet"])
        out.append("    fix: %s" % f["fix"])
        out.append("")
    if quiet:
        return "\n".join(out)
    counts = report["counts"]
    order = [s for s in reversed(SEVERITIES) if counts.get(s)]
    summary = ", ".join("%d %s" % (counts[s], s) for s in order) or "nothing"
    out.append("scanned %d file(s), %d finding(s): %s"
               % (report["files_scanned"], report["total_findings"], summary))
    if report.get("errors"):
        out.append("%d file(s) could not be read; see the JSON report" % len(report["errors"]))
    out.append("rules run: %d of %d (profile %s)"
               % (report["rules_run"], len(scanner.RULES), report["profile"]))
    out.append("This scanner's measured recall and false-positive rate are in README.md. "
               "A clean report here is not an audit.")
    return "\n".join(out)


def render_sarif(report):
    """SARIF 2.1.0, so the output drops into GitHub code scanning without a converter."""
    rules, seen = [], set()
    for f in report["findings"]:
        if f["rule_id"] in seen:
            continue
        seen.add(f["rule_id"])
        rules.append({
            "id": f["rule_id"],
            "name": f["rule_id"],
            "shortDescription": {"text": f["title"]},
            "help": {"text": f["fix"]},
            "properties": {"category": f["category"], "kind": f["kind"], "cwe": f["cwe"]},
        })
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
             "LOW": "note", "INFO": "note"}
    results = [{
        "ruleId": f["rule_id"],
        "level": level.get(f["severity"], "note"),
        "message": {"text": "%s. %s" % (f["title"], f["fix"])},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f["file"].replace("\\", "/")},
            "region": {"startLine": max(1, f["line"])},
        }}],
    } for f in report["findings"]]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "sol-audit", "version": "3.0",
                                      "informationUri": "https://github.com/halobartku/sol-audit",
                                      "rules": rules}},
                  "results": results}],
    }, indent=1)


def main(argv=None):
    args = build_parser().parse_args(argv)

    if args.list_rules:
        list_rules(sys.stdout)
        return EXIT_CLEAN

    if not args.path:
        build_parser().print_usage(sys.stderr)
        sys.stderr.write("sol-audit: give it a path to scan, or --list-rules\n")
        return EXIT_USAGE

    if not os.path.exists(args.path):
        sys.stderr.write("sol-audit: no such path: %s\n" % args.path)
        return EXIT_USAGE

    try:
        rules = scanner.select_rules(
            profile=args.profile,
            categories=_split(args.category),
            exclude_categories=_split(args.exclude_category),
            rules=_split(args.rule),
            exclude_rules=_split(args.exclude_rule),
        )
    except ValueError as e:
        sys.stderr.write("sol-audit: %s\n" % e)
        return EXIT_USAGE

    if not rules:
        sys.stderr.write("sol-audit: that selection leaves no rules to run. Refusing, because a "
                         "report from zero rules looks exactly like a clean repository.\n")
        return EXIT_USAGE

    report = scanner.scan_repo(args.path, rules)
    report["profile"] = args.profile
    report["rules_run"] = len(rules)
    report["rule_ids"] = [r[0] for r in rules]

    floor = SEVERITIES.index(args.min_severity)
    kept = [f for f in report["findings"] if SEVERITIES.index(f["severity"]) >= floor]
    if len(kept) != len(report["findings"]):
        report["findings"] = kept
        report["total_findings"] = len(kept)
        counts = {}
        for f in kept:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        report["counts"] = counts

    if args.log:
        # One line per file the scanner actually opened. ScannerTruth's AGENTS.md is right that a
        # findings file cannot prove coverage: a file that was analysed and was clean leaves
        # exactly the same silence as one that was never opened.
        hit_files = {f["file"] for f in report["findings"]}
        with open(args.log, "w", encoding="utf-8") as fh:
            base = args.path if os.path.isdir(args.path) else os.path.dirname(
                os.path.abspath(args.path))
            for p in scanner.iter_rust_files(args.path):
                rel = os.path.relpath(p, base)
                fh.write(json.dumps({"leaf": rel.replace("\\", "/"),
                                     "status": "ok",
                                     "findings": sum(1 for f in report["findings"]
                                                     if f["file"] == rel)}) + "\n")
            for e in report.get("errors", []):
                fh.write(json.dumps({"leaf": e["file"], "status": "error",
                                     "error": e["error"]}) + "\n")

    if args.format == "json":
        text = json.dumps(report, indent=1)
    elif args.format == "sarif":
        text = render_sarif(report)
    else:
        text = render_text(report, _use_colour(args.color) and not args.out, args.quiet)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        if not args.quiet:
            sys.stderr.write("sol-audit: wrote %d finding(s) to %s\n"
                             % (report["total_findings"], args.out))
    else:
        print(text)

    if args.fail_on == "none":
        return EXIT_CLEAN
    bar = SEVERITIES.index(args.fail_on)
    if any(SEVERITIES.index(f["severity"]) >= bar for f in report["findings"]):
        return EXIT_FINDINGS
    return EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
