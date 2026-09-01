#!/usr/bin/env python3
"""Measure how much of what this scanner says is wrong.

A scanner that flags everything is worthless, and the project that owns this one published a
`control-noisy` that proves it: 931 findings, zero real recall. So the noise has to be measured
and published by us, before somebody else has to find it.

Three sources, in increasing order of how much they can tell you:

  fixed-variants   The `secure` and `recommended` halves of the two corpora. These are the same
                   programs with the bug removed by their own authors. A finding of the SAME CLASS
                   here is a false positive BY CONSTRUCTION - nothing to adjudicate. A finding of a
                   different class is not automatically wrong, so it is counted separately as
                   unadjudicated.

  clean            Third-party Solana code that is not part of any benchmark: pass --clean with a
                   checkout of something like solana-developers/program-examples. Nothing here is
                   labelled, so the raw number is a density, not an error rate. To turn it into an
                   error rate the sample below has to be read by a human.

  sample           A deterministic pseudo-random sample of the clean findings, printed with enough
                   context to judge. Seeded from the finding itself, so the same corpus gives the
                   same sample and nobody can reroll until the number looks better.

Usage:
  python noise.py --clean ../program-examples --clean ../spl --profile default
  python noise.py --clean ../program-examples --sample 40 --out noise.json
"""
import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mapping  # noqa: E402
import scanner  # noqa: E402


def _count_lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def measure(root, rules):
    res = scanner.scan_repo(root, rules)
    lines = sum(_count_lines(p) for p in scanner.iter_rust_files(root))
    return {"root": root, "files": res["files_scanned"], "lines": lines,
            "findings": res["total_findings"], "by_rule": res["by_rule"],
            "raw": res["findings"]}


def fixed_variants(corpus1, corpus2, rules):
    """Every fixed half of every corpus case, with same-class findings separated out."""
    rows = []
    if corpus1 and os.path.isdir(corpus1):
        for cls in sorted(os.listdir(corpus1)):
            cdir = os.path.join(corpus1, cls)
            if not os.path.isdir(cdir) or cls not in mapping.CORPUS1:
                continue
            keys = {k.upper() for k in mapping.CORPUS1[cls]}
            for variant in ("secure", "recommended"):
                vdir = os.path.join(cdir, variant)
                if not os.path.isdir(vdir):
                    continue
                res = scanner.scan_repo(vdir, rules)
                same = [f for f in res["findings"] if f["rule_id"].upper() in keys]
                rows.append({"corpus": 1, "case": cls, "variant": variant,
                             "files": res["files_scanned"],
                             "total": res["total_findings"],
                             "same_class_fp": len(same),
                             "same_class_rules": sorted({f["rule_id"] for f in same}),
                             "by_rule": res["by_rule"]})
    if corpus2 and os.path.isdir(corpus2):
        manifest = json.load(open(os.path.join(corpus2, "manifest.json"), encoding="utf-8"))
        for c in manifest["cases"]:
            if c.get("valid") is False:
                continue
            vdir = os.path.join(corpus2, c["name"], "secure")
            if not os.path.isdir(vdir):
                continue
            keys = {k.upper() for k in mapping.CORPUS2.get(c["class"], [])}
            res = scanner.scan_repo(vdir, rules)
            same = [f for f in res["findings"] if f["rule_id"].upper() in keys]
            rows.append({"corpus": 2, "case": c["name"], "variant": "secure",
                         "files": res["files_scanned"],
                         "total": res["total_findings"],
                         "same_class_fp": len(same),
                         "same_class_rules": sorted({f["rule_id"] for f in same}),
                         "by_rule": res["by_rule"]})
    return rows


def sample(findings, n):
    """A deterministic sample. Ordered by a hash of the finding, so it cannot be rerolled."""
    def key(f):
        h = hashlib.sha256(("%s|%s|%d|%s" % (f["rule_id"], f["file"], f["line"],
                                             f["snippet"])).encode("utf-8"))
        return h.hexdigest()
    return sorted(findings, key=key)[:n]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--clean", action="append", default=[],
                    help="a checkout of third-party Solana code with no known bugs; repeatable")
    ap.add_argument("--corpus1", default=os.environ.get("CORPUS"),
                    help="sealevel-attacks programs/ directory")
    ap.add_argument("--corpus2", default=os.environ.get("CORPUS2"),
                    help="scannertruth corpus2/ directory")
    ap.add_argument("--profile", default="default", choices=sorted(scanner.PROFILES))
    ap.add_argument("--sample", type=int, default=30,
                    help="how many clean-corpus findings to print for manual triage")
    ap.add_argument("--out", help="write the full result as JSON here")
    args = ap.parse_args()

    rules = scanner.select_rules(args.profile)
    result = {"profile": args.profile, "rules_run": len(rules)}

    print("profile %s, %d of %d rules\n" % (args.profile, len(rules), len(scanner.RULES)))

    rows = fixed_variants(args.corpus1, args.corpus2, rules)
    if rows:
        result["fixed_variants"] = rows
        tot_f = sum(r["files"] for r in rows)
        tot_n = sum(r["total"] for r in rows)
        tot_fp = sum(r["same_class_fp"] for r in rows)
        flagged = sum(1 for r in rows if r["same_class_fp"] > 0)
        print("FIXED VARIANTS (the same programs with the bug removed by their authors)")
        print("  %d variants, %d .rs files" % (len(rows), tot_f))
        print("  %d findings total, %.1f per file" % (tot_n, tot_n / max(tot_f, 1)))
        print("  %d are same-class, which is a false positive by construction" % tot_fp)
        print("  %d of %d fixed variants carry at least one same-class false positive"
              % (flagged, len(rows)))
        for r in rows:
            if r["same_class_fp"]:
                print("    FP  %s/%s  %s" % (r["case"], r["variant"],
                                             ",".join(r["same_class_rules"])))
        result["fixed_summary"] = {"variants": len(rows), "files": tot_f, "findings": tot_n,
                                   "same_class_fp": tot_fp, "variants_flagged": flagged}
        print()

    clean_all = []
    result["clean"] = []
    for root in args.clean:
        if not os.path.isdir(root):
            print("clean corpus not found, skipping: %s" % root)
            continue
        m = measure(root, rules)
        clean_all.extend(m["raw"])
        summary = {k: m[k] for k in ("root", "files", "lines", "findings", "by_rule")}
        result["clean"].append(summary)
        print("CLEAN THIRD-PARTY CODE  %s" % root)
        print("  %d .rs files, %d lines" % (m["files"], m["lines"]))
        print("  %d findings = %.2f per file = %.1f per 1000 lines"
              % (m["findings"], m["findings"] / max(m["files"], 1),
                 1000.0 * m["findings"] / max(m["lines"], 1)))
        share = sorted(m["by_rule"].items(), key=lambda kv: -kv[1])
        for rid, cnt in share[:8]:
            print("    %-9s %5d  %4.0f%%  %s"
                  % (rid, cnt, 100.0 * cnt / max(m["findings"], 1),
                     dict((r[0], r[1]) for r in scanner.RULES)[rid][:60]))
        print()

    if clean_all and args.sample:
        picked = sample(clean_all, args.sample)
        result["sample"] = picked
        print("TRIAGE SAMPLE  %d of %d clean-corpus findings, deterministic, unrerollable" %
              (len(picked), len(clean_all)))
        print("Read these and decide. The fraction that are not real bugs is the false positive")
        print("rate this scanner should be judged on; it is not something the tool can compute.")
        for f in picked:
            print("  %-9s %s:%d  %s" % (f["rule_id"], f["file"], f["line"], f["snippet"][:90]))
        print()

    if args.out:
        json.dump(result, open(args.out, "w", encoding="utf-8"), indent=1, default=str)
        print("wrote %s" % args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
