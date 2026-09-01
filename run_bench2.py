#!/usr/bin/env python3
"""Score sol-audit against ScannerTruth corpus 2: real vulnerabilities, real fix commits.

Corpus 1 (sealevel-attacks) is eleven hand-written teaching programs, public since 2022, and every
score on it is in-sample. Corpus 2 is nine production bugs, each pinned to the commit its own
maintainers wrote to fix it, so the answer key is somebody else's.

Usage:
  CORPUS2=../scannertruth/corpus2 python run_bench2.py
  PROFILE=strict CORPUS2=... python run_bench2.py

Writes bench2-out.json and, beside it, bench2-out.json.log with one row per file analysed.
That log exists because a findings file cannot prove coverage: a case that was analysed and
came back clean leaves exactly the same silence as a case that was never opened. ScannerTruth
lists the absence of that log as an open gap against this scanner; this closes it.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner  # noqa: E402

CORPUS2 = os.environ.get("CORPUS2", os.path.abspath("../scannertruth/corpus2"))
PROFILE = os.environ.get("PROFILE", "all")
OUT = os.environ.get("OUT", "bench2-out.json")

# PRE-REGISTERED. Derived from each rule's own title in scanner.RULES, matched against the class
# name the corpus manifest gives the case. Not from which rules turned out to fire. Committed
# before the run that scores it.
#
# `arithmetic-rounding-drain` is mapped to the arithmetic rules with a caveat recorded in RULES.md:
# this scanner has no rounding-DIRECTION rule, because whether rounding up is a bug depends on
# which side of the trade benefits, and that is semantic. SOL-024 catches the neighbouring defect
# (dividing before multiplying), not the one this case actually is. It is mapped anyway so the
# class appears in the denominator rather than being quietly dropped.
MAP = {
    "signer-authorization":      ["SOL-001", "SOL-007"],
    "owner-checks":              ["SOL-002", "SOL-006", "SOL-030"],
    "account-data-matching":     ["SOL-002", "SOL-023"],
    "type-cosplay":              ["SOL-002", "SOL-022"],
    "sysvar-address-checking":   ["SOL-019", "SOL-027"],
    "instruction-introspection": ["SOL-027"],
    "arithmetic-rounding-drain": ["SOL-004", "SOL-024", "SOL-025"],
}


def load_cases():
    manifest = json.load(open(os.path.join(CORPUS2, "manifest.json"), encoding="utf-8"))
    out = []
    for c in manifest["cases"]:
        if c.get("valid") is False:
            out.append({"name": c["name"], "class": c["class"], "status": "excluded",
                        "reason": c.get("invalid_reason", "")[:120]})
            continue
        d = os.path.join(CORPUS2, c["name"])
        if not os.path.isdir(d):
            out.append({"name": c["name"], "class": c["class"], "status": "not-built",
                        "reason": "no directory in corpus2/"})
            continue
        out.append({"name": c["name"], "class": c["class"], "status": "built", "dir": d})
    return out


def main():
    rules = scanner.select_rules(PROFILE)
    log = []
    rows = []
    for case in load_cases():
        if case["status"] != "built":
            rows.append(case)
            log.append({"leaf": case["name"], "status": case["status"],
                        "reason": case.get("reason", "")})
            continue
        keys = {k.upper() for k in MAP.get(case["class"], [])}
        rec = dict(case)
        rec["mapped_rules"] = sorted(keys) or ["no-rule"]
        for variant in ("insecure", "secure"):
            vdir = os.path.join(case["dir"], variant)
            if not os.path.isdir(vdir):
                rec[variant] = None
                log.append({"leaf": "%s/%s" % (case["name"], variant), "status": "missing"})
                continue
            try:
                res = scanner.scan_repo(vdir, rules)
            except Exception as e:
                rec[variant] = {"error": str(e)[:200]}
                log.append({"leaf": "%s/%s" % (case["name"], variant),
                            "status": "error", "error": str(e)[:200]})
                continue
            on_target = [f for f in res["findings"] if f["rule_id"].upper() in keys]
            rec[variant] = {"files": res["files_scanned"],
                            "total": res["total_findings"],
                            "on_target": len(on_target),
                            "on_target_lines": sorted({(f["rule_id"], f["file"], f["line"])
                                                       for f in on_target}),
                            "rules": sorted(res["by_rule"])}
            log.append({"leaf": "%s/%s" % (case["name"], variant), "status": "ok",
                        "files": res["files_scanned"], "findings": res["total_findings"],
                        "on_target": len(on_target)})
        rows.append(rec)

    scored = [r for r in rows if r["status"] == "built"]
    nominal = sum(1 for r in scored if (r.get("insecure") or {}).get("on_target", 0) > 0)
    real = sum(1 for r in scored
               if (r.get("insecure") or {}).get("on_target", 0) > 0
               and (r.get("secure") or {}).get("on_target", 0) == 0)
    noise_files = sum((r.get("secure") or {}).get("files", 0) for r in scored)
    noise_findings = sum((r.get("secure") or {}).get("total", 0) for r in scored)

    print("\n%-28s %-10s %-22s %-22s" % ("case", "class", "insecure", "secure"))
    print("-" * 96)
    for r in rows:
        if r["status"] != "built":
            print("%-28s %-10s %s (%s)" % (r["name"], "", r["status"], r.get("reason", "")[:50]))
            continue

        def cell(v):
            x = r.get(v)
            if not x:
                return "n/a"
            if "error" in x:
                return "ERROR"
            return "%d on-target /%d" % (x["on_target"], x["total"])
        det = ((r.get("insecure") or {}).get("on_target", 0) > 0
               and (r.get("secure") or {}).get("on_target", 0) == 0)
        print("%-28s %-10s %-22s %-22s %s"
              % (r["name"], r["class"][:10], cell("insecure"), cell("secure"),
                 "DETECTED" if det else "miss"))

    n = len(scored)
    print("\n" + "=" * 60)
    print("profile          : %s (%d rules)" % (PROFILE, len(rules)))
    print("NOMINAL RECALL   : %d/%d" % (nominal, n))
    print("REAL RECALL      : %d/%d" % (real, n))
    print("NOISE on fixed   : %d findings across %d .rs files in the secure variants"
          % (noise_findings, noise_files))
    print("=" * 60)

    json.dump({"profile": PROFILE, "corpus": CORPUS2, "rows": rows,
               "nominal": nominal, "real": real, "scored": n},
              open(OUT, "w", encoding="utf-8"), indent=1, default=str)
    with open(OUT + ".log", "w", encoding="utf-8") as fh:
        for row in log:
            fh.write(json.dumps(row) + "\n")
    print("\nwrote %s and %s.log" % (OUT, OUT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
