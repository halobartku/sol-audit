#!/usr/bin/env python3
"""Score sol-audit against coral-xyz/sealevel-attacks. Protocol pre-registered in PROTOCOL.md.

Ground truth: `insecure/` has the bug, `secure/` and `recommended/` are the SAME program fixed.
A finding of the class on a fixed variant is a false positive by construction.
"""
import json, os, re, subprocess, sys

CORPUS = os.environ.get("CORPUS", os.path.abspath("../sealevel-attacks/programs"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import scanner  # noqa: E402

# FIXED BEFORE RUNNING - see PROTOCOL.md. Do not widen these to rescue a result.
# CORRECTED MAPPING. The first version guessed semantic rule ids (SOL-MISSING-SIGNER); the
# scanner actually emits numeric codes (SOL-001..SOL-016), so nothing could ever match. This
# remap is derived from each rule's OWN description in scanner.RULES - what the rule says it
# detects - NOT from which rules happened to fire. Three corpus classes have NO corresponding
# rule in the scanner at all; they are recorded as structural gaps, and they still count as
# misses because a scanner that cannot detect a bug does not detect it.
#
# v3 additions below are derived the same way, from each new rule's own title and docstring, and
# were committed before the run that scored them. Adding a rule id here because it turned out to
# fire would invert the whole procedure.
MAP = {
    "0-signer-authorization":       ["SOL-001", "SOL-007"],   # UncheckedAccount w/o Signer; next_account_info w/o is_signer
    "1-account-data-matching":      ["SOL-002", "SOL-023"],   # raw AccountInfo, no owner/type validation; authority field never compared
    "2-owner-checks":               ["SOL-002", "SOL-006", "SOL-030"],  # no owner validation; raw CPI w/o owner check; native unpack w/o owner
    "3-type-cosplay":               ["SOL-002", "SOL-022"],   # no type validation via deserialization; no discriminator
    "4-initialization":             ["SOL-003", "SOL-015", "SOL-028"],  # init_if_needed reinit; init without space; no initialised flag
    "5-arbitrary-cpi":              ["SOL-010", "SOL-006"],   # invoke() with program from accounts
    "6-duplicate-mutable-accounts": ["SOL-017"],              # v2: added
    "7-bump-seed-canonicalization": ["SOL-011", "SOL-020", "SOL-021"],  # bump stored and trusted; create_program_address; caller-chosen bump
    "8-pda-sharing":                ["SOL-016", "SOL-008"],   # PDA seeds not namespaced; dynamic seed material
    "9-closing-accounts":           ["SOL-018"],              # v2: added
    "10-sysvar-address-checking":   ["SOL-019", "SOL-027"],   # sysvar never validated; introspected instruction never attributed
}
NO_RULE = {k for k, v in MAP.items() if not v}

# Which rules run. `all` keeps continuity with the published v2 number, which was measured with
# every rule enabled. PROFILE=strict re-runs the same protocol with the guard-aware rules only.
PROFILE = os.environ.get("PROFILE", "all")
RULE_SET = scanner.select_rules(PROFILE)

def matches(rule_id, keys):
    """Exact rule-id membership. Keys are explicit SOL-0NN codes from scanner.RULES."""
    return (rule_id or "").upper().strip() in {k.upper() for k in keys}

def scan_dir(d):
    """Run the real scanner over d, through scan_repo - the same entry point the CLI uses.

    It used to call scan_text per file, one file at a time. That was a fair approximation until
    v3 added a cross-file pre-pass (scan_repo learns which state structs carry an authority field
    before any rule runs), at which point the harness was exercising a code path no user has. The
    rule that needs the pre-pass would have scored zero here for a reason that has nothing to do
    with the rule. Measuring a path the product does not have is how a benchmark lies in your
    favour, so this now calls what the CLI calls.
    """
    try:
        res = scanner.scan_repo(d, RULE_SET)
    except Exception as e:
        print("   SCAN ERROR %s: %s" % (d, str(e)[:120]))
        return []
    out = []
    for f2 in res.get("findings", []):
        # scanner.scan_repo returns dicts; older versions returned `Finding` dataclasses. Normalise
        # anyway - the first version of this harness assumed dicts, threw on every file that
        # actually had findings, and silently scored 0/11. A broken harness that reports FAIL is
        # worse than no harness.
        if not isinstance(f2, dict):
            try:
                f2 = scanner.asdict(f2)
            except Exception:
                f2 = {k: getattr(f2, k) for k in dir(f2)
                      if not k.startswith("_") and not callable(getattr(f2, k))}
        f2["_file"] = f2.get("file")
        out.append(f2)
    return out

rows, tot_fp_findings, tot_clean_files = [], 0, 0
for cls in sorted(os.listdir(CORPUS)):
    cdir = os.path.join(CORPUS, cls)
    if not os.path.isdir(cdir) or cls not in MAP:
        continue
    keys = MAP[cls]
    rec = {"class": cls}
    for variant in ("insecure", "secure", "recommended"):
        vdir = os.path.join(cdir, variant)
        if not os.path.isdir(vdir):
            rec[variant] = None
            continue
        fnd = scan_dir(vdir)
        on_target = [f for f in fnd if matches(f.get("rule_id"), keys)]
        rec[variant] = {"total": len(fnd), "on_target": len(on_target),
                        "rules": sorted({f.get("rule_id") for f in fnd})}
        if variant in ("secure", "recommended"):
            tot_fp_findings += len(fnd)
            tot_clean_files += sum(1 for _, _, fs in os.walk(vdir) for x in fs if x.endswith(".rs"))
    rows.append(rec)

print("\n%-30s %-22s %-22s %s" % ("class", "insecure (want HIT)", "secure (want NONE)", "recommended (want NONE)"))
print("-" * 104)
detected = fp_variants = considered = 0
for r in rows:
    def cell(v):
        if not r.get(v):
            return "n/a"
        return "%d on-target /%d tot" % (r[v]["on_target"], r[v]["total"])
    ins = r.get("insecure")
    hit = bool(ins and ins["on_target"] > 0)
    detected += hit
    for v in ("secure", "recommended"):
        if r.get(v):
            considered += 1
            if r[v]["on_target"] > 0:
                fp_variants += 1
    print("%-30s %-22s %-22s %s  %s" % (r["class"], cell("insecure"), cell("secure"),
                                        cell("recommended"), "HIT" if hit else "MISS"))

n = len(rows)
print("\n" + "=" * 60)
print("RECALL           : %d/%d classes detected = %.0f%%" % (detected, n, 100 * detected / max(n, 1)))
print("FALSE POSITIVE   : %d/%d fixed variants flagged = %.0f%%" % (
    fp_variants, considered, 100 * fp_variants / max(considered, 1)))
print("NOISE on fixed   : %d findings across %d clean .rs files = %.1f per file" % (
    tot_fp_findings, tot_clean_files, tot_fp_findings / max(tot_clean_files, 1)))
print("=" * 60)

rc = 100 * fp_variants / max(considered, 1)
rr = 100 * detected / max(n, 1)
print("\nVERDICT under the pre-registered decision rule:")
if rc > 30 or rr < 50:
    print("  FAIL - the scanner is not our specialization. Do not pitch Superteam with it.")
elif rr >= 70 and rc <= 20:
    print("  PASS - defensible claim, real grant application.")
else:
    print("  MIDDLING - commodity scanner. The grant pitch must rest on something else.")

json.dump(rows, open(os.environ.get("OUT","bench-out.json"), "w"), indent=1, default=str)
print("\nraw output: /tmp/benchmark-raw.json")
