#!/usr/bin/env python3
"""The whole test suite. `python run_tests.py`, and nothing to install.

Standard library only, on purpose. This project's install story is "Python 3 and nothing else" and
a test framework dependency would be the first thing to break it. unittest is in the standard
library and would have been fine too; a plain runner was chosen so the output reads as the record
of what was checked, which is the point of the exercise.

Three groups of checks:

  fixtures  every rule has a vulnerable fixture it must fire on and a fixed fixture it must stay
            silent on. Both were written by hand for this repository from a published description
            of the class. Neither came from a benchmark corpus.
  engine    comment stripping, suppression, rule selection, the things a wrong answer here would
            quietly corrupt.
  cli       exit codes and output formats, driven the way a user drives them.

Caveat stated up front: there is no cargo on the machine this was written on, so no fixture has
ever been compiled. They are Rust-shaped text. A fixture that would not build would still pass
these tests, and that is a real weakness of the suite.
"""
import io
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "tests", "fixtures")
sys.path.insert(0, HERE)

import guards    # noqa: E402
import scanner   # noqa: E402

PASS, FAIL = [], []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append(name)
    if not ok:
        print("FAIL  %s%s" % (name, ("  <- " + detail) if detail else ""))
    return ok


def rule_by_id(rid):
    for r in scanner.RULES:
        if r[0] == rid:
            return r
    raise KeyError(rid)


def fire(rid, variant):
    """Findings of rule `rid` on its own `variant` fixture, with only that rule enabled."""
    path = os.path.join(FIXTURES, "%s_%s.rs" % (rid, variant))
    if not os.path.exists(path):
        return None
    return scanner.scan_file(path, [rule_by_id(rid)])


# ---------------------------------------------------------------- guards
def test_guards():
    try:
        guards.demo()
        check("guards.demo self-check", True)
    except AssertionError as e:
        check("guards.demo self-check", False, repr(e))
    for family in guards.GUARDS:
        check("guard family %s compiles" % family,
              bool(guards._COMPILED.get(family)))


# ---------------------------------------------------------------- fixtures
def test_fixtures():
    for rid, title, sev, cwe, fix, fn in scanner.RULES:
        vuln = fire(rid, "vulnerable")
        fixed = fire(rid, "fixed")
        if vuln is None or fixed is None:
            check("%s has both fixtures" % rid, False,
                  "missing tests/fixtures/%s_{vulnerable,fixed}.rs" % rid)
            continue
        check("%s has both fixtures" % rid, True)
        check("%s fires on its vulnerable fixture" % rid, len(vuln) >= 1,
              "expected at least one finding, got 0")
        check("%s stays silent on its fixed fixture" % rid, len(fixed) == 0,
              "expected 0 findings, got %d at line(s) %s"
              % (len(fixed), [f.line for f in fixed]))


def test_fixture_hygiene():
    """A fixture that is empty, or identical to its pair, would pass the tests above vacuously."""
    for rid, _t, _s, _c, _f, _fn in scanner.RULES:
        v = os.path.join(FIXTURES, "%s_vulnerable.rs" % rid)
        f = os.path.join(FIXTURES, "%s_fixed.rs" % rid)
        if not (os.path.exists(v) and os.path.exists(f)):
            continue
        vt = io.open(v, encoding="utf-8").read()
        ft = io.open(f, encoding="utf-8").read()
        check("%s fixtures differ" % rid, vt != ft)
        check("%s fixtures are non-trivial" % rid, len(vt) > 120 and len(ft) > 120)
        check("%s fixtures carry no em dash" % rid,
              "—" not in vt + ft and "–" not in vt + ft)


# ---------------------------------------------------------------- engine
def test_comment_stripping():
    src = 'let a = 1; // total += amount;\n/* total += amount; */\nlet s = "// not a comment";\n'
    out = scanner._strip_comments(src.splitlines())
    check("line comments are blanked", "total" not in out[0])
    check("block comments are blanked", "total" not in out[1])
    check("string literals survive comment stripping", "not a comment" in out[2])
    check("comment stripping preserves line count", len(out) == 3)


def test_suppression():
    src = "pub fn f(a: &mut u64, b: u64) {\n    *a += b; // audit-ok\n}\n"
    found = scanner.scan_text(src, "x.rs", [rule_by_id("SOL-004")])
    check("`// audit-ok` suppresses a finding", len(found) == 0,
          "got %d" % len(found))
    src2 = "pub fn f(a: &mut u64, b: u64) {\n    *a += b;\n}\n"
    check("the same line without audit-ok is reported",
          len(scanner.scan_text(src2, "x.rs", [rule_by_id("SOL-004")])) == 1)


def test_rule_selection():
    check("strict profile is guarded only",
          all(scanner.kind_of(r[0]) == "guarded" for r in scanner.select_rules("strict")))
    check("broad profile excludes heuristics",
          all(scanner.kind_of(r[0]) != "heuristic" for r in scanner.select_rules("broad")))
    check("strict is the default profile",
          scanner.select_rules() == scanner.select_rules("strict"))
    check("all profile is every rule",
          len(scanner.select_rules("all")) == len(scanner.RULES))
    check("category filter works",
          all(scanner.category_of(r[0]) == "cpi"
              for r in scanner.select_rules("all", categories=["cpi"])))
    check("category exclusion works",
          all(scanner.category_of(r[0]) != "cpi"
              for r in scanner.select_rules("all", exclude_categories=["cpi"])))
    check("explicit --rule overrides the profile",
          [r[0] for r in scanner.select_rules("strict", rules=["SOL-004"])] == ["SOL-004"])
    check("rule exclusion works",
          "SOL-004" not in [r[0] for r in scanner.select_rules("all", exclude_rules=["SOL-004"])])
    for bad, kwargs in (("profile", {"profile": "nope"}),
                        ("category", {"categories": ["nope"]}),
                        ("rule id", {"rules": ["SOL-999"]})):
        try:
            scanner.select_rules(**kwargs)
            check("unknown %s is rejected" % bad, False, "no ValueError raised")
        except ValueError:
            check("unknown %s is rejected" % bad, True)


def test_every_rule_has_metadata():
    ids = [r[0] for r in scanner.RULES]
    check("no duplicate rule ids", len(ids) == len(set(ids)))
    for rid in ids:
        check("%s has metadata" % rid, rid in scanner.META)
        cat, kind = scanner.META.get(rid, (None, None))
        check("%s category is known" % rid, cat in scanner.CATEGORIES)
        check("%s kind is known" % rid, kind in ("guarded", "shape", "heuristic"))


def test_project_index():
    """The cross-file pre-pass is what lets SOL-023 know that Vault carries an authority."""
    idx = scanner.ProjectIndex()
    idx.add_text("#[account]\npub struct Vault { pub authority: Pubkey, pub balance: u64 }\n")
    idx.add_text("#[account]\npub struct Counter { pub count: u64 }\n")
    check("project index finds authority-bearing structs", "Vault" in idx.authority_structs)
    check("project index ignores plain structs", "Counter" not in idx.authority_structs)


def test_scan_repo_shape():
    report = scanner.scan_repo(FIXTURES)
    for key in ("files_scanned", "total_findings", "counts", "by_rule", "errors", "findings"):
        check("scan_repo reports %s" % key, key in report)
    check("scan_repo scanned every fixture", report["files_scanned"] == 60,
          "got %d" % report["files_scanned"])
    check("findings carry a category",
          all("category" in f for f in report["findings"]))


# ---------------------------------------------------------------- cli
def run_cli(args):
    p = subprocess.run([sys.executable, os.path.join(HERE, "cli.py")] + args,
                       capture_output=True, text=True, cwd=HERE)
    return p.returncode, p.stdout, p.stderr


def test_cli():
    rc, out, _ = run_cli(["--help"])
    check("--help exits 0", rc == 0)
    for word in ("--profile", "exit code", "--format", "guarded", "heuristic"):
        check("--help explains %r" % word, word in out)

    rc, out, _ = run_cli(["--list-rules"])
    check("--list-rules exits 0", rc == 0)
    check("--list-rules lists every rule",
          all(r[0] in out for r in scanner.RULES))

    vuln = os.path.join(FIXTURES, "SOL-001_vulnerable.rs")
    fixed = os.path.join(FIXTURES, "SOL-001_fixed.rs")

    rc, out, _ = run_cli([vuln, "--rule", "SOL-001", "--color", "never"])
    check("findings give exit 1", rc == 1, "got %d" % rc)
    check("text output names the rule", "SOL-001" in out)

    rc, out, _ = run_cli([fixed, "--rule", "SOL-001", "--color", "never"])
    check("no findings gives exit 0", rc == 0, "got %d" % rc)

    rc, out, _ = run_cli([vuln, "--rule", "SOL-001", "--fail-on", "none"])
    check("--fail-on none forces exit 0", rc == 0)

    rc, out, _ = run_cli([vuln, "--rule", "SOL-001", "--format", "json"])
    try:
        doc = json.loads(out)
        check("--format json emits valid JSON", True)
        check("json report carries rule_ids", "rule_ids" in doc)
        check("json findings carry category and kind",
              all("category" in f and "kind" in f for f in doc["findings"]))
    except ValueError as e:
        check("--format json emits valid JSON", False, str(e))

    rc, out, _ = run_cli([vuln, "--rule", "SOL-001", "--format", "sarif"])
    try:
        doc = json.loads(out)
        check("--format sarif emits valid JSON", True)
        check("sarif has a runs array", isinstance(doc.get("runs"), list) and doc["runs"])
        check("sarif results carry a location",
              bool(doc["runs"][0]["results"][0]["locations"]))
    except (ValueError, KeyError, IndexError) as e:
        check("--format sarif emits valid JSON", False, str(e))

    rc, _, err = run_cli(["/no/such/path/anywhere"])
    check("missing path gives exit 2", rc == 2, "got %d" % rc)
    check("missing path says so", "no such path" in err)

    rc, _, err = run_cli([vuln, "--rule", "SOL-999"])
    check("unknown rule gives exit 2", rc == 2, "got %d" % rc)

    rc, _, err = run_cli([vuln, "--profile", "strict",
                          "--category", "cpi", "--exclude-category", "cpi"])
    check("an empty rule selection is refused, not reported as clean", rc == 2, "got %d" % rc)
    check("the refusal explains why", "clean repository" in err)

    rc, out, _ = run_cli([vuln, "--rule", "SOL-001", "--min-severity", "CRITICAL"])
    check("--min-severity filters findings out", rc == 0, "got %d" % rc)

    with tempfile.TemporaryDirectory() as td:
        logp = os.path.join(td, "run.log")
        outp = os.path.join(td, "out.json")
        rc, _, _ = run_cli([FIXTURES, "--format", "json", "--out", outp, "--log", logp,
                            "--quiet"])
        check("--out writes a file", os.path.exists(outp))
        check("--log writes a file", os.path.exists(logp))
        rows = [json.loads(l) for l in io.open(logp, encoding="utf-8") if l.strip()]
        check("the run log has one row per file", len(rows) == 60, "got %d" % len(rows))
        check("every log row says whether the file was analysed",
              all(r.get("status") == "ok" for r in rows))


# ---------------------------------------------------------------- published numbers
STDLIB_ONLY = ("scanner.py", "guards.py", "mapping.py", "cli.py", "run_tests.py",
               "noise.py", "run_bench.py", "run_bench2.py", "realrecall.py")
THIRD_PARTY = re.compile(
    r"^\s*(?:import|from)\s+(?!__future__)(pytest|numpy|requests|yaml|toml|click|rich|"
    r"tree_sitter|regex|attrs|pydantic|colorama|tabulate)\b", re.M)


def test_stdlib_only():
    """The install story is 'Python 3 and nothing else'. Assert it rather than claim it."""
    here = os.listdir(HERE)
    for name in ("requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "poetry.lock"):
        check("no %s" % name, name not in here)
    for mod in STDLIB_ONLY:
        p = os.path.join(HERE, mod)
        if not os.path.exists(p):
            check("%s exists" % mod, False)
            continue
        src = io.open(p, encoding="utf-8").read()
        check("%s imports nothing outside the standard library" % mod,
              not THIRD_PARTY.search(src))
    # and the real proof: every one of them imports cleanly with nothing installed
    for mod in STDLIB_ONLY:
        if mod in ("run_bench.py", "run_bench2.py", "realrecall.py"):
            continue   # scripts with side effects at import; covered by the source check above
        r = subprocess.run([sys.executable, "-c", "import " + mod[:-3]],
                           capture_output=True, text=True, cwd=HERE)
        check("%s imports cleanly" % mod, r.returncode == 0, r.stderr.strip()[:120])


def _readme():
    return io.open(os.path.join(HERE, "README.md"), encoding="utf-8").read()


def test_published_numbers_are_derived():
    """Re-derive every headline in README.md from the committed JSON.

    ScannerTruth's own rule, applied to us before anyone else: never type a count a machine can
    compute. Both times that project's front page was wrong the arithmetic was fine and the
    freshness was not. If a measurement is rerun and a number moves, this fails and the README
    has to be corrected before anything can be committed.
    """
    readme = _readme()

    p = os.path.join(HERE, "v3-strict.json")
    if not os.path.exists(p):
        check("v3-strict.json is committed", False)
        return
    rows = json.load(io.open(p, encoding="utf-8"))

    def on(e, v):
        return (e.get(v) or {}).get("on_target", 0)
    nominal = sum(1 for e in rows if on(e, "insecure") > 0)
    real = sum(1 for e in rows if on(e, "insecure") > 0
               and on(e, "secure") == 0 and on(e, "recommended") == 0)
    check("README corpus-1 real recall matches v3-strict.json",
          "**%d / %d**" % (real, len(rows)) in readme,
          "computed %d/%d" % (real, len(rows)))
    check("README corpus-1 nominal recall matches v3-strict.json",
          "**%d / %d**" % (nominal, len(rows)) in readme,
          "computed %d/%d" % (nominal, len(rows)))

    p = os.path.join(HERE, "bench2-strict.json")
    if os.path.exists(p):
        doc = json.load(io.open(p, encoding="utf-8"))
        check("README corpus-2 real recall matches bench2-strict.json",
              "**0 / %d**" % doc["scored"] in readme and doc["real"] == 0,
              "computed %d/%d" % (doc["real"], doc["scored"]))

    p = os.path.join(HERE, "noise-strict.json")
    if os.path.exists(p):
        doc = json.load(io.open(p, encoding="utf-8"))
        files = sum(c["files"] for c in doc["clean"])
        lines = sum(c["lines"] for c in doc["clean"])
        found = sum(c["findings"] for c in doc["clean"])
        check("README clean-corpus file count matches noise-strict.json",
              "%d `.rs` files" % files in readme, "computed %d" % files)
        check("README clean-corpus line count matches noise-strict.json",
              format(lines, ",") in readme, "computed %s" % format(lines, ","))
        check("README strict finding count matches noise-strict.json",
              "| strict (default) | %d |" % found in readme, "computed %d" % found)
        fx = doc["fixed_summary"]
        check("README fixed-variant false positives match noise-strict.json",
              "| strict (default) | %d | %d | %d | **%d** | %d of %d |"
              % (fx["variants"], fx["files"], fx["findings"], fx["same_class_fp"],
                 fx["variants_flagged"], fx["variants"]) in readme,
              "computed %s" % fx)

    p = os.path.join(HERE, "TRIAGE.md")
    if os.path.exists(p):
        t = io.open(p, encoding="utf-8").read()
        for line in t.splitlines():
            if line.startswith("| actionable |"):
                n = line.split("|")[2].strip()
                check("README triage count agrees with TRIAGE.md",
                      "**%s actionable" % n in readme, "TRIAGE says %s" % n)


def main():
    for t in (test_guards, test_fixtures, test_fixture_hygiene, test_comment_stripping,
              test_suppression, test_rule_selection, test_every_rule_has_metadata,
              test_project_index, test_scan_repo_shape, test_stdlib_only,
              test_published_numbers_are_derived, test_cli):
        t()
    total = len(PASS) + len(FAIL)
    print("\n%d checks, %d passed, %d failed" % (total, len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
