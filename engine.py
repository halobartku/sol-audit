"""The engine: comment stripping, the per-file scan, the file walk and the repository scan.

`scan_text` runs the final rule list from rules_v3 unless told otherwise; the metadata each finding
carries comes from profiles.META.
"""
import os
from dataclasses import asdict
from model import Finding, SEV_ORDER, _PROJECT, _suppressed
from profiles import META
from rules_v3 import RULES

def _strip_comments(lines):
    """Blank out // and /* */ comments (string-literal aware), preserving line numbers."""
    out, in_block = [], False
    for l in lines:
        res, i, n, in_str = [], 0, len(l), False
        while i < n:
            c = l[i]
            if in_block:
                if c == "*" and i + 1 < n and l[i + 1] == "/":
                    in_block = False; res.append("  "); i += 2; continue
                res.append(" "); i += 1; continue
            if in_str:
                res.append(c)
                if c == "\\": res.append(l[i + 1] if i + 1 < n else " "); i += 2; continue
                if c == '"': in_str = False
                i += 1; continue
            if c == '"':
                in_str = True; res.append(c); i += 1; continue
            if c == "/" and i + 1 < n and l[i + 1] == "*":
                in_block = True; res.append("  "); i += 2; continue
            if c == "/" and i + 1 < n and l[i + 1] == "/":
                res.append(" " * (n - i)); break
            res.append(c); i += 1
        out.append("".join(res))
    return out

def scan_text(text, rel, rules=None):
    raw = text.splitlines()
    lines = _strip_comments(raw)
    findings = []
    for rule_id, title, sev, cwe, fix, fn in (RULES if rules is None else rules):
        try:
            hits = fn(lines, rel)
        except Exception:
            hits = []
        cat, kind = META.get(rule_id, ("hygiene", "shape"))
        for h in hits:
            if _suppressed(raw, h):
                continue
            findings.append(Finding(rule_id, title, sev, cwe,
                                    rel, h + 1, raw[h].strip()[:160], fix, cat, kind))
    return findings

SKIP_DIRS = (".git", "target", "node_modules", "tests", "macros")

def iter_rust_files(root):
    """Every .rs file under root, or root itself if it is a file. Sorted, so a run is repeatable."""
    if os.path.isfile(root):
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            if fn.endswith(".rs"):
                yield os.path.join(dirpath, fn)

def scan_repo(root, rules=None):
    findings = []
    files_scanned = 0
    errors = []
    base = root if os.path.isdir(root) else os.path.dirname(os.path.abspath(root))

    # First pass: learn what the crate declares, so cross-file rules have something to work with.
    _PROJECT.clear()
    sources = []
    for p in iter_rust_files(root):
        try:
            text = open(p, encoding="utf-8", errors="replace").read()
        except OSError as e:
            errors.append({"file": p, "error": str(e)})
            continue
        sources.append((p, text))
        _PROJECT.add_text(text)

    # Second pass: the rules themselves.
    for p, text in sources:
        files_scanned += 1
        findings += scan_text(text, os.path.relpath(p, base), rules)

    findings.sort(key=lambda f: (-SEV_ORDER[f.severity], f.file, f.line))
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    by_rule = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {"files_scanned": files_scanned,
            "total_findings": len(findings),
            "counts": counts,
            "by_rule": by_rule,
            "errors": errors,
            "findings": [asdict(f) for f in findings]}

def scan_file(path, rules=None):
    """Scan a single file. Cross-file rules see only this file, which is a real loss of context."""
    text = open(path, encoding="utf-8", errors="replace").read()
    _PROJECT.clear()
    _PROJECT.add_text(text)
    return scan_text(text, path, rules)
