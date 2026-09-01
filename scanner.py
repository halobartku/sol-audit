#!/usr/bin/env python3
"""
sol-audit: static security scanner for Solana / Anchor Rust programs.
Self-contained (stdlib only). Detects common vulnerability classes in
Anchor programs and raw solana_program code.

Usage:
  from scanner import scan_repo, scan_file
  report = scan_repo("/path/to/checkout")

The code lives in six modules and this one re-exports them, so `import scanner` keeps working
for every caller: model.py (Finding, the rule tuple, ProjectIndex), rules_v1.py, rules_v2.py and
rules_v3.py (each extends the RULES list of the one before it; rules_v3.RULES is the final list
and its order is the output order), profiles.py (categories, kinds, select_rules) and engine.py
(scan_text, scan_repo, scan_file).
"""
from dataclasses import asdict  # noqa: F401  run_bench.py reaches it as scanner.asdict
from model import (Finding, SEV_ORDER, ProjectIndex, _PROJECT,  # noqa: F401
                   _ctx, _suppressed, _make)
from rules_v3 import RULES  # noqa: F401
from profiles import (CATEGORIES, META, PROFILES,  # noqa: F401
                      category_of, kind_of, select_rules)
from engine import (SKIP_DIRS, _strip_comments, scan_text,  # noqa: F401
                    iter_rust_files, scan_repo, scan_file)

# NOTE: the `if __name__ == "__main__"` block used to sit here, in the middle of the file. Python
# executes a module top to bottom, so it ran BEFORE the v2 section below had replaced RULES. Anyone
# who ran `python scanner.py <dir>` - which is what the README told them to do - got the v1 rules
# and none of the guard-aware ones. The library import path was correct, so every benchmark number
# was correct; only the command line a human would actually use was wrong. It is now at the bottom.


if __name__ == "__main__":
    import cli
    raise SystemExit(cli.main())
