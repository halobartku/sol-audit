# ---------------------------------------------------------------------------
# Rule metadata: category, and how the rule decides.
#
#   guarded   - construct present AND the corresponding guard absent. The v2 architecture.
#   shape     - construct present, full stop. There is no guard to look for because the construct
#               IS the defect (order of operations, an unsafe block). Correct, but blind to
#               context, so these are the rules that produce most of the noise.
#   heuristic - fires on a pattern that is often but not always wrong. Off unless you ask for it.
#
# Kept as a table rather than as extra tuple fields so that nothing above changes arity.
# ---------------------------------------------------------------------------
from rules_v3 import RULES

CATEGORIES = ("authorization", "accounts", "cpi", "arithmetic", "pda", "hygiene")

META = {
    "SOL-001": ("authorization", "guarded"),
    "SOL-002": ("authorization", "guarded"),
    "SOL-003": ("accounts",      "shape"),
    "SOL-004": ("arithmetic",    "shape"),
    "SOL-005": ("hygiene",       "heuristic"),
    "SOL-006": ("cpi",           "guarded"),
    "SOL-007": ("authorization", "guarded"),
    "SOL-008": ("pda",           "heuristic"),
    "SOL-009": ("hygiene",       "shape"),
    "SOL-010": ("cpi",           "guarded"),
    "SOL-011": ("pda",           "heuristic"),
    "SOL-012": ("arithmetic",    "heuristic"),
    "SOL-013": ("authorization", "heuristic"),
    "SOL-014": ("hygiene",       "shape"),
    "SOL-015": ("accounts",      "shape"),
    "SOL-016": ("pda",           "heuristic"),
    "SOL-017": ("accounts",      "guarded"),
    "SOL-018": ("accounts",      "guarded"),
    "SOL-019": ("accounts",      "guarded"),
    "SOL-020": ("pda",           "guarded"),
    "SOL-021": ("pda",           "guarded"),
    "SOL-022": ("accounts",      "guarded"),
    "SOL-023": ("authorization", "guarded"),
    "SOL-024": ("arithmetic",    "shape"),
    "SOL-025": ("arithmetic",    "shape"),
    "SOL-026": ("accounts",      "heuristic"),
    "SOL-027": ("cpi",           "guarded"),
    "SOL-028": ("accounts",      "guarded"),
    "SOL-029": ("accounts",      "guarded"),
    "SOL-030": ("authorization", "guarded"),
}

# Profiles select rules by `kind`.
#
# `strict` is the DEFAULT, and that is a measured choice rather than a taste. On the teaching
# corpus all three profiles reach the same real recall, 7 of 11; on 460 files of third-party
# example code `strict` produces 501 findings where `all` produces 962. Same detections, half the
# noise, so the extra rules buy nothing and cost the reader a thousand lines. The numbers are in
# README.md and were produced by noise.py, which anyone can rerun.
#
# `broad` adds the shape rules: unchecked arithmetic, unwrap, unsafe blocks. They are correct and
# worth reading once on a codebase you own; they are lint, not detections, and on SPL a single one
# of them (SOL-009) is half of everything the scanner says. `all` adds the heuristics on top.
PROFILES = {
    "strict": ("guarded",),
    "broad":  ("guarded", "shape"),
    "all":    ("guarded", "shape", "heuristic"),
}


def category_of(rule_id):
    return META.get(rule_id, ("hygiene", "shape"))[0]


def kind_of(rule_id):
    return META.get(rule_id, ("hygiene", "shape"))[1]


def select_rules(profile="strict", categories=None, exclude_categories=None,
                 rules=None, exclude_rules=None):
    """The rule list a run should use.

    Raises ValueError on an unknown profile, category or rule id rather than silently selecting
    nothing. A scanner that quietly runs no rules reports a clean repository, which is the single
    worst thing this tool can do.
    """
    if profile not in PROFILES:
        raise ValueError("unknown profile %r (choose from %s)" % (profile, ", ".join(PROFILES)))
    kinds = PROFILES[profile]
    known = {r[0] for r in RULES}
    for name in list(rules or []) + list(exclude_rules or []):
        if name not in known:
            raise ValueError("unknown rule %r" % name)
    for name in list(categories or []) + list(exclude_categories or []):
        if name not in CATEGORIES:
            raise ValueError("unknown category %r (choose from %s)"
                             % (name, ", ".join(CATEGORIES)))
    out = []
    for r in RULES:
        rid = r[0]
        cat, kind = META.get(rid, ("hygiene", "shape"))
        if rules:
            if rid not in rules:
                continue
        elif kind not in kinds:
            continue
        if categories and cat not in categories:
            continue
        if exclude_categories and cat in exclude_categories:
            continue
        if exclude_rules and rid in exclude_rules:
            continue
        out.append(r)
    return out
