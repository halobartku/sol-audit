"""Which sol-audit rule claims which corpus class. One file, because two copies drift.

PRE-REGISTERED. Every entry is derived from the rule's OWN title and docstring in scanner.RULES,
matched against the class name the corpus gives the case. Never from which rules turned out to
fire. `no-rule` is a permitted outcome and appears as an empty list; a class with no rule still
counts in the denominator, because a scanner that cannot detect a bug does not detect it.

History, kept because the mistakes are the useful part:

  The first version of the corpus-1 map guessed semantic rule ids (SOL-MISSING-SIGNER). The
  scanner emits numeric codes, so nothing could ever match and every class scored zero for a
  reason that had nothing to do with the rules.

  `declare_id!` was briefly treated as a program-id guard. Every Anchor program declares its own
  id, so it guards nothing about a CPI target, and counting it silently suppressed a correct
  detection on 5-arbitrary-cpi. Presence of a symbol is not evidence of a check.

  These two maps used to live inside run_bench.py and run_bench2.py. noise.py needs the same
  mapping to decide which findings on a fixed variant are false positives by construction, and
  a third copy of a pre-registered mapping is how a pre-registration quietly stops being one.
"""

# coral-xyz/sealevel-attacks, eleven teaching programs. Public since 2022, so IN-SAMPLE.
CORPUS1 = {
    "0-signer-authorization":       ["SOL-001", "SOL-007"],   # UncheckedAccount w/o Signer; next_account_info w/o is_signer
    "1-account-data-matching":      ["SOL-002", "SOL-023"],   # raw AccountInfo, no owner/type validation; authority field never compared
    "2-owner-checks":               ["SOL-002", "SOL-006", "SOL-030"],  # no owner validation; raw CPI w/o owner check; native unpack w/o owner
    "3-type-cosplay":               ["SOL-002", "SOL-022"],   # no type validation via deserialization; no discriminator
    "4-initialization":             ["SOL-003", "SOL-015", "SOL-028"],  # init_if_needed reinit; init without space; no initialised flag
    "5-arbitrary-cpi":              ["SOL-010", "SOL-006"],   # invoke() with program from accounts
    "6-duplicate-mutable-accounts": ["SOL-017"],              # two mutable accounts of one type, never compared
    "7-bump-seed-canonicalization": ["SOL-011", "SOL-020", "SOL-021"],  # bump stored and trusted; create_program_address; caller-chosen bump
    "8-pda-sharing":                ["SOL-016", "SOL-008"],   # PDA seeds not namespaced; dynamic seed material
    "9-closing-accounts":           ["SOL-018"],              # drained without being marked closed
    "10-sysvar-address-checking":   ["SOL-019", "SOL-027"],   # sysvar never validated; introspected instruction never attributed
}

# ScannerTruth corpus 2: real production bugs, each pinned to its maintainers' own fix commit.
# NOT in-sample: this scanner has never been fitted to it and the answer key is somebody else's.
#
# `arithmetic-rounding-drain` is mapped to the arithmetic rules with a caveat recorded in RULES.md:
# this scanner has no rounding-DIRECTION rule, because whether rounding up is a bug depends on
# which side of the trade benefits, and that is semantic. SOL-024 catches the neighbouring defect,
# dividing before multiplying, not the one this case actually is. It is mapped anyway so the class
# stays in the denominator rather than being quietly dropped.
#
# Corpus 2 grew from 10 cases to 18 during the session that wrote the v3 rules. The six classes
# below the rule were mapped after the corpus grew but before that larger corpus was scored, and
# committed in that order. Three of them come out `no-rule`, which is a permitted outcome and a
# more useful thing to publish than a strained mapping onto a rule that means something else.
CORPUS2 = {
    "signer-authorization":      ["SOL-001", "SOL-007"],
    "owner-checks":              ["SOL-002", "SOL-006", "SOL-030"],
    "account-data-matching":     ["SOL-002", "SOL-023"],
    "type-cosplay":              ["SOL-002", "SOL-022"],
    "sysvar-address-checking":   ["SOL-019", "SOL-027"],
    "instruction-introspection": ["SOL-027"],
    "arithmetic-rounding-drain": ["SOL-004", "SOL-024", "SOL-025"],
    "arbitrary-cpi":             ["SOL-006", "SOL-010"],
    # "is this account really the program I think it is" - the same question SOL-010 asks before a
    # CPI, and the one Anchor's typed accounts answer, which is what SOL-002 looks for.
    "program-account-validation": ["SOL-002", "SOL-010"],
    # deriving an address and then trusting it: the bump rules and the seed-namespace rule.
    "pda-derived-address-validation": ["SOL-011", "SOL-016", "SOL-020"],
    # a check that was true before a CPI and is not after it. SOL-026 is the rule about reading
    # account state across a CPI without reloading it; it is the nearest thing this scanner has.
    "owner-check-after-cpi":     ["SOL-026"],
    # no-rule. A program calling itself is a control-flow property; nothing here reasons about
    # call graphs, and inventing a keyword rule for "recursion" would be a mapping, not a detector.
    "cpi-recursion":             [],
    # no-rule. Whether a mint's decimals or freeze authority are the right ones is a question about
    # this protocol's intent, not about a missing check that is visible in the text.
    "mint-configuration-validation": [],
}
