#!/usr/bin/env python3
"""
sol-audit: static security scanner for Solana / Anchor Rust programs.
Self-contained (stdlib only). Detects common vulnerability classes in
Anchor programs and raw solana_program code.

Usage:
  from scanner import scan_repo, scan_file
  report = scan_repo("/path/to/checkout")
"""
import os, re, json, hashlib
from dataclasses import dataclass, asdict, field

# ---------------------------------------------------------------- rules

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str      # CRITICAL / HIGH / MEDIUM / LOW / INFO
    cwe: str
    file: str
    line: int
    snippet: str
    fix: str
    category: str = "hygiene"   # see CATEGORIES at the bottom of this file
    kind: str = "shape"         # guarded / shape / heuristic, see META

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

def _ctx(lines, i, pad=1):
    return " ".join(l.strip() for l in lines[max(0, i - pad):i + pad + 1])[:220]

def _suppressed(lines, i):
    # any `// audit-ok` on this line or the one above suppresses the finding
    return "audit-ok" in lines[i] or (i > 0 and "audit-ok" in lines[i - 1])

# Each detector: (rule_id, title, severity, cwe, fix, fn(lines, relpath) -> [line_no])
def _make(rule_id, title, sev, cwe, fix, fn):
    return (rule_id, title, sev, cwe, fix, fn)

def rule_missing_signer(lines, rel):
    """Anchor instruction takes UncheckedAccount / AccountInfo without Signer semantics."""
    out = []
    for i, l in enumerate(lines):
        if ("UncheckedAccount" in l or "UncheckedAccount<" in l) and "audit-ok" not in l:
            if any("Signer" in x or "signer" in x for x in lines[max(0, i - 2):i]):
                continue
            out.append(i)
    return out

def rule_account_info_field(lines, rel):
    """Raw AccountInfo in struct fields: no owner/derive validation by type."""
    return [i for i, l in enumerate(lines)
            if re.search(r"AccountInfo<['\"]info['\"]>", l) and "pub " in l]

def rule_init_if_needed(lines, rel):
    """init_if_needed: re-initialization / dust-account attack surface."""
    return [i for i, l in enumerate(lines) if "init_if_needed" in l]

def rule_unchecked_math(lines, rel):
    """Compound unchecked arithmetic on u*/i* (overflow panics = DoS, or wraps in release)."""
    return [i for i, l in enumerate(lines)
            if re.search(r"[a-zA-Z_)\]]\s*(\+=|\-=|\*=)", l)
            and "checked_" not in l and "saturating_" not in l
            and not l.strip().startswith("//")]

def rule_insecure_random(lines, rel):
    """Clock/hash used as randomness - predictable by validators/adversaries."""
    return [i for i, l in enumerate(lines)
            if ("unix_timestamp" in l or "Clock::default" in l or "hashv" in l.lower())
            and re.search(r"random|seed|shuffle|rand|winner|lottery|pick", _ctx(lines, i, 3), re.I)]

def rule_invoke_no_owner_check(lines, rel):
    """Raw CPI (invoke/invoke_signed) in a file with no account owner verification."""
    has_invoke = any(re.search(r"\binvoke(_signed)?\s*\(", l) for l in lines)
    if not has_invoke:
        return []
    has_owner_check = any(re.search(r"\.owner\b|owner\(\)\s*==|check_owner|to_account_info\(\)\.owner", l)
                          for l in lines)
    if has_owner_check:
        return []
    return [i for i, l in enumerate(lines) if re.search(r"\binvoke(_signed)?\s*\(", l)]

def rule_next_account_no_signer(lines, rel):
    """next_account_info used but no is_signer validation in file (missing signer check)."""
    nai = [i for i, l in enumerate(lines) if "next_account_info" in l]
    if not nai:
        return []
    if any("is_signer" in l for l in lines):
        return []
    return nai[:2]  # point at first usages, not every one

def rule_create_account_dyn(lines, rel):
    """create_account / space or lamports taken from instruction data."""
    return [i for i, l in enumerate(lines)
            if ("create_account" in l or "create_program_address" in l)
            and re.search(r"(space|lamports|amount|len)\s*[,:]?\s*\w+\.?(len|data)?\b", _ctx(lines, i, 2))]

def rule_unwrap(lines, rel):
    """unwrap()/expect() on deserialized account data - panic on crafted input = DoS."""
    return [i for i, l in enumerate(lines)
            if re.search(r"\.unwrap\(\)|\.expect\(", l) and "try_from" not in l][:5]

def rule_arbitrary_cpi_program(lines, rel):
    """CPI where the program id comes from user-passed account (invoke with unvalidated program)."""
    return [i for i, l in enumerate(lines)
            if re.search(r"invoke\s*\(", l) and "invoke_signed" not in l
            and ("program" in l.lower() or "instruction" in l.lower())]

def rule_bump_from_input(lines, ret):
    return []

def rule_bump_trusted(lines, rel):
    """Bump seed read from account data and re-used in invoke_signed without re-derivation."""
    hits = []
    for i, l in enumerate(lines):
        if re.search(r"bump\s*=\s*(seed_bump|bump|data\.bump)", l) or \
           re.search(r"\bbump\s*:\s*u8\b", l):
            if "seeds" in _ctx(lines, i, 5):
                hits.append(i)
    return hits

def rule_transfer_uncapped(lines, rel):
    """system transfer where amount originates from instruction argument (uncapped drain)."""
    out = []
    for i, l in enumerate(lines):
        if "transfer" in l and ("amount" in l or "lamports" in l):
            ctx = _ctx(lines, i, 3)
            if re.search(r"amount|lamports", l) and "checked" not in ctx:
                # only flag inside fns taking amount-ish params
                out.append(i)
    return out[:3]

def rule_mint_to_arbitrary(lines, rel):
    """mint_to without mint-authority constraint nearby."""
    hits = []
    for i, l in enumerate(lines):
        if "mint_to" in l:
            ctx = _ctx(lines, i, 6)
            if not re.search(r"has_one|constraint|authority\s*=|mint_authority", ctx):
                hits.append(i)
    return hits

def rule_unsafe(lines, rel):
    return [i for i, l in enumerate(lines) if "unsafe " in l]

def rule_missing_space(lines, rel):
    """Account init without space constraint (rent/resize issues)."""
    hits = []
    for i, l in enumerate(lines):
        if re.search(r"#\[account\(.*init(,|\))", l) and "space" not in l and "init_if_needed" not in l:
            hits.append(i)
    return hits

def rule_seeds_user_only(lines, rel):
    """PDA seeds fully or mostly user-controlled (collision/squatting)."""
    hits = []
    for i, l in enumerate(lines):
        if "seeds" in l and not re.search(r'seeds\s*=\s*\[\s*b"', l):
            hits.append(i)
    return hits

RULES = [
    _make("SOL-001", "UncheckedAccount used without Signer/validation in instruction",
          "HIGH", "CWE-862",
          "Replace with `Signer<'info>` or `Account<'info, T>` and add `#[account(...)]` constraints; never trust UncheckedAccount.",
          rule_missing_signer),
    _make("SOL-002", "Raw AccountInfo field - no owner/type validation enforced by deserialization",
          "MEDIUM", "CWE-20",
          "Use `Account<'info, T>` / `Program<'info, T>` types, or manually check `.owner == expected_program_id` and `.key()`.",
          rule_account_info_field),
    _make("SOL-003", "init_if_needed - reinitialization & account-takeover risk",
          "HIGH", "CWE-284",
          "Prefer separate `init` + explicit state transition; if kept, guard with a `initialized` flag constraint.",
          rule_init_if_needed),
    _make("SOL-004", "Unchecked compound arithmetic - overflow panic (DoS) / wraparound",
          "MEDIUM", "CWE-190",
          "Use checked_add/checked_sub/checked_mul or the `checked` math pattern; anchor 0.29+ `#[access_control]` won't save you here.",
          rule_unchecked_math),
    _make("SOL-005", "Predictable 'randomness' (Clock/hash-derived) used in game/selection logic",
          "HIGH", "CWE-338",
          "Use Switchboard/Chainlink VRF or commit-reveal; on-chain time and hash are validator-visible.",
          rule_insecure_random),
    _make("SOL-006", "Raw CPI without account owner verification in file",
          "HIGH", "CWE-20",
          "Verify `account.to_account_info().owner == &expected_program` before every invoke, or use Anchor CPI crates.",
          rule_invoke_no_owner_check),
    _make("SOL-007", "next_account_info without is_signer checks (missing signer validation)",
          "HIGH", "CWE-862",
          "Check `account.is_signer` for every authority account before use; bail with InstructionError::MissingRequiredSignature.",
          rule_next_account_no_signer),
    _make("SOL-008", "create_account/create_program_address with dynamic space/seed material",
          "MEDIUM", "CWE-20",
          "Fix space at compile time; derive PDAs from program-owned namespaces, not raw input.",
          rule_create_account_dyn),
    _make("SOL-009", "unwrap()/expect() on account/instruction data - panic DoS",
          "LOW", "CWE-248",
          "Use `try_from`/`Deref` with error propagation instead of unwrap on external input.",
          rule_unwrap),
    _make("SOL-010", "invoke() with program/instruction from accounts (arbitrary CPI)",
          "HIGH", "CWE-20",
          "Hardcode expected program IDs (`declare_id!`/static Pubkey) and validate `program.key() == EXPECTED` before CPI.",
          rule_arbitrary_cpi_program),
    _make("SOL-011", "Bump seed stored in account data and trusted for invoke_signed",
          "MEDIUM", "CWE-345",
          "Re-derive with find_program_address and compare, or use Anchor seeds/bump constraints.",
          rule_bump_trusted),
    _make("SOL-012", "Transfer with amount from instruction args (possible uncapped drain)",
          "MEDIUM", "CWE-770",
          "Cap amount (`require!(amount <= MAX)`), derive from on-chain state, or check source authority + balance.",
          rule_transfer_uncapped),
    _make("SOL-013", "mint_to without visible mint-authority constraint",
          "HIGH", "CWE-862",
          "Add `#[account(mut, mint::authority = <signer>)]` (or token authority check) on the mint account.",
          rule_mint_to_arbitrary),
    _make("SOL-014", "unsafe block in on-chain code",
          "MEDIUM", "CWE-119",
          "Justify + audit every unsafe; most Solana patterns have safe equivalents.",
          rule_unsafe),
    _make("SOL-015", "Account init without space constraint",
          "LOW", "CWE-400",
          "Add `space = 8 + <size>` (or `Space` trait) to prevent undersized/oversized accounts.",
          rule_missing_space),
    _make("SOL-016", "PDA seeds not anchored to a program-owned namespace literal",
          "LOW", "CWE-327",
          "Prefix seeds with byte literals (b\"...\") unique to your program; avoid fully user-controlled seeds.",
          rule_seeds_user_only),
]

# ---------------------------------------------------------------- engine

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

# NOTE: the `if __name__ == "__main__"` block used to sit here, in the middle of the file. Python
# executes a module top to bottom, so it ran BEFORE the v2 section below had replaced RULES. Anyone
# who ran `python scanner.py <dir>` - which is what the README told them to do - got the v1 rules
# and none of the guard-aware ones. The library import path was correct, so every benchmark number
# was correct; only the command line a human would actually use was wrong. It is now at the bottom.


# ---------------------------------------------------------------------------
# v2: guard-aware rules.
#
# v1 scored 0/11 real recall because every rule tested for the presence of a construct and none
# tested for the absence of a check. A bug and its fix contain the same constructs, so those rules
# fired on both. Everything below has the shape: construct present AND guard absent.
# See guards.py. No pattern below is derived from any specific corpus file.
# ---------------------------------------------------------------------------
from guards import missing as _missing  # noqa: E402

_AUTHORITY_FIELD = re.compile(
    r"\b(authority|owner|admin|signer|user|payer)\s*:\s*(AccountInfo|UncheckedAccount)\s*<")
_RAW_ACCOUNTINFO = re.compile(r":\s*(AccountInfo|UncheckedAccount)\s*<")
_INVOKE = re.compile(r"\binvoke(_signed)?\s*\(")
_MUT_TYPED = re.compile(r"#\[account\([^)]*\bmut\b[^)]*\)\]\s*\n?\s*pub\s+(\w+)\s*:\s*Account\s*<\s*'\w+\s*,\s*(\w+)")
_SYSVAR_FIELD = re.compile(r"\b(rent|clock|instructions|slot_hashes|epoch_schedule)\s*:\s*(AccountInfo|UncheckedAccount)\s*<")


_LAMPORT_DRAIN = re.compile(
    r"\blamports\s*\.\s*borrow_mut\s*\(\s*\)\s*[-+]?=|"
    r"\btry_borrow_mut_lamports\s*\(\s*\)\s*\??\s*[-+]?=")


def _text(lines):
    return "\n".join(lines)


def _offset_to_line(text, offset):
    """0-based line number of a character offset in the joined file text."""
    return text.count("\n", 0, offset)


def rule_missing_signer_v2(lines, rel):
    """An authority-like account passed raw, with no signer enforcement anywhere in the file."""
    t = _text(lines)
    if not _missing(t, "signer"):
        return []
    return [i for i, l in enumerate(lines) if _AUTHORITY_FIELD.search(l)]


def rule_owner_unchecked_v2(lines, rel):
    """A raw AccountInfo/UncheckedAccount field with no owner validation anywhere in the file."""
    t = _text(lines)
    if not _missing(t, "owner"):
        return []
    return [i for i, l in enumerate(lines) if _RAW_ACCOUNTINFO.search(l)]


def rule_arbitrary_cpi_v2(lines, rel):
    """A CPI whose target program id is never compared against a known id."""
    t = _text(lines)
    if not _missing(t, "program_id"):
        return []
    return [i for i, l in enumerate(lines) if _INVOKE.search(l)]


def rule_duplicate_mutable_v2(lines, rel):
    """Two or more mutable typed accounts of the SAME type, with no check that they differ."""
    t = _text(lines)
    if not _missing(t, "distinct_accounts"):
        return []
    types = {}
    for m in _MUT_TYPED.finditer(t):
        types.setdefault(m.group(2), []).append(m.start())
    dup_offsets = sorted(o for v in types.values() if len(v) >= 2 for o in v)
    if not dup_offsets:
        return []
    # Report the duplicated fields themselves. The first version reported "the first line in the
    # file containing `mut`", which is a finding the reader cannot act on and which the benchmark
    # scores as `unlocated` even when the detection is right.
    return sorted({_offset_to_line(t, o) for o in dup_offsets})


def rule_closing_accounts_v2(lines, rel):
    """Lamports drained out of an account without the data being zeroed (revival attack).

    Draining the lamports is only one third of a safe close. Per the Solana Foundation
    program-security course the other two thirds - zero the data, write a closed discriminator -
    are what stops an attacker refunding the rent in the same transaction and reusing the account.
    """
    t = _text(lines)
    if not _missing(t, "account_closed"):
        return []
    return [i for i, l in enumerate(lines) if _LAMPORT_DRAIN.search(l)]


def rule_sysvar_address_v2(lines, rel):
    """A sysvar passed as a raw account and never checked against the real sysvar address."""
    t = _text(lines)
    if not _missing(t, "sysvar_address"):
        return []
    return [i for i, l in enumerate(lines) if _SYSVAR_FIELD.search(l)]


def rule_cpi_no_owner_v2(lines, rel):
    """A CPI in a file that validates neither the target program id nor the account owners."""
    t = _text(lines)
    if not (_missing(t, "owner") and _missing(t, "program_id")):
        return []
    return [i for i, l in enumerate(lines) if _INVOKE.search(l)]


_V2_OVERRIDE = {
    "SOL-001": rule_missing_signer_v2,
    "SOL-006": rule_cpi_no_owner_v2,
    "SOL-002": rule_owner_unchecked_v2,
    "SOL-010": rule_arbitrary_cpi_v2,
}

RULES = [
    (rid, title, sev, cwe, fix, _V2_OVERRIDE.get(rid, fn))
    for (rid, title, sev, cwe, fix, fn) in RULES
] + [
    _make("SOL-017", "Two mutable accounts of the same type with no check that they differ",
          "HIGH", "CWE-20",
          "Add `require_keys_neq!(a.key(), b.key())` or an Anchor `constraint = a.key() != b.key()`.",
          rule_duplicate_mutable_v2),
    _make("SOL-018", "Account drained or repurposed without being marked closed",
          "HIGH", "CWE-672",
          "Use Anchor's `close = destination`, or write CLOSED_ACCOUNT_DISCRIMINATOR and zero the lamports.",
          rule_closing_accounts_v2),
    _make("SOL-019", "Sysvar passed as a raw account and never validated against its known address",
          "MEDIUM", "CWE-20",
          "Use `Sysvar<'info, T>`, or `require_eq!(account.key(), sysvar::rent::ID)`.",
          rule_sysvar_address_v2),
]


# ---------------------------------------------------------------------------
# v3: additional classes.
#
# Every rule below was written from a published description of the vulnerability CLASS, cited on
# the rule, and tested first against fixtures in tests/fixtures/ that were written by hand for this
# repository. None of them was written by reading a corpus case. The scores each one achieved on
# the corpora afterwards, including the zeroes, are recorded in RULES.md.
# ---------------------------------------------------------------------------

# Some classes cannot be decided inside one file. Whether `Account<'info, Vault>` needs a `has_one`
# depends on whether `Vault` carries an authority field, and in a real crate the state struct lives
# in state.rs while the accounts struct lives in instructions.rs. scan_repo does a cheap first pass
# and leaves what it learned here for the rules that need it. Single-file scans simply see less.
_ACCOUNT_STRUCT = re.compile(
    r"#\[account[^\n]*\]\s*(?:#\[[^\n]*\]\s*)*pub\s+struct\s+(\w+)\s*\{([^}]*)\}", re.S)
_AUTHORITY_PUBKEY_FIELD = re.compile(
    r"\bpub\s+(authority|owner|admin|manager|delegate|creator|update_authority)\s*:\s*Pubkey")


class ProjectIndex:
    """What a rule may know about the crate as a whole, rather than about one file."""

    def __init__(self):
        self.authority_structs = set()   # #[account] structs carrying an authority-ish Pubkey

    def add_text(self, text):
        for m in _ACCOUNT_STRUCT.finditer(text):
            if _AUTHORITY_PUBKEY_FIELD.search(m.group(2)):
                self.authority_structs.add(m.group(1))

    def clear(self):
        self.authority_structs.clear()


_PROJECT = ProjectIndex()

_CREATE_PDA = re.compile(r"\bcreate_program_address\s*\(")
_INSTRUCTION_ATTR = re.compile(r"#\[instruction\(([^)]*)\)\]")
_BUMP_EQ = re.compile(r"\bbump\s*=\s*([A-Za-z_]\w*)\s*[,)\]]")
_MANUAL_DESER = re.compile(
    r"\btry_from_slice\s*\(|\b\w+::unpack(_unchecked)?\s*\(|\bdeserialize\s*\(\s*&mut\s")
_TYPED_ACCOUNT = re.compile(
    r"pub\s+(\w+)\s*:\s*(?:Box\s*<\s*)?Account\s*<\s*'\w+\s*,\s*(\w+)\s*>")
_SIGNER_FIELD = re.compile(r"pub\s+\w+\s*:\s*Signer\s*<")
_DIV_THEN_MUL = [
    re.compile(r"checked_div\s*\(.*?\)\s*\??\s*(?:\.unwrap\(\)\s*)?\.\s*checked_mul\s*\("),
    re.compile(r"try_div\s*\(.*?\)\s*\??\s*\.\s*try_mul\s*\("),
    re.compile(r"\([^()]*/[^()]*\)\s*\*"),
]
_AMOUNT_WORD = re.compile(
    r"\b(amount|lamports|balance|supply|liquidity|collateral|shares|deposit|borrow|"
    r"principal|reward|fee|price|total)\w*\b", re.I)
_NARROW_CAST = re.compile(r"\bas\s+(u8|u16|u32|u64|i8|i16|i32|i64)\b")
_CPI_CALL = re.compile(
    r"\binvoke(_signed)?\s*\(|::cpi::\w+\s*\(|\btoken::(transfer|mint_to|burn)\s*\(")
_CTX_FIELD_READ = re.compile(r"ctx\.accounts\.(\w+)\.(\w+)\b")
_NOT_STATE_FIELD = {
    "to_account_info", "key", "clone", "reload", "lamports", "owner", "data", "bump",
    "try_borrow_data", "try_borrow_mut_data", "is_signer", "is_writable", "to_accounts",
    "executable", "rent_epoch", "as_ref", "into", "borrow", "borrow_mut",
}
_INTROSPECT = re.compile(
    r"\bload_instruction_at(_checked)?\s*\(|\bget_instruction_relative\s*\(|"
    r"\bload_current_index(_checked)?\s*\(")
_INIT_FN_NAME = re.compile(r"\bfn\s+(\w+)\s*[<(]")
_REMAINING = re.compile(r"\bremaining_accounts\b")
_NATIVE_ENTRY = re.compile(r"\bnext_account_info\s*\(")


def rule_noncanonical_bump_v3(lines, rel):
    """A PDA derived with create_program_address, with no canonical bump anywhere in the file.

    Class: bump seed canonicalization. create_program_address accepts whatever bump byte you hand
    it, so several valid PDAs exist per seed set and an attacker picks one the program has not
    seen. find_program_address, or Anchor's `bump` constraint, pins the canonical one.
    Source: Solana Foundation program-security course, bump-seed-canonicalization.md;
            Helius, "A Hitchhiker's Guide to Solana Program Security", section 6.
    """
    t = _text(lines)
    if not _missing(t, "canonical_bump"):
        return []
    return [i for i, l in enumerate(lines) if _CREATE_PDA.search(l)]


def rule_bump_from_instruction_v3(lines, rel):
    """An Anchor `bump = x` constraint whose x is an instruction argument, so the caller picks it.

    Class: bump seed canonicalization, Anchor flavour. `bump = state.bump` re-uses a bump that was
    stored canonically and is correct; `bump = user_supplied_bump` lets the caller choose.
    The `#[instruction(...)]` attribute is what tells us which identifiers are caller-supplied.
    Source: as above, plus the Anchor account-constraint reference for `#[instruction(..)]`.
    """
    t = _text(lines)
    args = set()
    for m in _INSTRUCTION_ATTR.finditer(t):
        for part in m.group(1).split(","):
            name = part.split(":")[0].strip()
            if name:
                args.add(name)
    if not args:
        return []
    out = []
    for i, l in enumerate(lines):
        m = _BUMP_EQ.search(l)
        if m and m.group(1) in args:
            out.append(i)
    return out


def rule_type_cosplay_v3(lines, rel):
    """Account bytes deserialised by hand with nothing in the file distinguishing one type.

    Class: type cosplay / account confusion. Two account structs with the same layout deserialise
    from each other's bytes, so an attacker substitutes one for the other. The check is a
    discriminator: Anchor's 8 bytes, or a hand-written tag field compared before use.
    Source: Neodyme, "Common Pitfalls", pitfall 5; Solana Foundation course, type-cosplay.md.
    """
    t = _text(lines)
    if not _missing(t, "discriminator"):
        return []
    out = []
    for i, l in enumerate(lines):
        if _MANUAL_DESER.search(l) and re.search(r"data|borrow", _ctx(lines, i, 1)):
            out.append(i)
    return out


def rule_account_data_matching_v3(lines, rel):
    """A state account carrying an authority field is used beside a Signer, and never compared.

    Class: account data matching. The account says who may act on it; the instruction never checks
    that the signer IS that party. Anchor spells the check `has_one = authority`, or a
    `constraint = x.authority == signer.key()`.
    The state struct is found by the repo pre-pass, because in a real crate it is in another file.
    Source: sealevel-attacks class 1; Helius guide, section 1.
    """
    t = _text(lines)
    if not _missing(t, "account_match"):
        return []
    if not _SIGNER_FIELD.search(t):
        return []
    out = []
    for i, l in enumerate(lines):
        m = _TYPED_ACCOUNT.search(l)
        if m and m.group(2) in _PROJECT.authority_structs:
            out.append(i)
    return out


def rule_division_before_multiplication_v3(lines, rel):
    """Integer division performed before the multiplication that would have preserved precision.

    Class: loss of precision. (a / c) * b truncates twice; (a * b) / c truncates once. On token
    amounts the difference is value that leaks to whoever repeats the operation.
    This is a shape rule: there is no guard to look for, the order of operations IS the bug.
    Source: Helius guide, section 11; Neodyme lending disclosure.
    """
    return [i for i, l in enumerate(lines)
            if any(rx.search(l) for rx in _DIV_THEN_MUL)]


def rule_narrowing_cast_v3(lines, rel):
    """An `as` cast on a token-amount expression, which truncates silently instead of erroring.

    Class: unchecked cast. Neodyme: "Use checked math and checked casts whenever possible."
    Restricted to lines that also mention an amount-like identifier, because `as usize` on a
    length is ubiquitous and harmless and flagging it would drown the real ones.
    Source: Neodyme, "Common Pitfalls", pitfall 3; Helius guide, section 14.
    """
    out = []
    for i, l in enumerate(lines):
        if _NARROW_CAST.search(l) and _AMOUNT_WORD.search(l) and _missing(l, "checked_cast"):
            out.append(i)
    return out


def rule_stale_after_cpi_v3(lines, rel):
    """A field of an Anchor account is read shortly after a CPI, with no reload() in the file.

    Class: account reloading. Anchor deserialised the account at entry; a CPI that mutates it on
    chain does not update the in-memory copy, so the program then acts on a stale number.
    Heuristic: it cannot tell whether the CPI touched THAT account, so it over-reports.
    Source: Helius guide, section 3; Anchor `reload()` documentation.
    """
    t = _text(lines)
    if not _missing(t, "reload"):
        return []
    hits, last_cpi = [], None
    for i, l in enumerate(lines):
        if _CPI_CALL.search(l):
            last_cpi = i
            continue
        if last_cpi is not None and i - last_cpi <= 25:
            m = _CTX_FIELD_READ.search(l)
            if m and m.group(2) not in _NOT_STATE_FIELD:
                hits.append(i)
                last_cpi = None
    return hits


def rule_introspection_v3(lines, rel):
    """A neighbouring instruction is read out of the instructions sysvar and never attributed.

    Class: instruction introspection. Reading the adjacent instruction only means something if you
    also check whose program it belongs to; otherwise an attacker supplies their own instruction
    with the shape you are looking for.
    Source: sealevel-attacks class 10 and the solana_program sysvar::instructions API contract.
    """
    t = _text(lines)
    if not _missing(t, "introspected_program_id"):
        return []
    return [i for i, l in enumerate(lines) if _INTROSPECT.search(l)]


def rule_reinitialization_v3(lines, rel):
    """A native initialise handler with no is_initialized flag anywhere in the file.

    Class: re-initialization. Nothing about writing an account is one-shot; without a flag or a
    discriminator, an initialise instruction can be called again on a live account and reset its
    authority. Anchor's `init` and its 8-byte discriminator both count as the guard, so this rule
    is aimed at native programs.
    Source: sealevel-attacks class 4; Helius guide, section 10.
    """
    t = _text(lines)
    if not _missing(t, "initialized"):
        return []
    out = []
    for i, l in enumerate(lines):
        m = _INIT_FN_NAME.search(l)
        if m and re.match(r"(process_)?init", m.group(1)):
            out.append(i)
    return out


def rule_remaining_accounts_v3(lines, rel):
    """ctx.remaining_accounts used with no explicit owner check written out anywhere.

    Class: unvalidated remaining accounts. Anchor validates the declared accounts and nothing else;
    everything in remaining_accounts arrives raw. A typed `Account<'info, T>` elsewhere in the file
    is not a check on these, so this rule uses the explicit-owner-check guard family only.
    Source: Helius guide, section 16.
    """
    t = _text(lines)
    if not _missing(t, "explicit_owner_check"):
        return []
    return [i for i, l in enumerate(lines) if _REMAINING.search(l)]


def rule_native_owner_check_v3(lines, rel):
    """A native program unpacks account data without ever comparing an owner.

    Class: missing ownership check, native flavour. Neodyme's first pitfall and the one they call
    the most common: "Your contract should only trust accounts owned by itself." next_account_info
    hands you an AccountInfo with no ownership guarantee at all.
    Source: Neodyme, "Common Pitfalls", pitfall 1.
    """
    t = _text(lines)
    if not _NATIVE_ENTRY.search(t):
        return []
    if not _missing(t, "explicit_owner_check"):
        return []
    out = []
    for i, l in enumerate(lines):
        if _MANUAL_DESER.search(l) and re.search(r"data|borrow", _ctx(lines, i, 1)):
            out.append(i)
    return out


RULES = RULES + [
    _make("SOL-020", "PDA derived with create_program_address and a non-canonical bump",
          "HIGH", "CWE-345",
          "Use `find_program_address`, which returns the canonical bump, or Anchor's "
          "`#[account(seeds = [..], bump)]`.",
          rule_noncanonical_bump_v3),
    _make("SOL-021", "Anchor bump constraint takes its bump from an instruction argument",
          "HIGH", "CWE-345",
          "Drop the argument and write a bare `bump`, or store the canonical bump on the account "
          "and use `bump = state.bump`.",
          rule_bump_from_instruction_v3),
    _make("SOL-022", "Account data deserialised by hand with no discriminator distinguishing types",
          "HIGH", "CWE-843",
          "Use `Account<'info, T>`, or add a type tag as the first field and compare it before "
          "trusting the rest.",
          rule_type_cosplay_v3),
    _make("SOL-023", "State account with an authority field used beside a Signer, never compared",
          "HIGH", "CWE-863",
          "Add `has_one = authority` to the account constraint, or "
          "`require_keys_eq!(state.authority, signer.key())`.",
          rule_account_data_matching_v3),
    _make("SOL-024", "Division performed before multiplication, truncating twice",
          "MEDIUM", "CWE-682",
          "Reorder to multiply first: `a.checked_mul(b)?.checked_div(c)?`.",
          rule_division_before_multiplication_v3),
    _make("SOL-025", "Token amount narrowed with an `as` cast, which truncates silently",
          "MEDIUM", "CWE-197",
          "Use `u64::try_from(x)?` / `x.try_into()?` so an out-of-range value errors instead of "
          "wrapping.",
          rule_narrowing_cast_v3),
    _make("SOL-026", "Account state read after a CPI without reload()",
          "MEDIUM", "CWE-367",
          "Call `ctx.accounts.<account>.reload()?` after any CPI that can change it.",
          rule_stale_after_cpi_v3),
    _make("SOL-027", "Introspected instruction never checked against an expected program id",
          "HIGH", "CWE-345",
          "Compare `ix.program_id` with the program you expect before trusting the instruction.",
          rule_introspection_v3),
    _make("SOL-028", "Initialise handler with no initialised flag or discriminator to stop a rerun",
          "HIGH", "CWE-665",
          "Check `is_initialized` and set it, or use Anchor's `init` constraint.",
          rule_reinitialization_v3),
    _make("SOL-029", "remaining_accounts used without an explicit owner check",
          "MEDIUM", "CWE-20",
          "Validate every account you pull out of `remaining_accounts`: owner, then type, then "
          "authority.",
          rule_remaining_accounts_v3),
    _make("SOL-030", "Native program unpacks account data without checking the account owner",
          "HIGH", "CWE-862",
          "Compare `account.owner` with the expected program id before deserialising, or wrap the "
          "unpack in a helper that does.",
          rule_native_owner_check_v3),
]


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

# Profiles select rules by `kind`. `strict` is the guard-aware architecture on its own and is the
# lowest-noise thing this scanner can do; `all` adds the heuristics. See README for the measured
# noise of each.
PROFILES = {
    "strict":  ("guarded",),
    "default": ("guarded", "shape"),
    "all":     ("guarded", "shape", "heuristic"),
}


def category_of(rule_id):
    return META.get(rule_id, ("hygiene", "shape"))[0]


def kind_of(rule_id):
    return META.get(rule_id, ("hygiene", "shape"))[1]


def select_rules(profile="default", categories=None, exclude_categories=None,
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


if __name__ == "__main__":
    import cli
    raise SystemExit(cli.main())
