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
    """Clock/hash used as randomness — predictable by validators/adversaries."""
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
    """unwrap()/expect() on deserialized account data — panic on crafted input = DoS."""
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
    _make("SOL-002", "Raw AccountInfo field — no owner/type validation enforced by deserialization",
          "MEDIUM", "CWE-20",
          "Use `Account<'info, T>` / `Program<'info, T>` types, or manually check `.owner == expected_program_id` and `.key()`.",
          rule_account_info_field),
    _make("SOL-003", "init_if_needed — reinitialization & account-takeover risk",
          "HIGH", "CWE-284",
          "Prefer separate `init` + explicit state transition; if kept, guard with a `initialized` flag constraint.",
          rule_init_if_needed),
    _make("SOL-004", "Unchecked compound arithmetic — overflow panic (DoS) / wraparound",
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
    _make("SOL-009", "unwrap()/expect() on account/instruction data — panic DoS",
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

def scan_text(text, rel):
    raw = text.splitlines()
    lines = _strip_comments(raw)
    findings = []
    for rule_id, title, sev, cwe, fix, fn in RULES:
        try:
            hits = fn(lines, rel)
        except Exception:
            hits = []
        for h in hits:
            if _suppressed(raw, h):
                continue
            findings.append(Finding(rule_id, title, sev, cwe,
                                    rel, h + 1, raw[h].strip()[:160], fix))
    return findings

def scan_repo(root):
    findings = []
    files_scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "node_modules", "tests", "macros")]
        for fn in filenames:
            if not fn.endswith(".rs"):
                continue
            p = os.path.join(dirpath, fn)
            files_scanned += 1
            try:
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            findings += scan_text(text, os.path.relpath(p, root))
    findings.sort(key=lambda f: (-SEV_ORDER[f.severity], f.file, f.line))
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {"files_scanned": files_scanned,
            "total_findings": len(findings),
            "counts": counts,
            "findings": [asdict(f) for f in findings]}

if __name__ == "__main__":
    import sys
    r = scan_repo(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(json.dumps(r, indent=1)[:4000])


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


def _text(lines):
    return "\n".join(lines)


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
    if not any(len(v) >= 2 for v in types.values()):
        return []
    return [i for i, l in enumerate(lines) if re.search(r"\bmut\b", l)][:1]


def rule_closing_accounts_v2(lines, rel):
    """An account is emptied or repurposed without being marked closed."""
    t = _text(lines)
    if not _missing(t, "account_closed"):
        return []
    hits = [i for i, l in enumerate(lines)
            if re.search(r"lamports.*(borrow_mut|-=|\+=)|\bclose\b|data\.borrow_mut", l)]
    return hits[:3]


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
