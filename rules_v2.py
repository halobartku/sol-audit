# ---------------------------------------------------------------------------
# v2: guard-aware rules.
#
# v1 scored 0/11 real recall because every rule tested for the presence of a construct and none
# tested for the absence of a check. A bug and its fix contain the same constructs, so those rules
# fired on both. Everything below has the shape: construct present AND guard absent.
# See guards.py. No pattern below is derived from any specific corpus file.
# ---------------------------------------------------------------------------
import re
from guards import missing as _missing
from model import _make
from rules_v1 import RULES

_AUTHORITY_FIELD = re.compile(
    r"\b(authority|owner|admin|signer|user|payer)\s*:\s*(AccountInfo|UncheckedAccount)\s*<")
_RAW_ACCOUNTINFO = re.compile(r":\s*(AccountInfo|UncheckedAccount)\s*<")
# A free-function `invoke(&ix, ..)`, NOT a method call `Something { .. }.invoke()`. The method
# form belongs to a typed instruction builder (pinocchio_system::CreateAccount, the spl helpers)
# whose program id is a constant inside the builder, so there is nothing for the caller to check.
# The earlier pattern matched both, and the method form was a large share of the measured noise.
_INVOKE = re.compile(r"(?<![.\w])invoke(_signed)?\s*\(")

# The CPI target at THIS site is a compile-time constant, so no runtime comparison is possible or
# needed. Established by reading forty findings on third-party example code, not on a corpus case:
# `invoke(&system_instruction::create_account(..), ..)` cannot invoke anything but the system
# program, and telling somebody to validate it is advice they cannot act on.
_CONST_CPI_TARGET = re.compile(
    r"\b(system_instruction|solana_system_interface::instruction|"
    r"system_program::instruction)::"
    r"|program_id:\s*&?\s*[A-Z][A-Z0-9_]{3,}\b"
    r"|&\s*\w+::ID\b"
    r"|\b[a-z_]+::ID\b")


# The SPL token family's instruction builders take the program id as their FIRST argument, by
# documented convention: spl_token::instruction::transfer(token_program_id, ..). So a call to one
# of these is exactly the case where the CPI target IS caller-supplied and does need checking.
# Everything else on this list hardcodes its own program id inside the builder.
_CALLER_SUPPLIED_TARGET = re.compile(
    r"\b(spl_token|spl_token_2022|spl_token_interface|token_instruction|"
    r"token_2022_instruction|spl_token_client)\w*::")
_CONST_BUILDER = re.compile(
    r"\b(system_instruction|solana_system_interface::instruction|system_program::instruction|"
    r"associated_token_account_instruction|spl_associated_token_account\w*|"
    r"pinocchio_system|pinocchio_token\w*)::"
    # the same builders imported bare, which is how solana-program-library writes them
    r"|\b(create_account|create_account_with_seed|allocate|assign|advance_nonce_account)\s*\(")
_LET_INSTRUCTION = re.compile(r"\blet\s+(\w+)\s*=\s*$|\blet\s+(\w+)\s*=\s*\S")


def _window(lines, i, before=0, after=10):
    """The raw text around line i. Unlike _ctx it is NOT truncated to 220 characters.

    _ctx exists to give a rule a short blob to keyword-search. Truncating it at 220 characters is
    fine for that and wrong here: an `invoke(` on its own line puts the instruction expression
    below it, and the truncation was cutting the window off before it reached the line that says
    which program is being called. Five of the forty findings in the first triage sample were this
    bug and not a rule error.
    """
    return "\n".join(lines[max(0, i - before):i + after + 1])


def _target_is_constant(lines, i):
    """True if the instruction invoked at line i is built against a constant program id.

    Established by reading forty findings on third-party example code, not on a corpus case:
    `invoke(&system_instruction::create_account(..), ..)` cannot invoke anything but the system
    program, and telling somebody to validate the target is advice they cannot act on.
    """
    here = _window(lines, i, 0, 10)
    if _CALLER_SUPPLIED_TARGET.search(here):
        return False
    if _CONST_CPI_TARGET.search(here) or _CONST_BUILDER.search(here):
        return True
    # `invoke(&ix, ..)` where ix was bound earlier: judge the binding instead.
    m = re.search(r"invoke(?:_signed)?\s*\(\s*&\s*(\w+)\s*,", here)
    if m:
        name = m.group(1)
        back = "\n".join(lines[max(0, i - 14):i])
        b = re.search(r"\blet\s+" + re.escape(name) + r"\s*=", back)
        if b:
            expr = back[b.start():]
            if _CALLER_SUPPLIED_TARGET.search(expr):
                return False
            if _CONST_CPI_TARGET.search(expr) or _CONST_BUILDER.search(expr):
                return True
    return False
_MUT_TYPED = re.compile(r"#\[account\([^)]*\bmut\b[^)]*\)\]\s*\n?\s*pub\s+(\w+)\s*:\s*Account\s*<\s*'\w+\s*,\s*(\w+)")
_SYSVAR_FIELD = re.compile(r"\b(rent|clock|instructions|slot_hashes|epoch_schedule)\s*:\s*(AccountInfo|UncheckedAccount)\s*<")


# Emptying an account, not merely debiting it. `**source.try_borrow_mut_lamports()? -= 5` moves
# five lamports and leaves the account alive; it is not a close and there is nothing to zero.
# The close pattern is setting the balance to zero, or moving the source's ENTIRE balance out.
# One of the forty findings in the second triage sample was a two-line lamport transfer example.
_LAMPORT_DRAIN = re.compile(
    r"\blamports\s*\.\s*borrow_mut\s*\(\s*\)\s*=\s*0|"
    r"\btry_borrow_mut_lamports\s*\(\s*\)\s*\??\s*=\s*0|"
    r"\blamports\s*\.\s*borrow_mut\s*\(\s*\)\s*[-+]?=[^;]*\.lamports\s*\(\s*\)|"
    r"\btry_borrow_mut_lamports\s*\(\s*\)\s*\??\s*[-+]?=[^;]*\.lamports\s*\(\s*\)")


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
    return [i for i, l in enumerate(lines)
            if _INVOKE.search(l) and not _target_is_constant(lines, i)]


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
    return [i for i, l in enumerate(lines)
            if _INVOKE.search(l) and not _target_is_constant(lines, i)]


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
