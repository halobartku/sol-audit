# ---------------------------------------------------------------------------
# v3: additional classes.
#
# Every rule below was written from a published description of the vulnerability CLASS, cited on
# the rule, and tested first against fixtures in tests/fixtures/ that were written by hand for this
# repository. None of them was written by reading a corpus case. The scores each one achieved on
# the corpora afterwards, including the zeroes, are recorded in RULES.md.
# ---------------------------------------------------------------------------
import re
from guards import missing as _missing
from model import _PROJECT, _make
from rules_v1 import _STATE_WRITE
from rules_v2 import RULES, _text, _window

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
_CREATES_ACCOUNT = re.compile(r"\bcreate_account\s*\(|\bCreateAccount\b|\bcreate_pda_account\s*\(")
_NATIVE_ENTRY = re.compile(r"\bnext_account_info\s*\(")

# Deserialising the INSTRUCTION payload is not deserialising an account, and neither type cosplay
# nor a missing owner check applies to it: instruction data has no owner and no discriminator to
# confuse. The first version tested for "data" anywhere in the surrounding context, which matched
# the identifier `instruction_data`, so the scanner told people to add an owner check to a byte
# slice that arrived in the transaction. Found by reading third-party code, not a corpus case.
_ACCOUNT_DATA_SOURCE = re.compile(r"borrow|\.data\b|try_borrow_data|account_data")


def _reads_account_data(line):
    return bool(_ACCOUNT_DATA_SOURCE.search(line)) and "instruction_data" not in line


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
        if _MANUAL_DESER.search(l) and _reads_account_data(l):
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
        if not (m and re.match(r"(process_)?init", m.group(1))):
            continue
        # If the handler CREATES the account, the system program refuses to create one that
        # already holds lamports or data, so creation is itself the re-initialization guard and
        # there is nothing to add. Only a handler that writes into an account somebody else
        # supplied can be re-run on live state.
        body = _window(lines, i, 0, 30)
        if _CREATES_ACCOUNT.search(body):
            continue
        # `pub fn init_reserve(program_id: Pubkey, ..) -> Instruction` is a CLIENT-SIDE builder
        # that assembles an Instruction for a caller to send. It initialises nothing and has no
        # account to guard. Four of the forty findings in the second triage sample were these,
        # all of them in an instruction.rs. A handler writes account bytes; a builder does not.
        if not _STATE_WRITE.search(body):
            continue
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
        if _MANUAL_DESER.search(l) and _reads_account_data(l):
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
