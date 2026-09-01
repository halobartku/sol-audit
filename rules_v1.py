"""v1 rules: the original detectors, each a test for the presence of a construct.

Every one of them is still live. rules_v2 rebuilds the list with guard-aware replacements for
some ids and leaves the rest as they are.
"""
import re
from model import _ctx, _make

# The program writing bytes into an account it owns, as opposed to only forwarding CPIs.
_STATE_WRITE = re.compile(
    r"\bserialize\s*\(|\btry_borrow_mut_data\s*\(|\bdata\.borrow_mut\s*\(|"
    r"\b\w+::pack\s*\(|\bpack_into_slice\s*\(")

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
    """next_account_info used but no is_signer validation in file (missing signer check).

    Matches a CALL, `next_account_info(`, not the bare name. Matching the name meant the finding
    was often reported on the `use solana_program::account_info::{next_account_info, ..}` import,
    which is a line a reader can do nothing with. Two of the forty findings in the triage sample
    published in README.md pointed at an import.
    """
    nai = [i for i, l in enumerate(lines) if re.search(r"next_account_info\s*\(", l)]
    if not nai:
        return []
    if any("is_signer" in l for l in lines):
        return []
    # Only where the program writes its OWN account state. Neodyme's pitfall 2 is about
    # instructions "that should be restricted": if all the file does is forward CPIs, the callee
    # enforces its own authorization and the runtime enforces the payer's signature, so demanding
    # an is_signer check here is advice with nothing behind it. Five of the forty findings in the
    # second triage sample were native token-creation handlers of exactly that shape.
    if not any(_STATE_WRITE.search(l) for l in lines):
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
