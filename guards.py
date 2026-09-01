"""Guard detection.

The reason sol-audit v1 scored 0/11 real recall is structural, not accidental: every rule tested
for the PRESENCE OF A CONSTRUCT (an `invoke(`, an `AccountInfo`, a PDA seed) and no rule tested for
the ABSENCE OF A CHECK. But a vulnerable program and its fix contain the same constructs. The fix
adds a guard. A rule that cannot see the guard cannot tell them apart, and will fire on both.

So every detection rule in v2 has the shape:

    construct is present  AND  the corresponding guard is absent

These patterns are general Anchor / solana_program idioms. **No pattern here is derived from any
particular file in any corpus.** That constraint is what keeps this an engineering fix rather than
fitting to a test set; see PROTOCOL.md in the scannertruth repository.
"""
import re

# Each guard is a family of idioms that a competent Solana program uses to enforce one property.
# Written from the Anchor book and solana_program conventions, not from corpus files.
GUARDS = {
    # `if !x.is_signer { return Err(..) }`, `require!(x.is_signer, ..)`, Anchor `Signer<'info>`,
    # or an `#[account(signer)]` / `has_one = authority` constraint.
    "signer": [
        r"\.is_signer\b",
        r"\bSigner\s*<",
        r"#\[account\([^)]*\bsigner\b",
        r"require(_keys)?(_eq)?!\s*\([^)]*is_signer",
        r"has_one\s*=",
    ],
    # `if x.owner != &SOME::ID { return Err(..) }`, `require_keys_eq!(x.owner, ..)`,
    # or Anchor's typed accounts, which enforce the owner at deserialization.
    "owner": [
        r"\.owner\s*(!=|==)",
        r"(!=|==)\s*&?\s*[\w.]+\.owner",
        r"require(_keys)?(_eq|_neq)?!\s*\([^)]*\.owner",
        r"\bAccount\s*<\s*'\w+\s*,",       # Account<'info, T> checks owner + discriminator
        r"\bProgram\s*<\s*'\w+\s*,",       # Program<'info, T> checks the program id
        r"#\[account\([^)]*\bowner\s*=",
    ],
    # The owner check written out by hand, WITHOUT counting Anchor's typed accounts. Some classes
    # need the check on a specific account that Anchor is not deserialising for you - anything
    # reached through `remaining_accounts`, or through `next_account_info` in a native program -
    # and there the presence of `Account<'info, T>` elsewhere in the file proves nothing.
    # https://neodyme.io/en/blog/solana_common_pitfalls/  (pitfall 1, missing ownership check)
    "explicit_owner_check": [
        r"\.owner\s*[!=]=",
        r"[!=]=\s*&?\s*[\w.]+\.owner\b",
        r"require(_keys)?(_eq|_neq)?!\s*\([^)]*\.owner",
        r"\bAccount::try_from\s*\(",
        r"\bInterfaceAccount::try_from\s*\(",
        r"\bassert_owned_by\s*\(",
        r"\bcheck_account_owner\s*\(",
    ],
    # Comparing a program account's key against a known program id before a CPI.
    "program_id": [
        r"(!=|==)\s*&?\s*\w+::ID\b",
        r"\b\w+::ID\s*(!=|==)",
        r"require_keys_eq!\s*\([^)]*(program|ID)",
        r"IncorrectProgramId",
        r"\bProgram\s*<\s*'\w+\s*,",
        # NOT declare_id!: every Anchor program declares its OWN id. It guards nothing about a
        # CPI target, and treating it as a guard silently suppressed a correct detection.
    ],
    # Rejecting the case where two supposedly distinct accounts are the same account.
    "distinct_accounts": [
        r"\.key\(\)\s*==\s*ctx\.accounts\.\w+\.key\(\)",
        r"\.key\s*==\s*\w+\.key\b",
        r"require(_keys)?_neq!",
        r"constraint\s*=\s*[^,)]*!=",
    ],
    # Properly closing an account: mark it closed and drain it, or use Anchor's `close =`.
    # Properly closing an account. Per the Solana Foundation program-security course, a secure close
    # is THREE things: move the lamports out, zero the data, and write a closed discriminator.
    # `**account.lamports.borrow_mut() = 0` on its own is the *vulnerable* construct, not a guard:
    # it is exactly what the insecure variant does before the revival attack. Treating it as a guard
    # meant SOL-018 suppressed itself on every file it was written to catch, which is why the README
    # recorded that rule as "added, does not fire". Same class of error as the `declare_id!` one.
    # https://github.com/solana-foundation/developer-content/blob/main/content/courses/program-security/closing-accounts.md
    "account_closed": [
        r"CLOSED_ACCOUNT_DISCRIMINATOR",
        r"#\[account\([^)]*\bclose\s*=",
        r"\bsol_memset\s*\(",
        r"\.fill\s*\(\s*0\s*\)",
        r"\brealloc\s*\(\s*0\s*,",
        r"\bclose_account\s*\(",
    ],
    # Validating that a passed sysvar is the real sysvar.
    "sysvar_address": [
        r"sysvar::\w+::ID",
        r"require_eq!\s*\([^)]*sysvar",
        r"\bSysvar\s*<",
        r"\bRent\s*>\s*",
    ],
    # Deriving a PDA with the canonical bump, or re-deriving before trusting one.
    # find_program_address searches down from 255 and returns the canonical bump;
    # create_program_address accepts whatever bump you hand it. Anchor's bare `bump` constraint
    # uses the canonical bump, and `bump = state.bump` re-uses one that was stored canonically.
    # https://github.com/solana-foundation/developer-content/blob/main/content/courses/program-security/bump-seed-canonicalization.md
    "canonical_bump": [
        r"\bfind_program_address\s*\(",
        r"[,(]\s*bump\s*[,)\]]",          # Anchor's bare `bump` constraint: canonical by definition
        r"\bbump\s*=\s*\w+\.bump\b",
        r"\bbump\s*=\s*ctx\.bumps",
    ],
    # Distinguishing one account type from another before trusting the bytes. Anchor's 8-byte
    # discriminator, or a hand-rolled enum/tag field that is compared before use.
    # https://github.com/solana-foundation/developer-content/blob/main/content/courses/program-security/type-cosplay.md
    "discriminator": [
        r"\bAccount\s*<\s*'\w+\s*,",
        r"\btry_deserialize\b",
        r"\bDISCRIMINATOR\b",
        r"\bdiscriminant\b",
        r"\bdiscriminator\b",
        r"\bAccountDiscriminant\b",
        r"\baccount_type\s*[!=]=",
        r"\bis_initialized\b",
    ],
    # Comparing a field stored inside one account against the key of another account. This is the
    # check that account-data-matching bugs are missing: Anchor `has_one`, a key comparison
    # constraint, or an explicit require_keys_eq!/assert_keys_eq!.
    # https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security
    "account_match": [
        r"\bhas_one\s*=",
        r"constraint\s*=[^,)]*\.key\(\)",
        r"require_keys_(eq|neq)!",
        r"assert_keys_(eq|neq)",
        r"\.key\(\)\s*[!=]=",
        r"\.key\s*[!=]=",
        r"require!\s*\([^)]*\.key",
    ],
    # Converting between integer widths without losing the high bits silently.
    # Neodyme: "Use checked math and checked casts whenever possible."
    # https://neodyme.io/en/blog/solana_common_pitfalls/
    "checked_cast": [
        r"\btry_from\s*\(",
        r"\btry_into\s*\(",
        r"\bTryFrom\b",
        r"\bTryInto\b",
    ],
    # Re-reading an Anchor account from the chain after a CPI mutated it.
    "reload": [
        r"\.reload\s*\(\s*\)",
    ],
    # Refusing to initialise an account that is already initialised.
    "initialized": [
        r"\bis_initialized\b",
        r"\bIsInitialized\b",
        r"AlreadyInitialized",
        r"AccountAlreadyInitialized",
        r"#\[account\([^)]*\binit\b",
        r"\bDISCRIMINATOR\b",
    ],
    # Checking which program owns an instruction you introspected out of the instructions sysvar.
    # Reading the neighbouring instruction is only meaningful if you also check whose it is.
    "introspected_program_id": [
        r"\.program_id\s*[!=]=",
        r"program_id\s*[!=]=\s*&?\s*\w+",
        r"require_keys_eq!\s*\([^)]*program_id",
        r"\bcheck_id\s*\(",
        r"\bcheck_program_account\s*\(",
    ],
}

_COMPILED = {k: [re.compile(p) for p in v] for k, v in GUARDS.items()}


def has_guard(text, kind):
    """True if `text` contains any idiom from guard family `kind`.

    Scope is the whole file. That is deliberately generous: a guard anywhere in the file suppresses
    the finding. It trades recall for precision, which is the correct direction here, because the
    failure mode we are fixing is firing on code that is already correct.
    """
    return any(rx.search(text) for rx in _COMPILED[kind])


def missing(text, kind):
    return not has_guard(text, kind)


def demo():
    """Self-check. Each case is written by hand, not taken from any corpus."""
    vulnerable = "let acct = next_account_info(iter)?; transfer(acct)?;"
    guarded = "if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }"
    assert missing(vulnerable, "signer")
    assert has_guard(guarded, "signer")

    assert missing("invoke(&ix, accounts)?;", "program_id")
    assert has_guard("if &spl_token::ID != ctx.accounts.token_program.key { return Err(e); }",
                     "program_id")

    assert missing("for a in ctx.remaining_accounts { total += a.lamports(); }",
                   "explicit_owner_check")
    assert has_guard("require_keys_eq!(*acct.owner, crate::ID);", "explicit_owner_check")
    # a typed Anchor account elsewhere in the file is NOT an owner check on a raw account
    assert missing("pub vault: Account<'info, Vault>,", "explicit_owner_check")

    assert missing("let t = &ctx.accounts.token;", "owner")
    assert has_guard("if ctx.accounts.token.owner != &spl_token::ID { return Err(e); }", "owner")
    assert has_guard("pub token: Account<'info, TokenAccount>,", "owner")

    assert missing("user_a.balance -= x; user_b.balance += x;", "distinct_accounts")
    assert has_guard("if ctx.accounts.user_a.key() == ctx.accounts.user_b.key() { return Err(e); }",
                     "distinct_accounts")

    assert missing("account.data = &[];", "account_closed")
    assert has_guard("use anchor_lang::__private::CLOSED_ACCOUNT_DISCRIMINATOR;", "account_closed")
    # draining the lamports is the vulnerable construct, not the guard
    assert missing("**acct.lamports.borrow_mut() = 0;", "account_closed")
    assert has_guard("sol_memset(&mut acct.data.borrow_mut(), 0, len);", "account_closed")

    assert missing("let rent = &ctx.accounts.rent;", "sysvar_address")
    assert has_guard("require_eq!(ctx.accounts.rent.key(), sysvar::rent::ID);", "sysvar_address")

    assert missing("let a = Pubkey::create_program_address(&[k, &[b]], id).unwrap();",
                   "canonical_bump")
    assert has_guard("let (pda, bump) = Pubkey::find_program_address(&[k], id);", "canonical_bump")
    assert has_guard("#[account(seeds = [payer.key().as_ref()], bump)]", "canonical_bump")
    assert has_guard("#[account(seeds = [payer.key().as_ref()], bump = state.bump)]",
                     "canonical_bump")

    assert missing("let c = AdminConfig::try_from_slice(&info.data.borrow())?;", "discriminator")
    assert has_guard("if data.discriminant != AccountDiscriminant::Admin { return Err(e); }",
                     "discriminator")

    assert missing("let v = pool.total; pool.total = v + 1;", "account_match")
    assert has_guard("#[account(mut, has_one = authority)]", "account_match")
    assert has_guard("require_keys_eq!(vault.authority, signer.key());", "account_match")

    assert missing("let small = big as u32;", "checked_cast")
    assert has_guard("let small = u32::try_from(big)?;", "checked_cast")

    assert missing("token::transfer(cpi_ctx, amt)?; let b = ctx.accounts.pool.balance;", "reload")
    assert has_guard("ctx.accounts.pool.reload()?;", "reload")

    assert missing("state.admin = admin.key(); state.total = 0;", "initialized")
    assert has_guard("if state.is_initialized { return Err(e.into()); }", "initialized")

    assert missing("let ix = load_instruction_at_checked(0, &sysvar_info)?;",
                   "introspected_program_id")
    assert has_guard("if ix.program_id != crate::ID { return Err(e.into()); }",
                     "introspected_program_id")

    print("guards: OK (%d families)" % len(GUARDS))


if __name__ == "__main__":
    demo()
