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
    "account_closed": [
        r"CLOSED_ACCOUNT_DISCRIMINATOR",
        r"#\[account\([^)]*\bclose\s*=",
        r"lamports\.borrow_mut\(\)\s*=\s*0",
    ],
    # Validating that a passed sysvar is the real sysvar.
    "sysvar_address": [
        r"sysvar::\w+::ID",
        r"require_eq!\s*\([^)]*sysvar",
        r"\bSysvar\s*<",
        r"\bRent\s*>\s*",
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

    assert missing("let t = &ctx.accounts.token;", "owner")
    assert has_guard("if ctx.accounts.token.owner != &spl_token::ID { return Err(e); }", "owner")
    assert has_guard("pub token: Account<'info, TokenAccount>,", "owner")

    assert missing("user_a.balance -= x; user_b.balance += x;", "distinct_accounts")
    assert has_guard("if ctx.accounts.user_a.key() == ctx.accounts.user_b.key() { return Err(e); }",
                     "distinct_accounts")

    assert missing("account.data = &[];", "account_closed")
    assert has_guard("use anchor_lang::__private::CLOSED_ACCOUNT_DISCRIMINATOR;", "account_closed")

    assert missing("let rent = &ctx.accounts.rent;", "sysvar_address")
    assert has_guard("require_eq!(ctx.accounts.rent.key(), sysvar::rent::ID);", "sysvar_address")

    print("guards: OK")


if __name__ == "__main__":
    demo()
