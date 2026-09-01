# Every rule: what class, what source, what fixtures, what it scored

This file exists because the author of this scanner also owns the benchmark that scores it. The
defence against that is not a promise, it is this table: for every rule, the public description of
the vulnerability class it was written from, the hand-written fixtures it was tested against before
any corpus was touched, and the score it got afterwards, including the zeroes.

**The constraint.** No rule in this repository was written by reading a corpus case and matching its
text. Each was written from a published description of the CLASS, cited on the rule in `rules_v3.py`
and repeated below, then tested against a vulnerable and a fixed fixture invented for this
repository, and only then measured. A rule that scored zero is still here and still says zero.

**Sources used.** These are the documents the rules were written from.

| Short name | Document |
|---|---|
| sealevel | [`coral-xyz/sealevel-attacks`](https://github.com/coral-xyz/sealevel-attacks), the class taxonomy itself |
| neodyme | [Neodyme, "Solana: Common Pitfalls"](https://neodyme.io/en/blog/solana_common_pitfalls/) |
| course | [Solana Foundation program-security course](https://github.com/solana-foundation/developer-content/tree/main/content/courses/program-security) |
| helius | [Helius, "A Hitchhiker's Guide to Solana Program Security"](https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security) |
| anchor | The Anchor account-constraint reference |

`sealevel` is also corpus 1. Its per-class prose is the public taxonomy and was read; its `.rs`
fixture files were not read while any rule was being written. That distinction is the whole
argument, and a reader who does not accept it should discount every corpus-1 number below, which
is in-sample regardless.

## How the fixtures work

`tests/fixtures/SOL-0NN_vulnerable.rs` must produce at least one finding from rule SOL-0NN.
`tests/fixtures/SOL-0NN_fixed.rs` must produce none. `python run_tests.py` enforces both for every
rule, plus that the two files differ and are not trivial. 341 checks, standard library only.

**The fixtures have never been compiled.** There is no cargo on the machine this was written on.
They are Rust-shaped text that the scanner reads. A fixture that would not build would still pass
these tests, so "the fixture passes" means "the scanner behaves as intended on this text", not
"this is valid Rust". That is a real weakness and it is stated here rather than left to be found.

## Kinds

- **guarded** - the construct is present AND the check that would make it safe is absent. These are
  the only rules that can tell a bug from its fix. `--profile strict`, the default, runs these.
- **shape** - the construct itself is the defect, so there is no check to look for. Correct but
  blind to context. `--profile broad` adds these.
- **heuristic** - often wrong, sometimes right. `--profile all` adds these.

---

## Rules added in v3

Eleven new rules. Measured against corpus 1 (`sealevel-attacks`, in-sample) and corpus 2
(ScannerTruth, 18 real cases, not in-sample), plus 676 files of third-party code in no benchmark.

### SOL-020 - PDA derived with create_program_address and a non-canonical bump
- **Class** bump seed canonicalization
- **Source** course, `bump-seed-canonicalization.md`; helius section 6. `create_program_address`
  accepts whatever bump byte it is handed, so several valid PDAs exist per seed set and an attacker
  picks one the program has not seen. `find_program_address` searches down from 255 and returns the
  canonical one.
- **Shape** `create_program_address(` present AND no `find_program_address`, no Anchor bare `bump`
  constraint, no `bump = state.bump` anywhere in the file.
- **Fixtures** vulnerable: a native `claim` that derives a reward PDA from a `seed_bump: u8`
  parameter. fixed: the same function using `find_program_address` and dropping the parameter.
- **Corpus 1** fires on `7-bump-seed-canonicalization/insecure`, silent on both fixed variants.
  **A real detection, and a class v2 missed entirely.**
- **Corpus 2** 0. Nothing in corpus 2 uses `create_program_address`.
- **Clean code** 11 findings across 676 files. One was sampled and triaged: a generic
  `authority_id(program_id, my_info, bump_seed)` helper in `binary-oracle-pair` whose caller stores
  a canonical bump in another file. Judged undecided, leaning false.

### SOL-021 - Anchor bump constraint takes its bump from an instruction argument
- **Class** bump seed canonicalization, Anchor flavour
- **Source** course as above, plus the Anchor reference for `#[instruction(..)]`. `bump = state.bump`
  re-uses a bump that was stored canonically and is correct. `bump = caller_supplied` is not.
- **Shape** the `#[instruction(..)]` attribute names the caller-supplied identifiers; if a
  `bump = X` names one of them, the caller chooses the bump.
- **Fixtures** vulnerable: `#[instruction(claim_bump: u8)]` with `bump = claim_bump`. fixed: the
  same struct with `#[instruction(amount: u64)]` and `bump = claim.bump`.
- **Corpus 1** 0. Corpus 1's bump class is written in native style, not with Anchor constraints.
- **Corpus 2** 0.
- **Clean code** 0 across 676 files.
- **Kept because** it is the correct rule for the Anchor half of a class the corpus only covers in
  its native half, and it is precise: it fires on nothing else in 676 files of real code.

### SOL-022 - Account data deserialised by hand with no discriminator distinguishing types
- **Class** type cosplay / account confusion
- **Source** neodyme pitfall 5; course `type-cosplay.md`. Two account structs with the same layout
  deserialise from each other's bytes. The check is a discriminator: Anchor's 8 bytes, or a
  hand-written tag field compared before use.
- **Shape** a manual `try_from_slice` / `T::unpack` **of account data** AND no discriminator idiom
  anywhere in the file.
- **Fixtures** vulnerable: a native `set_fee` deserialising `AdminConfig` straight from
  `config_info.data.borrow()`. fixed: the same with an `AccountTag` first field compared before use.
- **Corpus 1** fires on `3-type-cosplay/insecure`, silent on the fixed variant. **A real detection,
  and a class v2 missed entirely.** It also fires on `1-account-data-matching` and `2-owner-checks`,
  where it is not the mapped rule.
- **Corpus 2** 0 on `anchor-interface-account`, which is the one type-cosplay case: it is a bug in
  Anchor's own `InterfaceAccount` implementation, not in a program, and there is no missing
  discriminator to see.
- **Clean code** 25 findings. Five sampled: four not actionable, all four SPL `Pack::unpack` calls
  where the fixed byte length of the struct already discriminates the type; one actionable, a
  custom `BinaryOption::try_from_slice` with no tag at all.

### SOL-023 - State account with an authority field used beside a Signer, never compared
- **Class** account data matching
- **Source** sealevel class 1; helius section 1. The account records who may act on it; the
  instruction never checks that the signer is that party. Anchor spells the check `has_one`.
- **Shape** needs three things at once, which is why it is the only rule using the cross-file
  pre-pass: an `#[account]` struct somewhere in the crate carrying an authority-like `Pubkey`, an
  `Account<'info, ThatStruct>` beside a `Signer` in this file, and no key comparison anywhere.
- **Fixtures** vulnerable: a `Vault { authority, balance }` withdrawn by any `caller: Signer`.
  fixed: `has_one = authority` and the signer renamed to `authority`.
- **Corpus 1** **0.** The mapped class, `1-account-data-matching`, remains nominal-only, and the
  rule that was written for it does not fire on it. Reported as zero.
- **Corpus 2** 0 on all three `account-data-matching` cases.
- **Clean code** 6 findings across 676 files.
- **Not investigated further, deliberately.** Finding out why it misses would mean opening the
  corpus case and reading it, which is where fitting begins. The rule matches the published
  description of the class and its own fixtures; the corpus says zero; both facts are printed.

### SOL-024 - Division performed before multiplication, truncating twice
- **Class** loss of precision
- **Source** helius section 11; Neodyme's lending disclosure. `(a / c) * b` truncates twice,
  `(a * b) / c` once. On token amounts the difference is value that leaks.
- **Kind** shape. There is no guard to look for: the order of operations is the defect.
- **Fixtures** vulnerable: `(total_deposits / total_shares) * user_shares`. fixed: the same in
  `checked_mul` then `checked_div` order.
- **Corpus 1** 0. **Corpus 2** 0, including on both `arithmetic-rounding-drain` cases.
- **Clean code** 0 across 676 files.
- **Honest note** this rule scores zero everywhere. It is kept because the class is real and the
  rule is right about it; it is also, on this evidence, rare enough in the code available here that
  it detects nothing. See "what a static rule cannot do" below for the rounding-direction bug it
  does *not* catch, which is the one the corpus actually contains.

### SOL-025 - Token amount narrowed with an `as` cast
- **Class** unchecked cast
- **Source** neodyme pitfall 3, "use checked math and checked casts whenever possible"; helius 14.
- **Kind** shape, and deliberately narrowed: it only fires on lines that also mention an
  amount-like identifier, because `as usize` on a length is ubiquitous and harmless and flagging it
  would drown everything else.
- **Fixtures** vulnerable: `total_amount as u32`. fixed: `u32::try_from(total_amount)`.
- **Corpus 1** 0. **Corpus 2** 0. **Clean code** 27 findings under `--profile broad`.
- **The amount-word restriction is a heuristic** and is the reason this rule is `shape` rather than
  `guarded`. A cast of a variable called `n` that happens to hold a token amount is missed.

### SOL-026 - Account state read after a CPI without reload()
- **Class** account reloading
- **Source** helius section 3; Anchor's `reload()` documentation. Anchor deserialised the account at
  entry; a CPI that mutates it on chain does not update the in-memory copy.
- **Kind** heuristic, and labelled so, because it cannot tell whether the CPI touched *that*
  account. It over-reports by construction.
- **Fixtures** vulnerable: a deposit that transfers then reads `pool.total_liquidity`. fixed: the
  same with `ctx.accounts.pool.reload()?` in between.
- **Corpus 1** 0. **Corpus 2** 0, including on `anchor-account-reload-owner`, which is the case
  this class was mapped to. **Clean code** not in the default profile.

### SOL-027 - Introspected instruction never checked against an expected program id
- **Class** instruction introspection
- **Source** sealevel class 10 and the `solana_program::sysvar::instructions` API contract. Reading
  the adjacent instruction means nothing unless you also check whose program it belongs to.
- **Shape** `load_instruction_at_checked` / `get_instruction_relative` present AND no comparison of
  a `program_id` anywhere in the file.
- **Fixtures** vulnerable: a guarded mint that loads the previous instruction and inspects its data.
  fixed: the same with `require_keys_eq!(previous.program_id, crate::ID, ..)`.
- **Corpus 1** 0.
- **Corpus 2** fires on `metaplex-candy-machine/insecure`, **and on the fixed variant too**. A
  nominal detection and a false positive on the same case. That is the exact failure mode this
  whole project was built to expose, and it is ours. Reported, not hidden.
- **Clean code** 0 across 676 files.

### SOL-028 - Initialise handler with no initialised flag or discriminator
- **Class** re-initialization
- **Source** sealevel class 4; helius section 10. Nothing about writing an account is one-shot.
- **Shape** a function named `init*` or `process_init*` that writes account bytes, with no
  `is_initialized`, no Anchor `init` constraint and no discriminator in the file, and which does
  not itself create the account (creating it is the guard: the system program refuses to create an
  account that already holds lamports or data).
- **Fixtures** vulnerable: a native `process_initialize` that serialises a `Config` over whatever
  account it is handed. fixed: the same with an `is_initialized` field checked first.
- **Corpus 1** fires on `4-initialization/insecure` **and on the fixed variant**. Nominal only, and
  a false positive by construction. The fixed variant evidently uses an idiom the guard family does
  not recognise; identifying which one means reading the case, so it is reported as an FP instead.
- **Corpus 2** 0. **Clean code** 2 findings across 676 files, after the fix for instruction
  builders described below; before that fix it was 45.

### SOL-029 - remaining_accounts used without an explicit owner check
- **Class** unvalidated remaining accounts
- **Source** helius section 16. Anchor validates the declared accounts and nothing else.
- **Shape** `remaining_accounts` present AND no owner check written out by hand. It uses the
  `explicit_owner_check` guard family rather than `owner`, because a typed `Account<'info, T>`
  elsewhere in the file proves nothing about a raw account pulled out of `remaining_accounts`.
- **Fixtures** vulnerable: a distribute loop writing into every remaining account. fixed: the same
  loop with `require_keys_eq!(*account.owner, crate::ID, ..)` first.
- **Corpus 1** 0. **Corpus 2** 0.
- **Clean code** 17 findings. Four sampled, all four judged not actionable: every one was a
  compressed-NFT program forwarding Merkle proof nodes to `spl-account-compression`, which
  validates them itself. This rule is the clearest case in the set of a correct rule whose
  precision depends on knowledge it does not have.

### SOL-030 - Native program unpacks account data without checking the account owner
- **Class** missing ownership check, native flavour
- **Source** neodyme pitfall 1, the one they list first: "your contract should only trust accounts
  owned by itself". `next_account_info` hands you an `AccountInfo` with no ownership guarantee.
- **Shape** the file uses `next_account_info` AND deserialises account data AND contains no
  explicit owner comparison.
- **Fixtures** vulnerable: a native `require_balance` unpacking an SPL token account straight from
  `token_info.data.borrow()`. fixed: the same with `token_info.owner != &spl_token::ID` first.
- **Corpus 1** 0 on `2-owner-checks`, which is detected by SOL-002 instead.
- **Corpus 2** 0 on `solend-owner-checks`, which is the real owner-check case and the one that
  matters. Reported as zero.
- **Clean code** 7 findings across 676 files.

---

## Corrections to rules that already existed

Two, and both are the same class of error as the `declare_id!` mistake the v2 README already
records: a construct mistaken for a check.

**`guards.py` treated `**account.lamports.borrow_mut() = 0` as evidence that an account had been
properly closed.** That is the vulnerable construct itself. Per the Solana Foundation course a safe
close is three things and the other two are zeroing the data and writing a closed discriminator.
SOL-018 was therefore suppressing itself on exactly the code it was written to catch, which is why
the v2 README recorded it as "rule added, does not fire". With the guard corrected, **SOL-018 now
detects `9-closing-accounts` on corpus 1 and stays silent on the fixed variant.** A real detection
recovered by deleting one wrong pattern.

**The `if __name__ == "__main__"` block sat in the middle of `scanner.py`,** above the section that
replaces `RULES` with the guard-aware ones. Python runs a module top to bottom, so
`python scanner.py <dir>`, which is what the README told people to run, executed the v1 rules and
none of the v2 ones. The library import path was correct, so no published benchmark number is
affected; only the command a human would actually type was wrong. Nobody had run it.

---

## Where the noise came from, and what was done about it

The method: run the scanner over 676 files of third-party Solana code that is in no benchmark,
take a deterministic sample of 40 findings that cannot be rerolled, and read every one.
`python noise.py --clean <dir> --sample 40` reproduces it.

**First pass: 9 of 40 actionable, 27 not, 4 undecided.** Seven causes, all found on third-party
code and none on a corpus case:

| # | Defect | Findings in sample |
|---|---|---|
| 1 | `_ctx` truncates its context window at 220 characters, so an `invoke(` on its own line never saw the line naming the program | 5 |
| 2 | SOL-006 and SOL-010 fired on CPIs whose target is a compile-time constant, `invoke(&system_instruction::create_account(..))` | 9 |
| 3 | `Something { .. }.invoke()` is a typed builder, not a raw CPI, and matched the same pattern | 6 |
| 4 | SOL-007 reported the `use ..::{next_account_info}` import line | 2 |
| 5 | SOL-007 fired on handlers that only forward CPIs, where the runtime enforces the signature | 5 |
| 6 | SOL-022 and SOL-030 fired on `Type::try_from_slice(instruction_data)`; instruction data has no owner and no discriminator | 2 |
| 7 | SOL-028 fired on client-side instruction builders, `pub fn init_reserve(..) -> Instruction` | 4 |

Two guard families were also incomplete: `spl_token::id()` is the older SPL spelling of the same
constant and is still the dominant form, 38 comparisons against a `::id()` in
solana-program-library today; and SOL-018 was firing on any lamport arithmetic rather than on a
close, so a two-line lamport-transfer example was reported as an unclosed account.

**Result: 668 findings on the clean corpora became 239, a 64% reduction, with real recall
unchanged** at 7/11 on corpus 1 and 0/16 on corpus 2. Fixing precision cost no detections.

**Second pass on a fresh sample of 40: 21 actionable, 15 not, 4 undecided.** The full item-by-item
judgement is in [`TRIAGE.md`](TRIAGE.md) so a reader can disagree with any single line of it.

---

## What a static pattern rule cannot do, and why

This section is more useful than five more rules.

**PDA sharing (`8-pda-sharing`) is not statically decidable and no rule was written for it.** The
fix does not add a check. It changes the PDA seed from a value shared between users to one specific
to the account authority. The difference is semantic. A text scanner has no way to know whether a
seed is unique per authority, and any rule that appeared to catch it would be matching something
else. Corpus 1's `8-pda-sharing` is a miss under the default profile and stays one.

**Rounding direction is not statically decidable.** Corpus 2 contains two
`arithmetic-rounding-drain` cases, both of which are fixed by rounding the other way. Whether
rounding up is a bug depends entirely on which side of the trade benefits, which is protocol
intent, not syntax. `try_round_u64` is a legitimate API. A rule that flagged it would flag every
correct use of it. SOL-024 catches the neighbouring defect, dividing before multiplying, and is
mapped to the class so it appears in the denominator, but it is not the same bug and it scores zero
on both cases.

**CPI recursion is not decidable without a call graph.** Corpus 2's `squads-recursive-execute` is a
program that can be made to invoke itself. Nothing in this scanner reasons about call graphs, and a
keyword rule for "recursion" would be a mapping rather than a detector. Mapped `no-rule`.

**Mint configuration validation is a question about protocol intent.** Whether a mint's decimals or
freeze authority are the right ones for this protocol is not a missing check visible in the text.
Mapped `no-rule`.

**Duplicate mutable accounts (`6-duplicate-mutable-accounts`) has a rule, SOL-017, which fires on
its own fixture and scores zero on the corpus class it was written for.** The rule requires two
`#[account(mut)]` fields of the same type in one `Accounts` struct with no distinctness check. It
finds 12 such structs in 676 files of third-party code, so it is not inert. Why it misses the
corpus case has not been investigated, because investigating would mean reading the case, and a
rule adjusted until it fires on a case you have read is not a detector.

**Cross-file reasoning is shallow.** One pre-pass collects which `#[account]` structs carry an
authority-like `Pubkey`, and that is all. Every other rule sees one file. A guard in `state.rs` does
not suppress a finding in `instructions.rs`. Several of the judged-false findings are exactly this.

**Nothing here parses Rust.** These are regular expressions over comment-stripped text. Macros,
generics, trait implementations and anything built by a proc macro are invisible. That is the
ceiling on the whole approach and no amount of rule-writing raises it.
