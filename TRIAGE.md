# The triage behind the false-positive number

A finding count is not a false-positive rate. Turning one into the other means reading the
findings, and nobody but a person can do that, so this file is the reading.

## Method

1. Run the scanner at its default profile over third-party Solana code that is in **no**
   benchmark: `solana-developers/program-examples` and `solana-labs/solana-program-library`,
   676 `.rs` files, 75,427 lines.
2. Take a sample of 40 of the 239 findings, ordered by a SHA-256 of the finding itself. It is
   deterministic, so the same corpus always gives the same forty, and it cannot be rerolled
   until the answer improves. `python noise.py --clean <dir> --sample 40` reproduces it.
3. Read the code around each one and decide:
   - **actionable** - the check the rule names really is absent and adding it would help.
   - **not-actionable** - the guard exists somewhere the scanner cannot see, the construct is
     provably safe, or the requirement is enforced by the runtime or by the callee.
   - **undecided** - could not be settled without more analysis than a reader would do.

## Result

| | count | of 40 |
|---|---|---|
| actionable | 21 | 52% |
| not actionable | 15 | 38% |
| undecided | 4 | 10% |

**False positive rate: 42% of the findings that could be decided, 48% if every undecided
one is counted against the scanner.** The second number is the one to quote, because counting
your own undecided cases in your own favour is how a vendor gets to a good number.

Before the precision work described in RULES.md the same procedure gave 9 actionable, 27 not
actionable and 4 undecided, so roughly three in four findings were noise. It is now roughly
two in five.

## By rule

| rule | actionable | not actionable | undecided |
|---|---|---|---|
| SOL-002 | 0 | 0 | 1 |
| SOL-006 | 11 | 2 | 0 |
| SOL-007 | 1 | 5 | 0 |
| SOL-010 | 8 | 1 | 0 |
| SOL-017 | 0 | 0 | 1 |
| SOL-020 | 0 | 0 | 1 |
| SOL-022 | 1 | 4 | 0 |
| SOL-029 | 0 | 3 | 1 |

The two CPI rules, SOL-006 and SOL-010, are most of the sample and most of the actionable half.
They also duplicate each other: items 08 and 14 are the same line reported twice under two rule
ids, as are 17 and 34. That is a reporting defect, not a detection.

## The forty

| # | rule | location | verdict | why |
|---|---|---|---|---|
| 01 | SOL-020 | `binary-oracle-pair/program/src/processor.rs:34` | undecided | A generic `authority_id(program_id, my_info, bump_seed)` helper. The bump is supplied by callers that store a canonical one in another file, which this rule cannot see. |
| 02 | SOL-029 | `compression/cnft-burn/anchor/programs/cnft-burn/src/lib.rs:70` | not-actionable | The remaining accounts are Merkle proof nodes forwarded to mpl-bubblegum, which validates them itself. |
| 03 | SOL-006 | `tokens/escrow/native/program/src/instructions/refund_offer.rs:90` | actionable | `close_account(token_program.key, ..)` takes the CPI target from an account that is never compared with the SPL token program id. |
| 04 | SOL-010 | `binary-option/program/src/spl_utils.rs:167` | actionable | `mint_to(token_program.key, ..)` then invoke_signed; the token program is never checked. |
| 05 | SOL-007 | `basics/realloc/native/program/src/instructions/reallocate.rs:14` | actionable | Rewrites `target_account`'s data with no signer check and no owner check on the account being resized. |
| 06 | SOL-010 | `binary-option/program/src/spl_utils.rs:51` | actionable | `initialize_mint(token_program.key, ..)`; the token program is never checked. |
| 07 | SOL-029 | `tokens/token-2022/transfer-hook/block-list/pinocchio/program/src/instructions/tx_hook.rs:109` | undecided | A transfer hook reading `remaining_accounts[1]` as a wallet-block account. Whether the extra-account-meta resolution already constrains it was not established. |
| 08 | SOL-006 | `tokens/token-2022/non-transferable/native/program/src/lib.rs:64` | actionable | `token_instruction::initialize_mint(token_program.key, ..)`; the token program is never checked. |
| 09 | SOL-010 | `binary-oracle-pair/program/src/processor.rs:74` | actionable | `spl_token::instruction::transfer(token_program_id.key, ..)`; the token program is never checked. |
| 10 | SOL-006 | `tokens/token-2022/transfer-fee/native/program/src/lib.rs:67` | actionable | `initialize_transfer_fee_config(token_program.key, ..)`; the token program is never checked. |
| 11 | SOL-006 | `tokens/escrow/native/program/src/instructions/take_offer.rs:188` | actionable | `close_account(token_program.key, ..)`; the token program is never checked. |
| 12 | SOL-007 | `basics/cross-program-invocation/native/programs/lever/src/lib.rs:40` | not-actionable | `initialize` creates the account through the system program, which enforces the payer's signature. There is no unauthorised state write to guard. |
| 13 | SOL-006 | `managed-token/program/src/token.rs:34` | actionable | `thaw_account(token_program.key, ..)`; the token program is never checked. |
| 14 | SOL-010 | `tokens/token-2022/non-transferable/native/program/src/lib.rs:64` | actionable | Same site as 08 under the other CPI rule; the finding is duplicated, which is itself a reporting defect. |
| 15 | SOL-022 | `examples/rust/transfer-tokens/src/processor.rs:49` | not-actionable | `Mint::unpack` on an SPL account. The fixed byte length of Mint already discriminates it from a token Account, so there is no type to confuse. |
| 16 | SOL-022 | `binary-option/program/src/processor.rs:220` | actionable | `BinaryOption::try_from_slice` on a custom struct with no tag field and no discriminator anywhere. Exactly the type-cosplay shape. |
| 17 | SOL-006 | `tokens/transfer-tokens/native/program/src/instructions/mint_spl.rs:53` | actionable | `token_instruction::mint_to(token_program.key, ..)`; the token program is never checked. |
| 18 | SOL-017 | `tokens/external-delegate-token-master/anchor/programs/external-delegate-token-master/src/lib.rs:99` | undecided | Reported on a `has_one = authority` line. Two mutable accounts of one type exist somewhere in the crate, but the location given does not let a reader find the pair. |
| 19 | SOL-010 | `binary-oracle-pair/program/src/processor.rs:145` | actionable | `spl_token::instruction::burn(token_program_id.key, ..)`; the token program is never checked. |
| 20 | SOL-022 | `tokens/escrow/native/program/src/instructions/take_offer.rs:128` | not-actionable | `TokenAccount::unpack`, length-discriminated as in 15. |
| 21 | SOL-022 | `tokens/escrow/native/program/src/instructions/refund_offer.rs:73` | not-actionable | `TokenAccount::unpack` immediately after an `assert_is_associated_token_account` on the same account. |
| 22 | SOL-006 | `binary-option/program/src/spl_utils.rs:137` | actionable | burn instruction built from `token_program.key`; the token program is never checked. |
| 23 | SOL-010 | `managed-token/program/src/token.rs:184` | actionable | `spl_token::instruction::revoke(token_program.key, ..)`; the token program is never checked. |
| 24 | SOL-006 | `tokens/create-token/native/program/src/lib.rs:78` | not-actionable | `mpl_util::create_metadata_account_v3(metadata_account.key, ..)`. The first argument is an account, so the builder hardcodes the Metaplex program id; the scanner cannot see inside a local helper. |
| 25 | SOL-006 | `tokens/token-2022/default-account-state/native/program/src/lib.rs:73` | actionable | `token_instruction::initialize_mint(token_program.key, ..)`; the token program is never checked. |
| 26 | SOL-006 | `tokens/pda-mint-authority/native/program/src/instructions/mint.rs:59` | actionable | `token_instruction::mint_to(token_program.key, ..)`; the token program is never checked. |
| 27 | SOL-010 | `token-lending/program/src/processor.rs:1896` | actionable | `spl_token::instruction::initialize_mint(token_program.key, ..)` in token-lending; no comparison against the token program id in this file. |
| 28 | SOL-007 | `governance/program/src/processor/process_update_program_metadata.rs:30` | not-actionable | `process_update_program_metadata` is permissionless by design and the payer's signature is enforced by the system CPI that creates the account. |
| 29 | SOL-007 | `basics/realloc/native/program/src/instructions/create.rs:16` | not-actionable | Creates the account it writes; the payer signs through the system program. |
| 30 | SOL-006 | `tokens/escrow/native/program/src/instructions/refund_offer.rs:75` | actionable | `token_instruction::transfer(token_program.key, ..)`; the token program is never checked. |
| 31 | SOL-007 | `tokens/pda-mint-authority/native/program/src/instructions/init.rs:19` | not-actionable | Creates a PDA; the payer signs through the system program. |
| 32 | SOL-029 | `compression/cnft-vault/anchor/programs/cnft-vault/src/lib.rs:102` | not-actionable | Merkle proof nodes forwarded to spl-account-compression, as in 02. |
| 33 | SOL-029 | `compression/cutils/anchor/programs/cutils/src/actions/verify.rs:56` | not-actionable | Merkle proof nodes forwarded to spl-account-compression, as in 02. |
| 34 | SOL-010 | `tokens/transfer-tokens/native/program/src/instructions/mint_spl.rs:53` | actionable | Same site as 17 under the other CPI rule; duplicated finding. |
| 35 | SOL-010 | `tokens/transfer-tokens/native/program/src/instructions/mint_nft.rs:70` | not-actionable | `crate::mpl_util::create_master_edition_v3(edition_account.key, ..)`, a local helper that hardcodes the program id, as in 24. |
| 36 | SOL-006 | `binary-option/program/src/spl_utils.rs:226` | actionable | SPL token transfer instruction built from an unchecked token program account. |
| 37 | SOL-022 | `tokens/escrow/native/program/src/instructions/take_offer.rs:173` | not-actionable | `TokenAccount::unpack`, length-discriminated as in 15. |
| 38 | SOL-002 | `tokens/token-2022/transfer-hook/allow-block-list-token/anchor/programs/abl-token/src/instructions/tx_hook.rs:29` | undecided | A token-2022 transfer hook whose accounts are all `UncheckedAccount`. Whether the meta-list resolution constrains them was not established. |
| 39 | SOL-007 | `governance/program/src/processor/process_update_program_metadata.rs:29` | not-actionable | Same file as 28. |
| 40 | SOL-006 | `tokens/pda-mint-authority/native/program/src/instructions/create.rs:76` | not-actionable | `crate::mpl_util::create_metadata_account_v3`, as in 24. |

## What to distrust about this

**The author of the scanner judged the scanner's own findings.** That is the same conflict the
README states about the benchmark, and the mitigation is the same: every judgement is above with
a file and a line, so a reader can disagree item by item rather than having to accept a summary.

**The corpora were chosen by the same person.** `program-examples` is deliberately simple
teaching code and `solana-program-library` is deliberately careful production code. Neither is a
random sample of what a team would point this at, and both are more likely to be correct than an
average codebase, which biases the false-positive rate **upward**: findings on code that is
mostly right are mostly wrong. A less careful codebase would score better here and that would
mean nothing.

**Forty is a small sample.** At 40 items the 95% interval on a 42% rate is roughly plus or
minus 16 points. The honest reading is "a large minority of findings are noise", not a decimal.

**Some judgements are arguable.** The largest actionable group is CPIs into the SPL token
program where the token program account is never compared against `spl_token::ID`. That is a
real missing check, and in an example program of twenty lines it is also not how anybody gets
robbed. A reader who counts those as noise gets a much worse number, and they would not be
wrong to.
