# sol-audit v2

A static security scanner for Solana / Anchor programs. **Version 1 of this tool scored 0 out of 11
real recall on the Anchor team's own corpus. We published that. This is the repair.**

| | v1 | v2 |
|---|---|---|
| Nominal recall | 2 / 11 | 6 / 11 |
| **Real recall** | **0 / 11** | **4 / 11** |

Measured by [ScannerTruth](https://github.com/halobartku/scannertruth) against
[`coral-xyz/sealevel-attacks`](https://github.com/coral-xyz/sealevel-attacks). Real recall counts
only classes where the scanner fires on the buggy program **and stays silent on the same program
fixed**. Nominal recall counts firing on the bug regardless. The gap between the two columns is the
whole story.

## What was actually wrong, and it was structural

Every v1 rule tested for the **presence of a construct**: an `invoke(`, a raw `AccountInfo`, a PDA
seed. No rule tested for the **absence of a check**.

But a vulnerable program and its fix contain the same constructs. The fix adds a guard. So a rule
that cannot see the guard cannot distinguish them, and fires on both. That is why v1 produced 194
findings on a real repository while detecting nothing: it was matching code shapes.

**This is predictable by reading the rules, without running anything.** If no rule looks for a
missing guard, real recall is zero before you start.

Every v2 rule has the shape:

```
construct is present  AND  the corresponding guard is absent
```

Guards live in [`guards.py`](guards.py): signer enforcement, owner validation, program-id
comparison before CPI, distinctness checks between accounts, proper account closing, sysvar address
validation. They are general Anchor and `solana_program` idioms.

**No pattern in this repository is derived from any specific file in any corpus.** That constraint
is what makes this an engineering fix rather than fitting to a test set. `python guards.py` runs a
self-check on hand-written cases, none of them taken from the corpus.

## Per class

| Class | v1 | v2 | |
|---|---|---|---|
| 0-signer-authorization | miss | **real** | fixed |
| 1-account-data-matching | miss | nominal | **regression, see below** |
| 2-owner-checks | miss | **real** | fixed |
| 3-type-cosplay | miss | miss | |
| 4-initialization | miss | miss | |
| 5-arbitrary-cpi | nominal | **real** | fixed |
| 6-duplicate-mutable-accounts | miss | miss | rule added, does not fire |
| 7-bump-seed-canonicalization | miss | miss | |
| 8-pda-sharing | nominal | nominal | probably not statically decidable, see below |
| 9-closing-accounts | miss | miss | rule added, does not fire |
| 10-sysvar-address-checking | miss | **real** | fixed |

## What we made worse, and what we still cannot do

**We introduced one regression.** `1-account-data-matching` was a clean miss in v1 and now fires on
both the buggy and the fixed variant. We traded a silent miss for a false positive. It is in the
table rather than left out.

**`8-pda-sharing` is probably not detectable this way at all.** The fix does not add a check. It
changes the PDA seed from a value shared between users to one that is specific to the account
authority. The difference is semantic, not syntactic, and a text scanner has no way to know whether
a seed is unique per authority. We would rather say so than write a rule that appears to catch it.

**Three classes have rules that never fire** (`6-duplicate-mutable-accounts`, `9-closing-accounts`,
and the miss cases above). The rules exist and are wrong or too narrow. They are counted as misses,
because a scanner that does not detect a bug does not detect it.

**Five of eleven classes remain undetected.** 4/11 is not a good scanner. It is a scanner that is
no longer lying about what it does.

## Honest limits on the number itself

The improvement was developed against the same corpus it is measured on, so **4/11 is an in-sample
result**. The defence is the constraint above, that no rule keys on corpus-specific text, and that
the change is one architectural principle applied uniformly rather than eleven special cases. That
is an argument, not a proof. The real test is a corpus we have not seen, which does not exist yet
and is the next piece of work.

One bug found in our own guard logic during development is worth recording, because it is the same
class of error as the original defect: we briefly treated `declare_id!` as a program-id guard. Every
Anchor program declares its own id, so this silently suppressed a correct detection on
`5-arbitrary-cpi` and cost a class. Presence of a symbol is not evidence of a check.

## Run it

```
python guards.py                  # self-check the guard patterns
python run_bench.py               # score against the corpus (see ScannerTruth PROTOCOL.md)
python realrecall.py v2.json      # real vs nominal recall from a run
```

MIT. Part of [Forge](https://github.com/halobartku).
