# sol-audit

A static security scanner for Solana / Anchor programs. Python 3, nothing to install.

**Read this before you trust a clean report from it.** Its recall is measured, its noise is
measured, and both numbers are below. On eight real production vulnerabilities it detects **none**.

```bash
git clone https://github.com/halobartku/sol-audit && cd sol-audit
python cli.py path/to/programs
```

---

## The conflict of interest, stated first

**The author of this scanner also owns [ScannerTruth](https://github.com/halobartku/scannertruth),
the benchmark that scores it.** That is a conflict and there is no way to make it not be one. This
project handles it by being explicit rather than by pretending:

1. **No rule here was written by reading a corpus case.** Every rule was written from a published
   description of the vulnerability CLASS, cited on the rule in `scanner.py`, then tested against a
   vulnerable and a fixed fixture invented for this repository, and only then measured. The record
   is [`RULES.md`](RULES.md): class, source, fixtures, and score, including every zero.
2. **Rules that score zero stay, and say zero.** SOL-021, SOL-023, SOL-024 and SOL-026 detect
   nothing on either corpus. They are in the rule table and in `RULES.md` with their zeroes.
3. **The mapping from rule to corpus class is committed before the run that uses it.** It lives in
   [`mapping.py`](mapping.py); `git log` shows it landing before each measurement.
4. **Every corpus-1 number here is in-sample** and says so. `sealevel-attacks` has been public since
   2022 and this scanner was developed against it. The number that is not in-sample is corpus 2,
   and on corpus 2 this scanner scores zero.
5. **The noise number was measured and published by us**, before anybody had to find it.

None of that makes an in-sample score trustworthy. The only real answer is somebody else measuring
this, which has not happened.

---

## What it scores

### Corpus 1: `coral-xyz/sealevel-attacks`, eleven teaching programs. **In-sample.**

**Real recall** counts a class only if the mapped rule fires on the buggy program **and stays
silent on the same program after its authors fixed it**. Nominal recall counts firing on the bug
regardless. A rule that fires on both has detected nothing.

| | v1 | v2 | **v3** |
|---|---|---|---|
| Nominal recall | 2 / 11 | 6 / 11 | **9 / 11** |
| **Real recall** | **0 / 11** | **4 / 11** | **7 / 11** |

Per class, at the default profile:

| Class | v2 | v3 | |
|---|---|---|---|
| 0-signer-authorization | real | **real** | SOL-001 |
| 1-account-data-matching | nominal | nominal | SOL-002 fires on the fix too |
| 2-owner-checks | real | **real** | SOL-002 |
| 3-type-cosplay | miss | **real** | **new**, SOL-022 |
| 4-initialization | miss | nominal | SOL-028 fires on the fix too |
| 5-arbitrary-cpi | real | **real** | SOL-010, SOL-006 |
| 6-duplicate-mutable-accounts | miss | miss | rule exists, scores zero |
| 7-bump-seed-canonicalization | miss | **real** | **new**, SOL-020 |
| 8-pda-sharing | nominal | miss | not statically decidable, see below |
| 9-closing-accounts | miss | **real** | **fixed**, SOL-018 |
| 10-sysvar-address-checking | real | **real** | SOL-019 |

Three of the four gains came from new rules for classes v2 missed. The fourth,
`9-closing-accounts`, came from **deleting a wrong pattern**: `guards.py` was treating
`**account.lamports.borrow_mut() = 0` as evidence that an account had been safely closed, when that
is the vulnerable construct itself. The rule had been suppressing itself on exactly the code it was
written to catch.

### Corpus 2: ScannerTruth, real production vulnerabilities. **Not in-sample.**

Eighteen cases, each pinned to the fix commit its own maintainers wrote. Sixteen scored; one is
excluded as an invalid pair by the corpus itself and one is not built.

| profile | nominal | **real** |
|---|---|---|
| strict (default) | 2 / 16 | **0 / 16** |
| broad | 3 / 16 | **0 / 16** |
| all | 4 / 16 | **0 / 16** |

**Zero.** Every case was analysed - `bench2-strict.json.log` has one row per case per variant
proving it, so these are measured zeroes and not silent failures to run. Two cases produce a
nominal hit that fires on the fixed variant as well, which is the exact failure this project exists
to expose, and it is ours:

- `squads-signer-auth`: SOL-007 fires on both halves.
- `metaplex-candy-machine`: SOL-027 fires on the fix **more** than on the bug.

Corpus 2 is drawn from public postmortems, which are famous because nobody caught them in time, so
it is systematically harder than the population of real bugs and understates every scanner measured
on it. It still answers the question a team actually has, which is whether a tool catches the ones
that cost money. This one does not.

---

## What it gets wrong

A scanner that flags everything is worthless. This project published a `control-noisy` that proves
it: 931 findings, zero real recall. So here is our own number.

### On code that is correct by construction

The `secure` and `recommended` halves of every corpus case are the same programs with the bug
removed by their own authors. A finding **of the same class** there is a false positive with
nothing to adjudicate.

| profile | fixed variants | .rs files | findings | same-class false positives | variants flagged |
|---|---|---|---|---|---|
| strict (default) | 38 | 39 | 48 | **6** | 4 of 38 |
| broad | 38 | 39 | 125 | **19** | 5 of 38 |
| all | 38 | 39 | 348 | **42** | 8 of 38 |

### On third-party code that is in no benchmark

676 `.rs` files, 75,427 lines, from `solana-developers/program-examples` and
`solana-labs/solana-program-library`.

| profile | findings | per file | per 1000 lines |
|---|---|---|---|
| strict (default) | 239 | 0.35 | 3.2 |
| broad | 721 | 1.07 | 9.6 |
| all | 1350 | 2.00 | 17.9 |

A density is not an error rate. To get an error rate somebody has to read the findings, so somebody
did: a deterministic, unrerollable sample of 40, each one read with its surrounding code.

**21 actionable, 15 not actionable, 4 undecided. A false positive rate of 42%, or 48% if every
undecided case is counted against us.**

Item by item, with the reasoning for each, in [`TRIAGE.md`](TRIAGE.md), so you can disagree line by
line rather than having to accept a summary. Before the precision work described in `RULES.md` the
same procedure gave **9 actionable and 27 not**, so about three findings in four were noise; fixing
seven defects found that way cut the findings from 668 to 239 and cost no detections at all.

Reproduce it:

```bash
python noise.py --clean ../program-examples --clean ../solana-program-library --sample 40
```

### The things it is still wrong about

- **SOL-006 and SOL-010 duplicate each other.** The same CPI is often reported twice under two rule
  ids. That is a reporting defect and it inflates the count.
- **It scans everything ending in `.rs`.** Fuzz harnesses, build scripts and `asm` crates get
  scanned as if they were on-chain programs. Excluding those directories would improve the noise
  number, so it was deliberately **not** done: shrinking your own denominator is the behaviour this
  project criticises in other people.
- **A guard in another file does not count.** One cross-file pre-pass exists and it only collects
  which `#[account]` structs carry an authority field. Everything else is per-file, and several of
  the judged-false findings are exactly that.

---

## What it does not catch, and why not

The honest version of a rule table is the list of things a static pattern rule cannot decide.
Full reasoning in [`RULES.md`](RULES.md); the short list:

- **PDA sharing.** The fix does not add a check, it changes a seed from shared to per-authority.
  The difference is semantic. No rule was written, and the class is a miss.
- **Rounding direction.** Whether rounding up is a bug depends on which side of the trade benefits.
  `try_round_u64` is a legitimate API and a rule flagging it would flag every correct use.
- **CPI recursion.** Needs a call graph. Nothing here has one.
- **Mint configuration.** Whether a mint's decimals are the right ones is protocol intent.
- **Anything a macro generates.** Nothing here parses Rust. These are regular expressions over
  comment-stripped text, and that is the ceiling on the approach.

---

## Using it

```
python cli.py PATH                        scan a directory or a single .rs file
python cli.py --list-rules                every rule with its category, kind and severity
python cli.py --help                      the flags, explained
```

Exit codes are the usual contract: **0** ran and found nothing at or above `--fail-on`, **1** ran
and found something, **2** could not run. A selection that leaves no rules enabled is refused with
exit 2 rather than reported as a clean repository.

| flag | |
|---|---|
| `--profile strict\|broad\|all` | which kinds of rule to run. Default `strict` |
| `--category`, `--exclude-category` | authorization, accounts, cpi, arithmetic, pda, hygiene |
| `--rule`, `--exclude-rule` | by id, e.g. `SOL-004,SOL-009` |
| `--min-severity`, `--fail-on` | filter output, and decide what makes the exit code 1 |
| `--format text\|json\|sarif` | SARIF drops straight into GitHub code scanning |
| `--out`, `--log` | write the report to a file; write one JSON row per file analysed |
| `--quiet`, `--color` | |

`--log` exists because a findings file cannot prove coverage: a file that was analysed and came
back clean leaves exactly the same silence as one that was never opened. ScannerTruth listed the
absence of that log for this scanner as an open gap while other tools had one. It is closed.

**The three profiles, and why `strict` is the default.** Rules come in three kinds. `guarded` rules
test that a construct is present AND the check that would make it safe is absent; they are the only
ones that can tell a bug from its fix. `shape` rules fire on a construct alone, because for some
classes the construct is the defect. `heuristic` rules are often wrong. On corpus 1 all three
profiles reach the same real recall, 7 of 11, while `strict` produces a third of the findings. The
extra rules buy no detections and cost the reader a thousand lines, so they are off by default.
That is a measured choice and `noise.py` reproduces it.

Add `// audit-ok` on or above a line to suppress a finding there.

---

## Tests

```
python run_tests.py       341 checks
python guards.py          the guard patterns, self-checked
```

Every rule has a vulnerable fixture it must fire on and a fixed fixture it must stay silent on,
both hand-written for this repository, in `tests/fixtures/`. The suite also checks the two fixtures
differ and are not trivial, so a rule cannot pass by having empty fixtures.

**Standard library only, and this project does honour that** - `scanner.py`, `guards.py`, `cli.py`,
`run_tests.py`, `noise.py` and both benchmark harnesses import nothing outside the Python 3 standard
library, and there is no `requirements.txt`, no `setup.py` and no build step. A test framework
dependency would have been the first thing to break it, so the runner is a plain script.

**The fixtures have never been compiled.** There is no cargo on the machine this was written on, so
they are Rust-shaped text that the scanner reads. A fixture that would not build would still pass
these tests. Stated here rather than left to be discovered.

---

## Re-running the measurements

```bash
CORPUS=../sealevel-attacks/programs        PROFILE=strict python run_bench.py
python realrecall.py bench-out.json

CORPUS2=../scannertruth/corpus2            PROFILE=strict python run_bench2.py

python noise.py --corpus1 ../sealevel-attacks/programs \
                --corpus2 ../scannertruth/corpus2 \
                --clean ../program-examples --sample 40
```

The JSON each of those writes is committed, so every number on this page recomputes from raw data
in this repository rather than being typed.

---

## Layout

```
scanner.py     the rules and the engine
guards.py      the guard families: what a correct program does, which is what a rule looks for
mapping.py     rule to corpus class, pre-registered, one copy
cli.py         the command line
run_tests.py   341 checks, standard library only
noise.py       measures what the scanner gets wrong
run_bench.py   score against corpus 1        run_bench2.py  score against corpus 2
realrecall.py  real versus nominal recall from a run
RULES.md       every rule: class, source, fixtures, score. The record that matters
TRIAGE.md      the forty findings that produced the false-positive number, judged one by one
tests/fixtures 60 hand-written .rs files, never compiled
```

---

## Independence

This scanner stays **free and open source, permanently**. It exists as the first subject of the
ScannerTruth benchmark, not as a product. You cannot sell a scanner and credibly rank scanners. See
[COMMITMENTS.md](https://github.com/halobartku/scannertruth/blob/main/docs/COMMITMENTS.md).

MIT. Part of [Forge](https://github.com/halobartku).
