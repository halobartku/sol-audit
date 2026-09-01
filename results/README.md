# The committed measurements

Every number on the front page is recomputed from a file in this directory by
`test_published_numbers_are_derived` in `run_tests.py`, or is a row in a table that a file here
backs. Nothing in this directory is edited by hand; each file is the output of one harness run.

**What is recorded and what is inferred.** No harness in this repository writes its own command
line into its output, and no commit message records the exact invocation. So for every file below
the producing command is inferred, not recorded. The evidence for each inference is quoted: the
shape of the file matched against the `json.dump` in the harness, the values the file carries
(`profile`, `corpus`, `clean[].root`, `rules_run`), and the commit that added it. Three files are
read by `run_tests.py` by exact name and one log is named in `README.md`; the other ten are named
by no code and no document, which is the same situation with one less witness.

Each harness takes the output path from the environment or a flag, and the committed names are
not the defaults (`run_bench.py` and `run_bench2.py` default to `bench-out.json` and
`bench2-out.json`; `noise.py` writes nothing unless `--out` is given), so the name of each file is
itself evidence that `OUT=` or `--out` was passed.

## Corpus 1: `coral-xyz/sealevel-attacks`, eleven teaching programs, in-sample

Producer: `run_bench.py`. A JSON list with one row per corpus class, each row
`{"class", "insecure", "secure", "recommended"}` and each variant `{"total", "on_target", "rules"}`.
That is exactly the `rec` that `run_bench.py` builds per class and dumps with
`json.dump(rows, open(os.environ.get("OUT", "bench-out.json"), ...))`. The profile is chosen with
`PROFILE=`, which `run_bench.py` reads into `scanner.select_rules(PROFILE)`.

| file | inferred command | inferred from |
|---|---|---|
| `v3-strict.json` | `CORPUS=../sealevel-attacks/programs PROFILE=strict OUT=v3-strict.json python run_bench.py` | read by `run_tests.py` for the corpus-1 recall line in `README.md` (7 / 11 real, 9 / 11 nominal); the rule ids it carries (`SOL-001, 002, 006, 010, 018, 019, 020, 022, 028`) are all in the strict profile; last regenerated in commit `5b7892f` |
| `v3-broad.json` | `CORPUS=../sealevel-attacks/programs PROFILE=broad OUT=v3-broad.json python run_bench.py` | carries `SOL-009` and `SOL-012` in addition to the strict set, which are broad-profile rules; committed as `v3-default.json` in `8623244` and renamed when `broad` replaced `default` as the profile name in `5b7892f` |
| `v3-all.json` | `CORPUS=../sealevel-attacks/programs PROFILE=all OUT=v3-all.json python run_bench.py` | carries `SOL-016` as well, which only the `all` profile runs; nominal 10 / 11 against 9 / 11 for the other two, real 7 / 11 for all three, which is the "all three profiles reach the same real recall" statement in the message of commit `5b7892f` (the corpus-1 table in `README.md` reports only the default profile); added in `8623244`, regenerated in `5b7892f` |
| `v2.json` | `CORPUS=../sealevel-attacks/programs OUT=v2.json python run_bench.py` at commit `1a2ffb1` | same shape; committed with the v2 rules on 2026-08-31, before profiles existed (`run_bench.py` at `1a2ffb1` has no `PROFILE`), so every rule then in the scanner ran; recomputes to 6 / 11 nominal and 4 / 11 real, which is the "v2" column of the corpus-1 table in `README.md` |

`run_bench.py` also prints a verdict and the recall percentages to stdout; those are not kept.
`realrecall.py <file>` recomputes nominal and real recall from any of the four.

## Corpus 2: ScannerTruth, eighteen real cases, not in-sample

Producer: `run_bench2.py`. A JSON object `{"profile", "corpus", "rows", "nominal", "real",
"scored"}`, which is the literal dict `run_bench2.py` dumps, and beside it `<OUT>.log` with one
JSON line per case per variant, written by the same run (`open(OUT + ".log", "w")`). The three
files each carry `"profile"` set to their own name and `"corpus"` set to
`D:/Users/stank/Desktop/Forge/scannertruth/corpus2`, so the corpus path is recorded, the profile is
recorded, and only the `OUT=` name is inferred from the basename.

| file | inferred command | inferred from |
|---|---|---|
| `bench2-strict.json` | `CORPUS2=../scannertruth/corpus2 PROFILE=strict OUT=bench2-strict.json python run_bench2.py` | `"profile": "strict"` inside the file; read by `run_tests.py` for the corpus-2 line in `README.md` (0 / 16 real) |
| `bench2-strict.json.log` | written by the run above | 34 rows: 32 `ok`, one `excluded`, one `not-built`, matching the 16 scored plus 2 unscored rows of the JSON; named in `README.md` as the proof that every case was analysed |
| `bench2-broad.json` | `CORPUS2=../scannertruth/corpus2 PROFILE=broad OUT=bench2-broad.json python run_bench2.py` | `"profile": "broad"` inside the file; nominal 3 / 16, the broad row of the corpus-2 table |
| `bench2-broad.json.log` | written by the run above | 34 rows, same statuses as the strict log; committed as `bench2-default.json.log` in `8623244`, renamed in `5b7892f` |
| `bench2-all.json` | `CORPUS2=../scannertruth/corpus2 PROFILE=all OUT=bench2-all.json python run_bench2.py` | `"profile": "all"` inside the file; nominal 4 / 16, the all row of the corpus-2 table |
| `bench2-all.json.log` | written by the run above | 34 rows, same statuses as the other two logs |

The `"corpus"` value is an absolute Windows path on the author's machine. It is left as written
because the file is a record of the run, not a template for the next one.

## Noise: fixed variants of both corpora, plus third-party code in no benchmark

Producer: `noise.py`. A JSON object with `"profile"` and `"rules_run"` always, `"fixed_variants"`
and `"fixed_summary"` only when `--corpus1` or `--corpus2` was given, `"clean"` (one summary per
`--clean` root) and `"sample"` only when `--sample N` is non-zero and there were clean findings.
Written by `--out`. Every file below records its two clean roots inside `"clean"[].root`: a
checkout of `solana-developers/program-examples` and one of `solana-labs/solana-program-library`
(`spl`), both under a scratch directory on the author's machine. All four sum to the same
676 `.rs` files and 75,427 lines, which is the clean-corpus line in `README.md`.

| file | inferred command | inferred from |
|---|---|---|
| `noise-strict.json` | `python noise.py --profile strict --corpus1 ../sealevel-attacks/programs --corpus2 ../scannertruth/corpus2 --clean <program-examples> --clean <spl> --sample 0 --out noise-strict.json` | `"profile": "strict"`, `"rules_run": 16`; `fixed_variants` has 38 rows from both corpora, so both corpus flags were passed; no `"sample"` key although `clean` has 239 findings, and `noise.py` only omits it when `--sample` is 0; read by `run_tests.py` for the clean-corpus counts and the strict rows of both noise tables in `README.md` |
| `noise-broad.json` | same with `--profile broad --out noise-broad.json` | `"profile": "broad"`, `"rules_run": 23`, 38 fixed variants, 721 clean findings, no `"sample"` key; the broad rows of both noise tables |
| `noise-all.json` | same with `--profile all --out noise-all.json` | `"profile": "all"`, `"rules_run": 30`, 38 fixed variants, 1350 clean findings, no `"sample"` key; the all rows of both noise tables |
| `noise-strict-sample.json` | `python noise.py --profile strict --clean <program-examples> --clean <spl> --sample 40 --out noise-strict-sample.json` | `"profile": "strict"`, no `fixed_variants` key (so neither corpus flag was passed), `"sample"` has 40 entries; those forty are the findings `TRIAGE.md` judges one by one, and `README.md` and `RULES.md` document the command as `python noise.py --clean <dir> --sample 40` |

The fixed-variant totals (38 variants, 39 files; 48, 125 and 348 findings; 6, 19 and 42
same-class false positives) are the `fixed_summary` objects of the three profile files, and the
strict one is asserted against `README.md` by `run_tests.py`.

## History

All fourteen files were last regenerated in commit `5b7892f` (2026-09-01, the precision pass)
except `v2.json`, which dates from `1a2ffb1` (2026-08-31) and is kept as the v2 baseline. Before
`5b7892f` the middle profile was called `default`; the two files that git detected as renames
(`v3-default.json` to `v3-broad.json`, `bench2-default.json.log` to `bench2-broad.json.log`) are
noted above, and `bench2-default.json` and `noise-default.json` were replaced rather than renamed.
The files moved from the repository root into this directory on 2026-09-01 with their basenames
unchanged.
