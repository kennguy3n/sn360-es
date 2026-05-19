# sn360-es Benchmarks

This directory holds the committed baseline output of the SN360-ES
benchmark suite. The suite is split into three parts that can be run
independently or together:

| Target              | What it measures                                          | Build tag      |
| ------------------- | --------------------------------------------------------- | -------------- |
| `make bench`        | Go `testing.B` microbenchmarks (ns/op, B/op, allocs/op)   | none           |
| `make bench-accuracy` | Classification accuracy / precision / recall / F1 / confusion matrix | `benchmark` |
| `make bench-profile`  | Resource footprint (latency p50/p95/p99, GC pauses, peak memory, throughput) | `benchmark` |
| `make bench-all`      | All of the above, against the regenerated corpus      | -              |
| `make gen-corpus`     | Regenerate `internal/testdata/corpus/corpus_<size>.json` | none          |

All Make targets accept the following knobs:

| Variable             | Default                                            |
| -------------------- | -------------------------------------------------- |
| `BENCH_DIR`          | `benchmarks`                                       |
| `BENCH_COUNT`        | `3`                                                |
| `BENCH_TIME`         | `1s`                                               |
| `CORPUS_SIZE`        | `1000`                                             |
| `CORPUS_BENCH_SEED`  | `42`                                               |
| `CORPUS_FILE`        | `internal/testdata/corpus/corpus_$(CORPUS_SIZE).json` |

## Layout

```
benchmarks/
├── README.md                      # this file
├── BASELINE.md                    # narrative baseline summary
├── bench_<YYYYMMDD>.txt           # Go microbenchmark output
├── accuracy_<YYYYMMDD>.md         # Accuracy report (Markdown tables)
├── accuracy_<YYYYMMDD>.log        # Full test log for the accuracy harness
├── profile_<YYYYMMDD>.txt         # Resource profile (memory / GC / latency)
├── profile_<YYYYMMDD>.json        # Same data as JSON for dashboards
└── latency_distribution_<YYYYMMDD>.txt   # Prometheus-bucket histogram
```

Filenames are datestamped (UTC) so multiple runs can coexist; CI commits
the latest run on every merge to `main`.

## Comparing across runs

Use [`benchstat`](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat) to
diff Go microbenchmark output:

```
go install golang.org/x/perf/cmd/benchstat@latest
benchstat benchmarks/bench_20260517.txt benchmarks/bench_20260601.txt
```

For accuracy / profile artefacts, the Markdown reports are diff-friendly —
prefer `git diff benchmarks/accuracy_*.md` over scraping the JSON blob.

## Acceptance criteria

Acceptance targets for the SN360-ES detection pipeline:

| Metric                                 | Target              |
| -------------------------------------- | ------------------- |
| Tier 0 gate latency (fake)             | < 1 ms              |
| Tier 0 bypass rate                     | 60 – 70% of corpus  |
| End-to-end p95 latency (fake backends) | < 10 ms             |
| End-to-end p95 latency (real Tier 1)   | < 200 ms            |
| End-to-end p95 latency (Tier 2 LLM)    | < 5 s               |
| False-positive rate (benign → raised)  | < 5%                |
| False-negative rate (threat → trusted) | < 2%                |
| Categoriser top-1 accuracy             | ≥ 85% overall       |
| Memory footprint at 10k evals          | < 200 MB peak       |

The microbenchmarks in this directory exercise the in-process pipeline
with deterministic fake Tier 1 / Tier 2 / Rspamd backends. Real-model
runs are tracked separately under `scripts/corpus/evaluation/` (see
`make generate-corpus`, `make validate-corpus-models`) because they
require the encoder and LLM containers.

## Corpus generator

`internal/testdata/corpus` is a pure-Go labelled-email generator. It
covers all 16 categories, all 6 tiers, and every relationship category
(`Partner`, `Customer`, `FirstTimeExternal`, `LapsedContact`,
`RecurringService`, `Unknown`) with locale-weighted multilingual
content (en / vi / th / ja / ko / zh).

```
go run ./cmd/gen-corpus -size=1000 -seed=42 -out=corpus.json
go run ./cmd/gen-corpus -size=2000 -seed=7  -out=corpus.csv -format=csv
```

The default Make target writes `internal/testdata/corpus/corpus_1000.json`
which is committed alongside the benchmark output so external tools
(perf-harness, evaluation runs) can consume the exact same fixture set
as the in-tree harness.

## Adding new benchmarks

* **Microbenchmarks** (Go `testing.B`): add a `*_bench_test.go` file in
  the relevant package, name the function `BenchmarkXxx`, use the
  corpus generator for realistic input shapes. No build tag.
* **Accuracy or profile tests**: add a `*_test.go` file under
  `internal/service/evaluate/`, tag with `//go:build benchmark`, and
  invoke via `go test -tags=benchmark`. Make sure the test writes its
  artefact to `$ACCURACY_REPORT_DIR` or `$BENCH_PROFILE_DIR` so it gets
  picked up by `make bench-all`.
