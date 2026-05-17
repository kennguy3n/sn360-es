# Benchmark Baseline (2026-05-17)

This is the first committed baseline of the SN360-ES benchmark suite. It
was produced on a clean `main` checkout by running:

```
make gen-corpus
make bench-all
```

All numbers below come from a single host:

| Field        | Value                                              |
| ------------ | -------------------------------------------------- |
| Host         | AMD EPYC 7763 64-Core (8 vCPU available to runner) |
| OS           | Linux x86_64                                       |
| Go           | 1.25.x                                             |
| Corpus seed  | `42`                                               |
| Corpus size  | `1000` labelled emails (16 categories, 6 tiers)    |
| Backend mode | Fake Tier 1 / Tier 2 / Rspamd (signal-driven)      |

The microbenchmarks were taken with `-benchtime=1s -count=3` against
`internal/service/evaluate/...`, `internal/service/tier0/...`,
`internal/service/action/...`, and `internal/service/education/...`.

## Microbenchmark headline numbers (median of 3)

| Benchmark                              | ns/op   | B/op   | allocs/op |
| -------------------------------------- | ------: | -----: | --------: |
| `Evaluator_SingleMessage`              |  17,000 |  4,666 |        47 |
| `Evaluator_BatchOf64` (per message)    |  17,300 |  4,738 |        47 |
| `Evaluator_Tier0Bypass`                |     900 |     96 |         5 |
| `Evaluator_FullEscalation`             |  17,200 |  4,666 |        47 |
| `Score_AllWeights`                     |       5 |      0 |         0 |
| `Score_ZeroWeights`                    |       2 |      0 |         0 |
| `Score_FromResult`                     |      13 |      0 |         0 |
| `RuleCategorizer_HighSignal`           |   1,560 |    288 |         4 |
| `RuleCategorizer_LowSignal`            |     520 |    160 |         3 |
| `RuleCategorizer_AllSignals`           |   1,460 |    288 |         4 |
| `RuleCategorizer_Categorise`           |   1,400 |    272 |         3 |
| `Gate_InternalBypass`                  |      20 |      0 |         0 |
| `Gate_VendorBypass`                    |      20 |      0 |         0 |
| `Gate_ExternalFullPath`                |     830 |     96 |         5 |
| `Gate_HighVolumeRspamdOnly`            |     780 |     96 |         5 |
| `BannerRenderer_HighRisk`              |  29,400 | 11,725 |       133 |
| `BannerRenderer_AllTiers`              |  28,250 | 11,413 |       126 |
| `BannerRenderer_RTL`                   |  25,500 | 10,997 |       109 |
| `TemplateLibrary_Render`               |   1,800 |  1,424 |        26 |
| `TemplateLibrary_Get`                  |      38 |      0 |         0 |
| `SimulationEngine_Dispatch` (8 targets)|  15,330 | 11,420 |       209 |

Raw output is in [`bench_20260517.txt`](./bench_20260517.txt).

## Resource profile (10 000 evaluations)

```
Total duration:   ~100 ms
Avg latency:      ~10 µs
p50 latency:      ~8 µs
p95 latency:      ~26 µs
p99 latency:      ~43 µs
max latency:      ~390 µs
Throughput:       ~96 000 emails/sec
Peak heap:        ~14 MB
Total allocs:     ~30 MB
GC pauses:        4 (max ≈ 0.24 ms)
Peak goroutines:  2
```

Raw output is in [`profile_20260517.txt`](./profile_20260517.txt) and
[`profile_20260517.json`](./profile_20260517.json).

### Latency distribution (5 000-sample bucketed histogram, Prometheus buckets)

| le      | count | %      |
| ------- | ----: | -----: |
| 1 ms    |  4999 | 99.98% |
| 5 ms    |     1 |  0.02% |
| ≥ 10 ms |     0 |  0.00% |

Raw output is in
[`latency_distribution_20260517.txt`](./latency_distribution_20260517.txt).

## Classification quality (1 000-email corpus, seed = 42)

| Metric                              | Value         | Target (PROPOSAL §6) |
| ----------------------------------- | ------------- | -------------------- |
| Overall precision (threat class)    | **1.0000**    | ≥ 0.85               |
| Overall recall (threat class)       | **0.9807**    | ≥ 0.85               |
| Overall F1                          | **0.9903**    | ≥ 0.85               |
| Overall accuracy                    | **0.9860**    | ≥ 0.85               |
| False-positive rate (benign→raised) | **0.0000**    | < 0.05               |
| False-negative rate (threat→trusted)| **0.0193**    | < 0.02               |

Per-category, per-tier, per-difficulty, and confusion-matrix breakdowns
are in [`accuracy_20260517.md`](./accuracy_20260517.md). Some categories
(LIKELY_PHISHING, BEC_IMPERSONATION, SCAM_FRAUD, AUTH_FAILED) currently
have 0 top-1 hits because the deterministic rule categoriser maps their
signal mix to neighbouring labels (e.g. CREDENTIAL_HARVESTING /
FIRST_CONTACT_EXTERNAL) — those gaps are the first thing to tighten in
the Tier 1 model rollout, and this baseline gives the categoriser
something to regress against.

## How to refresh

```
make bench-all
```

This overwrites the `*_$(date +%Y%m%d).txt|md|json|log` files for the
current UTC date — commit the new artefacts to track regressions. Use
`benchstat` to compare two `bench_*.txt` files.
