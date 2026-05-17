# corpus_generator

Standalone Go CLI that produces the SN360-ES evaluation corpus —
synthetic test emails covering all 16 detection categories at three
difficulty levels and six locales.

The tool reads no inputs; everything is template-driven and seeded by
`--seed` so the output is byte-identical across runs. JSON files are
written to `--output-dir` (default `./scripts/corpus/evaluation/`), one
per category plus an aggregated `all.json`.

## Models referenced

This tool only knows about two model deployments and will not be made
generic. All references below match the schema at
[`scripts/corpus_schema.json`](../corpus_schema.json) and the
service URLs at:

- **Tier 1** — XLM-RoBERTa encoder served by
  [`deployments/encoder/`](../../deployments/encoder/) on port 8080.
  The generator calls `/predict` to validate ground-truth labels.
- **Tier 2** — Ternary-Bonsai-8B-Q2_0 GGUF served by
  [`deployments/llm/`](../../deployments/llm/) on port 9000 via the
  kennguy3n/llama.cpp fork at <https://github.com/kennguy3n/llama.cpp>.
  The generator calls `/v1/chat/completions` for LLM-assisted body
  variation and Tier 2 agreement checks.

No other LLM provider, runtime, or upstream llama.cpp build is
supported. Do not patch the references — the corpus must remain
reproducible against this exact pipeline.

## Usage

Run from the repo root:

```bash
make generate-corpus
```

Or invoke the binary directly:

```bash
go run ./scripts/corpus_generator/ \
    --output-dir ./scripts/corpus/evaluation/ \
    --seed 42
```

### Useful flags

- `--categories all|LIKELY_PHISHING,BEC_IMPERSONATION,...` — restrict
  output to a subset.
- `--count-per-category 470` — total per-category email count
  (default 470 = ~7,500 total).
- `--difficulty-split 33/34/33` — easy/medium/hard percentage split.
- `--locales en,th,ja,ko,zh,vi` and `--locale-split 80/4/4/4/4/4` —
  natural-language mix.
- `--llm-assist --llm-url http://127.0.0.1:9000` — use
  Ternary-Bonsai-8B (via kennguy3n/llama.cpp) for ACCOUNT_TAKEOVER,
  VENDOR_COMPROMISE, BEC categories where deterministic templates
  struggle to capture nuance.
- `--validate-only` — skip generation and run the validator over an
  existing corpus directory.
- `--validate-models --tier1-url http://127.0.0.1:8080 --llm-url http://127.0.0.1:9000`
  — after generation, push every email through the real Tier 1 and
  Tier 2 services and emit an agreement report.

## Files

| File | Responsibility |
|------|---------------|
| `main.go` | CLI flag parsing and run-orchestration. |
| `types.go` | `TestEmail` / `GenerateOptions` structs that mirror `corpus_schema.json`. |
| `generator.go` | Per-category orchestration: threat/benign split, difficulty/locale distribution, scoring, ID assignment, file writes. |
| `noise.go` | Deterministic per-email variation: greetings, sign-offs, whitespace, typo injection. |
| `multilingual.go` | Locale-specific phrase pools used by the noise injector. |
| `validator.go` | Schema completeness, category/tier/score consistency, distribution, dedup, unique IDs. |
| `llm_assist.go` | OpenAI-compatible client for the Ternary-Bonsai-8B server (kennguy3n/llama.cpp). |
| `model_validate.go` | Pushes every email through the real Tier 1 + Tier 2 services and reports per-category agreement. |
| `templates/*.go` | One file per category implementing `Generator`. |

## Reproducibility

All randomness flows through `rand.New(rand.NewSource(seed))`. Two
runs with the same `--seed` and the same `templates/` package produce
byte-identical JSON output. Changing any of the following invalidates
that guarantee:

- Adding/removing/reordering generators in `templates.DefaultRegistry`.
- Adding/removing phrase entries in `templates/helpers.go` pools.
- Changing the locale order in `templates.Pool.t`.

If you need to evolve a template, bump `--seed` for the next corpus
release so downstream consumers can reason about diffs explicitly.
