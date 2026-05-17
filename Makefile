# SN360-ES Makefile

GO              ?= go
GOTEST_FLAGS    ?= -race -timeout 120s
BIN_DIR         ?= bin
APP_NAME        ?= sn360-es
MIGRATE_BIN     ?= $(BIN_DIR)/sn360-es-migrate
MIGRATIONS_DIR  ?= migrations
DOCKER_COMPOSE  ?= docker compose
VERSION         ?=

.PHONY: all
all: lint test build

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(BIN_DIR)/$(APP_NAME) ./cmd/$(APP_NAME)

.PHONY: run
run:
	$(GO) run ./cmd/$(APP_NAME)

.PHONY: test
test:
	$(GO) test $(GOTEST_FLAGS) ./...

.PHONY: test-integration
test-integration:
	$(GO) test $(GOTEST_FLAGS) -tags=integration ./...

.PHONY: cover
cover:
	$(GO) test $(GOTEST_FLAGS) -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

.PHONY: lint
lint: openapi-check
	$(GO) vet ./...
	@out=$$(gofmt -l . 2>&1); if [ -n "$$out" ]; then echo "$$out"; exit 1; fi

# --- OpenAPI spec sync ---------------------------------------------------
#
# The canonical OpenAPI document lives under api/openapi.yaml so it shows
# up where API consumers expect it. internal/handler/openapi.yaml is an
# exact mirror used by go:embed — go:embed does not follow symlinks, so
# we keep a real file and enforce parity via `make openapi-check` (run
# from `make lint`). `make openapi-sync` regenerates the embedded copy
# whenever the canonical spec changes.

.PHONY: openapi-sync
openapi-sync:
	cp api/openapi.yaml internal/handler/openapi.yaml

.PHONY: openapi-check
openapi-check:
	@diff -q api/openapi.yaml internal/handler/openapi.yaml > /dev/null \
		|| { echo "api/openapi.yaml and internal/handler/openapi.yaml are out of sync — run 'make openapi-sync'"; exit 1; }

.PHONY: fmt
fmt:
	gofmt -w .

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: docker-up
docker-up:
	$(DOCKER_COMPOSE) up -d

.PHONY: docker-down
docker-down:
	$(DOCKER_COMPOSE) down

# --- Migrations -----------------------------------------------------------
#
# All migration targets shell out to the in-tree `sn360-es-migrate` command,
# which embeds the golang-migrate v4 library and the Postgres driver. No
# external `migrate` binary is required.

.PHONY: migrate-bin
migrate-bin:
	@mkdir -p $(BIN_DIR)
	$(GO) build -o $(MIGRATE_BIN) ./cmd/sn360-es-migrate

.PHONY: migrate-up
migrate-up: migrate-bin
	$(MIGRATE_BIN) --path $(MIGRATIONS_DIR) up

.PHONY: migrate-down
migrate-down: migrate-bin
	$(MIGRATE_BIN) --path $(MIGRATIONS_DIR) down 1

.PHONY: migrate-status
migrate-status: migrate-bin
	$(MIGRATE_BIN) --path $(MIGRATIONS_DIR) status

.PHONY: migrate-check
migrate-check: migrate-bin
	$(MIGRATE_BIN) --path $(MIGRATIONS_DIR) check

.PHONY: migrate-force
migrate-force: migrate-bin
	@if [ -z "$(VERSION)" ]; then echo "VERSION=<n> required"; exit 1; fi
	$(MIGRATE_BIN) --path $(MIGRATIONS_DIR) force $(VERSION)

# --- Corpus generation ---------------------------------------------------
#
# Synthetic test corpus for the SN360-ES evaluation harness. The
# generator imports internal/constant so the category / tier vocabulary
# stays in lock-step with runtime code. Real-model validation requires
# both the Tier 1 XLM-RoBERTa encoder (deployments/encoder/) and the
# Tier 2 Ternary-Bonsai-8B server (deployments/llm/, built from
# https://github.com/kennguy3n/llama.cpp) running locally.

CORPUS_OUTPUT_DIR ?= ./scripts/corpus/evaluation/
CORPUS_TIER1_URL  ?= http://127.0.0.1:8080
CORPUS_LLM_URL    ?= http://127.0.0.1:9000
CORPUS_SEED       ?= 42

.PHONY: generate-corpus
generate-corpus:
	$(GO) run ./scripts/corpus_generator/ \
		--output-dir $(CORPUS_OUTPUT_DIR) \
		--seed $(CORPUS_SEED)

.PHONY: generate-corpus-llm
generate-corpus-llm:
	$(GO) run ./scripts/corpus_generator/ \
		--output-dir $(CORPUS_OUTPUT_DIR) \
		--seed $(CORPUS_SEED) \
		--llm-assist --llm-url $(CORPUS_LLM_URL)

.PHONY: validate-corpus
validate-corpus:
	$(GO) run ./scripts/corpus_generator/ \
		--validate-only \
		--output-dir $(CORPUS_OUTPUT_DIR)

.PHONY: validate-corpus-models
validate-corpus-models:
	$(GO) run ./scripts/corpus_generator/ \
		--validate-models \
		--output-dir $(CORPUS_OUTPUT_DIR) \
		--tier1-url $(CORPUS_TIER1_URL) \
		--llm-url $(CORPUS_LLM_URL)

# --- Tier 2 LLM container -----------------------------------------------
#
# Builds the kennguy3n/llama.cpp server image used as the Tier 2 LLM
# inference runtime. The Ternary-Bonsai-8B-Q2_0 GGUF is fetched at
# deploy time by deployments/llm/download-model.sh (not at build time)
# so the image stays small.

.PHONY: docker-build-llm
docker-build-llm:
	docker build -f deployments/llm/Dockerfile -t ghcr.io/kennguy3n/sn360-es-llm:latest .

.PHONY: docker-run-llm
docker-run-llm:
	docker run --rm -p 9000:9000 -v $$(pwd)/models:/models ghcr.io/kennguy3n/sn360-es-llm:latest

# --- Benchmarks & Performance Profiling ---------------------------------
#
# The benchmark suite drives the corpus generator (internal/testdata/corpus),
# Go testing.B microbenchmarks, an accuracy harness that reports
# precision/recall/F1/confusion-matrix, and a resource profiler that
# records latency percentiles, GC pauses, and peak memory.
#
# Run `make bench-all` for the full suite. Results land under benchmarks/
# with a UTC datestamp and are committed for regression tracking; use
# `benchstat` to diff successive runs.

BENCH_DIR         ?= benchmarks
BENCH_DATE        := $(shell date -u +%Y%m%d)
BENCH_COUNT       ?= 3
BENCH_TIME        ?= 1s
CORPUS_SIZE       ?= 1000
CORPUS_BENCH_SEED ?= 42
CORPUS_FILE       ?= internal/testdata/corpus/corpus_$(CORPUS_SIZE).json

.PHONY: gen-corpus
gen-corpus:
	$(GO) run ./cmd/gen-corpus \
		-size=$(CORPUS_SIZE) \
		-seed=$(CORPUS_BENCH_SEED) \
		-out=$(CORPUS_FILE)

.PHONY: bench
bench: $(BENCH_DIR)
	$(GO) test -bench=. -benchmem -benchtime=$(BENCH_TIME) -count=$(BENCH_COUNT) -run=^$$ \
		./internal/service/evaluate/... \
		./internal/service/tier0/... \
		./internal/service/action/... \
		./internal/service/education/... \
		| tee $(BENCH_DIR)/bench_$(BENCH_DATE).txt

.PHONY: bench-accuracy
bench-accuracy: $(BENCH_DIR)
	ACCURACY_REPORT_DIR=$(abspath $(BENCH_DIR)) \
	$(GO) test -tags=benchmark -run=TestAccuracy -v -timeout=300s \
		./internal/service/evaluate/... \
		| tee $(BENCH_DIR)/accuracy_$(BENCH_DATE).log

.PHONY: bench-profile
bench-profile: $(BENCH_DIR)
	BENCH_PROFILE_DIR=$(abspath $(BENCH_DIR)) \
	$(GO) test -tags=benchmark -run='TestResourceProfile|TestLatencyDistribution' -v -timeout=600s \
		./internal/service/evaluate/... \
		| tee $(BENCH_DIR)/profile_$(BENCH_DATE).log

.PHONY: bench-all
bench-all: gen-corpus bench bench-accuracy bench-profile
	@echo ""
	@echo "Benchmarks complete. Artefacts in $(BENCH_DIR)/."

$(BENCH_DIR):
	@mkdir -p $(BENCH_DIR)

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out
