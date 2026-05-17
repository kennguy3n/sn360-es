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

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out
