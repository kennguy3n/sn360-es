# SN360-ES Makefile

GO              ?= go
GOTEST_FLAGS    ?= -race -timeout 120s
BIN_DIR         ?= bin
APP_NAME        ?= sn360-es
DOCKER_COMPOSE  ?= docker compose

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
lint:
	$(GO) vet ./...
	gofmt -l . | tee /dev/stderr | (! read)

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

.PHONY: migrate-up
migrate-up:
	@echo "Apply migrations (Atlas/golang-migrate not yet wired in this scaffold)"
	@ls migrations 2>/dev/null || true

.PHONY: migrate-down
migrate-down:
	@echo "Rollback migrations (Atlas/golang-migrate not yet wired in this scaffold)"
	@ls migrations 2>/dev/null || true

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) coverage.out
