GOLANG_VERSION 		?= $(shell cat .tool-versions | grep golang | cut -d' ' -f2)
GOLANGCI_LINT_VERSION	?= v2.11.1
VERSION 			?= $(shell go tool svu current)
REGISTRY 			?= twingate
IMAGE				:= gateway
IMAGE_NAME			:= $(REGISTRY)/$(IMAGE)
DOCKER_BUILDX_BUILDER ?= twingate-gateway-builder
DOCKER_BUILDX_CACHE_FROM ?=
DOCKER_BUILDX_CACHE_TO ?=

export DOCKER_CLI_EXPERIMENTAL=enabled

HELP_FUN = \
    %help; \
    while(<>) { push @{$$help{$$2 // 'options'}}, [$$1, $$3] if /^([a-zA-Z\-_]+)\s*:.*\#\#(?:@([a-zA-Z\-]+))?\s(.*)$$/ }; \
    print "usage: make [target]\n\n"; \
    print "${WHITE}Variables:${RESET}\n"; \
    print "  ${YELLOW}GOLANG_VERSION${RESET} = ${GREEN}$(GOLANG_VERSION)${RESET}\n"; \
    print "  ${YELLOW}VERSION${RESET}        = ${GREEN}$(VERSION)${RESET}\n"; \
    print "  ${YELLOW}IMAGE_NAME${RESET}     = ${GREEN}$(IMAGE_NAME)${RESET}\n"; \
    print "  ${YELLOW}GOLANGCI_LINT_VERSION${RESET} = ${GREEN}$(GOLANGCI_LINT_VERSION)${RESET}\n"; \
	print "\n"; \
    for (sort keys %help) { \
    print "${WHITE}$$_:${RESET}\n"; \
    for (@{$$help{$$_}}) { \
    $$sep = " " x (32 - length $$_->[0]); \
    print "  ${YELLOW}$$_->[0]${RESET}$$sep${GREEN}$$_->[1]${RESET}\n"; \
    }; \
    print "\n"; }

COVPROFILE_UNIT := covprofile-unit
COVPROFILE_INTEGRATION := covprofile-integration
JUNIT_UNIT := junit-unit.xml
JUNIT_INTEGRATION := junit-integration.xml
COVERED_PACKAGES := ./cmd/...,./internal/...
UNIT_TEST_PACKAGES := ./cmd/... ./internal/...
INTEGRATION_TEST_PACKAGES := ./test/integration/...
E2E_TEST_PACKAGES := ./test/e2e/...

.PHONY: help
help: ##@other Show this help
	@perl -e '$(HELP_FUN)' $(MAKEFILE_LIST)

.PHONY: version
version: ##@other Show the version
	@echo $(VERSION)

.PHONY: lint
lint: ##@lint Lint Go code
	@echo "Running Linter..."
	docker run --rm -t -v $$(pwd):/app -w /app \
		--user $$(id -u):$$(id -g) \
		-v $$(go env GOCACHE):/.cache/go-build -e GOCACHE=/.cache/go-build \
		-v $$(go env GOMODCACHE):/.cache/mod -e GOMODCACHE=/.cache/mod \
		-v ~/.cache/golangci-lint:/.cache/golangci-lint -e GOLANGCI_LINT_CACHE=/.cache/golangci-lint \
		golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) golangci-lint run --fix ./...

.PHONY: lint-dockerfile
lint-dockerfile: ##@lint Lint Dockerfile
	docker run --rm -i hadolint/hadolint < Dockerfile.goreleaser
	docker run --rm -i hadolint/hadolint < Dockerfile.goreleaser-debug

.PHONY: lint-markdown
lint-markdown: ##@lint Lint Markdown files
	@echo "Linting Markdown files..."
	@if npx --version >/dev/null 2>&1; then \
		echo "Using npx markdownlint-cli2..."; \
		npx --yes markdownlint-cli2 "**/*.md"; \
	else \
		echo "npx not available, using Docker..."; \
		docker run --rm -v "$$(pwd):/work" -w /work davidanson/markdownlint-cli2:latest "**/*.md"; \
	fi

.PHONY: test-helm
test-helm: ##@test Run helm-unittest
	@echo "Running Helm unit tests..."
	helm unittest deploy/gateway

.PHONY: test-helm-and-update-snapshots
test-helm-and-update-snapshots: ##@test Run helm-unittest and update the test snapshots
	@echo "Running Helm unit tests and update test snapshots..."
	helm unittest deploy/gateway -u

.PHONY: test
test: ##@test Run unit tests
	@echo "Running unit tests..."
	go test -race -v $(UNIT_TEST_PACKAGES)

.PHONY: test-with-coverage
test-with-coverage: ##@test Run unit tests with coverage
	@echo "Running unit tests with coverage..."
	@if command -v gotestsum >/dev/null 2>&1; then \
		gotestsum --junitfile $(JUNIT_UNIT) --format testname -- -race -covermode atomic -coverpkg="$(COVERED_PACKAGES)" -coverprofile=$(COVPROFILE_UNIT) $(UNIT_TEST_PACKAGES); \
	else \
		go run gotest.tools/gotestsum@latest --junitfile $(JUNIT_UNIT) --format testname -- -race -covermode atomic -coverpkg="$(COVERED_PACKAGES)" -coverprofile=$(COVPROFILE_UNIT) $(UNIT_TEST_PACKAGES); \
	fi

.PHONY: test-integration
test-integration: ##@test Run integration tests
	@echo "Running integration tests..."
	go test -race -v $(INTEGRATION_TEST_PACKAGES)

.PHONY: test-integration-with-coverage
test-integration-with-coverage: ##@test Run integration tests with coverage
	@echo "Running integration tests with coverage..."
	@if command -v gotestsum >/dev/null 2>&1; then \
		gotestsum --junitfile $(JUNIT_INTEGRATION) --format testname -- -race -covermode atomic -coverpkg="$(COVERED_PACKAGES)" -coverprofile=$(COVPROFILE_INTEGRATION) $(INTEGRATION_TEST_PACKAGES); \
	else \
		go run gotest.tools/gotestsum@latest --junitfile $(JUNIT_INTEGRATION) --format testname -- -race -covermode atomic -coverpkg="$(COVERED_PACKAGES)" -coverprofile=$(COVPROFILE_INTEGRATION) $(INTEGRATION_TEST_PACKAGES); \
	fi

.PHONY: test-e2e
test-e2e: ##@test Run e2e tests
	@echo "Running e2e tests..."
	go test -race -v $(E2E_TEST_PACKAGES)

.PHONY: upload-coverage
upload-coverage: ##@test Upload code coverage to CodeCov (requires CI environment)
	@echo "Note: Coverage upload is handled by GitHub Actions in CI"
	@echo "To upload manually, use codecov/codecov-action or codecov CLI"
	@echo "Coverage files ready: $(COVPROFILE_UNIT), $(COVPROFILE_INTEGRATION)"


.PHONY: prepare-buildx
prepare-buildx: ##@build Prepare buildx
	@echo "Preparing buildx..."
	docker buildx inspect $(DOCKER_BUILDX_BUILDER) >/dev/null 2>&1 && docker buildx use $(DOCKER_BUILDX_BUILDER) || \
		docker buildx create --use --name $(DOCKER_BUILDX_BUILDER) --node=$(DOCKER_BUILDX_BUILDER)

.PHONY: build
build: prepare-buildx ##@build Build the Go binaries and container images
	DOCKER_BUILDX_BUILDER=$(DOCKER_BUILDX_BUILDER) DOCKER_BUILDX_CACHE_FROM=$(DOCKER_BUILDX_CACHE_FROM) DOCKER_BUILDX_CACHE_TO=$(DOCKER_BUILDX_CACHE_TO) GOLANG_VERSION=$(GOLANG_VERSION) goreleaser release --snapshot --clean

.PHONY: cut-release-prod
cut-release-prod: ##@release Cut a production release (create a version tag and push it)
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "master" ]; then \
		echo "❌ Error: cut-release-prod can only be run on master branch. Current branch: $$(git rev-parse --abbrev-ref HEAD)"; \
		exit 1; \
	fi
	echo "🚀 Cutting a new production release - $(shell go tool svu next)"
	git tag "$(shell go tool svu next)"
	git push --tags

.PHONY: cut-release-dev
cut-release-dev: ##@release Cut a development pre-release (create a version tag and push it)
	@if [ "$$(git rev-parse --abbrev-ref HEAD)" != "master" ]; then \
		echo "❌ Error: cut-release-dev can only be run on master branch. Current branch: $$(git rev-parse --abbrev-ref HEAD)"; \
		exit 1; \
	fi
	echo "🚀 Cutting a new development pre-release - $(shell go tool svu next)"
	git tag "$(shell go tool svu next --prerelease dev-$(shell git rev-parse --short HEAD))"
	git push --tags
