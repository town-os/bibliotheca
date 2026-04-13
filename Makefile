# Makefile for bibliotheca.
#
# Common usage:
#   make            # same as `make help`
#   make test       # clippy, then the full test suite
#   make ci         # fmt-check, clippy, then tests — what CI runs

CARGO ?= cargo

# Clippy treats any warning as a hard error.
CLIPPY_FLAGS ?= -D warnings

# The integration tests reach into bibliotheca-core::testing::MemoryBackend
# which lives behind this feature. Flip it with `make FEATURES=...` if you
# want to run a narrower slice.
FEATURES ?= bibliotheca-core/test-support

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "; print "Usage: make <target>\n\nTargets:"} \
		/^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---- build / check ----

.PHONY: check
check: ## cargo check the full workspace
	$(CARGO) check --workspace --all-targets --features '$(FEATURES)'

.PHONY: build
build: ## Build the full workspace (debug profile)
	$(CARGO) build --workspace --features '$(FEATURES)'

.PHONY: release
release: ## Release-build the daemon and CLI
	$(CARGO) build --release -p bibliothecad -p bibliothecactl

# ---- formatting / lint ----

.PHONY: fmt
fmt: ## Format all crates with rustfmt
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Verify formatting without writing changes
	$(CARGO) fmt --all -- --check

.PHONY: lint
lint: ## Run clippy across the workspace (warnings are errors)
	$(CARGO) clippy --workspace --all-targets --features '$(FEATURES)' -- $(CLIPPY_FLAGS)

# ---- tests ----
#
# `make test` runs clippy first, then the full suite — unit tests inside
# each crate's src/, integration tests under each crate's tests/ directory,
# and doc tests. That's what the user is expected to run locally.

.PHONY: test
test: lint ## Run clippy, then unit + integration + doc tests
	$(CARGO) test --workspace --features '$(FEATURES)'

.PHONY: test-unit
test-unit: ## Run only library unit tests (no integration, no doc)
	$(CARGO) test --workspace --lib

.PHONY: test-integration
test-integration: ## Run only integration tests under crates/*/tests/
	$(CARGO) test --workspace --tests --features '$(FEATURES)'

.PHONY: test-doc
test-doc: ## Run doc tests
	$(CARGO) test --workspace --doc --features '$(FEATURES)'

.PHONY: test-real-btrfs
test-real-btrfs: ## Run ignored real-btrfs tests (set BIBLIOTHECA_REAL_BTRFS_ROOT=...)
	$(CARGO) test -p bibliotheca-btrfs --test backend -- --ignored

# ---- composites ----

.PHONY: ci
ci: fmt-check lint test ## Full pipeline: fmt-check → clippy → test
	@echo "ci: all green"

# ---- housekeeping ----

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
