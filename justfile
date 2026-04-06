# anz Build System
#
# This is the SOURCE OF TRUTH for all build/test/lint operations.
# GitHub Actions calls `just ci` — nothing else.
#
# All cargo commands use --locked to ensure Cargo.lock is respected.
# If Cargo.lock is out of date, the build fails instead of silently
# resolving new dependency versions.

# Default recipe: show available commands
default:
    @just --list

# Build the release binary
build:
    @echo "Building anz..."
    cargo build --locked --release
    @echo "Built: target/release/anz"

# Run clippy on all targets (warnings are errors)
lint:
    @echo "Running clippy..."
    cargo clippy --locked --workspace --all-targets -- -D warnings

# Check formatting without modifying files
fmt-check:
    @echo "Checking code formatting..."
    cargo fmt --all -- --check

# Format all code
fmt:
    @echo "Formatting code..."
    cargo fmt --all

# Run all tests
test:
    @echo "Running tests..."
    cargo test --locked --workspace --all-targets

# Run all CI checks (same as GitHub Actions!)
# This is what developers should run before pushing
ci: fmt-check lint test build
    @echo ""
    @echo "All CI checks passed!"
    @echo "  - Code formatting"
    @echo "  - Clippy lints (warnings are errors)"
    @echo "  - Tests"
    @echo "  - Release build"
    @echo ""
    @echo "Safe to push to GitHub - CI will pass."

# Development: quick format + build + test
dev: fmt build test

# Build the Docker image locally
docker-build:
    docker build -t anz:local .

# Clean all build artifacts
clean:
    @echo "Cleaning build artifacts..."
    cargo clean
