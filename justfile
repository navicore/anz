# anz Build System
#
# This is the SOURCE OF TRUTH for all build/test/lint operations.
# GitHub Actions calls these recipes directly - no duplication!

# Default recipe: show available commands
default:
    @just --list

# Build the release binary
build:
    @echo "Building anz..."
    cargo build --release
    @echo "Built: target/release/anz"

# Run clippy on all targets (warnings are errors)
lint:
    @echo "Running clippy..."
    cargo clippy --all-targets -- -D warnings

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
    cargo test --all-targets

# Run all CI checks (same as GitHub Actions!)
# This is what developers should run before pushing
ci: fmt-check lint test
    @echo ""
    @echo "All CI checks passed!"
    @echo "  - Code formatting"
    @echo "  - Clippy lints"
    @echo "  - Tests"
    @echo ""
    @echo "Safe to push."

# Development: quick format + build + test
dev: fmt build test

# Build the Docker image locally
docker-build:
    docker build -t anz:local .

# Clean all build artifacts
clean:
    @echo "Cleaning build artifacts..."
    cargo clean
