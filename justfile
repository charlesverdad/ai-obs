# ai-obs — run everything through nix-shell so no global toolchain is needed.
# Inside `nix-shell` already? cargo commands work directly too.

set shell := ["bash", "-cu"]

default:
    @just --list

# Build debug binary
build:
    nix-shell --run "cargo build"

# Build release binary
release:
    nix-shell --run "cargo build --release"

# Run all tests
test:
    nix-shell --run "cargo test"

# Typecheck fast
check:
    nix-shell --run "cargo check --all-targets"

# Lint (warnings are errors, same as CI)
lint:
    nix-shell --run "cargo clippy --all-targets -- -D warnings"

# Format
fmt:
    nix-shell --run "cargo fmt"

# Everything CI runs: fmt-check, clippy, test
verify:
    nix-shell --run "cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test"

# Run the daemon in the foreground (debug)
daemon *ARGS:
    nix-shell --run "cargo run -- daemon {{ARGS}}"

# Run any ai-obs subcommand, e.g. `just run top`
run *ARGS:
    nix-shell --run "cargo run -- {{ARGS}}"
