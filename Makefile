.PHONY: build test lint fmt live verify
build:
	cargo build --locked --release
test:
	cargo test --locked
fmt:
	cargo fmt --check
lint:
	cargo clippy --locked --all-targets -- -D warnings
live:
	cargo test --locked --test scanner live_public_upstream -- --ignored
	cargo test --locked --test evidence live_public_reference -- --ignored
	cargo test --locked --test check_workflow live_ -- --ignored
verify: fmt lint test
