.PHONY: fmt test build sam-build

fmt:
	cargo fmt

test:
	cargo test

build:
	cargo lambda build --release --arm64

sam-build:
	sam build --beta-features --no-use-container
