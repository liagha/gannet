# FILE: Makefile
# PURPOSE: Build automation with termux and raw feature targets

.PHONY: build build-termux build-raw test test-termux test-raw check check-termux check-raw clean run run-termux run-raw

CARGO := cargo

build:
	$(CARGO) build --features raw

build-termux:
	$(CARGO) build --features termux

build-raw:
	$(CARGO) build --features raw

test:
	$(CARGO) test --features raw

test-termux:
	$(CARGO) test --features termux

test-raw:
	$(CARGO) test --features raw

check:
	$(CARGO) check --features raw

check-termux:
	$(CARGO) check --features termux

check-raw:
	$(CARGO) check --features raw

clean:
	$(CARGO) clean

run:
	$(CARGO) run --features raw

run-termux:
	$(CARGO) run --features termux

run-raw:
	$(CARGO) run --features raw