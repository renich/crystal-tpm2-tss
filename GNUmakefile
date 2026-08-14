.PHONY: all clean test lint docs deps
.DEFAULT_GOAL := all

CRYSTAL ?= crystal

all: lint test

deps:
	shards install
	@if ! bin/ameba --version >/dev/null 2>&1 && [ -f lib/ameba/src/cli.cr ]; then \
		echo "Building bin/ameba natively..."; \
		mkdir -p bin; \
		$(CRYSTAL) build lib/ameba/src/cli.cr -o bin/ameba; \
	fi
	@if ! bin/flaw --version >/dev/null 2>&1 && [ -f lib/flaw/src/cli.cr ]; then \
		echo "Building bin/flaw natively..."; \
		mkdir -p bin; \
		$(CRYSTAL) build lib/flaw/src/cli.cr -o bin/flaw; \
	fi

test: deps
	$(CRYSTAL) spec

lint: deps
	bin/ameba
	bin/flaw scan .

docs: deps
	$(CRYSTAL) docs --output=docs/technical/api

clean:
	rm -rf docs/technical/api
	rm -rf .crystal
	rm -rf lib
	rm -rf bin
