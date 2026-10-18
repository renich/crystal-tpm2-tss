SHELL = /bin/sh
.SHELLFLAGS := -ec
.ONESHELL:
.DELETE_ON_ERROR:
.SUFFIXES:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

.DEFAULT_GOAL := all

CRYSTAL  ?= crystal
SHARDS   ?= shards
CRSTLINT ?= crstlint
RSTCHECK ?= rstcheck
PREFIX   ?= /usr/local
DESTDIR  ?=
DATADIR  ?= $(PREFIX)/share
DOCDIR   ?= $(DATADIR)/doc/crystal-tpm2-tss

AMEBA := bin/ameba
FLAW  := bin/flaw

RST_FILES := $(wildcard *.rst) $(shell find docs -path 'docs/build' -prune -o -path 'docs/technical/api' -prune -o -type f -name '*.rst' -print 2>/dev/null)

.PHONY: all deps test check lint doc-check format docs install uninstall clean help

all: lint doc-check test ## Run static analysis, documentation checks, and test suite

deps: $(AMEBA) $(FLAW) ## Install shard dependencies and build linter binaries

bin:
	mkdir -p $@

$(AMEBA): | bin
	@if [ ! -f lib/ameba/src/cli.cr ]; then $(SHARDS) install; rm -f shard.lock; fi
	$(CRYSTAL) build lib/ameba/src/cli.cr -o $@

$(FLAW): | bin
	@if [ ! -f lib/flaw/src/cli.cr ]; then $(SHARDS) install; rm -f shard.lock; fi
	$(CRYSTAL) build lib/flaw/src/cli.cr -o $@

test: ## Run Crystal test suite
	$(CRYSTAL) spec

check: lint doc-check test ## Run all quality gates and tests

lint: $(AMEBA) $(FLAW) ## Run Crystal formatter check, Ameba, and Flaw static analysis
	$(CRYSTAL) tool format --check src spec
	./$(AMEBA) --all
	./$(FLAW) scan .

doc-check: ## Lint reStructuredText documentation with crstlint and rstcheck
	@if command -v $(CRSTLINT) >/dev/null 2>&1; then $(CRSTLINT) -r .; fi
	@if command -v $(RSTCHECK) >/dev/null 2>&1; then $(RSTCHECK) $(RST_FILES); fi

format: ## Format Crystal source and spec files
	$(CRYSTAL) tool format src spec

docs: ## Generate Crystal API reference and Sphinx documentation portal
	$(CRYSTAL) docs -o docs/technical/api
	$(MAKE) -C docs dirhtml

install: docs ## Install documentation to DESTDIR/DOCDIR
	install -d $(DESTDIR)$(DOCDIR)
	cp -r docs/* $(DESTDIR)$(DOCDIR)/

uninstall: ## Remove installed documentation from DESTDIR/DOCDIR
	rm -rf $(DESTDIR)$(DOCDIR)

clean: ## Remove build artifacts and generated documentation
	rm -rf docs/technical/api .crystal lib bin shard.lock
	$(MAKE) -C docs clean

help: ## Display available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
