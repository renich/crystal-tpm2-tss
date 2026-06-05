.PHONY: all clean test lint docs deps
.DEFAULT_GOAL := all

CRYSTAL ?= crystal

all: lint test

deps:
	shards install

test: deps
	$(CRYSTAL) spec --format progress

lint: deps
	bin/ameba
	[ -x bin/flaw ] && bin/flaw scan . || flaw scan .

docs: deps
	$(CRYSTAL) docs --output=docs/technical/api

clean:
	rm -rf docs/technical/api
	rm -rf .crystal
	rm -rf lib
	rm -rf bin
