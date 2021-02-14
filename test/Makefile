SHELL = /usr/bin/env bash

TESTS = $(shell ls -d */)

.PHONY: tests
tests: $(TESTS)

$(TESTS):
	cd $@ && ./test.sh
