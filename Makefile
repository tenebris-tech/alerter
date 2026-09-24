SHELL := /bin/bash
# alerter — build and test entry points (see ~/.claude/standards/makefile.md).
#
#   make          run the full test suite, then build (only if the tests pass)
#   make test     the one gate: format check, go vet, go test -race with a
#                 coverage floor, and a summary; exits non-zero on any failure
#   make test-live  send one real alert through every channel configured in
#                 ~/.alerter (not part of the gate)
#   make build    compile the package (a library: nothing is produced)
#   make clean    remove test artifacts and the Go test cache
#   make fmt      rewrite formatting (the gate only verifies it)
#   make lint     golangci-lint, when installed
#
# There is no install target: this is a library, consumed as a Go module.

COVERAGE_MIN ?= 90
GOLANGCI_LINT ?= $(shell command -v golangci-lint 2>/dev/null || echo "$$(go env GOPATH)/bin/golangci-lint")

.PHONY: all test test-live build clean fmt fmt-check vet lint

all: test build

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt: files need formatting:"; echo "$$out"; exit 1; fi

vet:
	@go vet ./...

test: fmt-check vet
	@set -o pipefail; ALERTER_LIVE_TEST= go test -race -count=1 -v -coverprofile=coverage.out ./... 2>&1 | tee test.log | grep -E '^(=== RUN|--- (PASS|FAIL|SKIP)|FAIL|ok|PASS)' >/dev/null; \
	status=$$?; \
	pass=$$(grep -c '^\s*--- PASS' test.log); fail=$$(grep -c '^\s*--- FAIL' test.log); skip=$$(grep -c '^\s*--- SKIP' test.log); \
	total=$$((pass+fail+skip)); \
	cov=$$(go tool cover -func=coverage.out | awk '/^total:/ {gsub("%","",$$3); print $$3}'); \
	echo ""; echo "Tests: $$total  passed: $$pass  failed: $$fail  skipped: $$skip  coverage: $$cov% (minimum $(COVERAGE_MIN)%)"; \
	if [ "$$status" -ne 0 ] || [ "$$fail" -ne 0 ]; then echo "FAILURES DETECTED"; exit 1; fi; \
	if [ "$$(echo "$$cov < $(COVERAGE_MIN)" | bc -l)" -eq 1 ]; then echo "coverage $$cov% is below the minimum $(COVERAGE_MIN)%"; exit 1; fi; \
	echo "All tests passed."

test-live:
	@ALERTER_LIVE_TEST=1 go test -count=1 -v -run '^TestLive$$' ./...

build:
	@go build ./...

clean:
	@rm -f coverage.out test.log
	@go clean -testcache

fmt:
	@gofmt -w .

lint:
	@$(GOLANGCI_LINT) run ./...
