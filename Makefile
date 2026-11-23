.DEFAULT_GOAL := help

.PHONY: help clean build test lint fix trivy

help: ## List available targets
	@printf 'Usage: make <target>\n\nTargets:\n'
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-10s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

clean: ## Remove the notify binary
	rm -f notify

build: ## Build the notify binary
	go build -o notify .

test: ## Run all Go tests
	go test -v ./...

lint: ## Run golangci-lint
	golangci-lint run

fix: ## Apply Go toolchain fixes
	go fix ./...

trivy: ## Run the CI security scan locally and write trivy-results.sarif
	trivy fs \
		--exit-code 1 --ignore-unfixed --severity CRITICAL,HIGH \
		--scanners vuln,secret,misconfig --skip-dirs testdata .
