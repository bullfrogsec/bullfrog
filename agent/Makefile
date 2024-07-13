.PHONY: bootstrap
bootstrap:

.PHONY: build
build:
	go build -trimpath -ldflags=-buildid=

.PHONY: fix
fix:
	go fmt


GOFMT_OUTPUT = $(shell gofmt -l .)

.PHONY: test.lint
test.lint:
	@if [ -n "$(GOFMT_OUTPUT)" ]; then \
		echo "$(GOFMT_OUTPUT)"; \
		exit 1; \
	fi

.PHONY: test.types
test.types: build

.PHONY: test.unit
test.unit:
	go test

.PHONY: test.generate-coverage
test.generate-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
