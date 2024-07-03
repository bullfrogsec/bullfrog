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
