.PHONY: bootstrap
bootstrap:

.PHONY: build
build:
	docker build --tag agent-build-image --build-arg BUILDOS=linux --build-arg BUILDARCH=amd64 .

	docker rm --force agent-build
	docker run --name agent-build agent-build-image

	docker cp agent-build:/agent/agent .

	docker rm --force agent-build

	sha256sum agent | tee agent.sha256

.PHONY: fix
fix:
	go fmt

.PHONY: test.artifacts
test.artifacts:
	sha256sum --check --strict agent.sha256

GOFMT_OUTPUT = $(shell gofmt -l .)

.PHONY: test.lint
test.lint:
	@if [ -n "$$(gofmt -l ./pkg/agent ./cmd/agent)" ]; then \
		echo "$$(gofmt -l ./pkg/agent ./cmd/agent)"; \
		exit 1; \
	fi

.PHONY: test.types
test.types:
	echo "We don't need it since `go build` verifies the types"

.PHONY: test.unit
test.unit:
	go test ./pkg/agent/...

.PHONY: test.generate-coverage
test.generate-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
