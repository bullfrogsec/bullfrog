.PHONY: bootstrap
bootstrap:

.PHONY: build
build:
	go build -trimpath -ldflags=-buildid=

.PHONY: test
test: test.binary-is-up-to-date

.PHONY: test.binary-is-up-to-date
test.binary-is-up-to-date:
	make build
	git diff --exit-code --name-only HEAD -- agent
