ACTION_DIRECTORY := action

.PHONY: bootstrap
bootstrap:
	cd $(ACTION_DIRECTORY) && make bootstrap

.PHONY: build
build:
	cd $(ACTION_DIRECTORY) && make build

.PHONY: test.integration
test.integration: test.integration.block

.PHONY: test.integration.block
test.integration.block:
	vagrant ssh --command "bash /vagrant/test/block.sh"

.PHONY: test.artifacts
test.artifacts:
	cd $(ACTION_DIRECTORY) && make test.artifacts

.PHONY: test.lint
test.lint:
	cd $(ACTION_DIRECTORY) && make test.lint

.PHONY: test.types
test.types:
	cd $(ACTION_DIRECTORY) && make test.types

.PHONY: test.unit
test.unit:
	cd $(ACTION_DIRECTORY) && make test.unit

.PHONY: vagrant.up
vagrant.up:
	vagrant up