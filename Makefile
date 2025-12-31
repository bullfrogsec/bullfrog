ACTION_DIRECTORY := action
AGENT_DIRECTORY := agent

.PHONY: bootstrap
bootstrap: bootstrap.action bootstrap.agent

.PHONY: bootstrap.action
bootstrap.action:
	cd $(ACTION_DIRECTORY) && make bootstrap

.PHONY: bootstrap.agent
bootstrap.agent:
	cd $(AGENT_DIRECTORY) && make bootstrap

.PHONY: build
build: build.action build.agent

.PHONY: build.action
build.action:
	cd $(ACTION_DIRECTORY) && make build

.PHONY: build.agent
build.agent:
	cd $(AGENT_DIRECTORY) && make build

.PHONY: test.integration
test.integration: test.integration.block

.PHONY: test.integration.block
test.integration.block:
	vagrant ssh --command "bash /vagrant/test/block.sh"

.PHONY: test.artifacts
test.artifacts: test.artifacts.action

.PHONY: test.artifacts.action
test.artifacts.action:
	cd $(ACTION_DIRECTORY) && make test.artifacts

.PHONY: test.lint
test.lint: test.lint.action test.lint.agent

.PHONY: test.lint.action
test.lint.action:
	cd $(ACTION_DIRECTORY) && make test.lint

.PHONY: test.lint.agent
test.lint.agent:
	cd $(AGENT_DIRECTORY) && make test.lint

.PHONY: test.types
test.types: test.types.action test.types.agent

.PHONY: test.types.action
test.types.action:
	cd $(ACTION_DIRECTORY) && make test.types

.PHONY: test.types.agent
test.types.agent:
	cd $(AGENT_DIRECTORY) && make test.types

.PHONY: test.unit
test.unit: test.unit.action test.unit.agent

.PHONY: test.unit.action
test.unit.action:
	cd $(ACTION_DIRECTORY) && make test.unit

.PHONY: test.unit.agent
test.unit.agent:
	cd $(AGENT_DIRECTORY) && make test.unit

.PHONY: vagrant.up
vagrant.up:
	vagrant up
