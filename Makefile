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

.PHONY: test.lint
test.lint: test.lint.action test.lint.agent

.PHONY: test.lint.action
test.lint.action:
	cd $(ACTION_DIRECTORY) && make test.lint

.PHONY: test.lint.agent
test.lint.agent:
	cd $(AGENT_DIRECTORY) && make test.lint

.PHONY: vagrant.up
vagrant.up:
	vagrant up
