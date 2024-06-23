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
