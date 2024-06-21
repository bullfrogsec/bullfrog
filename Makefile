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
