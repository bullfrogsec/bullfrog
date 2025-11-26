# Bullfrog

Increase the security of your Github Actions workflows using Bullfrog! With Bullfrog, you can easily control all your outbound network connections made from within your Github Actions workflows by defining a list of IPs and/or domains that you want to allow.

Not sure what IPs or domains? Simply use the default `egress-policy: audit` mode to get a list of all outbound network connections, without impacting your existing workflows.

## Usage

<!-- start usage -->

```yaml
# This action should be the first step of your job, and should be loaded on every separate job.
# If this action is not loaded first, it will not be able to see or block any requests that occured prior to the action running.
- uses: bullfrogsec/bullfrog@1831f79cce8ad602eef14d2163873f27081ebfb3 # v0.8.4
  with:
    # List of IPs to allow outbound connections to.
    # By default, only localhost and IPs required for the essential operations of Github Actions are allowed.
    allowed-ips:

    # List of domains to allow outbound connections to.
    # Wildcards are accepted. For example, if allowing `*.google.com`, this will allow `www.google.com`, `console.cloud.google.com` but not `google.com`.
    # By default, only domains required for essential operations of Github Actions and uploading job summaries are allowed.
    # Refer to https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners#communication-requirements-for-github-hosted-runners-and-github for additional domains that should be allowed for additional Github Actions features.
    allowed-domains:

    # Controls the policy for DNS requests when `egress-policy` is set to `block`.
    #
    #  - `allowed-domains-only` (default): Allows DNS requests only for domains specified in `allowed-domains`.
    #  - `any`: Allows any DNS requests.
    #
    # Default: `allowed-domains-only`
    dns-policy:

    # The egress policy to enforce. Valid values are `audit` and `block`.
    # Default: audit
    egress-policy:

    # Enable this option to allow steps to execute commands with sudo.
    # This is useful for workflows that require elevated privileges to perform certain tasks.
    # Options: `true` (default) or `false`.
    enable-sudo:
```

<!-- end usage -->

## Scenarios

- [Default](#default)
- [Block every outbound connections](#block-every-outbound-connections)
- [Only allow requests to domains required for pulling a docker image from the docker hub](#only-allow-requests-to-domains-required-for-pulling-a-docker-image-from-the-docker-hub)
- [Only allow requests to a specific IP address without blocking DNS requests](#only-allow-requests-to-a-specific-ip-address-without-blocking-dns-requests)

### Default

The default usage will run in audit mode and will not block any request.

```yaml
- uses: bullfrogsec/bullfrog@1831f79cce8ad602eef14d2163873f27081ebfb3 # v0.8.4
```

### Block every outbound connections

```yaml
- uses: bullfrogsec/bullfrog@1831f79cce8ad602eef14d2163873f27081ebfb3 # v0.8.4
  with:
    egress-policy: block
```

### Only allow requests to domains required for pulling a docker image from the docker hub

```yaml
- uses: bullfrogsec/bullfrog@1831f79cce8ad602eef14d2163873f27081ebfb3 # v0.8.4
  with:
    egress-policy: block
    allowed-domains: |
      *.docker.com
      docker.io
      *.docker.io
```

### Only allow requests to a specific IP address without blocking DNS requests

```yaml
- uses: bullfrogsec/bullfrog@1831f79cce8ad602eef14d2163873f27081ebfb3 # v0.8.4
  with:
    egress-policy: block
    allowed-ips: |
      1.2.3.4
    dns-policy: any
```

## Reviewing blocked or unallowed outbound requests

You can view blocked or unallowed outbound requests in the workflow summary.
![blocked or unallowed outbound requests are available in the workflow summary](.github/assets/annotations.png)

## Limitations

- This action is currently only supporting Github-hosted runners on Ubuntu (`ubuntu-latest`, `ubuntu-22.04` and `ubuntu-24.04`).
- Jobs running in [containers](https://docs.github.com/en/actions/writing-workflows/choosing-where-your-workflow-runs/running-jobs-in-a-container) are not supported.
- Packets sent using the raw IP layer will bypass the agent responsible for the egress filtering. For this reason, we highly recommend using the `enable-sudo: false` to prevent usage of the raw IP layer.

## Support or Feedback

If you need support or have any feedback to share, join us on [Slack](https://join.slack.com/t/bullfogsec/shared_invite/zt-2mbf603gn-TRfhXvf_x8J7yB9fJ3Os7Q). And if you find Bullfrog useful, please leave a star ⭐️.

## License

The code and documentation in this project are released under the [MIT License](LICENSE).
