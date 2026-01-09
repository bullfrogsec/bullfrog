# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please help us responsibly disclose it by following these steps:

- Use the GitHub Security Advisory ["Report a Vulnerability"](https://github.com/bullfrogsec/bullfrog/security/advisories/new) tab.
- Provide detailed information about the vulnerability, including steps to reproduce and any potential impact.

The Bullfrog Security team takes security issues seriously and will respond promptly to evaluate and address the reported vulnerabilities.

Thank you for helping us keep the project secure!

## Build Provenance

Bullfrog implements multiple layers of artifact validation to ensure the integrity and trustworthiness of the action and its components.

### Agent Binary Attestation

The agent binary is protected using GitHub's native [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) system, which provides:

- **SLSA Build Provenance**: Every agent binary is cryptographically signed with build provenance metadata following the [SLSA framework](https://slsa.dev/)
- **Tamper Detection**: When you use Bullfrog, the agent binary is automatically verified against its attestation before execution, ensuring it hasn't been modified since being built
- **Supply Chain Transparency**: Attestations are publicly verifiable and include information about the build environment, workflow, and repository state

The attestation verification happens automatically during action execution. The verification ensures the downloaded binary matches exactly what was built in the official GitHub Actions workflow.

You can manually verify the agent release artifact using:

```bash
# Download and verify the release tarball
curl -L https://github.com/bullfrogsec/bullfrog/releases/download/v0.9.2/agent.tar.gz -o agent.tar.gz
gh attestation verify agent.tar.gz --owner bullfrogsec
```

### Action Distribution Files

The action's distribution files (`action/dist`) are the compiled JavaScript code that executes when you use the Bullfrog action. These files are protected through two mechanisms:

- **Build Provenance Attestation**: Every build generates cryptographically signed attestations for `dist/main.js` and `dist/post.js`, proving the dist files that are built in the official CI pipeline matches the files that are executed when you use the Bullfrog action.
- **Automated Diff Checks**: Every pull request and CI pipeline run validate that the dist files are properly synchronized with the TypeScript source

#### Why aren't dist files auto-verified at runtime?

Unlike the agent binary which is downloaded and can be verified before execution, the action's dist files are checked out directly by GitHub Actions and already executing when your workflow runs. This creates a chicken-and-egg problem where the action can't verify itself before running.

However, **users can manually verify** the dist files before trusting a release:

```bash
# Clone the repository at a specific release tag
git clone --depth 1 --branch v0.9.2 https://github.com/bullfrogsec/bullfrog.git
cd bullfrog

# Verify the attestations for the dist files
gh attestation verify action/dist/main.js --owner bullfrogsec
gh attestation verify action/dist/post.js --owner bullfrogsec
```

The attestations prove that the committed dist files were built in GitHub's CI from the corresponding Typescript source code and have not been tampered.
