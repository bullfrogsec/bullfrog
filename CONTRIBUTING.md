# Contributing Guidelines

Thank you for considering contributing to the Bullfrog project! We welcome contributions from everyone. Before starting any work, you should consider opening an [issue](https://github.com/bullfrogsec/bullfrog/issues) and sharing with the maintainers what you plan on working on.

## Getting Started

1. **Fork the Repository**: Click the "Fork" button on the top right of the repository page to create a copy of the repository on your own GitHub account.

2. **Clone Your Fork**: Clone your fork to your local machine using:

   ```bash
   git clone https://github.com/your-username/bullfrog.git
   ```

3. **Create a Branch**: Create a new branch for your work to ensure that your changes can be isolated and easily reviewed.

   ```bash
   git checkout -b your-branch-name
   ```

4. **Set Up the Environment**: We recommend installing and using vagrant for your local environment. Install [vagrant](https://developer.hashicorp.com/vagrant/docs/installation) and run `vagrant up`, then `vagrant ssh` from the repository folder to work from the vagrant VM.

## Making Changes

1. **Write Code**: Implement your changes, following the project's coding standards and guidelines.

2. **Add Tests**: Ensure your changes are well-tested. We strive for high test coverage to maintain the project's reliability.

3. **Commit Changes**: Commit your changes with clear and concise commit messages.

   ```bash
   git add .
   git commit -m "Clear and descriptive commit message"
   ```

4. **Push to Your Fork**: Push your branch to your fork on GitHub.

   ```bash
   git push origin your-branch-name
   ```

5. **Create a Pull Request**: Open a pull request (PR) from your branch to the main repository. Provide a descriptive title and detailed description of your changes. Your pull request title need to follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).

## Code Review Process

1. **CI Checks**: Once you open a PR, Continuous Integration (CI) checks will run automatically. Ensure that all checks pass.

2. **Review**: One of the maintainers will review your PR. You may be asked to make additional changes. Please be responsive to feedback.

3. **Approval and Merge**: Once your PR is approved, a maintainer will merge it into the main branch.

## Style Guide

- **Code Formatting**: Follow the style guidelines provided by the project. You can run `make test.lint` from the repository folder run a linter and confirm your code adhere to the style guidelines.
- **Documentation**: Update documentation where necessary. This includes comments in code, as well as updates to `README.md` or other relevant documentation files.

## Reporting Issues

If you find a bug or have an idea for a new feature, please open an [issue](https://github.com/bullfrogsec/bullfrog/issues) on GitHub. Use the provided templates to ensure all necessary information is included.

## Getting Help

If you need help, feel free to reach out by opening an issue with the `question` label or joining our [Slack community](https://join.slack.com/t/bullfrogglobal/shared_invite/zt-2mbf603gn-TRfhXvf_x8J7yB9fJ3Os7Q).

## Community

- **Discussions**: Participate in discussions on GitHub issues or our Slack community.

Thank you for your contributions and for helping make Bullfrog better for everyone!
