<p align="center">
  <a href="https://github.com/coinbase/salus">
    <img width="350px" alt="Salus" src="logo.png">
  </a>
</p>
<h3 align="center">
   Salus: Guardian of Code Safety and Security
</h3>


[![CircleCI](https://circleci.com/gh/coinbase/salus/tree/master.svg?style=svg)](https://circleci.com/gh/coinbase/salus/tree/master)

## 🔍 Overview

Salus (Security Automation as a Lightweight Universal Scanner), named after the [Roman goddess of protection](https://en.wikipedia.org/wiki/Salus), is a tool for coordinating the execution of security scanners. You can run Salus on a repository via the Docker daemon and it will determine which scanners are relevant, run them and provide the output. Most scanners are other mature open source projects which we include directly in the container.

Salus is particularly useful for CI/CD pipelines because it becomes a centralized place to coordinate scanning across a large fleet of repositories. Typically, scanners are configured at the repository level for each project. This means that when making org wide changes to how the scanners are run, each repository must be updated. Instead, you can update Salus and all builds will instantly inherit the change.

Salus supports powerful configuration that allows for global defaults and local tweaks. Finally, Salus can report metrics on each repository, such as what packages are included or what concerns exist. These reports can be centrally evaluated in your infrastructure to allow for scalable security tracking.

## Using Salus

```sh
# Navigate to the root directory of the project you want to run Salus on
cd /path/to/repo

# Run the following line while in the root directory (No edits necessary)
docker run --rm -t -v $(pwd):/home/repo coinbase/salus
```

## Supported Scanners

- [Bandit](docs/scanners/bandit.md) - Execution of [Bandit](https://pypi.org/project/bandit/) 1.6.2, looks for common security issues in Python code.
- [Brakeman](docs/scanners/brakeman.md) - Execution of [Brakeman](https://brakemanscanner.org/) 4.10.0, looks for vulnerable code in Rails projects.
- [semgrep](docs/scanners/semgrep.md) - Execution of [`semgrep`](https://semgrep.dev) 0.62.0 which looks for semantic and syntactical patterns in code at the AST level.
- [BundleAudit](docs/scanners/bundle_audit.md) - Execution of [bundle-audit](https://github.com/rubysec/bundler-audit) 0.8.0, looks for CVEs in ruby gem dependencies.
- [Gosec](docs/scanners/gosec.md) - Execution of [gosec](https://github.com/securego/gosec) 2.11.0, looks for security problems in go code.
- [npm audit](docs/scanners/npm_audit.md) - Execution of [`npm audit`](https://docs.npmjs.com/getting-started/running-a-security-audit) 6.14.8 which looks for CVEs in node module dependencies.
- [yarn audit](docs/scanners/yarn_audit.md) - Execution of [`yarn audit`](https://yarnpkg.com/lang/en/docs/cli/audit/) 1.22.0 which looks for CVEs in node module dependencies.
- [PatternSearch](docs/scanners/pattern_search.md) - Execution of [`sift`](https://sift-tool.org/docs) 0.9.0, looks for certain strings in a project that might be dangerous or could require that certain strings be present.
- [Cargo Audit](docs/scanners/cargo_audit.md) - Execution of [Cargo Audit](https://github.com/RustSec/cargo-audit) 0.14.0 Audit Cargo.lock files for crates with security vulnerabilities reported to the RustSec Advisory Database

## Dependency Tracking

Salus also parses dependency files and reports which libraries and versions are being used. This can be useful for tracking dependencies across your fleet.

Currently supported languages are:
- Ruby
- Node.js (Javascript)
- Python
- Go
- Rust

## Configuration

Salus is designed to be [highly configurable](docs/configuration.md) so that it can work in many different types of environments and with many different scanners. It supports environment variable interpolation and cascading configurations, and can read configuration and post reports over HTTP.

Sometimes it's necessary to ignore certain CVEs, rules, tests, groups, directories, or otherwise modify the default configuration for a scanner. The [docs/scanners directory](docs/scanners) explains how to do so for each scanner that Salus supports.

If you would like to build custom scanners or support more languages that are not currently supported, you can use [this method of building custom Salus images](docs/custom_salus.md).

## CircleCI Integration

Salus can be integrated with CircleCI by using a public Orb. All Salus configuration options are supported, and defaults are the same as for Salus itself.

Example CircleCI `config.yml`:

```
version: 2.1

orbs:
  salus: federacy/salus@3.0.0

workflows:
  main:
    jobs:
      - salus/scan
```

[Orb documentation](integrations/circleci/README.md)

## Github Actions Integration

Salus can also be used with Github Actions.

Example `.github/workflows/main.yml`:

```
on: [push]

jobs:
  salus_scan_job:
    runs-on: ubuntu-latest
    name: Salus Security Scan Example
    steps:
    - uses: actions/checkout@v1
    - name: Salus Scan
      id: salus_scan
      uses: federacy/scan-action@0.1.1
```

[Github Action documentation](https://github.com/federacy/scan-action)

## Using Salus in your Repo

For your given CI, update the config file to run salus. In circle, it will look like this: 

```sh
docker run --rm -t -v $(pwd):/home/repo coinbase/salus
```

coinbase/salus pulls the docker image


## [Detailed Documentation](docs)

## 👷‍♂️ Development

Contribution to this project is extremely welcome and it's our sincere hope that the work we've done to this point only serves as a foundation for allowing the security/development communities as a whole to come together to improve the security of **everyone's** infrastructure.

You can read more about [getting your development environment set up](docs/development.md), or [the architecture of Salus](docs/architecture.md).

You can also find [steps to add a new scanner to Salus](docs/adding_scanner.md)

## 📃 License

This project is available open source under the terms of the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).
