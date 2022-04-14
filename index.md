---
label: Salus Overview
icon: home
---
Salus (Security Automation as a Lightweight Universal Scanner), named after the [Roman goddess of protection](https://en.wikipedia.org/wiki/Salus), is a tool for coordinating the execution of security scanners. You can run Salus on a repository via the Docker daemon and it will determine which scanners are relevant, run them and provide the output. Most scanners are other mature open source projects which we include directly in the container.

Salus is particularly useful for CI/CD pipelines because it becomes a centralized place to coordinate scanning across a large fleet of repositories. Typically, scanners are configured at the repository level for each project. This means that each repository must be updated when making org-wide changes to how the scanners are run. Instead, you can update Salus and all builds will instantly inherit the change.

Salus provides extensive configurations that allow for global defaults and local tweaks. Finally, Salus can report metrics on each repository, such as what packages are included or what concerns exist. These reports can be centrally evaluated in your infrastructure to allow scalable security tracking.

---
## Supported Scanners
Salus serves as an orchestrator for security scanners. Salus triggers the appropriate scanners if a project meets a scanner's requirements

Salus currently supports the following scanners:

Scanner | Description
--- | --- 
[Bandit](/configuration/scanners/bandit/) | This scanner executes [`Bandit 1.6.2`](https://pypi.org/project/bandit/) which looks for common security issues in Python code.
[Brakeman](/configuration/scanners/brakeman.md) | This scanner executes [`Brakeman 4.10.0`](https://brakemanscanner.org/) which looks for vulnerable code in Rails projects.
[semgrep](/configuration/scanners/semgrep.md) | This scanner executes [`semgrep 0.62.0`](https://semgrep.dev) which looks for semantic and syntactical patterns in code at the AST level.
[BundleAudit](/configuration/scanners/bundle_audit.md) | This scanner executes [`bundle-audit 0.8.0`](https://github.com/rubysec/bundler-audit) which looks for CVEs in ruby gem dependencies.
[Gosec](/configuration/scanners/gosec.md) | This scanner executes [`gosec 2.11.0`](https://github.com/securego/gosec) which looks for security problems in go code.
[npm audit](/configuration/scanners/npm_audit.md) | This scanner executes [`npm audit 6.14.8`](https://docs.npmjs.com/getting-started/running-a-security-audit) which looks for CVEs in node module dependencies.
[yarn audit](/configuration/scanners/yarn_audit.md) | This scanner executes [`yarn audit 1.22.0`](https://yarnpkg.com/lang/en/docs/cli/audit/) which looks for CVEs in node module dependencies.
[PatternSearch](/configuration/scanners/pattern_search.md) | This scanner executes [`sift 0.9.0`](https://sift-tool.org/docs) which looks for certain strings in a project that might be dangerous or could require that certain strings be present.
[Cargo Audit](/configuration/scanners/cargo_audit.md) | This scanner executes [`Cargo Audit 0.14.0`](https://github.com/RustSec/cargo-audit)scans Cargo.lock files for crates with security vulnerabilities reported to the RustSec Advisory Database

---

## Dependency Tracking
Salus also provides dependency reporting for the following languages:
- [Ruby](/configuration/scanners/dependency_scanners/)
- [Node.js](/configuration/scanners/dependency_scanners/) (Javascript)
- [Python](/configuration/scanners/dependency_scanners/)
- [Go](/configuration/scanners/dependency_scanners/)
- [Rust](/configuration/scanners/dependency_scanners/)
- [Rust](/configuration/scanners/dependency_scanners/)
- [Swift](/configuration/scanners/dependency_scanners/)

---

## Quick Start 

Docker is required to run Salus. The dependencies for the project are stored on a docker, which helps reduce the number of steps required to run Salus. 

Check out the [Getting Started Guide](guides/getting_started/) for detailed instructions or continue here for a more condensed process 

#### Installation
Docker is available on different operating systems. You can install the appropriate version for your operating system on the [Docker website](https://docs.docker.com/desktop/mac/install/)
+++ Mac

[Docker website](https://docs.docker.com/desktop/mac/install/)

``` Installing Docker with Homebrew
brew install docker
```
+++Windows
[Install Docker for Windows](https://docs.docker.com/desktop/windows/install/)


+++ Linux

[Install Docker for Linux](https://docs.docker.com/engine/install/)
+++


All Set! you are now ready to run Salus :sparkles:


#### Running Salus
Navigate to the root directory of the project you want to run Salus on
```sh
cd /path/to/repo
```
Run the following line in the root directory (No edits necessary). This will run the latest Version of Salus.
```sh 
docker run --rm -t -v $(pwd):/home/repo coinbase/Salus
```

Running specific versions of Salus is also possible. All you need to do is provide the version tag
```sh Running Salus Version 2.17.6
docker run --rm -t -v $(pwd):/home/repo coinbase/Salus:2.17.6
```

To view all versions of Salus, visit the [releases page](https://github.com/coinbase/Salus/releases)

---
## Configurations
Salus is [highly configurable](/configuration/salus_configurations/) to work in different environments and with different scanners. It supports [environment variable interpolation](/configuration/salus_configurations/#envar-interpolation) and [cascading configurations](/configuration/salus_configurations/#cascading-configurations) and can read configuration and post reports over HTTP.

Sometimes it's necessary to ignore certain CVEs, rules, tests, groups, directories, or otherwise modify the default configuration for a scanner. The [scanner configuration documentation](/configuration/scanners) explains how to do so for each scanner that Salus supports.

!!!
If you would like to build custom scanners or support more languages that are not currently supported, check out the guide for [creating custom scanners](/guides/development/adding_custom_scanners/).
!!!


##  Development 👷‍♂️

Contribution to this project is extremely welcome :icon-heart: and it's our sincere hope that the work we've done only serves as a foundation for allowing the security/development communities to come together to improve the security of **everyone's** infrastructure.

You can read more about [getting your development environment set up](/guides/development/getting_setup/), or [the architecture of Salus](/guides/development/architecture/).

## License 📃 

This project is available open source under the terms of the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).

---