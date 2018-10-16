<p align="center">
  <a href="https://salusscanner.org">
    <img width="350px" alt="Salus" src="logo.png">
  </a>
</p>
<h3 align="center">
   Salus: Guardian of Code Safety and Security
</h3>

[![CircleCI](https://circleci.com/gh/coinbase/salus/tree/master.svg?style=svg)](https://circleci.com/gh/coinbase/salus/tree/master)

## 🔍 Overview

Salus, named after the [Roman goddess of protection](https://en.wikipedia.org/wiki/Salus), is a tool for coordinating the execution of security scanners. You can run Salus on a repository via the Docker daemon and it will determine which scanners are relevant, run them and provide the output. Most scanners are other mature open source projects which we include directly in the container.

```sh
# Always run Salus from the root of your repository.
cd /path/to/repo

# One line command to run Salus locally with default configuration.
docker run --rm -t -v $(pwd):/home/repo coinbase/salus
```

Salus is particularly useful for CI/CD pipelines because it becomes a centralized place to coordinate scanning across a large fleet of repositories. Typically, scanners are configured at the repository level for each project. This means that when making org wide changes to how the scanners are run, each repository must be updated. Instead, you can update Salus and all builds will instantly inherit the change.

Salus supports powerful configuration that allows for global defaults and local tweaks. Finally, Salus can report metrics on each repository, such as what packages are included or what concerns exist. These reports can be centrally evaluated in your infrastructure to allow for scalable security tracking.

## Supported Scanners

- [BundleAudit](docs/scanners/bundle_audit.md) - Execution of [bundle-audit](https://github.com/rubysec/bundler-audit), looks for CVEs in ruby gem dependencies.
- [Brakeman](docs/scanners/brakeman.md) - Execution of [Brakeman](https://brakemanscanner.org/), looks for vulnerable code in Rails projects.
- [npm audit](docs/scanners/npm_audit.md) - Execution of [`npm audit`](https://docs.npmjs.com/getting-started/running-a-security-audit) which looks for CVEs in node module dependencies.
- [PatternSearch](docs/scanners/pattern_search.md) - Looks for certain strings in a project that might be dangerous or could require that certain strings be present.

Salus also parses dependency files and reports on what libraries and version are being used in any given project. This can be useful for tracking dependencies across your fleet.The currently supported languages are:
- Ruby
- Node
- Python
- Go

If you would like to build customer scanners or support more languages that are not currenclty supported, you can use [this method of building custom Salus images](docs/custom_salus.md).

## [Detailed Documentation](docs)

## 👷‍♂️ Development

Contribution to this project is extremely welcome and it's our sincere hope that the work we've done to this point only serves as a foundation for allowing the security/development communities as a whole to come together to improve the security of **everyone's** infrastructure.

You can read more about [getting your development environment set up](docs/development.md), or [the architecture of Salus](docs/architecture.md).

## 📃 License

This project is available open source under the terms of the [Apache 2.0 License](https://opensource.org/licenses/Apache-2.0).
