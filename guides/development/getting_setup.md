---
label: Getting Your Development Environment Setup
order: 101
---

# Environment Setup

To develop Salus, you will need to install Ruby and the relevant dependencies. Both Ruby gems and system dependencies are required depending on the scanners that are being executed.

#### Install dependencies
- install Ruby per https://www.ruby-lang.org/en/documentation/installation/
- for NPM, install per https://www.npmjs.com/get-npm
- for Yarn, install per https://classic.yarnpkg.com/en/docs/install/#mac-stable
- for Go reporting, install Go per https://golang.org/doc/install#install
- for PatternSearch, install sift per https://sift-tool.org/download
- for Semgrep, install semgrep per https://github.com/returntocorp/semgrep#getting-started
- for end-to-end tests and running Salus, install Docker per https://docs.docker.com/install

---

#### Install gems
```sh Install gems
gem install bundler
bundle install
```

---

#### Install docker
Docker is available on different operating systems. You can install the appropriate version for your operating system on the [Docker website](https://docs.docker.com/desktop/mac/install/)
+++ Mac

[Docker website](https://docs.docker.com/desktop/mac/install/)

```sh Installing Docker with Homebrew
brew install docker
```
+++Windows
[Install Docker for Windows](https://docs.docker.com/desktop/windows/install/)


+++ Linux

[Install Docker for Linux](https://docs.docker.com/engine/install/)
+++

---
## Running tests

If all installation was successful, you can run the test with rspec.

```sh
bundle exec rspec spec
```

There are also integration tests that check that the Salus container has all necessary dependencies installed in its container.

```sh
docker build -t salus-local .
docker build -f Dockerfile.tests -t salus-integration-tests .
docker run salus-integration-tests
```

---
