# Salus Development

## Installation

To develop Salus, you will need to install Ruby and the relevant dependencies. Both Ruby gems and system dependencies are required depending on the scanners that are being executed.

```
### install Ruby per https://www.ruby-lang.org/en/documentation/installation/

### Install gems
gem install bundler
bundle install

### Install other system dependencies
# for NPM, install per https://www.npmjs.com/get-npm
# for Yarn, install per https://classic.yarnpkg.com/en/docs/install/#mac-stable
# for Go reporting, install Go per https://golang.org/doc/install#install
# for PatternSearch, install sift per https://sift-tool.org/download
# for Semgrep, install semgrep per https://github.com/returntocorp/semgrep#getting-started
# for end-to-end tests and running Salus, install Docker per https://docs.docker.com/install
```

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
