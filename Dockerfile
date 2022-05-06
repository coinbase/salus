# See ./.dockerignore

# The dockerfile uses offical docker images for 
# ruby, python, golang, node, and rust
# The various scanners are installed in each multistage build
# Our final image then copies the relevant binaries from each

FROM ruby:2.7.2  as builder
#@sha256:0fee695f3bf397bb521d8ced9e30963835fac44bc27f46393a5b91941c8a40aa as builder

# Maintainer has been deprecated in favor of using a maintainer label
LABEL "maintainer"="security@coinbase.com"

# We want to order our entries via the least frequently chaning to the
# most frequently chaning to take advantage of Docker's build-from-
# what-has-changed flow


# This is a bad practice - package versions may change between runs and apt-get will have
# to crawl the remote repo index *each* time

RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
  g++ \
  gcc \
  libc6-dev \
  make \
  pkg-config \
  curl \
  git  \
  python \
  python3 \
  python-pip \
  python3-pip \
  python-setuptools \
  python3-setuptools \
  python-dev \
  python3-dev \
  libpython-dev \
  libpython3-dev \
  libicu-dev \
  cmake \
  pkg-config \
  wget \
  unzip  && apt-get clean


# The apt-get clean above is to reduce the size of the image by removing
# the apt cache. 

WORKDIR /root

#ENV PIP_VERSION 18.1
#RUN python -m easy_install pip==${PIP_VERSION} \
#  && python3 -m easy_install pip==${PIP_VERSION}


### Python
# Install bandit, python static code scanner
ENV BANDIT_VERSION 1.6.2

RUN pip install wheel \
  && pip3 install wheel \
  && pip install --user bandit==${BANDIT_VERSION} \
  && mv .local/bin/bandit .local/bin/bandit2 \
  && pip3 install --user bandit==${BANDIT_VERSION}

### Ruby
# ruby gems
COPY Gemfile Gemfile.lock /home/
RUN cd /home \
  && gem install bundler -v '2.3.1' \
  && bundle config --local path /root/vendor/bundle \
  && gem update --system \
  && bundle install --deployment --no-cache --clean --with scanners \
  && bundle exec bundle audit update

### Semgrep
ENV SEMGREP_VERSION 0.62.0
RUN pip3 install --user --no-cache-dir semgrep==${SEMGREP_VERSION}

############################################
# Java Tooling
############################################
FROM openjdk:11 as java-builder

### Gradle 7
RUN wget https://services.gradle.org/distributions/gradle-7.3.3-bin.zip -P /tmp
RUN unzip -d /opt/gradle /tmp/gradle-*.zip

### Gradle 6
RUN wget https://services.gradle.org/distributions/gradle-6.9.2-bin.zip -P /tmp2
RUN unzip -d /opt/gradle /tmp2/gradle-*.zip

ENV GRADLE_HOME="/opt/gradle/gradle-7.3.3"
ENV PATH="${GRADLE_HOME}/bin:${PATH}"


############################################
# Golang Tooling
############################################

FROM golang:1.18.0  as golang-builder 
#@sha256:478fcf47d5d8269f9b530784cca11b0386776b1d16417a5e694673e985f44253 as golang-builder 

ENV GOSEC_VERSION 2.11.0
ENV GOSEC_TARBALL_FILE gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
ENV GOSEC_DOWNLOAD_URL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${GOSEC_TARBALL_FILE}
ENV GOSEC_DOWNLOAD_SHA256 1ee94e43df294981a9ae41d04dcfeae9cd1b015e738a5caaa860adb7ac1dccd8
ENV GO111MODULE on

RUN curl -fsSL "$GOSEC_DOWNLOAD_URL" -o gosec.tar.gz \
  && echo "$GOSEC_DOWNLOAD_SHA256 gosec.tar.gz" | sha256sum -c - \
  && mkdir gosec && tar -C gosec -zxf gosec.tar.gz

### sift
ENV SIFT_VERSION v0.9.0
RUN go install github.com/svent/sift@${SIFT_VERSION}

############################################
# Rust Tooling (Rust, Cargo Audit, Ripgrep)
############################################

FROM rust:1.60.0 as rust-builder
ENV CARGO_AUDIT_VERSION 0.14.0

RUN rustc --version && cargo --version
RUN apt-get update && apt-get install -y --no-install-recommends cmake
# && rm -rf /var/lib/apt/lists/*
# List directory /var/lib/apt/lists/partial is missing

RUN cargo install -f cargo-audit
# --version "$CARGO_AUDIT_VERSION"
RUN cargo install ripgrep --version 13.0.0


############################################
# Node Tooling (Npm, Yarn, Yarn-lockfile)
############################################

# We need to install yarn-lockfile so we have the tooling available to parse lock files

# This is quite old, we should update
#FROM node:13.8.0@sha256:fccea1cdcd5725a32d59be757d71f01390906a23c81e953f0cea410d6fc95aaf as node-builder
FROM node:17.8.0  as node-builder
#@sha256:87cea4658eb63b6bc1fb52a5f0c7f3c833615449f6e803cb8f2182f2a59ae09d as node-builder
COPY build/package.json build/yarn.lock /home/
ENV NPM_VERSION 6.14.8
ENV YARN_VERSION 1.22.0
ENV NPM_CONFIG_LOGLEVEL info

RUN cd /home && yarn install \
  && rm -rf package.json yarn.lock /tmp/* ~/.npm


############################################
####
#### Multistage final image
####
############################################


FROM ruby:2.7.2-slim
#@sha256:b9eebc5a6956f1def4698fac0930e7a1398a50c4198313fe87af0402cab8d149

ENV PATH="/root/.cargo/bin:/home/salus-cli/.local/bin:${PATH}"

# make the folder for the repo (volumed in)
RUN mkdir -p /home/repo

RUN useradd --shell /bin/bash salus-cli

ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"

# Required so that Brakeman doesn't run into encoding
# issues when it parses non-ASCII characters.
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8


# This is a bad practice - package versions may change between runs and apt-get will have
# to crawl the remote repo index *each* time

RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
  python-minimal \
  python-setuptools \
  python3-minimal \
  python3-setuptools \
  curl \
  git \
  file \
  && rm -rf /var/lib/apt/lists/*


### Copy tools built in the previous
### `builder` stage into this image

# Copy golang binaries 
COPY --from=golang-builder /go/bin/sift /usr/local/bin
COPY --from=golang-builder /go/gosec/gosec /usr/local/bin
COPY --from=golang-builder /usr/local/go/bin /usr/local/go/bin
COPY --from=golang-builder /usr/local/go/src /usr/local/go/src
RUN ln -sf /usr/local/go/bin/go /usr/local/bin # We could do an env var here too

# rust-builder tooling
COPY --from=rust-builder /usr/local/cargo/bin/cargo /usr/local/bin
COPY --from=rust-builder /usr/local/cargo/bin/rg /usr/bin/rg
#COPY --from=rust-builder /root/.cargo /root/.cargo
COPY --from=rust-builder /var/lib/apt/lists /var/lib/apt/lists

# Copy over our gems and 
#  /home/vendor/bundle/ruby/2.7.0/gems etc
COPY --from=builder /root/vendor /home/vendor
COPY --from=builder /root/.local /root/.local


# Copy npm & yarn binaries
# Not needed unless we want to run npm from image
COPY --from=node-builder /usr/local/bin/npm /usr/local/bin
COPY --from=node-builder /usr/local/bin/yarn /usr/local/bin
COPY --from=node-builder /usr/local/lib/node_modules /usr/local/lib/node_modules

ENV JAVA_HOME /jdk-11.0.15
COPY --from=java-builder /opt/gradle/gradle-7.3.3 /opt/gradle/gradle-7.3.3
COPY --from=java-builder /opt/gradle/gradle-6.9.2 /opt/gradle/gradle-6.9.2

ENV PATH="/opt/gradle/gradle-7.3.3/bin:${PATH}"

ENV PIP_VERSION 18.1
RUN python -m easy_install pip==${PIP_VERSION} \
  && python3 -m easy_install pip==${PIP_VERSION}

ENV PATH="/opt/gradle/bin:${PATH}"

### Salus
# Copy over our gem and salus code
COPY --chown=salus-cli:salus-cli --from=builder /root/.local /home/salus-cli/.local

USER salus-cli

# ENV HOME /home
WORKDIR /home

# copy salus code
COPY Gemfile Gemfile.lock /home/
COPY bin /home/bin
COPY lib /home/lib
COPY salus-default.yaml /home/

# Make sure bundler is pointing to the previosuly installed dpes
RUN gem install bundler -v'2.3.1' \
  && bundle config --local path /home/vendor/bundle \
  && bundle config --local without development:test


# run the salus scan when this docker container is run
ENTRYPOINT ["bundle", "exec", "./bin/salus", "scan"]
