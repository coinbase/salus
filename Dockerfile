# See ./.dockerignore

# The dockerfile uses offical docker images for 
# ruby, python, golang, node, and rust
# The various scanners are installed in each multistage build
# Our final image then copies the relevant binaries from each




FROM ruby:2.7.2@sha256:0fee695f3bf397bb521d8ced9e30963835fac44bc27f46393a5b91941c8a40aa as builder

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

# pip above installs this
# /usr/bin/pip
# /usr/bin/pip3

#ENV PIP_VERSION 18.1
#RUN python -m easy_install pip==${PIP_VERSION} \
#  && python3 -m easy_install pip==${PIP_VERSION}



### JDK
RUN wget https://download.java.net/java/GA/jdk17.0.2/dfd4a8d0985749f896bed50d7138ee7f/8/GPL/openjdk-17.0.2_linux-x64_bin.tar.gz -P /tmp
RUN tar xvf /tmp/openjdk-17.0.2_linux-x64_bin.tar.gz -C /

### Gradle
RUN wget https://services.gradle.org/distributions/gradle-7.3.3-bin.zip -P /tmp
RUN unzip -d /opt/gradle /tmp/gradle-*.zip
ENV GRADLE_HOME="/opt/gradle/gradle-7.3.3"
ENV PATH="${GRADLE_HOME}/bin:${PATH}"

#TODO
# openjdk:19-jdk
# openjdk:17.0


### Rust
#ENV RUST_VERSION 1.58.1
## Add a .sha256 to the rust download URL to get this sha
#ENV RUST_VERSION_SHA256 4fac6df9ea49447682c333e57945bebf4f9f45ec7b08849e507a64b2ccd5f8fb
#ENV RUST_TARBALL_FILE rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.gz
#ENV RUST_DOWNLOAD_URL https://static.rust-lang.org/dist/${RUST_TARBALL_FILE}
#ENV CARGO_AUDIT_VERSION 0.14.0

# Download manually and verify the hash
#RUN curl -fsSL "$RUST_DOWNLOAD_URL" -o rust.tar.gz \
#  && echo "$RUST_VERSION_SHA256 rust.tar.gz" | sha256sum -c - \
#  && mkdir rust \
#  && tar -C rust -xf rust.tar.gz --strip-components=1 \
#  && rust/install.sh \
#  && cargo install cargo-audit --version "$CARGO_AUDIT_VERSION"


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
  && gem update --system \
  && bundle install --deployment --no-cache --clean --with scanners \
  && bundle exec bundle audit update


### Golang
# required for sift and gosec

ENV GOLANG_VERSION 1.18
ENV GOLANG_DOWNLOAD_SHA256 e85278e98f57cdb150fe8409e6e5df5343ecb13cebf03a5d5ff12bd55a80264f


### Ruby
COPY Gemfile Gemfile.lock ./
RUN bundle install --deployment --without development:test


### Semgrep
ENV SEMGREP_VERSION 0.62.0
RUN pip3 install --user --no-cache-dir semgrep==${SEMGREP_VERSION}



#COPY requirements.txt /requirements.txt
#RUN pip3 install -r /requirements.txt
#WORKDIR /app
#COPY . /app
#RUN pyinstaller run.py
#pip install lddcollect

# use `ldd` to find which libraries are called
#COPY --from=python-builder /lib/x86_64-linux-gnu/libdl.so.2 /lib/x86_64-linux-gnu/libdl.so.2
#COPY --from=python-builder /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
#COPY --from=python-builder /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libc.so.6

# this one was called from a python .so, which `ldd` did not pickup
#COPY --from=python-builder /lib/x86_64-linux-gnu/libutil.so.1 /lib/x86_64-linux-gnu/libutil.so.1


# /usr/local/bin/python
# /usr/local/bin/bandit


FROM golang:1.16.9 as golang-builder 

ENV GOLANG_TARBALL_FILE go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/${GOLANG_TARBALL_FILE}

ENV GOSEC_VERSION 2.11.0
ENV GOSEC_TARBALL_FILE gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
ENV GOSEC_DOWNLOAD_URL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${GOSEC_TARBALL_FILE}
ENV GOSEC_DOWNLOAD_SHA256 1ee94e43df294981a9ae41d04dcfeae9cd1b015e738a5caaa860adb7ac1dccd8
ENV GO111MODULE on


#RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
#  && echo "$GOLANG_DOWNLOAD_SHA256 golang.tar.gz" | sha256sum -c - \
#  && tar -C /usr/local -xzf golang.tar.gz \
#  && ln -sf /usr/local/go/bin/go /usr/local/bin

RUN curl -fsSL "$GOSEC_DOWNLOAD_URL" -o gosec.tar.gz \
  && echo "$GOSEC_DOWNLOAD_SHA256 gosec.tar.gz" | sha256sum -c - \
  && mkdir gosec && tar -C gosec -zxf gosec.tar.gz


### sift
ENV SIFT_VERSION v0.9.0

RUN go install github.com/svent/sift@${SIFT_VERSION}


# RipGrep - Used for recusive searches
#RUN curl -LO https://github.com/BurntSushi/ripgrep/releases/download/13.0.0/ripgrep_13.0.0_amd64.deb
#RUN dpkg -i ripgrep_13.0.0_amd64.deb


# Rust & Ripgrep
FROM rust:1.58.1 as rust-builder
ENV CARGO_AUDIT_VERSION 0.14.0
RUN cargo install cargo-audit --version "$CARGO_AUDIT_VERSION" && cargo install ripgrep --version 13.0.0


# Node - npm and yarn

# We need to install yarn-lockfile so we have the tooling available
# to parse lock files

FROM node:13.8.0 as node-builder
COPY build/package.json build/yarn.lock /home/
ENV NPM_VERSION 6.14.8
ENV YARN_VERSION 1.22.0
ENV NPM_CONFIG_LOGLEVEL info

#  npm install -g -f npm@${NPM_VERSION} \
#  && npm install -g yarn@${YARN_VERSION} \

RUN cd /home \
  && yarn install \
  && rm -rf package.json yarn.lock /tmp/* ~/.npm





######################################
####
#### Multistage final image
####
######################################





FROM ruby:2.7.2-slim@sha256:b9eebc5a6956f1def4698fac0930e7a1398a50c4198313fe87af0402cab8d149

# make the folder for the repo (volumed in)
RUN mkdir -p /home/repo

#RUN useradd -u 8877 salus
## Change to non-root privilege
#USER salus



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
  && rm -rf /var/lib/apt/lists/*



### JS + Node

#ENV NODE_VERSION 13.8.0
#ENV NODE_TARBALL_FILE node-v${NODE_VERSION}-linux-x64.tar.gz
#ENV NODE_DOWNLOAD_URL https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TARBALL_FILE}
#ENV NODE_DOWNLOAD_SHA256 bf30432175ea8a95fa3e5fe09e96d9fc17b07099742d5c83c4cf9d0edfc411ff
#ENV NPM_VERSION 6.14.8
#ENV YARN_VERSION 1.22.0
#ENV NPM_CONFIG_LOGLEVEL info
#
#
#COPY build/package.json build/yarn.lock /home/
#RUN curl -fsSL "$NODE_DOWNLOAD_URL" -o node.tar.gz \
#  && echo "$NODE_DOWNLOAD_SHA256 node.tar.gz" | sha256sum -c - \
#  && tar -C /usr/local -xzf node.tar.gz --strip-components=1 \
#  && npm install -g npm@${NPM_VERSION} \
#  && npm install -g yarn@${YARN_VERSION} \
#  && cd /home \
#  && yarn install \
#  && rm -rf /node.tar.gz package.json yarn.lock /tmp/* ~/.npm


### Copy tools built in the previous
### `builder` stage into this image


#/usr/local/go/bin/go

# /usr/local/bin/pip


# Copy golang binaries 
COPY --from=golang-builder /go/bin/sift /usr/local/bin
COPY --from=golang-builder /go/gosec/gosec /usr/local/bin
COPY --from=golang-builder /usr/local/go/bin /usr/local/go/bin
COPY --from=golang-builder /usr/local/go/src /usr/local/go/src
RUN ln -sf /usr/local/go/bin/go /usr/local/bin # We could do an env var here too


# Python pip - confirm this is still needed
#COPY --from=python-builder /usr/bin/python3 /usr/bin/python3 
#COPY --from=python-builder /var/lib/python /var/lib/python
#COPY --from=python-builder /usr/share/gcc/python /usr/share/gcc/python
## /usr/local/bin/bandit /usr/local/bin/semgrep
#COPY --from=python-builder /usr/local/bin/python  /usr/local/bin
#COPY --from=python-builder /root/.local /root/.local


# Semgrep
#COPY --from=python-builder /usr/local/bin/semgrep /root/.local/bin/semgrep
##COPY --from=python-builder /root/.local/lib/python3.7/site-packages/semgrep /root/.local/lib/python3.7/site-packages/semgrep
## /usr/bin/python3: error while loading shared libraries: libexpat.so.1: cannot open shared object file: No such file or directory


# Bandit
#COPY --from=python-builder /root/.local/bin/bandit /root/.local/bin/bandit
##COPY --from=python-builder /root/.local/bin/bandit2 /root/.local/bin/bandit2

# Cargo Audit
COPY --from=rust-builder /usr/local/cargo/bin/cargo /usr/local/bin
COPY --from=rust-builder /usr/local/cargo/bin/rg /usr/bin/rg
#COPY --from=rust-builder /root/.cargo /root/.cargo

COPY --from=builder /root/vendor /home/vendor
COPY --from=builder /root/.local /root/.local



# Copy npm & yarn binaries
# Not needed unless we want to run npm from image
COPY --from=node-builder /usr/local/bin/npm /usr/local/bin
COPY --from=node-builder /usr/local/bin/yarn /usr/local/bin
COPY --from=node-builder /usr/local/lib/node_modules /usr/local/lib/node_modules


#COPY --from=builder /jdk-17.0.2 /jdk-17.0.2
ENV JAVA_HOME /jdk-17.0.2
COPY --from=builder /opt/gradle/gradle-7.3.3 /opt/gradle/gradle-7.3.3
ENV PATH="/opt/gradle/gradle-7.3.3/bin:${PATH}"


#COPY --from=gradle:7.4.0 /opt/gradle /opt/gradle
#COPY --from=gradle:7.4.0 /opt/java/openjdk /opt/java/openjdk
#ENV JAVA_HOME /opt/java/openjdk
#ENV GRADLE_HOME /opt/gradle

ENV PIP_VERSION 18.1
RUN python -m easy_install pip==${PIP_VERSION} \
  && python3 -m easy_install pip==${PIP_VERSION}


ENV PATH="/opt/gradle/bin:${PATH}"

### Salus
WORKDIR /home

# copy salus code
COPY Gemfile Gemfile.lock ./
COPY bin /home/bin
COPY lib /home/lib
COPY salus-default.yaml /home/

# install salus dependencies
RUN gem install bundler -v'2.3.1' \
  && bundle config --local path vendor/bundle \
  && bundle config --local without development:test


#RUN useradd --create-home appuser
#WORKDIR /home/appuser
#USER appuser


#RUN useradd -ms /bin/bash salus
#USER salus

# Bandit, yarn, semgrep, npm


# run the salus scan when this docker container is run
ENTRYPOINT ["bundle", "exec", "./bin/salus", "scan"]
