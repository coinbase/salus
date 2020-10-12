FROM ruby:2.7.2@sha256:0fee695f3bf397bb521d8ced9e30963835fac44bc27f46393a5b91941c8a40aa
MAINTAINER security@coinbase.com

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
  && rm -rf /var/lib/apt/lists/*

# Rust
# We'll download rust manually to ensure signing looks good
COPY .rust-key.gpg.ascii .rust-key.gpg.ascii
COPY .rust-pgp-signature.asc rust-1.46.0-x86_64-unknown-linux-gnu.tar.gz.asc
RUN wget https://static.rust-lang.org/dist/rust-1.46.0-x86_64-unknown-linux-gnu.tar.gz
RUN cat .rust-key.gpg.ascii | gpg --import
RUN gpg --verify rust-1.46.0-x86_64-unknown-linux-gnu.tar.gz.asc rust-1.46.0-x86_64-unknown-linux-gnu.tar.gz
RUN tar -xf rust-1.46.0-x86_64-unknown-linux-gnu.tar.gz
RUN rust-1.46.0-x86_64-unknown-linux-gnu/install.sh
ENV PATH="/root/.cargo/bin:${PATH}"
RUN cargo install cargo-audit --version 0.12.0

# Required so that Brakeman doesn't run into encoding
# issues when it parses non-ASCII characters.
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

### JS + NODE
ENV NODE_VERSION 13.8.0
ENV NPM_VERSION 6.14.8
ENV YARN_VERSION 1.22.0
ENV NPM_CONFIG_LOGLEVEL info

# Downloaded from https://nodejs.org/en/download/
# Replace file if node js upgrade
COPY node_SHASUMS256.txt SHASUMS256.txt

RUN curl -SLO "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" \
  && grep " node-v$NODE_VERSION-linux-x64.tar.xz\$" SHASUMS256.txt | sha256sum -c -         \
  && tar -xJf "node-v$NODE_VERSION-linux-x64.tar.xz" -C /usr/local --strip-components=1     \
  && rm "node-v$NODE_VERSION-linux-x64.tar.xz" SHASUMS256.txt                               \
  && npm install -g npm@$NPM_VERSION                                                        \
  && npm install -g yarn@$YARN_VERSION

### GO - required for sift and gosec
ENV GO111MODULE on
ENV GOLANG_VERSION 1.13.7
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 b3dd4bd781a0271b33168e627f7f43886b4c5d1c794a4015abf34e99c6526ca3
ENV SIFT_VERSION v0.9.0
ENV GOSEC_VERSION 2.4.0
ENV GOSEC_DOWNLOAD_URL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
ENV GOSEC_DOWNLOAD_SHA256 3bb01d20a74342251854a429c3fa82a7b642eb6a467926407fda3c1364531c9d

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
  && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
  && tar -C /usr/local -xzf golang.tar.gz \
  && rm golang.tar.gz \
  && mv /usr/local/go/bin/go /usr/bin/

RUN go get github.com/svent/sift@$SIFT_VERSION \
  && mv /root/go/bin/sift /usr/bin/

RUN curl -sfL "$GOSEC_DOWNLOAD_URL" -o gosec.tar.gz \
  && echo "$GOSEC_DOWNLOAD_SHA256 gosec.tar.gz" | sha256sum -c - \
  && tar -zxf gosec.tar.gz \
  && mv gosec /usr/bin

### semgrep tool install https://semgrep.dev
ENV SEMGREP_VERSION 0.14.0
ENV SEMGREP_TARBALL_FILE semgrep-v$SEMGREP_VERSION-ubuntu-16.04.tgz
ENV SEMGREP_DOWNLOAD_URL https://github.com/returntocorp/semgrep/releases/download/v$SEMGREP_VERSION/$SEMGREP_TARBALL_FILE
ENV SEMGREP_DOWNLOAD_SHA256 8b9437af0540ed9664904f9603d9d6ad011dad46433cba74e524c7753c7732c9

RUN curl -fsSL "$SEMGREP_DOWNLOAD_URL" -o semgrep.tar.gz \
  && echo "$SEMGREP_DOWNLOAD_SHA256 semgrep.tar.gz" | sha256sum -c - \
  && tar -C /usr/local/lib -xzf semgrep.tar.gz \
  && rm semgrep.tar.gz \
  && ln -sf /usr/local/lib/semgrep-files/semgrep /usr/local/bin/semgrep \
  && ln -sf /usr/local/lib/semgrep-files/semgrep-core /usr/local/bin/semgrep-core

### Salus

# make the folder for the repo (volumed in)
RUN mkdir -p /home/repo
WORKDIR /home

# make sure we're on latest bundler
RUN gem install bundler -v'2.0.2'

# ruby gems
COPY Gemfile Gemfile.lock /home/
RUN gem update --system
RUN bundle install --deployment --without development:test

# node modules
COPY package.json yarn.lock /home/
RUN yarn

# prime the bundler-audit CVE DB
RUN bundle exec bundle-audit update

# install wheel, needed by bandit
RUN pip install wheel
RUN pip3 install wheel

# Install bandit, python static code scanner
RUN pip install bandit==1.6.2
RUN mv /usr/local/bin/bandit /usr/local/bin/bandit2
RUN pip3 install bandit==1.6.2

# copy salus code
COPY bin /home/bin
COPY lib /home/lib
COPY salus-default.yaml /home/

# run the salus scan when this docker container is run
ENTRYPOINT ["bundle", "exec", "./bin/salus", "scan"]
