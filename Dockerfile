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

WORKDIR /root

# Required so that Brakeman doesn't run into encoding
# issues when it parses non-ASCII characters.
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8


### Rust
ENV RUST_VERSION 1.46.0
ENV RUST_TARBALL_FILE rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.gz
ENV RUST_DOWNLOAD_URL https://static.rust-lang.org/dist/${RUST_TARBALL_FILE}
ENV CARGO_AUDIT_VERSION 0.12.0
ENV PATH="/root/.cargo/bin:${PATH}"

# We'll download rust manually to ensure signing looks good
COPY build/rust-key.gpg.asc build/rust-pgp-signature.asc ./
RUN curl -fsSL "$RUST_DOWNLOAD_URL" -o rust.tar.gz \
  && gpg --import rust-key.gpg.asc \
  && gpg --verify rust-pgp-signature.asc rust.tar.gz \
  && mkdir rust \
  && tar -C rust -xf rust.tar.gz --strip-components=1 \
  && rust/install.sh \
  && cargo install cargo-audit --version "$CARGO_AUDIT_VERSION" \
  && rm -rf rust rust.tar.gz rust-key.gpg.asc rust-pgp-signature.asc ~/.gnupg


### JS + Node
ENV NODE_VERSION 13.8.0
ENV NODE_TARBALL_FILE node-v${NODE_VERSION}-linux-x64.tar.gz
ENV NODE_DOWNLOAD_URL https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TARBALL_FILE}
ENV NODE_DOWNLOAD_SHA256 bf30432175ea8a95fa3e5fe09e96d9fc17b07099742d5c83c4cf9d0edfc411ff
ENV NPM_VERSION 6.14.8
ENV YARN_VERSION 1.22.0
ENV NPM_CONFIG_LOGLEVEL info

COPY build/package.json build/yarn.lock /home/
RUN curl -fsSL "$NODE_DOWNLOAD_URL" -o node.tar.gz \
  && echo "$NODE_DOWNLOAD_SHA256 node.tar.gz" | sha256sum -c - \
  && tar -C /usr/local -xzf node.tar.gz --strip-components=1 \
  && npm install -g npm@${NPM_VERSION} \
  && npm install -g yarn@${YARN_VERSION} \
  && rm node.tar.gz \
  && cd /home \
  && yarn install \
  && rm -rf package.json yarn.lock /tmp/* ~/.npm


### Python
# Install bandit, python static code scanner
ENV BANDIT_VERSION 1.6.2

RUN pip install wheel \
  && pip3 install wheel \
  && pip install bandit==${BANDIT_VERSION} \
  && mv /usr/local/bin/bandit /usr/local/bin/bandit2 \
  && pip3 install bandit==${BANDIT_VERSION} \
  && rm -rf ~/.cache


### Ruby
# ruby gems
COPY Gemfile Gemfile.lock /home/
RUN cd /home \
  && gem install bundler -v'2.0.2' \
  && gem update --system \
  && bundle install --with scanners \
  && bundle audit update


### Golang
# required for sift and gosec
ENV GOLANG_VERSION 1.13.7
ENV GOLANG_TARBALL_FILE go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/${GOLANG_TARBALL_FILE}
ENV GOLANG_DOWNLOAD_SHA256 b3dd4bd781a0271b33168e627f7f43886b4c5d1c794a4015abf34e99c6526ca3
ENV GOSEC_VERSION 2.4.0
ENV GOSEC_TARBALL_FILE gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
ENV GOSEC_DOWNLOAD_URL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${GOSEC_TARBALL_FILE}
ENV GOSEC_DOWNLOAD_SHA256 3bb01d20a74342251854a429c3fa82a7b642eb6a467926407fda3c1364531c9d
ENV GO111MODULE on

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
  && echo "$GOLANG_DOWNLOAD_SHA256 golang.tar.gz" | sha256sum -c - \
  && tar -C /usr/local -xzf golang.tar.gz \
  && ln -sf /usr/local/go/bin/go /usr/local/bin \
  && rm golang.tar.gz

RUN curl -fsSL "$GOSEC_DOWNLOAD_URL" -o gosec.tar.gz \
  && echo "$GOSEC_DOWNLOAD_SHA256 gosec.tar.gz" | sha256sum -c - \
  && mkdir gosec && tar -C gosec -zxf gosec.tar.gz \
  && mv gosec/gosec /usr/local/bin \
  && rm -rf gosec gosec.tar.gz


### sift
ENV SIFT_VERSION v0.9.0

RUN go get github.com/svent/sift@${SIFT_VERSION} \
  && mv /root/go/bin/sift /usr/local/bin \
  && rm -rf go ~/.cache


### semgrep
# https://semgrep.dev
ENV SEMGREP_VERSION 0.14.0
ENV SEMGREP_TARBALL_FILE semgrep-v${SEMGREP_VERSION}-ubuntu-16.04.tgz
ENV SEMGREP_DOWNLOAD_URL https://github.com/returntocorp/semgrep/releases/download/v${SEMGREP_VERSION}/${SEMGREP_TARBALL_FILE}
ENV SEMGREP_DOWNLOAD_SHA256 8b9437af0540ed9664904f9603d9d6ad011dad46433cba74e524c7753c7732c9

RUN curl -fsSL "$SEMGREP_DOWNLOAD_URL" -o semgrep.tar.gz \
  && echo "$SEMGREP_DOWNLOAD_SHA256 semgrep.tar.gz" | sha256sum -c - \
  && tar -C /usr/local/lib -xzf semgrep.tar.gz \
  && ln -sf /usr/local/lib/semgrep-files/semgrep /usr/local/bin/semgrep \
  && ln -sf /usr/local/lib/semgrep-files/semgrep-core /usr/local/bin/semgrep-core \
  && rm semgrep.tar.gz


### Salus
WORKDIR /home

# make the folder for the repo (volumed in)
RUN mkdir -p /home/repo

# ruby gems
COPY Gemfile Gemfile.lock /home/
RUN bundle install --deployment --without development:test

# copy salus code
COPY bin /home/bin
COPY lib /home/lib
COPY salus-default.yaml /home/

# run the salus scan when this docker container is run
ENTRYPOINT ["bundle", "exec", "./bin/salus", "scan"]
