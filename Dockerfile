FROM ruby:2.7.2@sha256:0fee695f3bf397bb521d8ced9e30963835fac44bc27f46393a5b91941c8a40aa as builder
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
  wget

WORKDIR /root


### Rust
ENV RUST_VERSION 1.46.0
ENV RUST_TARBALL_FILE rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.gz
ENV RUST_DOWNLOAD_URL https://static.rust-lang.org/dist/${RUST_TARBALL_FILE}
ENV CARGO_AUDIT_VERSION 0.12.0

# We'll download rust manually to ensure signing looks good
COPY build/rust-key.gpg.asc build/rust-pgp-signature.asc ./
RUN curl -fsSL "$RUST_DOWNLOAD_URL" -o rust.tar.gz \
  && gpg --import rust-key.gpg.asc \
  && gpg --verify rust-pgp-signature.asc rust.tar.gz \
  && mkdir rust \
  && tar -C rust -xf rust.tar.gz --strip-components=1 \
  && rust/install.sh \
  && cargo install cargo-audit --version "$CARGO_AUDIT_VERSION"


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
  && gem install bundler -v'2.0.2' \
  && gem update --system \
  && bundle install --deployment --no-cache --clean --with scanners \
  && bundle exec bundle audit update


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
  && ln -sf /usr/local/go/bin/go /usr/local/bin

RUN curl -fsSL "$GOSEC_DOWNLOAD_URL" -o gosec.tar.gz \
  && echo "$GOSEC_DOWNLOAD_SHA256 gosec.tar.gz" | sha256sum -c - \
  && mkdir gosec && tar -C gosec -zxf gosec.tar.gz


### sift
ENV SIFT_VERSION v0.9.0

RUN go get github.com/svent/sift@${SIFT_VERSION}


### semgrep
# https://semgrep.dev
ENV SEMGREP_VERSION 0.36.0

RUN pip3 install --user --no-cache-dir semgrep==${SEMGREP_VERSION}


### Ruby
COPY Gemfile Gemfile.lock ./
RUN bundle install --deployment --without development:test



FROM ruby:2.7.2-slim

ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"

# Required so that Brakeman doesn't run into encoding
# issues when it parses non-ASCII characters.
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
  python-minimal \
  python-setuptools \
  python3-minimal \
  python3-setuptools \
  curl \
  git \
  && rm -rf /var/lib/apt/lists/*


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
  && cd /home \
  && yarn install \
  && rm -rf package.json yarn.lock /tmp/* ~/.npm


### All other tools
ENV PIP_VERSION 18.1
COPY --from=builder /root/go/bin/sift /usr/local/bin
COPY --from=builder /root/gosec/gosec /usr/local/bin
COPY --from=builder /usr/local/bin/cargo /usr/local/bin
COPY --from=builder /root/vendor /home/vendor
COPY --from=builder /root/.local /root/.local
COPY --from=builder /root/.cargo /root/.cargo
COPY --from=builder /usr/local/go /usr/local/go
RUN ln -sf /usr/local/go/bin/go /usr/local/bin
RUN python -m easy_install pip==${PIP_VERSION} \
  && python3 -m easy_install pip==${PIP_VERSION}


### Salus
WORKDIR /home

# make the folder for the repo (volumed in)
RUN mkdir -p /home/repo

# copy salus code
COPY Gemfile Gemfile.lock ./
COPY bin /home/bin
COPY lib /home/lib
COPY salus-default.yaml /home/

# install salus dependencies
RUN gem install bundler -v'2.0.2' \
  && bundle config --local path vendor/bundle \
  && bundle config --local without development:test

# run the salus scan when this docker container is run
ENTRYPOINT ["bundle", "exec", "./bin/salus", "scan"]
