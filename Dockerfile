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
  wget \
  unzip

WORKDIR /root

### JDK
RUN wget https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz -P /tmp
RUN tar xvf /tmp/openjdk-11.0.2_linux-x64_bin.tar.gz -C /

### Gradle 7
RUN wget https://services.gradle.org/distributions/gradle-7.3.3-bin.zip -P /tmp
RUN unzip -d /opt/gradle /tmp/gradle-*.zip

### Gradle 6
RUN wget https://services.gradle.org/distributions/gradle-6.9.2-bin.zip -P /tmp2
RUN unzip -d /opt/gradle /tmp2/gradle-*.zip

ENV GRADLE_HOME="/opt/gradle/gradle-7.3.3"
ENV PATH="${GRADLE_HOME}/bin:${PATH}"

### Rust
ENV RUST_VERSION 1.58.1
# Add a .sha256 to the rust download URL to get this sha
ENV RUST_VERSION_SHA256 4fac6df9ea49447682c333e57945bebf4f9f45ec7b08849e507a64b2ccd5f8fb
ENV RUST_TARBALL_FILE rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.gz
ENV RUST_DOWNLOAD_URL https://static.rust-lang.org/dist/${RUST_TARBALL_FILE}
ENV CARGO_AUDIT_VERSION 0.14.0

# Download manually and verify the hash
RUN curl -fsSL "$RUST_DOWNLOAD_URL" -o rust.tar.gz \
  && echo "$RUST_VERSION_SHA256 rust.tar.gz" | sha256sum -c - \
  && mkdir rust \
  && tar -C rust -xf rust.tar.gz --strip-components=1 \
  && rust/install.sh \
  && cargo install cargo-audit --version "$CARGO_AUDIT_VERSION"

### Python
# Install bandit, python static code scanner
ENV BANDIT_VERSION 1.6.2

# added pip3 install --user importlib_metadata==4.7.1
# because the newer version causes a bandit error that is only reproducible with circle ci
# "No such file or directory: '/root/.cache/python-entrypoints/"
RUN pip install wheel \
  && pip3 install wheel \
  && pip install --user bandit==${BANDIT_VERSION} \
  && mv .local/bin/bandit .local/bin/bandit2 \
  && pip3 install --user bandit==${BANDIT_VERSION} \
  && pip3 install --user importlib_metadata==4.7.1

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

ENV GOLANG_TARBALL_FILE go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/${GOLANG_TARBALL_FILE}

ENV GOSEC_VERSION 2.11.0
ENV GOSEC_TARBALL_FILE gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
ENV GOSEC_DOWNLOAD_URL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${GOSEC_TARBALL_FILE}
ENV GOSEC_DOWNLOAD_SHA256 1ee94e43df294981a9ae41d04dcfeae9cd1b015e738a5caaa860adb7ac1dccd8
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

RUN go install github.com/svent/sift@${SIFT_VERSION}


### semgrep
# https://semgrep.dev
ENV SEMGREP_VERSION 0.112.1

RUN pip3 install --user --no-cache-dir semgrep==${SEMGREP_VERSION}


### Ruby
COPY Gemfile Gemfile.lock ./
RUN bundle install --deployment --without development:test

# RipGrep - Used for recusive searches
RUN curl -LO https://github.com/BurntSushi/ripgrep/releases/download/13.0.0/ripgrep_13.0.0_amd64.deb
RUN dpkg -i ripgrep_13.0.0_amd64.deb


FROM ruby:2.7.2-slim@sha256:b9eebc5a6956f1def4698fac0930e7a1398a50c4198313fe87af0402cab8d149

ENV PATH="/root/.cargo/bin:/root/.local/bin:${PATH}"

# Required so that Brakeman doesn't run into encoding
# issues when it parses non-ASCII characters.
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
  make \
  cmake \
  g++ \
  gcc \
  python-minimal \
  python-setuptools \
  python3-minimal \
  python3-setuptools \
  curl \
  git \
  && rm -rf /var/lib/apt/lists/*



### JS + Node
ENV NODE_VERSION 16.15.1
ENV NODE_TARBALL_FILE node-v${NODE_VERSION}-linux-x64.tar.gz
ENV NODE_DOWNLOAD_URL https://nodejs.org/dist/v${NODE_VERSION}/${NODE_TARBALL_FILE}
ENV NODE_DOWNLOAD_SHA256 f78a49c0c9c2f546c3a44eb434c49a852125441422a1bcfc433dedc58d6a241c
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
  && rm -rf /node.tar.gz package.json yarn.lock /tmp/* ~/.npm


### Copy tools built in the previous
### `builder` stage into this image
ENV PIP_VERSION 18.1
COPY --from=builder /root/go/bin/sift /usr/local/bin
COPY --from=builder /root/gosec/gosec /usr/local/bin
COPY --from=builder /usr/local/bin/cargo /usr/local/bin
COPY --from=builder /root/vendor /home/vendor
COPY --from=builder /root/.local /root/.local
COPY --from=builder /root/.cargo /root/.cargo
COPY --from=builder /usr/local/go /usr/local/go
COPY --from=builder /usr/bin/rg /usr/bin/rg
COPY --from=builder /jdk-11.0.2 /jdk-11.0.2
ENV JAVA_HOME /jdk-11.0.2
COPY --from=builder /opt/gradle/gradle-7.3.3 /opt/gradle/gradle-7.3.3
ENV PATH="/opt/gradle/gradle-7.3.3/bin:${PATH}"

COPY --from=builder /opt/gradle/gradle-6.9.2 /opt/gradle/gradle-6.9.2

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
RUN gem install bundler -v'2.3.1' \
  && bundle config --local path vendor/bundle \
  && bundle config --local without development:test

# run the salus scan when this docker container is run
ENTRYPOINT ["bundle", "exec", "./bin/salus", "scan"]
