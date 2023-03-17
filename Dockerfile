FROM ruby:3.2.1@sha256:b4a140656b0c5d26c0a80559b228b4d343f3fdbf56682fcbe88f6db1fa9afa6b as builder
MAINTAINER security@coinbase.com

RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends \
  g++ \
  gcc \
  libc6-dev \
  make \
  pkg-config \
  curl \
  git  \
  python3 \
  python3-pip \
  python3-setuptools \
  python3-dev \
  libpython3-dev \
  libicu-dev \
  cmake \
  pkg-config \
  wget \
  unzip

WORKDIR /root


# TODO install JDK 17 instead
### RUN apt-get update; \
###    apt-get install -y openjdk-17 apt-transport-https && \
###    apt-get update

### JDK
RUN wget https://download.java.net/java/GA/jdk11/9/GPL/openjdk-11.0.2_linux-x64_bin.tar.gz -P /tmp
RUN tar xvf /tmp/openjdk-11.0.2_linux-x64_bin.tar.gz -C /

### Gradle 7
RUN wget https://services.gradle.org/distributions/gradle-7.5.1-bin.zip -P /tmp
RUN unzip -d /opt/gradle /tmp/gradle-*.zip

### Gradle 6
RUN wget https://services.gradle.org/distributions/gradle-6.9.2-bin.zip -P /tmp2
RUN unzip -d /opt/gradle /tmp2/gradle-*.zip

ENV GRADLE_HOME="/opt/gradle/gradle-7.5.1"
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
ENV BANDIT_VERSION 1.7.5

# /root/.local/bin/bandit
# added pip3 install --user importlib_metadata==4.7.1
# because the newer version causes a bandit error that is only reproducible with circle ci
# "No such file or directory: '/root/.cache/python-entrypoints/"
RUN pip3 install wheel \
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

ENV GOLANG_VERSION 1.19.3
ENV GOLANG_DOWNLOAD_SHA256 74b9640724fd4e6bb0ed2a1bc44ae813a03f1e72a4c76253e2d5c015494430ba

ENV GOLANG_TARBALL_FILE go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/${GOLANG_TARBALL_FILE}

ENV GOSEC_VERSION 2.12.0
ENV GOSEC_TARBALL_FILE gosec_${GOSEC_VERSION}_linux_amd64.tar.gz
ENV GOSEC_DOWNLOAD_URL https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/${GOSEC_TARBALL_FILE}
ENV GOSEC_DOWNLOAD_SHA256 86797d46d40c0697fa7d7104fe8971a058616f8cb5785786574d1d3b3087a8ea
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

### truffle hog

ENV TRUFFLEHOG_VERSION 3.19.0
ENV TRUFFLEHOG_TARBALL trufflehog_${TRUFFLEHOG_VERSION}_linux_amd64.tar.gz
ENV TRUFFLEHOG_DOWNLOAD_URL https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/${TRUFFLEHOG_TARBALL}
ENV TRUFFLEHOG_DOWNLOAD_SHA c481e856e90af1a19ee847838adaa15220c3b0cf147ba940f88c23fb067bdcf3

RUN mkdir /root/trufflehog_files
RUN curl -fsSL "$TRUFFLEHOG_DOWNLOAD_URL" -o trufflehog.tar.gz \
  && echo "$TRUFFLEHOG_DOWNLOAD_SHA trufflehog.tar.gz" | sha256sum -c - \
  && tar -C /root/trufflehog_files -xzf trufflehog.tar.gz \
  && ln -sf /root/trufflehog_files/trufflehog /usr/local/bin

### semgrep
# https://semgrep.dev
ENV SEMGREP_VERSION 1.0.0

RUN pip3 install --user --no-cache-dir semgrep==${SEMGREP_VERSION}


### Ruby
COPY Gemfile Gemfile.lock ./
RUN bundle install --deployment --without development:test

# RipGrep - Used for recusive searches
RUN curl -LO https://github.com/BurntSushi/ripgrep/releases/download/13.0.0/ripgrep_13.0.0_amd64.deb
RUN dpkg -i ripgrep_13.0.0_amd64.deb


FROM ruby:3.2.1-slim@sha256:e799a6b57cfe691741744373cae0aea1b34b99d00a607a76c8dc7d3055bf85dd

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
  python3-minimal \
  python3-setuptools \
  python3-pip \
  curl \
  git \
  vim \
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
COPY --from=builder /root/trufflehog_files/trufflehog /usr/local/bin
COPY --from=builder /usr/local/bin/cargo /usr/local/bin
COPY --from=builder /root/vendor /home/vendor
COPY --from=builder /root/.local /root/.local
COPY --from=builder /root/.cargo /root/.cargo
COPY --from=builder /usr/local/go /usr/local/go
COPY --from=builder /usr/bin/rg /usr/bin/rg
COPY --from=builder /jdk-11.0.2 /jdk-11.0.2
ENV JAVA_HOME /jdk-11.0.2
COPY --from=builder /opt/gradle/gradle-7.5.1 /opt/gradle/gradle-7.5.1
ENV PATH="/opt/gradle/gradle-7.5.1/bin:${PATH}"

COPY --from=builder /opt/gradle/gradle-6.9.2 /opt/gradle/gradle-6.9.2

RUN ln -sf /usr/local/go/bin/go /usr/local/bin

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



