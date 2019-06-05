FROM ruby:2.4.6@sha256:3a31984805c5ad3b54baeb93d2c01c46845f681b712394b02d2e860cb5d5946b
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
    python-pip \
    python-setuptools \
    python-dev \
    libpython-dev \
    libicu-dev \
    cmake \
    pkg-config \
    wget \
  && rm -rf /var/lib/apt/lists/*

# Required so that Brakeman doesn't run into encoding
# issues when it parses non-ASCII characters.
ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

### JS + NODE
# Using node version 8.12.0 since it's the latest LTS.
ENV NODE_VERSION 8.12.0
ENV NPM_VERSION 6.4.1
ENV YARN_VERSION 1.12.3
ENV NPM_CONFIG_LOGLEVEL info

# Downloaded from https://nodejs.org/en/download/
COPY node_SHASUMS256.txt SHASUMS256.txt

RUN curl -SLO "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" \
  && grep " node-v$NODE_VERSION-linux-x64.tar.xz\$" SHASUMS256.txt | sha256sum -c -         \
  && tar -xJf "node-v$NODE_VERSION-linux-x64.tar.xz" -C /usr/local --strip-components=1     \
  && rm "node-v$NODE_VERSION-linux-x64.tar.xz" SHASUMS256.txt                               \
  && npm install -g npm@$NPM_VERSION                                                        \
  && npm install -g yarn@$YARN_VERSION

### GO - required for sift and gosec
ENV GO111MODULE on
ENV GOLANG_VERSION 1.12.4
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 d7d1f1f88ddfe55840712dc1747f37a790cbcaa448f6c9cf51bbe10aa65442f5
ENV SIFT_VERSION v0.9.0
ENV GOSEC_VERSION 2.0.0

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
  && echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
  && tar -C /usr/local -xzf golang.tar.gz \
  && rm golang.tar.gz \
  && mv /usr/local/go/bin/go /usr/bin/

RUN go get github.com/svent/sift@$SIFT_VERSION \
  && mv /root/go/bin/sift /usr/bin/

RUN go get github.com/securego/gosec/cmd/gosec@$GOSEC_VERSION \
  && mv /root/go/bin/gosec /usr/bin/

### Salus

# make the folder for the repo (volumed in)
RUN mkdir -p /home/repo
WORKDIR /home

# make sure we're on latest bundler
RUN gem install bundler

# ruby gems
COPY Gemfile Gemfile.lock /home/
RUN gem update --system
RUN bundle install --deployment --without development:test

# node modules
COPY package.json yarn.lock /home/
RUN yarn

# prime the bundler-audit CVE DB
RUN bundle exec bundle-audit update

# copy salus code
COPY bin /home/bin
COPY lib /home/lib
COPY salus-default.yaml /home/

# run the salus scan when this docker container is run
ENTRYPOINT ["bundle", "exec", "./bin/salus", "scan"]
