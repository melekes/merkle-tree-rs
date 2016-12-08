FROM ubuntu:latest

RUN apt-get update && \
    apt-get install \
       ca-certificates \
       curl \
       gcc \
       libc6-dev \
       -qqy \
       --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

ENV RUST_ARCHIVE=rust-nightly-x86_64-unknown-linux-gnu.tar.gz
ENV RUST_DOWNLOAD_URL=https://static.rust-lang.org/dist/2016-11-25/$RUST_ARCHIVE

RUN mkdir /rust
WORKDIR /rust

RUN curl -fsOSL $RUST_DOWNLOAD_URL \
    && curl -s $RUST_DOWNLOAD_URL.sha256 | sha256sum -c - \
    && tar -C /rust -xzf $RUST_ARCHIVE --strip-components=1 \
    && rm $RUST_ARCHIVE \
    && ./install.sh

RUN mkdir /usr/src/lib
WORKDIR /usr/src/lib
