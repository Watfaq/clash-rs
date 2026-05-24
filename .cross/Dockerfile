ARG CROSS_BASE_IMAGE
FROM $CROSS_BASE_IMAGE

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang llvm && \
    rm -rf /var/lib/apt/lists/*

ENV CC=clang
ENV CXX=clang++
ENV AR=llvm-ar

# sccache: distributed compilation cache via host TCP server
ARG SCCACHE_VERSION=0.15.0
RUN curl -LSfs https://github.com/mozilla/sccache/releases/download/v${SCCACHE_VERSION}/sccache-v${SCCACHE_VERSION}-x86_64-unknown-linux-musl.tar.gz \
    | tar xzf - -C /usr/local/bin --strip-components=1

# Container-local sccache server port (isolated from host on 4226)
ENV SCCACHE_SERVER_PORT=14266
