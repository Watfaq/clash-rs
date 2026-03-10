FROM alpine:latest
# Accept binary names and binary dir via build-args
ARG BINARY_DIR=./docker-bins
ARG SERVER_BINARY_AMD64=bin-amd64
ARG SERVER_BINARY_ARM64=bin-arm64

# copy prepared binaries into the image
COPY ${BINARY_DIR} /tmp/binaries/

# select correct binary based on TARGETARCH and move to /usr/bin/clash
ARG TARGETARCH
RUN if [ "${TARGETARCH}" = "amd64" ]; then \
      cp /tmp/binaries/${SERVER_BINARY_AMD64} /usr/bin/clash; \
    elif [ "${TARGETARCH}" = "arm64" ]; then \
      cp /tmp/binaries/${SERVER_BINARY_ARM64} /usr/bin/clash; \
    else \
      echo "Unsupported TARGETARCH: ${TARGETARCH}"; exit 1; \
    fi && \
    chmod +x /usr/bin/clash

# The yq library installed here is used to rewrite the config.yaml configuration file for clash, merge it, and other related operations.
RUN apk update && apk add --no-cache yq && mkdir -p /root/.config/clash/
WORKDIR /root
ENTRYPOINT [ "/usr/bin/clash" ]
CMD [ "-d", "/root/.config/clash/" ]
