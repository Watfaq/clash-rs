FROM alpine:latest
# Define an ARG for the target architecture
ARG TARGETARCH
COPY ./clash-rs/clash-${TARGETARCH} /usr/bin/clash
# The yq library installed here is used to rewrite the config.yaml configuration file for clash, merge it, and other related operations.
RUN apk update && apk add --no-cache -f yq && mkdir -p /root/.config/clash/ && chmod +x /usr/bin/clash
WORKDIR /root
ENTRYPOINT [ "/usr/bin/clash" ]
CMD [ "-d", "/root/.config/clash/" ]