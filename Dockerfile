# A base image built by an ops bigwig, open source
FROM wener/base:latest
COPY ./clash-rs-upx /usr/local/bin/clash
RUN apk add --no-cache -f yq && mkdir -p /root/.config/clash/
WORKDIR /root
CMD ["/usr/local/bin/clash","-d", "/root/.config/clash/"]
