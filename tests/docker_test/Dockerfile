FROM debian:latest

RUN apt-get update && apt-get install -y rustup cmake libclang-dev curl protobuf-compiler dnsutils iproute2
# install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

WORKDIR /root/clash-rs/
## To mount the whole clash-rs directory to /root/clash-rs in the container, use the following docker run option:
# docker run -v $(pwd)/../../..:/root/clash-rs ...
ENTRYPOINT [ "/root/.local/bin/uv" ]
CMD [ "run" , "--project", "/root/clash-rs/tests/docker_test/", "/root/clash-rs/tests/docker_test/main_test.py" ]