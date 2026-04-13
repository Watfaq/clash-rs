cd "$(dirname "$0")"
docker build -t clash-test .
docker run --privileged -v $(pwd)/../../:/root/clash-rs clash-test