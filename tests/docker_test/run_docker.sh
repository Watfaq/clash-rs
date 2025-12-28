cd "$(dirname "$0")"
docker build -t clash-test .
docker run -v $(pwd)/../../:/root/clash-rs clash-test