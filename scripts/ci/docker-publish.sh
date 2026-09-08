#!/usr/bin/env bash
set -euo pipefail

# Directory setup
DIST_DIR="${DIST_DIR:-dist}"
DOCKER_BINS_DIR="./docker-bins"
IMAGE_NAME="${DOCKER_IMAGE_NAME:-ghcr.io/watfaq/clash-rs}"
DOCKERFILE="${DOCKERFILE:-.github/Dockerfile}"

mkdir -p "$DOCKER_BINS_DIR"

# Ensure required musl binaries exist
AMD64_BIN="clash-rs-x86_64-unknown-linux-musl"
ARM64_BIN="clash-rs-aarch64-unknown-linux-musl"

if [ -f "$DIST_DIR/$AMD64_BIN" ]; then
    cp "$DIST_DIR/$AMD64_BIN" "$DOCKER_BINS_DIR/$AMD64_BIN"
elif [ ! -f "$DOCKER_BINS_DIR/$AMD64_BIN" ]; then
    echo "❌ Error: $AMD64_BIN not found in $DIST_DIR or $DOCKER_BINS_DIR" >&2
    exit 1
fi

if [ -f "$DIST_DIR/$ARM64_BIN" ]; then
    cp "$DIST_DIR/$ARM64_BIN" "$DOCKER_BINS_DIR/$ARM64_BIN"
elif [ ! -f "$DOCKER_BINS_DIR/$ARM64_BIN" ]; then
    echo "❌ Error: $ARM64_BIN not found in $DIST_DIR or $DOCKER_BINS_DIR" >&2
    exit 1
fi

chmod +x "$DOCKER_BINS_DIR/$AMD64_BIN" "$DOCKER_BINS_DIR/$ARM64_BIN"

# Registry login
if [ -n "${DOCKER_PASSWORD:-}" ] && [ -n "${DOCKER_USERNAME:-}" ]; then
    REGISTRY="${DOCKER_REGISTRY:-}"
    echo "Logging in to Docker registry $REGISTRY..."
    echo "$DOCKER_PASSWORD" | docker login $REGISTRY -u "$DOCKER_USERNAME" --password-stdin
elif [ -n "${ADMIN_PAT:-}" ] && [[ "$IMAGE_NAME" == ghcr.io/* ]]; then
    ACTOR="${GITHUB_ACTOR:-${CIRCLE_PROJECT_USERNAME:-watfaq}}"
    echo "Logging in to ghcr.io as $ACTOR..."
    echo "$ADMIN_PAT" | docker login ghcr.io -u "$ACTOR" --password-stdin
else
    echo "⚠️ Warning: No registry credentials found. Docker push may fail if authentication is required."
fi

# Determine tags
TAG_ARGS=()
GIT_TAG="${CIRCLE_TAG:-$(git describe --tags --exact-match 2>/dev/null || echo "")}"
BRANCH="${CIRCLE_BRANCH:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "")}"

if [[ "$GIT_TAG" =~ ^v[0-9] ]]; then
    CLEAN_VER="${GIT_TAG#v}"
    TAG_ARGS+=("-t" "$IMAGE_NAME:$GIT_TAG")
    TAG_ARGS+=("-t" "$IMAGE_NAME:$CLEAN_VER")
    TAG_ARGS+=("-t" "$IMAGE_NAME:latest")
elif [ "$BRANCH" = "master" ]; then
    TAG_ARGS+=("-t" "$IMAGE_NAME:alpha")
    TAG_ARGS+=("-t" "$IMAGE_NAME:latest")
else
    TAG_ARGS+=("-t" "$IMAGE_NAME:test")
fi

echo "Tags to build: ${TAG_ARGS[*]}"

# Setup buildx
echo "Setting up Docker buildx..."
docker run --privileged --rm tonistiigi/binfmt --install all 2>/dev/null || true
docker buildx create --name clash_builder --use 2>/dev/null || docker buildx use clash_builder
docker buildx inspect --bootstrap

# Build and push multi-arch image
echo "Building and pushing multi-platform image..."
docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --build-arg BINARY_DIR="$DOCKER_BINS_DIR" \
    --build-arg SERVER_BINARY_AMD64="$AMD64_BIN" \
    --build-arg SERVER_BINARY_ARM64="$ARM64_BIN" \
    -f "$DOCKERFILE" \
    "${TAG_ARGS[@]}" \
    --push .

echo "🎉 Docker image published successfully!"
