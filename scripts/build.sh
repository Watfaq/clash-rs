#!/bin/sh

set -xe

[ ! -d "target/artifacts" ] && mkdir -p target/artifacts

for TARGET in $1; do
  TARGET=$TARGET | tr -d '[:space:]' | tr -d '\n' | tr -d '\r'
  echo "building for $TARGET"
  rustup target add $TARGET
  cargo build -p clash --target $TARGET --release
  ls -l ./target/$TARGET/release/
  mv ./target/$TARGET/release/clash ./target/artifacts/clash-$TARGET
done
