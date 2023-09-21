#!/bin/sh

set -xe

[ ! -d "target/artifacts" ] && mkdir target/artifacts



for TARGET in $1; do
  echo "building for $TARGET"
  rustup target add $TARGET
  case $TARGET in
  aarch64-unknown-linux-gnu)
    sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
    export BINDGEN_EXTRA_CLANG_ARGS='-I/usr/aarch64-linux-gnu/include'
      ;;
  *)
      ;;
  esac
  cargo build -p clash --target $TARGET --release
  mv ./target/$TARGET/release/clash ./target/artifacts/clash-$TARGET
done
