#!/bin/sh

set -xe

[ ! -d "target/artifacts" ] && mkdir -p target/artifacts

for TARGET in $1; do
  TARGET=`echo "$TARGET" | tr -d '[:space:]' | tr -d '\n' | tr -d '\r'`
  echo "building for $TARGET"
  rustup target add $TARGET

  case $TARGET in
    aarch64-unknown-linux-gnu)
      sudo apt install -y gcc make gcc-aarch64-linux-gnu g++-aarch64-linux-gnu  binutils-aarch64-linux-gnu 
      export CC=aarch64-linux-gnu-gcc
      export CXX=aarch64-linux-gnu-g++
      export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/usr/aarch64-linux-gnu"
      ;;
    arm-unknown-linux-gnueabi)
      sudo apt install -y gcc make gcc-arm-linux-gnueabi g++-arm-linux-gnueabi binutils-arm-linux-gnueabi
      export CC=arm-linux-gnueabi-gcc
      export CXX=arm-linux-gnueabi-g++
      ;;
    armv7-unknown-linux-gnueabihf)
      sudo apt install -y gcc make gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf binutils-arm-linux-gnueabihf
      export CC=arm-linux-gnueabihf-gcc
      export CXX=arm-linux-gnueabihf-g++
      ;;
  esac
  cargo build -p clash --target $TARGET --release
  ls -l ./target/$TARGET/release/
  mv ./target/$TARGET/release/clash ./target/artifacts/clash-$TARGET
done
