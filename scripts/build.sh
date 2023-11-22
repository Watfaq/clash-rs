#!/bin/sh

set -xe

[ ! -d "target/artifacts" ] && mkdir -p target/artifacts

os=`uname`
case $os in
  Linux)
    sudo apt update
    sudo apt install -y gcc-multilib gcc make
    ;;
esac


for TARGET in $1; do
  TARGET=`echo "$TARGET" | tr -d '[:space:]' | tr -d '\n' | tr -d '\r'`
  echo "building for $TARGET"
  rustup target add $TARGET

  case $TARGET in
    aarch64-unknown-linux-gnu)
      sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-arm64-cross
      export CC=aarch64-linux-gnu-gcc
      export CXX=aarch64-linux-gnu-g++
      export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/usr/aarch64-linux-gnu"
      ;;
    arm-unknown-linux-gnueabi)
      sudo apt install -y gcc-arm-linux-gnueabi g++-arm-linux-gnueabi binutils-arm-linux-gnueabi libc6-dev-armel-cross
      export CC=arm-linux-gnueabi-gcc
      export CXX=arm-linux-gnueabi-g++
      ;;
    armv7-unknown-linux-gnueabihf)
      sudo apt install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf binutils-arm-linux-gnueabihf libc6-dev-armhf-cross
      export CC=arm-linux-gnueabihf-gcc
      export CXX=arm-linux-gnueabihf-g++
      ;;
  esac
  cargo build -p clash --target $TARGET --release
  ls -l ./target/$TARGET/release/
  mv ./target/$TARGET/release/clash ./target/artifacts/clash-$TARGET
done
