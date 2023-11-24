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

llvm_version=16

install_llvm() {
  if ! command -v -- "clang-$llvm_version" &> /dev/null
  then
    wget https://apt.llvm.org/llvm.sh -O /tmp/llvm.sh
    chmod +x /tmp/llvm.sh
    sudo /tmp/llvm.sh $llvm_version
  fi
}

ROOT_DIR=`git rev-parse --show-toplevel`


for TARGET in $1; do
  TARGET=`echo "$TARGET" | tr -d '[:space:]' | tr -d '\n' | tr -d '\r'`
  echo "building for $TARGET"
  rustup target add $TARGET

  case $TARGET in
    x86_64-unknown-linux-musl)
      install_llvm
      export CC=clang-$llvm_version
      export CXX=clang++-$llvm_version
      export CMAKE_TOOLCHAIN_FILE=$ROOT_DIR/scripts/cmake/x86_64-musl.cmake
      ;;
    aarch64-unknown-linux-gnu)
      sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu binutils-aarch64-linux-gnu libc6-dev-arm64-cross
      export CC=aarch64-linux-gnu-gcc
      export CXX=aarch64-linux-gnu-g++
      export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/usr/aarch64-linux-gnu"
      ;;
    aarch64-unknown-linux-musl)
      install_llvm
      export CC=clang-$llvm_version
      export CXX=clang++-$llvm_version
      export LDFLAGS="-fuse-ld=lld"
      export BINDGEN_EXTRA_CLANG_ARGS="--sysroot=/usr/aarch64-linux-gnu"
      export CMAKE_TOOLCHAIN_FILE=$ROOT_DIR/scripts/cmake/aarch64-musl.cmake
      ;;
    arm-unknown-linux-gnueabi | armv7-unknown-linux-gnueabi)
      sudo apt install -y gcc-arm-linux-gnueabi g++-arm-linux-gnueabi binutils-arm-linux-gnueabi libc6-dev-armel-cross
      export CC=arm-linux-gnueabi-gcc
      export CXX=arm-linux-gnueabi-g++
      ;;
    arm-unknown-linux-gnueabihf | armv7-unknown-linux-gnueabihf)
      sudo apt install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf binutils-arm-linux-gnueabihf libc6-dev-armhf-cross
      export CC=arm-linux-gnueabihf-gcc
      export CXX=arm-linux-gnueabihf-g++
      ;;
    arm-unknown-linux-musleabi)
      install_llvm
      export CC=clang-$llvm_version
      export CXX=clang++-$llvm_version
      export LDFLAGS="-fuse-ld=lld"
      export CMAKE_TOOLCHAIN_FILE=$ROOT_DIR/scripts/cmake/arm-musl.cmake
      ;;
    arm-unknown-linux-musleabihf)
      install_llvm
      export CC=clang-$llvm_version
      export CXX=clang++-$llvm_version
      export LDFLAGS="-fuse-ld=lld"
      export CMAKE_TOOLCHAIN_FILE=$ROOT_DIR/scripts/cmake/armhf-musl.cmake
      ;;
    armv7-unknown-linux-musleabi)
      install_llvm
      export CC=clang-$llvm_version
      export CXX=clang++-$llvm_version
      export LDFLAGS="-fuse-ld=lld"
      export CMAKE_TOOLCHAIN_FILE=$ROOT_DIR/scripts/cmake/armv7-musl.cmake
      ;;
    armv7-unknown-linux-musleabihf)
      install_llvm
      export CC=clang-$llvm_version
      export CXX=clang++-$llvm_version
      export LDFLAGS="-fuse-ld=lld"
      export CMAKE_TOOLCHAIN_FILE=$ROOT_DIR/scripts/cmake/armv7hf-musl.cmake
      ;;
    i686-unknown-linux-gnu)
      sudo apt install -y libc6-dev-i386
      ;;
    mips-unknown-linux-gnu)
      sudo apt install -y gcc-mips-linux-gnu g++-mips-linux-gnu binutils-mips-linux-gnu libc6-dev-mips-cross
      export CC=mips-linux-gnu-gcc
      export CXX=mips-linux-gnu-g++
      ;;
    mipsel-unknown-linux-gnu)
      sudo apt install -y gcc-mipsel-linux-gnu g++-mipsel-linux-gnu binutils-mipsel-linux-gnu libc6-dev-mipsel-cross
      export CC=mipsel-linux-gnu-gcc
      export CXX=mipsel-linux-gnu-g++
      ;;
    mips64-unknown-linux-gnuabi64)
      sudo apt install -y gcc-mips64-linux-gnuabi64 g++-mips64-linux-gnuabi64 binutils-mips64-linux-gnuabi64 libc6-dev-mips64-cross
      export CC=mips64-linux-gnuabi64-gcc
      export CXX=mips64-linux-gnuabi64-g++
      ;;
    mips64el-unknown-linux-gnuabi64)
      sudo apt install -y gcc-mips64el-linux-gnuabi64 g++-mips64el-linux-gnuabi64 binutils-mips64el-linux-gnuabi64 libc6-dev-mips64el-cross
      export CC=mips64el-linux-gnuabi64-gcc
      export CXX=mips64el-linux-gnuabi64-g++
      ;;
    powerpc-unknown-linux-gnu)
      sudo apt install -y gcc-powerpc-linux-gnu g++-powerpc-linux-gnu binutils-powerpc-linux-gnu libc6-dev-powerpc-cross
      export CC=powerpc-linux-gnu-gcc
      export CXX=powerpc-linux-gnu-g++
      ;;
    powerpc64-unknown-linux-gnu)
      sudo apt install -y gcc-powerpc64-linux-gnu g++-powerpc64-linux-gnu binutils-powerpc64-linux-gnu libc6-dev-powerpc64-cross
      export CC=powerpc64-linux-gnu-gcc
      export CXX=powerpc64-linux-gnu-g++
      ;;
    powerpc64le-unknown-linux-gnu)
      sudo apt install -y gcc-powerpc64le-linux-gnu g++-powerpc64le-linux-gnu binutils-powerpc64le-linux-gnu libc6-dev-powerpc64le-cross
      export CC=powerpc64le-linux-gnu-gcc
      export CXX=powerpc64le-linux-gnu-g++
      ;;
    s390x-unknown-linux-gnu)
      sudo apt install -y gcc-s390x-linux-gnu g++-s390x-linux-gnu binutils-s390x-linux-gnu libc6-dev-s390x-cross
      export CC=s390x-linux-gnu-gcc
      export CXX=s390x-linux-gnu-g++
      ;;
    riscv64gc-unknown-linux-gnu)
      sudo apt install -y gcc-riscv64-linux-gnu g++-riscv64-linux-gnu binutils-riscv64-linux-gnu libc6-dev-riscv64-cross
      export CC=riscv64-linux-gnu-gcc
      export CXX=riscv64-linux-gnu-g++
      ;;
  esac
  cargo build -p clash --target $TARGET --release
  ls -l ./target/$TARGET/release/
  mv ./target/$TARGET/release/clash ./target/artifacts/clash-$TARGET
done
