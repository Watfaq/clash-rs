#!/bin/bash

set -e

LIB=libclash_rs.a
FRAMEWORK=out/clash-rs-ffi.xcframework

[[ -d bindings ]] && rm -rf bindings
mkdir -p bindings
 
# Build the dylib
cargo build -p clash_ffi
 
# Generate bindings
cargo run --features=uniffi/cli --bin uniffi-bindgen generate --library target/debug/$LIB --out-dir bindings --language swift
 
# Add the iOS targets and build
for TARGET in \
        aarch64-apple-darwin \
        aarch64-apple-ios \
        aarch64-apple-ios-sim \
        x86_64-apple-darwin \
        x86_64-apple-ios
do
    rustup target add $TARGET
    cargo build -p clash_ffi --release --target=$TARGET
done

  
# Recreate XCFramework
rm -rf "$FRAMEWORK"
xcodebuild -create-xcframework \
        -library ./target/aarch64-apple-ios-sim/release/$LIB -headers ./bindings \
        -library ./target/aarch64-apple-ios/release/$LIB -headers ./bindings \
        -output "$FRAMEWORK"
