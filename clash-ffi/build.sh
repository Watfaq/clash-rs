#!/bin/bash

set -e

LIB=libclash_rs.a
FRAMEWORK=out/clash-rs-ffi.xcframework

[[ -d out ]] && rm -rf out
mkdir -p out

[[ -d bindings ]] && rm -rf bindings
mkdir -p bindings

# Build the dylib
cargo build -F ring -p clash-ffi

# Generate bindings
cargo run --features=uniffi/cli --bin uniffi-bindgen generate --library target/debug/$LIB --out-dir bindings --language swift

# Add the iOS targets and build
for TARGET in \
        aarch64-apple-ios \
        aarch64-apple-ios-sim; do
        rustup target add $TARGET
        # if simulator
        if [[ $TARGET == *-sim ]]; then
                export BINDGEN_EXTRA_CLANG_ARGS="-isysroot $(xcrun --sdk iphonesimulator --show-sdk-path)"

        else
                export BINDGEN_EXTRA_CLANG_ARGS="-isysroot $(xcrun --sdk iphoneos --show-sdk-path)"

        fi
        cargo build -F ring -p clash-ffi --release --target=$TARGET
done

# Recreate XCFramework
rm -rf "$FRAMEWORK"
xcodebuild -create-xcframework \
        -library ./target/aarch64-apple-ios-sim/release/$LIB -headers ./bindings \
        -library ./target/aarch64-apple-ios/release/$LIB -headers ./bindings \
        -output "$FRAMEWORK"
