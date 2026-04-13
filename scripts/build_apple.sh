#!/bin/bash

set -e  # Exit on errors
set -o pipefail  # Fail pipeline if any command fails

# Targets
IOS_ARCHS=("aarch64-apple-ios" "x86_64-apple-ios" "aarch64-apple-ios-sim")
MACOS_ARCHS=("aarch64-apple-darwin" "x86_64-apple-darwin")

# Min deploy version
MIN_IOS_VERSION="17.0"
MIN_MACOS_VERSION="14.0"

# Variables
CRATE_NAME="clash-ffi"
LIB_NAME="clashrs"
OUTPUT_DIR="build"
FULL_APPLE_BUILD="false"

if [ "${1:-}" = "--full" ]; then
    FULL_APPLE_BUILD="true"
elif [ -n "${1:-}" ]; then
    echo "Usage: $0 [--full]"
    exit 1
fi

HEADERS_DIR="${OUTPUT_DIR}/Headers"
HEADER_FILE="${HEADERS_DIR}/${LIB_NAME}/${LIB_NAME}.h"
MODULEMAP_FILE="${HEADERS_DIR}/${LIB_NAME}/module.modulemap"
XCFRAMEWORK_DIR="${OUTPUT_DIR}/${LIB_NAME}.xcframework"

# Ensure the toolchain from rust-toolchain.toml is installed and switched
echo "Ensuring the Rust toolchain from rust-toolchain.toml is installed..."
if [ -f "rust-toolchain.toml" ]; then
    rustup show active-toolchain &> /dev/null || rustup install $(cat rust-toolchain.toml | grep -E 'channel\s*=' | cut -d'"' -f2)
else
    echo "Error: rust-toolchain.toml not found. Please ensure it exists in the project directory."
    exit 1
fi

# Force the use of the correct toolchain by running all cargo commands through `cargo +<toolchain>`
TOOLCHAIN=$(cat rust-toolchain.toml | grep -E 'channel\s*=' | cut -d'"' -f2)
echo "Using toolchain: $TOOLCHAIN"

# Ensure necessary tools are installed
echo "Checking for required tools..."
if ! command -v cbindgen &> /dev/null; then
    echo "Installing cbindgen..."
    cargo +$TOOLCHAIN install cbindgen
fi

# Install necessary Rust targets
echo "Installing necessary Rust targets..."
TARGETS=("${IOS_ARCHS[@]}")
if [ "$FULL_APPLE_BUILD" = "true" ]; then
    TARGETS+=("${MACOS_ARCHS[@]}")
fi

for target in "${TARGETS[@]}"; do
    rustup target add "$target" --toolchain $TOOLCHAIN || echo "Target $target is Tier 3 and may need local stdlib build."
done

# Generate C header file using cbindgen
echo "Generating C header file..."
cbindgen --config $CRATE_NAME/cbindgen.toml --crate $CRATE_NAME --output $HEADER_FILE
echo "Creating modulemap..."
cat > "$MODULEMAP_FILE" <<EOF
module $LIB_NAME {
    umbrella header "$(basename $HEADER_FILE)"
    export *
}
EOF

# Create output directory
mkdir -p "$OUTPUT_DIR"
mkdir -p "$HEADERS_DIR"

# Build for selected targets
if [ "$FULL_APPLE_BUILD" = "true" ]; then
    echo "Building library for iOS and macOS targets..."
else
    echo "Building library for iOS targets only..."
fi

for target in "${TARGETS[@]}"; do
    MACOSX_DEPLOYMENT_TARGET=$MIN_MACOS_VERSION IPHONEOS_DEPLOYMENT_TARGET=$MIN_IOS_VERSION cargo +$TOOLCHAIN build --target "$target" --release
    mkdir -p "$OUTPUT_DIR/$target"
    cp "target/$target/release/lib${LIB_NAME}.a" "$OUTPUT_DIR/$target/"
done

# Ensure directories for universal binaries
mkdir -p "$OUTPUT_DIR/ios-simulator-universal"
if [ "$FULL_APPLE_BUILD" = "true" ]; then
    mkdir -p "$OUTPUT_DIR/macos-universal"
fi

# Lipo operations for universal binaries
echo "Creating universal binaries using lipo..."

# iOS lipo: x86_64-apple-ios + aarch64-apple-ios-sim
# lipo -create \
#     "$OUTPUT_DIR/x86_64-apple-ios/lib${LIB_NAME}.a" \
#     "$OUTPUT_DIR/aarch64-apple-ios-sim/lib${LIB_NAME}.a" \
#     -output "$OUTPUT_DIR/ios-simulator-universal/lib${LIB_NAME}.a"

if [ "$FULL_APPLE_BUILD" = "true" ]; then
    # macOS lipo: aarch64-apple-darwin + x86_64-apple-darwin
    lipo -create \
        "$OUTPUT_DIR/aarch64-apple-darwin/lib${LIB_NAME}.a" \
        "$OUTPUT_DIR/x86_64-apple-darwin/lib${LIB_NAME}.a" \
        -output "$OUTPUT_DIR/macos-universal/lib${LIB_NAME}.a"
fi

# Create XCFramework
echo "Creating XCFramework..."
rm -rf "$XCFRAMEWORK_DIR"

if [ "$FULL_APPLE_BUILD" = "true" ]; then
    xcodebuild -create-xcframework \
        -library "$OUTPUT_DIR/aarch64-apple-ios/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
        -library "$OUTPUT_DIR/aarch64-apple-ios-sim/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
        -library "$OUTPUT_DIR/macos-universal/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
        -output "$XCFRAMEWORK_DIR"
else
    xcodebuild -create-xcframework \
        -library "$OUTPUT_DIR/aarch64-apple-ios/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
        -library "$OUTPUT_DIR/aarch64-apple-ios-sim/lib${LIB_NAME}.a" -headers "$HEADERS_DIR" \
        -output "$XCFRAMEWORK_DIR"
fi

echo "XCFramework created at $XCFRAMEWORK_DIR"

# Cleanup all intermediate files, keep only the XCFramework
echo "Cleaning up intermediate files..."
find "$OUTPUT_DIR" -mindepth 1 -maxdepth 1 ! -name "$(basename $XCFRAMEWORK_DIR)" -exec rm -rf {} +

echo "Done!"
