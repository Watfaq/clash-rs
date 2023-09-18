workspace(name = "clash-rs")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# To find additional information on this release or newer ones visit:
# https://github.com/bazelbuild/rules_rust/releases

http_archive(
    name = "rules_rust",
    sha256 = "9d04e658878d23f4b00163a72da3db03ddb451273eb347df7d7c50838d698f49",
    urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.26.0/rules_rust-v0.26.0.tar.gz"],
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains(
    edition = "2021",
    versions = [
        "1.71.0",
    ],
)

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies()

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository", "splicing_config")

MACOS_BINDGEN_FLAGS = "-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include/"

LINUX_BINDGEN_FLAGS = "-I/usr/include/"

crates_repository(
    name = "crate_index",
    annotations = {
        "boring-sys": [crate.annotation(
            build_script_data = [
                "@//deps/boringssl:include",
            ],
            build_script_env = {
                "BORING_BAZEL_BUILD": "1",
                "BORING_BSSL_PATH": "$(GENDIR)/deps/boringssl",
                "BORING_BSSL_INCLUDE_PATH": "$(location @//deps/boringssl:include)",
                "BINDGEN_EXTRA_CLANG_ARGS_aarch64-apple-darwin": MACOS_BINDGEN_FLAGS,
                "BINDGEN_EXTRA_CLANG_ARGS_x86_64-apple-darwin": MACOS_BINDGEN_FLAGS,
                "BINDGEN_EXTRA_CLANG_ARGS_aarch64-unknown-linux-gnu": LINUX_BINDGEN_FLAGS,
                "BINDGEN_EXTRA_CLANG_ARGS_x86_64-unknown-linux-gnu": LINUX_BINDGEN_FLAGS,
            },
            data = [
                "@//deps/boringssl:lib",
            ],
        )],
    },
    cargo_lockfile = "//:Cargo.lock",
    lockfile = "//:Cargo.Bazel.lock",
    manifests = [
        "//:Cargo.toml",
        "//clash:Cargo.toml",
        "//clash_lib:Cargo.toml",
        "//clash_doc:Cargo.toml",
    ],
    splicing_config = splicing_config(
        resolver_version = "2",
    ),
)

load("@crate_index//:defs.bzl", "crate_repositories")

crate_repositories()
