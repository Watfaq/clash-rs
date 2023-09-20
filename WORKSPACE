workspace(name = "clash-rs")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# To find additional information on this release or newer ones visit:
# https://github.com/bazelbuild/rules_rust/releases

http_archive(
    name = "rules_rust",
    sha256 = "db89135f4d1eaa047b9f5518ba4037284b43fc87386d08c1d1fe91708e3730ae",
    urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.27.0/rules_rust-v0.27.0.tar.gz"],
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains(
    edition = "2021",
    versions = [
        "1.72.0",
    ],
)

load("@rules_rust//tools/rust_analyzer:deps.bzl", "rust_analyzer_dependencies")

rust_analyzer_dependencies()

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies()

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

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
)

load("@crate_index//:defs.bzl", "crate_repositories")

crate_repositories()
