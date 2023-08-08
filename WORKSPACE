workspace(name = "clash-rs")

#load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# To find additional information on this release or newer ones visit:
# https://github.com/bazelbuild/rules_rust/releases

# http_archive(
#     name = "rules_rust",
#     sha256 = "9d04e658878d23f4b00163a72da3db03ddb451273eb347df7d7c50838d698f49",
#     urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.26.0/rules_rust-v0.26.0.tar.gz"],
# )

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "rules_rust",
    branch = "pass-to-bindgen",
    remote = "https://github.com/ibigbug/rules_rust.git",
)

load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains(
    edition = "2021",
    versions = [
        "1.67.1",
    ],
)

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

crate_universe_dependencies(bootstrap = True)

load("@rules_rust//crate_universe:defs.bzl", "crate", "crates_repository")

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
            },
            data = [
                "@//deps/boringssl:lib",
            ],
        )],
    },
    cargo_lockfile = "//:Cargo.lock",
    generator = "@cargo_bazel_bootstrap//:cargo-bazel",
    lockfile = "//:Cargo.Bazel.lock",
    manifests = [
        "//:Cargo.toml",
        "//clash:Cargo.toml",
        "//clash_lib:Cargo.toml",
    ],
)

load("@crate_index//:defs.bzl", "crate_repositories")

crate_repositories()
