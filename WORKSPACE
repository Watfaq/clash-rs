workspace(name = "clash-rs")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

local_repository(
    name = "rules_rust",
    path = "../rules_rust",
)

# To find additional information on this release or newer ones visit:
# https://github.com/bazelbuild/rules_rust/releases
# http_archive(
#     name = "rules_rust",
#     sha256 = "2466e5b2514772e84f9009010797b9cd4b51c1e6445bbd5b5e24848d90e6fb2e",
#     urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.18.0/rules_rust-v0.18.0.tar.gz"],
# )
load("@rules_rust//rust:repositories.bzl", "rules_rust_dependencies", "rust_register_toolchains")

rules_rust_dependencies()

rust_register_toolchains(
    edition = "2021",
    versions = [
        "1.67.1"
    ],
)

load("@rules_rust//crate_universe:repositories.bzl", "crate_universe_dependencies")

# crate_universe_dependencies()
crate_universe_dependencies(bootstrap = True)


load("@rules_rust//crate_universe:defs.bzl", "crates_repository")

crates_repository(
    name = "crate_index",
    cargo_lockfile = "//:Cargo.lock",
    lockfile = "//:Cargo.Bazel.lock",
    manifests = [
        "//:Cargo.toml",
        "//clash:Cargo.toml",
        "//clash-bin:Cargo.toml",
    ],
    generator = "@cargo_bazel_bootstrap//:cargo-bazel",
)

load("@crate_index//:defs.bzl", "crate_repositories")

crate_repositories()