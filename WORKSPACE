workspace(name = "clash-rs")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "bazel_skylib",
    sha256 = "66ffd9315665bfaafc96b52278f57c7e2dd09f5ede279ea6d39b2be471e7e3aa",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.2/bazel-skylib-1.4.2.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.2/bazel-skylib-1.4.2.tar.gz",
    ],
)

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

bazel_skylib_workspace()

http_archive(
    name = "rules_python",
    sha256 = "84aec9e21cc56fbc7f1335035a71c850d1b9b5cc6ff497306f84cced9a769841",
    strip_prefix = "rules_python-0.23.1",
    url = "https://github.com/bazelbuild/rules_python/releases/download/0.23.1/rules_python-0.23.1.tar.gz",
)

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()

# To find additional information on this release or newer ones visit:
# https://github.com/bazelbuild/rules_rust/releases
#http_archive(
#name = "rules_rust",
#sha256 = "0c2ff9f58bbd6f2a4fc4fbea3a34e85fe848e7e4317357095551a18b2405a01c",
#urls = ["https://github.com/bazelbuild/rules_rust/releases/download/0.25.0/rules_rust-v0.25.0.tar.gz"],
#)
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
