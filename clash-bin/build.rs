#![feature(cfg_version)]
#![cfg_attr(not(version("1.88.0")), feature(let_chains))]

fn main() {
    // Watch both CLASH_* and GitHub-provided env vars so rebuilds trigger correctly
    let vars = ["CLASH_GIT_REF", "CLASH_GIT_SHA", "GITHUB_REF", "GITHUB_SHA"];
    for var in vars {
        println!("cargo:rerun-if-env-changed={var}");
    }

    // Prefer explicit CLASH_* vars; fall back to GITHUB_* which are set by GitHub
    // Actions
    let git_ref = option_env!("CLASH_GIT_REF").or(option_env!("GITHUB_REF"));
    let git_sha = option_env!("CLASH_GIT_SHA").or(option_env!("GITHUB_SHA"));

    let version = if let Some("refs/heads/master") = git_ref
        && let Some(sha) = git_sha
    {
        let short_sha = &sha[..7.min(sha.len())];
        // Nightly release below
        format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
    } else {
        env!("CARGO_PKG_VERSION").into()
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");
}
