#![feature(cfg_version)]
#![cfg_attr(not(version("1.88.0")), feature(let_chains))]

fn main() {
    // Watch both CLASH_* and GitHub-provided env vars so rebuilds trigger correctly
    let vars = ["CLASH_GIT_REF", "CLASH_GIT_SHA", "GITHUB_REF", "GITHUB_SHA"];
    for var in vars {
        println!("cargo:rerun-if-env-changed={var}");
    }

    // Prefer explicit CLASH_* vars; fall back to GITHUB_* which are set by GitHub
    // Actions. Use std::env::var_os to read at runtime, not option_env! at compile time.
    let git_ref = std::env::var_os("CLASH_GIT_REF")
        .or_else(|| std::env::var_os("GITHUB_REF"))
        .and_then(|v| v.into_string().ok());
    let git_sha = std::env::var_os("CLASH_GIT_SHA")
        .or_else(|| std::env::var_os("GITHUB_SHA"))
        .and_then(|v| v.into_string().ok());

    let version = if let Some(ref git_ref_val) = git_ref
        && git_ref_val == "refs/heads/master"
        && let Some(ref sha) = git_sha
    {
        let short_sha = &sha[..7.min(sha.len())];
        // Nightly release below
        format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
    } else {
        env!("CARGO_PKG_VERSION").into()
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");
}