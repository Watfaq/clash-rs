#![feature(let_chains)]
fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_REF");
    let version = if let Some("refs/heads/master") = option_env!("GITHUB_REF")
        && let Some(sha) = option_env!("GITHUB_SHA")
    {
        let short_sha = &sha[..7];
        // Nightly relase below
        format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
    } else {
        env!("CARGO_PKG_VERSION").into()
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");
}
