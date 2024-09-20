#![feature(let_chains)]
fn main() {
    let vars = ["CLASH_GIT_REF", "CLASH_GIT_SHA"];
    for var in vars {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let version = if let Some("refs/heads/master") = option_env!("CLASH_GIT_REF")
        && let Some(sha) = option_env!("CLASH_GIT_SHA")
    {
        let short_sha = &sha[..7];
        // Nightly relase below
        format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
    } else {
        env!("CARGO_PKG_VERSION").into()
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");
}
