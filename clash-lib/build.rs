fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(docker_test)");
    println!("cargo:rerun-if-env-changed=CLASH_DOCKER_TEST");
    if let Some("1" | "true") = option_env!("CLASH_DOCKER_TEST") {
        println!("cargo::rustc-cfg=docker_test");
    }

    println!("cargo:rerun-if-changed=src/common/geodata/geodata.proto");

    // Use protox (pure Rust) instead of system protobuf-compiler
    let file_descriptors = protox::compile(
        ["src/common/geodata/geodata.proto"],
        ["src/common/geodata"],
    )?;

    prost_build::compile_fds(file_descriptors)?;

    let vars = ["CLASH_GIT_REF", "CLASH_GIT_SHA"];
    for var in vars {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let version = if let Some("refs/heads/master") = option_env!("CLASH_GIT_REF")
        && let Some(sha) = option_env!("CLASH_GIT_SHA")
    {
        let short_sha = &sha[..7];
        // Nightly release below
        format!("{}-alpha+sha.{short_sha}", env!("CARGO_PKG_VERSION"))
    } else {
        env!("CARGO_PKG_VERSION").into()
    };
    println!("cargo:rustc-env=CLASH_VERSION_OVERRIDE={version}");

    Ok(())
}
