fn main() -> std::io::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(docker_test)");
    println!("cargo:rerun-if-env-changed=CLASH_DOCKER_TEST");
    if let Some("1" | "true") = option_env!("CLASH_DOCKER_TEST") {
        println!("cargo::rustc-cfg=docker_test");
    }

    println!("cargo:rerun-if-changed=src/common/geodata/geodata.proto");
    prost_build::compile_protos(
        &["src/common/geodata/geodata.proto"],
        &["src/common/geodata"],
    )
}
