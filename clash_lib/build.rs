fn main() -> std::io::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(ci)");
    println!("cargo:rerun-if-env-changed=CLASH_RS_CI");
    if std::env::var("CLASH_RS_CI").is_ok() {
        println!("cargo::rustc-cfg=ci");
    }

    println!("cargo:rerun-if-changed=src/common/geodata/geodata.proto");
    prost_build::compile_protos(
        &["src/common/geodata/geodata.proto"],
        &["src/common/geodata"],
    )
}
