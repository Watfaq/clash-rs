fn main() -> std::io::Result<()> {
    println!("cargo:rerun-if-changed=src/common/geodata/geodata.proto");
    prost_build::compile_protos(
        &["src/common/geodata/geodata.proto"],
        &["src/common/geodata"],
    )
}
