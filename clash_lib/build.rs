extern crate prost_build;

fn main() {
    println!("cargo:rerun-if-env-changed=CLASH_RS_CI");
    if std::env::var("CLASH_RS_CI").is_ok() {
        println!("cargo::rustc-cfg=ci");
    }

    prost_build::compile_protos(
        &["src/app/router/rules/geodata/geodata.proto"],
        &["src/app/router/rules/geodata"],
    )
    .unwrap();
}
