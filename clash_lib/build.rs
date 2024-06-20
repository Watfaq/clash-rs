fn main() {
    println!("cargo:rerun-if-env-changed=CLASH_RS_CI");
    if std::env::var("CLASH_RS_CI").is_ok() {
        println!("cargo::rustc-cfg=ci");
    }
}
