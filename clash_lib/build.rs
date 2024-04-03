fn main() {
    if std::env::var("CLASH_RS_CI").is_ok() {
        println!("cargo::rustc-cfg=ci");
    }
}
