extern crate clash_lib as clash;

use clap::Parser;
use clash::TokioRuntime;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(short, long, value_parser, value_name = "DIRECTORY")]
    directory: Option<PathBuf>,

    #[clap(
        short,
        long,
        value_parser,
        value_name = "FILE",
        default_value = "config.yaml"
    )]
    config: PathBuf,
}

fn main() {
    let cli = Cli::parse();
    let file = cli
        .directory
        .as_ref()
        .unwrap_or(&std::env::current_dir().unwrap())
        .join(cli.config)
        .to_string_lossy()
        .to_string();

    if !Path::new(&file).exists() {
        panic!("config file not found: {}", file);
    }

    clash::start(clash::Options {
        config: clash::Config::File(file),
        cwd: cli.directory.map(|x| x.to_string_lossy().to_string()),
        rt: Some(TokioRuntime::MultiThread),
        log_file: None,
    })
    .unwrap();
}
