extern crate clash_lib as clash;

use clap::Parser;
use std::path::PathBuf;

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

    #[clap(short, long, action)]
    test: bool,
}

fn main() {
    let cli = Cli::parse();
    clash::start(clash::Options {
        config: clash::Config::File("".to_string(), cli.config.to_string_lossy().to_string()),
        cwd: cli.directory.map(|x| x.to_string_lossy().to_string()),
    })
    .unwrap();
}
