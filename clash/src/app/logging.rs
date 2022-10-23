use crate::def::LogLevel;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{filter, EnvFilter};

impl From<LogLevel> for filter::LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => filter::LevelFilter::ERROR,
            LogLevel::Warning => filter::LevelFilter::WARN,
            LogLevel::Info => filter::LevelFilter::INFO,
            LogLevel::Debug => filter::LevelFilter::DEBUG,
            LogLevel::Silent => filter::LevelFilter::OFF,
        }
    }
}

pub fn setup_logging(level: LogLevel) -> anyhow::Result<()> {
    let filter =
        EnvFilter::from_default_env().add_directive(filter::LevelFilter::from(level).into());

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(Targets::new().with_target("clash", level))
        .with(
            tracing_subscriber::fmt::Layer::new()
                .with_ansi(atty::is(atty::Stream::Stdout))
                .pretty()
                .with_file(true)
                .with_line_number(true)
                .with_writer(std::io::stdout),
        );

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))
}
