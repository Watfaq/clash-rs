use crate::def::LogLevel;
use fern::colors::ColoredLevelConfig;
use log::LevelFilter;

use crate::Error;

pub fn setup_logging(level: LogLevel) -> Result<(), Error> {
    let colors = ColoredLevelConfig::new();

    fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                colors.color(record.level()),
                message
            ))
        })
        .level(match level {
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warning => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Silent => LevelFilter::Off,
        })
        .chain(std::io::stdout())
        .apply()
        .map_err(|x| Error::InvalidConfig(format!("setup logging: {}", x)))
}
