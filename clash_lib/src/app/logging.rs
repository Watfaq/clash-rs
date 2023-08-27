use crate::def::LogLevel;
use tokio::sync::broadcast::Sender;

use tracing_subscriber::filter::Directive;
use tracing_subscriber::prelude::*;
use tracing_subscriber::Layer;
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

#[derive(Clone)]
pub struct LogEvent {
    pub level: LogLevel,
    pub msg: String,
}

pub struct EventCollector(Vec<Sender<LogEvent>>);

impl EventCollector {
    pub fn new(recivers: Vec<Sender<LogEvent>>) -> Self {
        Self(recivers)
    }
}

impl<S> Layer<S> for EventCollector
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        // TODO: format log here
        let msg = format!("{}", event.metadata().name());
        let event = LogEvent {
            level: match event.metadata().level() {
                &tracing::Level::ERROR => LogLevel::Error,
                &tracing::Level::WARN => LogLevel::Warning,
                &tracing::Level::INFO => LogLevel::Info,
                &tracing::Level::DEBUG => LogLevel::Debug,
                &tracing::Level::TRACE => LogLevel::Debug,
            },
            msg,
        };
        for tx in &self.0 {
            _ = tx.send(event.clone());
        }
    }
}

pub fn setup_logging(level: LogLevel, collector: EventCollector) -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(
            format!("clash={}", level)
                .parse::<Directive>()
                .unwrap()
                .into(),
        )
        .from_env_lossy();

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(collector)
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
