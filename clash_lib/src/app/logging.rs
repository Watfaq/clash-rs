use crate::def::LogLevel;
use tokio::sync::broadcast::Sender;
use tracing::debug;
use tracing_subscriber::filter::Targets;
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

pub struct EventCollector(Vec<Sender<String>>);

impl EventCollector {
    pub fn new(recivers: Vec<Sender<String>>) -> Self {
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
        let mut msg = vec![];
        msg.push(format!("{}", event.metadata().level()));
        msg.push(format!("{}", event.metadata().target()));
        msg.push(format!("{}", event.metadata().name()));
        for field in event.fields() {
            msg.push(format!("{}", field.name()));
        }

        for tx in &self.0 {
            _ = tx.send(msg.join(""));
        }
    }
}

pub fn setup_logging(level: LogLevel, collector: EventCollector) -> anyhow::Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(filter::LevelFilter::from(level).into())
        .from_env_lossy();

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(Targets::new().with_target("clash", level))
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
