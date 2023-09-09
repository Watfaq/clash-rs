use std::io::IsTerminal;

use crate::def::LogLevel;
use serde::Serialize;
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

#[derive(Clone, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: LogLevel,
    #[serde(rename = "payload")]
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
        let mut strs = vec![];
        event.record(&mut EventVisitor(&mut strs));

        let event = LogEvent {
            level: match event.metadata().level() {
                &tracing::Level::ERROR => LogLevel::Error,
                &tracing::Level::WARN => LogLevel::Warning,
                &tracing::Level::INFO => LogLevel::Info,
                &tracing::Level::DEBUG => LogLevel::Debug,
                &tracing::Level::TRACE => LogLevel::Debug,
            },
            msg: strs.join(" "),
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
                .with_ansi(std::io::stdout().is_terminal())
                .pretty()
                .with_file(true)
                .with_line_number(true)
                .with_writer(std::io::stdout),
        );

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))
}

struct EventVisitor<'a>(&'a mut Vec<String>);

impl<'a> tracing::field::Visit for EventVisitor<'a> {
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        println!("bool {} = {}", field.name(), value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        println!("i64 {} = {}", field.name(), value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        println!("u64 {} = {}", field.name(), value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        println!("str {} = {}", field.name(), value);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0.push(format!("{:?}", value));
        } else {
            println!("debug {} = {:?}", field.name(), value);
        }
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        println!("f64 {} = {}", field.name(), value);
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        println!("u128 {} = {}", field.name(), value);
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        println!("i128 {} = {}", field.name(), value);
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        println!("error {} = {}", field.name(), value);
    }
}
