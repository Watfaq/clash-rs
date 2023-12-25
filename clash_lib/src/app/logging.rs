use std::io::IsTerminal;

use crate::def::LogLevel;
use opentelemetry::global;
use serde::Serialize;
use tokio::sync::broadcast::Sender;

use tracing::debug;
use tracing_appender::non_blocking::NonBlocking;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_oslog::OsLogger;
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
            level: match *event.metadata().level() {
                tracing::Level::ERROR => LogLevel::Error,
                tracing::Level::WARN => LogLevel::Warning,
                tracing::Level::INFO => LogLevel::Info,
                tracing::Level::DEBUG => LogLevel::Debug,
                tracing::Level::TRACE => LogLevel::Debug,
            },
            msg: strs.join(" "),
        };
        for tx in &self.0 {
            _ = tx.send(event.clone());
        }
    }
}

struct W(Option<NonBlocking>);

impl std::io::Write for W {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0 {
            Some(ref mut w) => w.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.0 {
            Some(ref mut w) => w.flush(),
            None => Ok(()),
        }
    }
}

pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<Option<WorkerGuard>> {
    let filter = EnvFilter::builder()
        .with_default_directive(format!("clash={}", level).parse::<Directive>().unwrap())
        .from_env_lossy();

    let jaeger = if let Ok(jager_endpoint) = std::env::var("JAGER_ENDPOINT") {
        global::set_text_map_propagator(opentelemetry_jaeger::Propagator::new());

        let tracer = opentelemetry_jaeger::new_collector_pipeline()
            .with_service_name("clash-rs")
            .with_endpoint(jager_endpoint)
            .with_hyper()
            .install_batch(opentelemetry_sdk::runtime::Tokio)?;

        Some(tracing_opentelemetry::layer().with_tracer(tracer))
    } else {
        None
    };

    let ios_os_log = if cfg!(target_os = "ios") {
        Some(OsLogger::new("com.watfaq.clash", "default"))
    } else {
        None
    };

    let (appender, g) = if let Some(log_file) = log_file {
        let file_appender = tracing_appender::rolling::daily(cwd, log_file);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    let console_layer = if cfg!(feature = "tracing") {
        Some(console_subscriber::spawn())
    } else {
        None
    };

    let subscriber = tracing_subscriber::registry()
        .with(jaeger)
        .with(filter)
        .with(collector)
        .with(console_layer)
        .with(
            tracing_subscriber::fmt::Layer::new()
                .with_ansi(std::io::stdout().is_terminal())
                .pretty()
                .with_file(true)
                .with_line_number(true)
                .with_writer(move || -> Box<dyn std::io::Write> { Box::new(W(appender.clone())) })
                .with_writer(std::io::stdout),
        )
        .with(ios_os_log);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))?;

    if let Ok(jager_endpiont) = std::env::var("JAGER_ENDPOINT") {
        debug!("jager endpoint: {}", jager_endpiont);
    }

    Ok(g)
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
