use std::io::IsTerminal;

use crate::def::LogLevel;

use serde::Serialize;
use tokio::sync::broadcast::Sender;

use tracing::level_filters::LevelFilter;
use tracing_appender::non_blocking::WorkerGuard;
#[cfg(target_os = "ios")]
use tracing_oslog::OsLogger;
use tracing_subscriber::{
    EnvFilter, Layer, filter::filter_fn, fmt::time::LocalTime, prelude::*,
};

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Silent => LevelFilter::OFF,
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
    pub fn new(receivers: Vec<Sender<LogEvent>>) -> Self {
        Self(receivers)
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
                tracing::Level::TRACE => LogLevel::Trace,
            },
            msg: strs.join(" "),
        };
        for tx in &self.0 {
            _ = tx.send(event.clone());
        }
    }
}

pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<Option<WorkerGuard>> {
    let filter = EnvFilter::from_default_env()
        .add_directive(format!("clash={}", level).parse().unwrap())
        .add_directive(format!("clash_lib={}", level).parse().unwrap())
        .add_directive("warn".parse().unwrap());

    let (appender, guard) = if let Some(log_file) = log_file {
        let file_appender = tracing_appender::rolling::daily(cwd, log_file);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    let subscriber = tracing_subscriber::registry();

    // Collect and expose data about the Tokio runtime (tasks, threads, resources,
    // etc.)
    #[cfg(feature = "tokio-console")]
    let subscriber = subscriber.with(console_subscriber::spawn());
    #[cfg(feature = "tokio-console")]
    let filter = filter
        .add_directive("tokio=trace".parse().unwrap())
        .add_directive("runtime=trace".parse().unwrap());
    let exclude = filter_fn(|metadata| {
        !metadata.target().contains("tokio")
            && !metadata.target().contains("runtime")
    });

    let timer = LocalTime::new(time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]"
    ));

    let subscriber = subscriber
        .with(filter) // Global filter
        .with(collector.with_filter(exclude.clone())) // Log collector for API controller
        .with(appender.map(|x| {
            tracing_subscriber::fmt::Layer::new()
                .with_timer(timer.clone())
                .with_ansi(false)
                .compact()
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_writer(x)
                .with_filter(exclude.clone())
        }))
        .with(
            tracing_subscriber::fmt::Layer::new()
                .with_timer(timer)
                .with_ansi(std::io::stdout().is_terminal())
                .compact()
                .with_target(cfg!(debug_assertions))
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_thread_ids(cfg!(debug_assertions))
                .with_writer(std::io::stdout)
                .with_filter(exclude),
        );

    #[cfg(target_os = "ios")]
    let subscriber =
        subscriber.with(Some(OsLogger::new("com.watfaq.clash", "default")));

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))?;

    Ok(guard)
}

struct EventVisitor<'a>(&'a mut Vec<String>);

impl tracing::field::Visit for EventVisitor<'_> {
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

    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
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
