use crate::def::LogLevel;
use anyhow::anyhow;
#[cfg(feature = "telemetry")]
use opentelemetry::trace::TracerProvider;
#[cfg(feature = "telemetry")]
use opentelemetry_otlp::{Protocol, WithExportConfig};
#[cfg(feature = "telemetry")]
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_VERSION},
};
use serde::Serialize;
use std::{io::IsTerminal, sync::Once};
use tokio::sync::broadcast::Sender;
use tracing::level_filters::LevelFilter;
use tracing_log::LogTracer;
#[cfg(feature = "telemetry")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(target_os = "ios")]
use tracing_oslog::OsLogger;
use tracing_subscriber::{Layer, fmt::time::LocalTime, prelude::*};

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

/// Represents a log event that can be broadcast to listeners.
#[derive(Clone, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: LogLevel,
    #[serde(rename = "payload")]
    pub msg: String,
}

/// A tracing layer that collects log events and broadcasts them to subscribers.
pub struct EventCollector(Vec<Sender<LogEvent>>);

impl EventCollector {
    /// Creates a new event collector with the given broadcast senders.
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

struct LoggingGuard {
    _file_appender: Option<tracing_appender::non_blocking::WorkerGuard>,
    #[cfg(feature = "telemetry")]
    _tracing_chrome_guard: Option<tracing_chrome::FlushGuard>,
    #[cfg(feature = "telemetry")]
    _tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

static SETUP_LOGGING: Once = Once::new();
static mut LOGGING_GUARD: Option<LoggingGuard> = None;

/// Initialize the logging system with the specified configuration.
///
/// This function sets up various logging layers including file output, console
/// output, and optional telemetry tracing. It can only be called once during
/// the application lifetime.
///
/// # Arguments
/// * `level` - The minimum log level to capture
/// * `collector` - Event collector for broadcasting log events
/// * `cwd` - Current working directory for resolving relative paths
/// * `log_file` - Optional path to a log file
pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) {
    unsafe {
        SETUP_LOGGING.call_once(|| {
            LogTracer::init().unwrap_or_else(|e| {
                eprintln!(
                    "Failed to init tracing-log: {e}, another env_logger might \
                     have been initialized"
                );
            });
            LOGGING_GUARD = setup_logging_inner(level, collector, cwd, log_file)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to setup logging: {e}");
                    None
                });
        });
    }
}

/// Create a filter configuration for different components.
fn create_filter(
    level: LogLevel,
    _exclude: bool,
) -> tracing_subscriber::filter::Targets {
    #[allow(unused_mut)]
    let mut filter = tracing_subscriber::filter::Targets::new()
        .with_targets(vec![
            ("clash_lib", level),
            ("clash_bin", level),
            ("clash_dns", level),
            ("clash_netstack", level),
        ])
        .with_default(LevelFilter::WARN);

    #[cfg(feature = "telemetry")]
    {
        if !_exclude {
            filter = filter
                .with_target("tokio", LevelFilter::TRACE)
                .with_target("runtime", LevelFilter::TRACE);
        }
    }

    filter
}

/// Setup file appender for logging to a file.
fn setup_file_appender(
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<(
    Option<tracing_appender::non_blocking::NonBlocking>,
    Option<tracing_appender::non_blocking::WorkerGuard>,
)> {
    if let Some(log_file) = log_file {
        let path_buf = std::path::PathBuf::from(&log_file);
        let log_path = if path_buf.is_absolute() {
            log_file
        } else {
            format!("{cwd}/{log_file}")
        };
        let writer = std::fs::File::options().append(true).open(log_path)?;
        let (non_blocking, guard) =
            tracing_appender::non_blocking::NonBlockingBuilder::default()
                .buffered_lines_limit(16_000)
                .lossy(true)
                .thread_name("clash-logger-appender")
                .finish(writer);
        Ok((Some(non_blocking), Some(guard)))
    } else {
        Ok((None, None))
    }
}

/// Setup chrome tracing layer if the feature is enabled.
#[cfg(feature = "telemetry")]
fn setup_chrome_tracing<S>()
-> (tracing_chrome::ChromeLayer<S>, tracing_chrome::FlushGuard)
where
    S: tracing::Subscriber
        + for<'a> tracing_subscriber::registry::LookupSpan<'a>
        + Send
        + Sync,
{
    let builder = tracing_chrome::ChromeLayerBuilder::new();
    builder.build()
}

/// Setup OpenTelemetry tracing with OTLP exporter.
#[cfg(feature = "telemetry")]
fn setup_opentelemetry_tracing()
-> anyhow::Result<opentelemetry_sdk::trace::SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .build()?;

    let sampling_rate = if cfg!(debug_assertions) {
        1.0 // 100% sampling in development
    } else {
        0.1 // 10% sampling in production
    };

    let environment = if cfg!(debug_assertions) {
        "development"
    } else {
        "production"
    };

    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
            opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(sampling_rate),
        )))
        .with_id_generator(opentelemetry_sdk::trace::RandomIdGenerator::default())
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(env!("CARGO_PKG_NAME"))
                .with_schema_url(
                    [
                        opentelemetry::KeyValue::new(
                            SERVICE_VERSION,
                            env!("CARGO_PKG_VERSION"),
                        ),
                        opentelemetry::KeyValue::new(
                            DEPLOYMENT_ENVIRONMENT_NAME,
                            environment,
                        ),
                    ],
                    SCHEMA_URL,
                )
                .build(),
        )
        .with_batch_exporter(exporter)
        .build();

    Ok(tracer_provider)
}

/// Create a timer formatter for log timestamps.
fn create_timer()
-> LocalTime<&'static [time::format_description::FormatItem<'static>]> {
    LocalTime::new(time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second]:[subsecond]"
    ))
}

fn setup_logging_inner(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<Option<LoggingGuard>> {
    let filter = create_filter(level, false);
    let (appender, file_guard) = setup_file_appender(cwd, log_file)?;
    let timer = create_timer();

    // Create output filter for file and stdout layers
    // When telemetry is enabled, exclude tokio and runtime targets
    let output_filter = create_filter(level, true);

    // Setup optional tracing features
    #[cfg(feature = "telemetry")]
    let (chrome_layer, chrome_guard) = setup_chrome_tracing();

    #[cfg(feature = "telemetry")]
    let tracer_provider = setup_opentelemetry_tracing()?;

    #[cfg(feature = "telemetry")]
    let tracer = tracer_provider.tracer("tracing-otel-subscriber");

    // Build file logging layer if appender is available
    let file_layer = appender.map(|writer| {
        tracing_subscriber::fmt::Layer::new()
            .with_timer(timer.clone())
            .with_ansi(false)
            .compact()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_writer(writer)
            .with_filter(output_filter.clone())
    });

    // Build stdout logging layer
    let stdout_layer = tracing_subscriber::fmt::Layer::new()
        .with_timer(timer)
        .with_ansi(std::io::stdout().is_terminal())
        .compact()
        .with_target(cfg!(debug_assertions))
        .with_file(true)
        .with_line_number(true)
        .with_level(true)
        .with_thread_ids(cfg!(debug_assertions))
        .with_writer(std::io::stdout)
        .with_filter(output_filter);

    // Build the subscriber with different layers based on features
    let subscriber = tracing_subscriber::registry();

    #[cfg(feature = "telemetry")]
    let subscriber = subscriber
        .with(console_subscriber::spawn())
        .with(chrome_layer)
        .with(OpenTelemetryLayer::new(tracer));

    let subscriber = subscriber
        .with(collector.with_filter(filter.clone()))
        .with(file_layer)
        .with(stdout_layer)
        .with(filter);

    // Add iOS-specific logging if on iOS
    #[cfg(target_os = "ios")]
    let subscriber =
        subscriber.with(Some(OsLogger::new("com.watfaq.clash", "default")));

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))?;

    Ok(Some(LoggingGuard {
        _file_appender: file_guard,
        #[cfg(feature = "telemetry")]
        _tracing_chrome_guard: Some(chrome_guard),
        #[cfg(feature = "telemetry")]
        _tracer_provider: Some(tracer_provider),
    }))
}

struct EventVisitor<'a>(&'a mut Vec<String>);

impl tracing::field::Visit for EventVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.record_value(field, &value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.record_value(field, &value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.record_value(field, &value);
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        self.record_value(field, &value);
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        self.record_value(field, &value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.record_value(field, &value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.record_value(field, &value);
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.record_value(field, &value);
    }

    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "message" {
            self.0.push(format!("{value:?}"));
        } else if field.name() != "message" {
            self.0.push(format!("{}: {:?}", field.name(), value));
        }
    }
}

impl EventVisitor<'_> {
    fn record_value<T: std::fmt::Display>(
        &mut self,
        field: &tracing::field::Field,
        value: &T,
    ) {
        if field.name() != "message" {
            self.0.push(format!("{}: {}", field.name(), value));
        }
    }
}
