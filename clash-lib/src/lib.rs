#![feature(cfg_version)]
#![feature(ip)]
#![feature(sync_unsafe_cell)]
#![feature(duration_millis_float)]
#![cfg_attr(not(version("1.87.0")), feature(unbounded_shifts))]
#![cfg_attr(not(version("1.88.0")), feature(let_chains))]
#![cfg_attr(not(version("1.94.0")), feature(lazy_get))]

#[cfg(feature = "tun")]
use crate::proxy::tun;
use crate::{
    app::{
        dispatcher::{Dispatcher, StatisticsManager},
        dns::{self, SystemResolver, ThreadSafeDNSResolver, config::DNSListenAddr},
        inbound::manager::InboundManager,
        logging::LogEvent,
        net::init_net_config,
        outbound::manager::OutboundManager,
        profile,
        router::Router,
    },
    common::{
        auth,
        geodata::{DEFAULT_GEOSITE_DOWNLOAD_URL, GeoDataLookup},
        http::new_http_client,
        mmdb::{
            self, DEFAULT_ASN_MMDB_DOWNLOAD_URL, DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL,
        },
    },
    config::{
        InternalConfig,
        def::{self, LogLevel},
        internal::proxy::OutboundProxy,
    },
    runner::Runner,
};

use std::{
    io,
    path::PathBuf,
    sync::{Arc, OnceLock},
};
use thiserror::Error;
use tokio::sync::{Mutex, broadcast, mpsc, oneshot};
use tracing::{debug, error, info, warn};

pub mod app;
pub mod config;

mod common;
mod proxy;
mod runner;
mod session;

use crate::common::{geodata, mmdb::MmdbLookup};
pub use config::{
    DNSListen as ClashDNSListen, RuntimeConfig as ClashRuntimeConfig,
    def::{Config as ClashConfigDef, DNS as ClashDNSConfigDef},
};

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IpNet(#[from] ipnet::AddrParseError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("profile error: {0}")]
    ProfileError(String),
    #[error("dns error: {0}")]
    DNSError(String),
    #[error(transparent)]
    DNSServerError(#[from] watfaq_dns::DNSError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("operation error: {0}")]
    Operation(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

type ArcRunner = Arc<dyn Runner>;

pub struct Options {
    pub config: Config,
    pub cwd: Option<String>,
    pub rt: Option<TokioRuntime>,
    pub log_file: Option<String>,
}

pub enum TokioRuntime {
    MultiThread,
    SingleThread,
}

#[allow(clippy::large_enum_variant)]
pub enum Config {
    Def(ClashConfigDef),
    Internal(InternalConfig),
    File(String),
    Str(String),
}

impl Config {
    pub fn try_parse(self) -> Result<InternalConfig> {
        match self {
            Config::Def(c) => c.try_into(),
            Config::Internal(c) => Ok(c),
            Config::File(file) => {
                TryInto::<def::Config>::try_into(PathBuf::from(file))?.try_into()
            }
            Config::Str(s) => s.parse::<def::Config>()?.try_into(),
        }
    }
}

pub struct GlobalState {
    log_level: LogLevel,
    #[cfg(feature = "tun")]
    tunnel_runner: ArcRunner,
    dns_listener: ArcRunner,
    #[allow(dead_code)]
    reload_tx: mpsc::Sender<(Config, oneshot::Sender<()>)>,
    cwd: String,
}

pub fn start_scaffold(opts: Options) -> Result<()> {
    let rt = match opts.rt.as_ref().unwrap_or(&TokioRuntime::MultiThread) {
        TokioRuntime::MultiThread => tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
        TokioRuntime::SingleThread => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?,
    };
    let config: InternalConfig = opts.config.try_parse()?;
    let cwd = opts.cwd.unwrap_or_else(|| ".".to_string());
    let (log_tx, _) = broadcast::channel(100);

    let log_collector = app::logging::EventCollector::new(vec![log_tx.clone()]);

    app::logging::setup_logging(
        config.general.log_level,
        log_collector,
        &cwd,
        opts.log_file,
    );

    rt.block_on(async {
        match start(config, cwd, log_tx).await {
            Err(e) => {
                eprintln!("start error: {e}");
                Err(e)
            }
            Ok(_) => Ok(()),
        }
    })
}

static SHUTDOWN_TOKEN: std::sync::Mutex<Vec<tokio_util::sync::CancellationToken>> =
    std::sync::Mutex::new(Vec::new());

pub fn shutdown() -> bool {
    let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
    if !token_guard.is_empty() {
        for token in token_guard.drain(..) {
            token.cancel();
        }
        warn!("Shutdown signal sent, waiting for shutdown to complete...");
        true
    } else {
        warn!("Shutdown token not initialized, cannot shutdown");
        false
    }
}

static CRYPTO_PROVIDER_LOCK: OnceLock<()> = OnceLock::new();

pub fn setup_default_crypto_provider() {
    CRYPTO_PROVIDER_LOCK.get_or_init(|| {
        #[cfg(feature = "aws-lc-rs")]
        {
            _ = rustls::crypto::aws_lc_rs::default_provider().install_default()
        }
        #[cfg(feature = "ring")]
        {
            _ = rustls::crypto::ring::default_provider().install_default()
        }
    });
}
pub async fn start(
    config: InternalConfig,
    cwd: String,
    log_tx: broadcast::Sender<LogEvent>,
) -> Result<()> {
    setup_default_crypto_provider();

    let shutdown_token = tokio_util::sync::CancellationToken::new();

    {
        let mut token_guard = SHUTDOWN_TOKEN.lock().unwrap();
        token_guard.push(shutdown_token.clone());
    }

    let cwd = PathBuf::from(cwd);

    // things we need to clone before consuming config
    let controller_cfg = config.general.controller.clone();
    let log_level = config.general.log_level;

    let components = create_components(cwd.clone(), config).await?;

    let (reload_tx, mut reload_rx) = mpsc::channel(1);

    let global_state = Arc::new(Mutex::new(GlobalState {
        log_level,
        #[cfg(feature = "tun")]
        tunnel_runner: components.tun_runner.clone(),
        dns_listener: components.dns_listener.clone(),
        reload_tx,
        cwd: cwd.to_string_lossy().to_string(),
    }));

    let api_listener: ArcRunner = Arc::new(app::api::ApiRunner::new(
        controller_cfg.clone(),
        log_tx.clone(),
        components.inbound_manager.clone(),
        components.dispatcher.clone(),
        global_state.clone(),
        components.dns_resolver.clone(),
        components.outbound_manager.clone(),
        components.statistics_manager.clone(),
        components.cache_store.clone(),
        components.router.clone(),
        cwd.to_string_lossy().to_string(),
        Some(shutdown_token.child_token()),
        components.dns_listen.clone(),
        components.dns_enabled,
    ));

    // api_listener is not part of components because it requires components to be
    // initialized before it can be initialized. start it manually.
    api_listener.run_async();

    {
        let mut g = global_state.lock().await;
        #[cfg(feature = "tun")]
        {
            g.tunnel_runner = components.tun_runner.clone();
        }
        g.dns_listener = components.dns_listener.clone();
    }

    components.start_all();

    let cwd_clone = cwd.clone();

    let reload_token = shutdown_token.child_token();
    tokio::spawn(async move {
        // Listen for config reload signal and reload config
        while let Some((config, done)) = reload_rx.recv().await {
            info!("reloading config");
            let config = match config.try_parse() {
                Ok(c) => c,
                Err(e) => {
                    error!("failed to reload config: {}", e);
                    continue;
                }
            };

            let controller_cfg = config.general.controller.clone();
            let new_components =
                create_components(cwd_clone.clone(), config).await?;

            done.send(()).unwrap();

            components.stop_all();
            new_components.start_all();

            // TODO: every reload is causing the API server to restart, we should
            // make the API server reloadable instead of restarting it.
            // maybe adding APIs to replace components
            // and only recreate the listeners when necessary (e.g. when the listen
            // address or port is changed)
            let new_api_listener: ArcRunner = Arc::new(app::api::ApiRunner::new(
                controller_cfg,
                log_tx.clone(),
                new_components.inbound_manager.clone(),
                new_components.dispatcher.clone(),
                global_state.clone(),
                new_components.dns_resolver.clone(),
                new_components.outbound_manager.clone(),
                new_components.statistics_manager.clone(),
                new_components.cache_store.clone(),
                new_components.router.clone(),
                cwd_clone.to_string_lossy().to_string(),
                Some(reload_token.clone()),
                new_components.dns_listen.clone(),
                new_components.dns_enabled,
            ));
            let mut g = global_state.lock().await;

            #[cfg(feature = "tun")]
            {
                g.tunnel_runner = new_components.tun_runner.clone();
            }
            g.dns_listener = new_components.dns_listener.clone();

            api_listener.shutdown();
            new_api_listener.run_async();
        }
        Ok::<(), Error>(())
    });

    tokio::select! {
        result = tokio::signal::ctrl_c() => { result.map_err(Error::Io)?; }
        _ = shutdown_token.cancelled() => {}
    }
    Ok(())
}

struct RuntimeComponents {
    cache_store: profile::ThreadSafeCacheFile,
    dns_resolver: ThreadSafeDNSResolver,
    outbound_manager: Arc<OutboundManager>,
    router: Arc<Router>,
    dispatcher: Arc<Dispatcher>,
    statistics_manager: Arc<StatisticsManager>,

    #[cfg(feature = "tun")]
    tun_runner: ArcRunner,
    dns_listener: ArcRunner,
    inbound_manager: Arc<InboundManager>,
    dns_listen: DNSListenAddr,
    dns_enabled: bool,
}

impl RuntimeComponents {
    fn start_all(&self) {
        #[cfg(feature = "tun")]
        self.tun_runner.run_async();
        self.dns_listener.run_async();
        self.inbound_manager.run_async();
    }

    fn stop_all(&self) {
        #[cfg(feature = "tun")]
        self.tun_runner.shutdown();
        self.dns_listener.shutdown();
        self.inbound_manager.shutdown();
    }
}

async fn create_components(
    cwd: PathBuf,
    config: InternalConfig,
) -> Result<RuntimeComponents> {
    if config.tun.enable {
        debug!("tun enabled, initializing default outbound interface");
        init_net_config(config.tun.so_mark).await;
    }

    let cancellation_token = tokio_util::sync::CancellationToken::new();

    debug!("initializing cache store");
    let cache_store = profile::ThreadSafeCacheFile::new(
        cwd.join("cache.db").as_path().to_str().unwrap(),
        config.profile.store_selected,
    );

    let system_resolver = Arc::new(
        SystemResolver::new(config.dns.ipv6)
            .map_err(|x| Error::DNSError(x.to_string()))?,
    );

    debug!("initializing bootstrap outbounds");
    let plain_outbounds = OutboundManager::load_plain_outbounds(
        config
            .proxies
            .into_values()
            .filter_map(|x| match x {
                OutboundProxy::ProxyServer(s) => Some(s),
                _ => None,
            })
            .collect(),
    );

    // Create a shared outbound registry seeded with plain outbounds.
    // After OutboundManager is initialized it will be extended with all
    // handlers (plain + proxy groups + provider proxies), so DNS clients
    // and the HTTP client can use any of them for bootstrap traffic.
    let outbound_registry: crate::proxy::utils::OutboundHandlerRegistry =
        Arc::new(tokio::sync::RwLock::new(
            plain_outbounds
                .iter()
                .map(|x| (x.name().to_string(), x.clone()))
                .collect(),
        ));

    let client =
        new_http_client(system_resolver.clone(), Some(outbound_registry.clone()))
            .map_err(|x| Error::DNSError(x.to_string()))?;

    debug!("initializing dns resolver");
    // Clone the dns.listen for the DNS Server later before we consume the config
    // TODO: we should separate the DNS resolver and DNS server config here
    let dns_listen = config.dns.listen.clone();
    let dns_enable = config.dns.enable;

    // Extract the country MMDB file/url config early so they can be consumed
    // here, while the actual MMDB loading happens after OutboundManager (like
    // geodata and asn_mmdb) so it benefits from the fully-populated outbound
    // registry when downloading the file.
    let country_mmdb_file = config.general.mmdb;
    let country_mmdb_download_url = config.general.mmdb_download_url;

    // Create a shared pending handle that the DNS resolver's GeoIPFilter holds.
    // It starts empty and is populated once the MMDB is loaded below.
    let pending_country_mmdb: Option<dns::PendingMmdb> = country_mmdb_file
        .as_ref()
        .map(|_| Arc::new(OnceLock::new()));

    let dns_resolver = dns::new_resolver(
        config.dns,
        Some(cache_store.clone()),
        pending_country_mmdb.clone(),
        outbound_registry.clone(),
    )
    .await;

    debug!("initializing outbound manager");
    let outbound_manager = Arc::new(
        OutboundManager::new(
            plain_outbounds,
            config
                .proxy_groups
                .into_values()
                .filter_map(|x| match x {
                    OutboundProxy::ProxyGroup(g) => Some(g),
                    _ => None,
                })
                .collect(),
            config.proxy_providers,
            config.proxy_names,
            dns_resolver.clone(),
            cache_store.clone(),
            cwd.to_string_lossy().to_string(),
            config.general.routing_mask,
            outbound_registry.clone(),
        )
        .await?,
    );

    debug!("initializing mmdb");
    let country_mmdb = if let Some(ref mmdb_file) = country_mmdb_file {
        let mmdb = Arc::new(
            mmdb::Mmdb::new(
                cwd.join(mmdb_file),
                country_mmdb_download_url
                    .unwrap_or(DEFAULT_COUNTRY_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup;
        // Populate the shared handle so the DNS resolver's GeoIPFilter can use
        // it. Any inflight DNS fallback-IP filtering that ran before this point
        // will have been permissive (MMDB absent = pass-through), which is the
        // safe default during startup.
        if let Some(pending) = &pending_country_mmdb
            && pending.set(mmdb.clone()).is_err()
        {
            warn!(
                "country MMDB OnceLock was already set — this is unexpected and \
                 indicates a double-initialization bug"
            );
        }
        Some(mmdb)
    } else {
        debug!("country mmdb not set, skipping");
        None
    };

    debug!("initializing geosite");
    let geodata = if let Some(geosite_file) = config.general.geosite {
        Some(Arc::new(
            geodata::GeoData::new(
                cwd.join(&geosite_file),
                config
                    .general
                    .geosite_download_url
                    .unwrap_or(DEFAULT_GEOSITE_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as GeoDataLookup)
    } else {
        debug!("geosite not set, skipping");
        None
    };

    debug!("initializing country asn mmdb");
    let asn_mmdb = if let Some(asn_mmdb_name) = config.general.asn_mmdb {
        Some(Arc::new(
            mmdb::Mmdb::new(
                cwd.join(&asn_mmdb_name),
                config
                    .general
                    .asn_mmdb_download_url
                    .unwrap_or(DEFAULT_ASN_MMDB_DOWNLOAD_URL.to_string()),
                client.clone(),
            )
            .await?,
        ) as MmdbLookup)
    } else {
        debug!("ASN mmdb not found and not configured for download, skipping");
        None
    };

    debug!("initializing router");
    let router = Arc::new(
        Router::new(
            config.rules,
            config.rule_providers,
            dns_resolver.clone(),
            country_mmdb,
            asn_mmdb,
            geodata,
            cwd.to_string_lossy().to_string(),
        )
        .await,
    );

    let statistics_manager = StatisticsManager::new();

    debug!("initializing dispatcher");
    let dispatcher = Arc::new(Dispatcher::new(
        outbound_manager.clone(),
        router.clone(),
        dns_resolver.clone(),
        config.general.mode,
        statistics_manager.clone(),
        config.experimental.and_then(|e| e.tcp_buffer_size),
    ));

    debug!("initializing authenticator");
    let authenticator = Arc::new(auth::PlainAuthenticator::new(config.users));

    debug!("initializing inbound manager");
    let inbound_manager = Arc::new(
        InboundManager::new(
            dispatcher.clone(),
            authenticator,
            config.listeners,
            Some(cancellation_token.child_token()),
        )
        .await,
    );
    if !config.inbound_providers.is_empty() {
        debug!("loading inbound providers");
        inbound_manager
            .load_inbound_providers(
                cwd.to_string_lossy().to_string(),
                config.inbound_providers,
                dns_resolver.clone(),
            )
            .await;
    }

    #[cfg(feature = "tun")]
    debug!("initializing tun runner");
    #[cfg(feature = "tun")]
    let tun_runner: ArcRunner = Arc::new(tun::TunRunner::new(
        config.tun,
        dispatcher.clone(),
        dns_resolver.clone(),
        Some(cancellation_token.child_token()),
    )?);

    debug!("initializing dns listener");
    let dns_listener: ArcRunner = Arc::new(dns::DnsRunner::new(
        dns_enable,
        dns_listen.clone(),
        dns_resolver.clone(),
        &cwd,
        Some(cancellation_token.child_token()),
    ));

    info!("all components initialized");
    Ok(RuntimeComponents {
        cache_store,
        dns_resolver,
        outbound_manager,
        router,
        dispatcher,
        statistics_manager,
        inbound_manager,
        #[cfg(feature = "tun")]
        tun_runner,
        dns_listener,
        dns_listen,
        dns_enabled: dns_enable,
    })
}

#[cfg(test)]
mod tests {
    use crate::{Config, Options, shutdown, start_scaffold};
    use std::{sync::Once, thread, time::Duration};

    static INIT: Once = Once::new();

    pub fn initialize() {
        INIT.call_once(|| {
            env_logger::init();
            crate::setup_default_crypto_provider();
        });
    }

    #[test]
    fn start_and_stop() {
        let conf = r#"
        socks-port: 7891
        bind-address: 127.0.0.1
        mmdb: "tests/data/Country.mmdb"
        proxies:
          - {name: DIRECT_alias, type: direct}
          - {name: REJECT_alias, type: reject}
        "#;

        let handle = thread::spawn(|| {
            start_scaffold(Options {
                config: Config::Str(conf.to_string()),
                cwd: None,
                rt: None,
                log_file: None,
            })
            .unwrap()
        });

        thread::spawn(|| {
            thread::sleep(Duration::from_secs(3));
            assert!(shutdown());
        });

        handle.join().unwrap();
    }
}
