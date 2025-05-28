use std::{
    collections::{HashMap, HashSet},
    io,
    time::Instant,
};

use erased_serde::Serialize;
use tracing::debug;

use crate::{
    app::{
        dispatcher::{BoxedChainedDatagram, BoxedChainedStream},
        dns::ThreadSafeDNSResolver,
        remote_content_manager::{
            ProxyManager, providers::proxy_provider::ThreadSafeProxyProvider,
        },
    },
    proxy::{
        AnyOutboundHandler, ConnectorType, DialWithConnector, HandlerCommonOptions,
        OutboundHandler, OutboundType,
        utils::{RemoteConnector, provider_helper::get_proxies_from_providers},
    },
    session::Session,
};

/// Error type for smart group failures
#[derive(Debug)]
enum SmartError {
    NoProxy,
    AllProxiesFailed(Vec<String>),
}

impl std::fmt::Display for SmartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoProxy => write!(f, "no available proxy in smart group"),
            Self::AllProxiesFailed(names) => {
                write!(f, "all proxies failed: {:?}", names)
            }
        }
    }
}

impl SmartError {
    fn log_error(&self) {
        match self {
            Self::NoProxy => debug!("no available proxy in smart group"),
            Self::AllProxiesFailed(names) => {
                debug!("all proxies failed: {:?}", names)
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct HandlerOptions {
    /// Common proxy handler options
    pub common_opts: HandlerCommonOptions,
    /// Name of this proxy group
    pub name: String,
    /// Whether UDP is supported
    pub udp: bool,
}

/// Tracks and manages the penalty score for a proxy
/// Higher penalty values indicate worse performance
struct ProxyPenalty {
    /// Current penalty value
    value: f64,
    /// When the penalty was last updated
    last_update: Instant,
}

impl ProxyPenalty {
    /// Create a new ProxyPenalty with initial score 0
    #[inline]
    fn new() -> Self {
        Self {
            value: 0.0,
            last_update: Instant::now(),
        }
    }

    /// Increase penalty exponentially after a failure
    /// Penalty grows more severely with consecutive failures
    #[inline]
    fn add_penalty(&mut self) {
        self.value = (self.value + 1.0) * 2.0; // Exponential growth
        self.last_update = Instant::now();
    }

    /// Decay penalty over time when not used
    /// Uses exponential decay based on elapsed time
    #[inline]
    fn decay(&mut self) {
        let elapsed = self.last_update.elapsed().as_secs_f64();
        if self.value > 0.0 && elapsed > 0.0 {
            // Half-life of ~10 seconds
            self.value *= 0.5f64.powf(elapsed / 10.0);
        }
        self.last_update = Instant::now();
    }

    /// Reduce penalty significantly after a success
    /// Quick recovery to allow retrying previously failed proxies
    #[inline]
    fn reward(&mut self) {
        self.value *= 0.2; // 80% reduction
        self.last_update = Instant::now();
    }
}

/// Track statistics and performance metrics for a proxy per site
struct SiteStats {
    /// History of connection delays
    delay_history: Vec<f64>,
    /// Track connection success/failure history
    success_history: Vec<bool>,
    /// Last time this site was accessed
    last_attempt: Instant,
    /// Maximum history size to prevent unbounded growth
    max_history: usize,
}

impl SiteStats {
    fn new() -> Self {
        Self {
            delay_history: Vec::with_capacity(10),
            success_history: Vec::with_capacity(10),
            last_attempt: Instant::now(),
            max_history: 10,
        }
    }

    /// Calculate success rate for this site
    fn success_rate(&self) -> f64 {
        if self.success_history.is_empty() {
            return 0.0;
        }
        self.success_history.iter().filter(|&&x| x).count() as f64
            / self.success_history.len() as f64
    }

    /// Add a new connection result
    fn add_result(&mut self, delay: f64, success: bool) {
        // Update delay history
        if success {
            if self.delay_history.len() >= self.max_history {
                self.delay_history.remove(0);
            }
            self.delay_history.push(delay);
        }

        // Update success history
        if self.success_history.len() >= self.max_history {
            self.success_history.remove(0);
        }
        self.success_history.push(success);

        self.last_attempt = Instant::now();
    }

    /// Check if stats are stale
    fn is_stale(&self) -> bool {
        self.last_attempt.elapsed().as_secs() > 300 // 5 minutes
    }

    /// Calculate weighted delay score considering recent history and success
    /// rate
    fn get_delay_score(&self) -> f64 {
        if self.delay_history.is_empty() {
            return 9999.0;
        }

        let mut sum = 0.0;
        let mut weight_sum = 0.0;
        let now = Instant::now();

        for delay in self.delay_history.iter() {
            let age = now.duration_since(self.last_attempt).as_secs_f64();
            // Faster decay for older samples and higher delays
            let time_weight = (-0.1 * age).exp();
            let delay_weight = (-0.001 * delay).exp(); // Higher delays get less weight
            let weight = time_weight * delay_weight;

            sum += delay * weight;
            weight_sum += weight;
        }

        let avg_delay = if weight_sum > 0.0 {
            sum / weight_sum
        } else {
            9999.0
        };

        // Adjust based on success rate
        let success_rate = self.success_rate();
        avg_delay * (2.0 - success_rate) // Higher success rate reduces effective delay
    }
}

pub struct SmartState {
    penalty: HashMap<String, ProxyPenalty>,
    site_stats: HashMap<String, HashMap<String, SiteStats>>, /* Proxy name ->
                                                              * Site -> Stats */
}

impl SmartState {
    fn new() -> Self {
        Self {
            penalty: HashMap::new(),
            site_stats: HashMap::new(),
        }
    }

    fn cleanup_stale(&mut self) {
        for stats in self.site_stats.values_mut() {
            stats.retain(|_, site_stat| !site_stat.is_stale());
        }
    }
}

pub struct Handler {
    opts: HandlerOptions,
    providers: Vec<ThreadSafeProxyProvider>,
    proxy_manager: ProxyManager,
    smart_state: tokio::sync::Mutex<SmartState>,
}

impl std::fmt::Debug for Handler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smart")
            .field("name", &self.opts.name)
            .finish()
    }
}

impl Handler {
    pub fn new(
        opts: HandlerOptions,
        providers: Vec<ThreadSafeProxyProvider>,
        proxy_manager: ProxyManager,
    ) -> Self {
        Self {
            opts,
            providers,
            proxy_manager,
            smart_state: tokio::sync::Mutex::new(SmartState::new()),
        }
    }

    async fn get_proxies(&self, touch: bool) -> Vec<AnyOutboundHandler> {
        get_proxies_from_providers(&self.providers, touch).await
    }

    /// Smart selection considering all available metrics
    async fn pick_smart(&self, sess: &Session) -> Option<AnyOutboundHandler> {
        let proxies = self.get_proxies(false).await;
        if proxies.is_empty() {
            debug!("{} no proxies available", self.name());
            return None;
        }

        let site = sess.destination.host();
        let dest_ip = sess.destination.ip().map(|ip| ip.to_string());

        debug!(
            "{} selecting proxy for site: {}, ip: {:?}",
            self.name(),
            site,
            dest_ip
        );

        let mut best: Option<(f64, AnyOutboundHandler, String)> = None;
        let mut state_guard = self.smart_state.lock().await;
        state_guard.cleanup_stale();

        for proxy in proxies {
            let name = proxy.name().to_string();

            // Get basic metrics
            let delay = self.proxy_manager.get_delay(&name).await.unwrap_or(9999.0);
            let packet_loss = self
                .proxy_manager
                .get_packet_loss(&name)
                .await
                .unwrap_or(1.0);
            let rtt = self.proxy_manager.get_rtt(&name).await.unwrap_or(9999.0);
            let alive = self.proxy_manager.alive(&name).await;

            debug!(
                "{} proxy {} metrics - delay: {:.1}ms, loss: {:.1}%, rtt: {:.1}ms, \
                 alive: {}",
                self.name(),
                name,
                delay,
                packet_loss * 100.0,
                rtt,
                alive
            );

            // Get site-specific tuning
            let site_tuning = self.proxy_manager.get_site_tuning(&site).await;
            let delay_weight = site_tuning.delay_weight.unwrap_or(1.0);
            let packet_loss_weight =
                site_tuning.packet_loss_weight.unwrap_or(1000.0);
            let rtt_weight = site_tuning.rtt_weight.unwrap_or(1.0);
            let alive_penalty = site_tuning.alive_penalty.unwrap_or(5000.0);

            // Get historical performance
            let site_stats = state_guard
                .site_stats
                .get(&name)
                .and_then(|m| m.get(&site))
                .map(|s| (s.get_delay_score(), s.success_rate()));

            let ip_stats = dest_ip.as_ref().and_then(|ip| {
                state_guard
                    .site_stats
                    .get(&name)
                    .and_then(|m| m.get(ip))
                    .map(|s| (s.get_delay_score(), s.success_rate()))
            });

            if let Some((sd, sr)) = site_stats {
                debug!(
                    "{} proxy {} site history - avg delay: {:.1}ms, success rate: \
                     {:.1}%",
                    self.name(),
                    name,
                    sd,
                    sr * 100.0
                );
            }

            if let Some((id, ir)) = ip_stats {
                debug!(
                    "{} proxy {} IP history - avg delay: {:.1}ms, success rate: \
                     {:.1}%",
                    self.name(),
                    name,
                    id,
                    ir * 100.0
                );
            }

            // Apply penalties
            let penalty = state_guard
                .penalty
                .entry(name.clone())
                .or_insert_with(ProxyPenalty::new);
            penalty.decay();
            let penalty_score = penalty.value;

            debug!(
                "{} proxy {} current penalty score: {:.1}",
                self.name(),
                name,
                penalty_score
            );

            // Calculate composite score
            let site_delay = site_stats.map(|(d, r)| d * (2.0 - r)).unwrap_or(delay);
            let ip_delay = ip_stats.map(|(d, r)| d * (2.0 - r)).unwrap_or(delay);

            let weight = ((site_delay + ip_delay) / 2.0) * delay_weight
                + packet_loss * packet_loss_weight
                + rtt * rtt_weight
                + if alive { 0.0 } else { alive_penalty }
                + penalty_score;

            debug!(
                "{} proxy {} final weight score: {:.1}",
                self.name(),
                name,
                weight
            );

            if best.is_none() || weight < best.as_ref().unwrap().0 {
                debug!(
                    "{} new best proxy: {} (score: {:.1})",
                    self.name(),
                    name,
                    weight
                );
                best = Some((weight, proxy.clone(), name));
            }
        }

        best.map(|(_, p, name)| {
            debug!("{} selected proxy: {}", self.name(), name);
            p
        })
    }

    /// Adaptive retry with exponential backoff and state updates
    async fn adaptive_retry(
        &self,
        sess: &Session,
        resolver: &ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        let site = sess.destination.host();
        let dest_ip = sess.destination.ip().map(|ip| ip.to_string());
        let mut tried = HashSet::new();
        let mut retry_delay = 100; // Initial retry delay in ms

        // Dynamic retry config based on site history
        let mut state_guard = self.smart_state.lock().await;
        state_guard.cleanup_stale();
        let site_stats = state_guard
            .site_stats
            .values()
            .filter_map(|stats| stats.get(&site))
            .collect::<Vec<_>>();

        // Calculate max retries based on site success rate
        let avg_success_rate = if !site_stats.is_empty() {
            site_stats.iter().map(|s| s.success_rate()).sum::<f64>()
                / site_stats.len() as f64
        } else {
            0.5 // Default to middle ground
        };

        drop(state_guard); // Release the lock early

        // More retries for historically problematic sites
        let max_retries = (3.0 * (2.0 - avg_success_rate)).round() as u32;
        let mut retries = 0;

        debug!(
            "{} starting adaptive retry for {}, max_retries: {}",
            self.name(),
            site,
            max_retries
        );

        while retries < max_retries {
            match self.pick_smart(sess).await {
                Some(proxy) => {
                    let name = proxy.name().to_string();
                    if tried.contains(&name) {
                        continue;
                    }
                    tried.insert(name.clone());

                    let start = Instant::now();
                    match proxy.connect_stream(sess, resolver.clone()).await {
                        Ok(stream) => {
                            let delay = start.elapsed().as_secs_f64() * 1000.0;
                            let mut state = self.smart_state.lock().await;

                            // Update success metrics
                            if let Some(penalty) = state.penalty.get_mut(&name) {
                                penalty.reward();
                            }

                            // Update site stats
                            let site_stats =
                                state.site_stats.entry(name.clone()).or_default();
                            let stats = site_stats
                                .entry(site.to_string())
                                .or_insert_with(SiteStats::new);
                            stats.add_result(delay, true);

                            // Update IP stats
                            if let Some(ip) = &dest_ip {
                                let ip_stats = site_stats
                                    .entry(ip.to_string())
                                    .or_insert_with(SiteStats::new);
                                ip_stats.add_result(delay, true);
                            }

                            debug!(
                                "{} successfully connected to {} via {}, delay: \
                                 {:.2}ms, attempts: {}",
                                self.name(),
                                site,
                                name,
                                delay,
                                retries + 1
                            );
                            return Ok(stream);
                        }
                        Err(e) => {
                            debug!(
                                "{} proxy {} connection failed: {}",
                                self.name(),
                                name,
                                e
                            );
                            let mut state = self.smart_state.lock().await;

                            // Update failure metrics
                            if let Some(penalty) = state.penalty.get_mut(&name) {
                                penalty.add_penalty();
                            }

                            let site_stats =
                                state.site_stats.entry(name.clone()).or_default();

                            // Update site stats for failure
                            let stats = site_stats
                                .entry(site.to_string())
                                .or_insert_with(SiteStats::new);
                            stats.add_result(9999.0, false);

                            // Update IP stats for failure
                            if let Some(ip) = &dest_ip {
                                let ip_stats = site_stats
                                    .entry(ip.to_string())
                                    .or_insert_with(SiteStats::new);
                                ip_stats.add_result(9999.0, false);
                            }

                            tokio::time::sleep(std::time::Duration::from_millis(
                                retry_delay,
                            ))
                            .await;
                            retry_delay *= 2; // Exponential backoff
                            retries += 1;
                            debug!(
                                "{} retry {} of {} for {}, next delay: {}ms",
                                self.name(),
                                retries,
                                max_retries,
                                site,
                                retry_delay
                            );
                            continue;
                        }
                    }
                }
                None => {
                    let error = SmartError::NoProxy;
                    error.log_error();
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "no available proxy in smart group",
                    ));
                }
            }
        }

        let error = SmartError::AllProxiesFailed(tried.into_iter().collect());
        error.log_error();
        Err(io::Error::new(
            io::ErrorKind::Other,
            "smart proxy selection failed",
        ))
    }
}

impl DialWithConnector for Handler {}

#[async_trait::async_trait]
impl OutboundHandler for Handler {
    fn name(&self) -> &str {
        &self.opts.name
    }

    fn proto(&self) -> OutboundType {
        OutboundType::Smart
    }

    async fn support_udp(&self) -> bool {
        self.opts.udp
    }

    async fn connect_stream(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedStream> {
        debug!("{} starting smart proxy selection", self.name());
        match self.adaptive_retry(sess, &resolver).await {
            Ok(stream) => {
                debug!(
                    "{} successfully connected using smart selection",
                    self.name()
                );
                Ok(stream)
            }
            Err(e) => {
                debug!(
                    "{} failed to connect with all available proxies: {:?}",
                    self.name(),
                    e
                );
                Err(e)
            }
        }
    }

    async fn connect_datagram(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
    ) -> io::Result<BoxedChainedDatagram> {
        // For UDP we just use the best proxy without retries
        if let Some(proxy) = self.pick_smart(sess).await {
            debug!("{} use proxy {} (smart)", self.name(), proxy.name());
            proxy.connect_datagram(sess, resolver).await
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "no available proxy in smart group",
            ))
        }
    }

    async fn support_connector(&self) -> ConnectorType {
        ConnectorType::Tcp
    }

    async fn connect_stream_with_connector(
        &self,
        sess: &Session,
        resolver: ThreadSafeDNSResolver,
        connector: &dyn RemoteConnector,
    ) -> io::Result<BoxedChainedStream> {
        if let Some(proxy) = self.pick_smart(sess).await {
            debug!("{} use proxy {} (smart)", self.name(), proxy.name());
            proxy
                .connect_stream_with_connector(sess, resolver, connector)
                .await
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "no available proxy in smart group",
            ))
        }
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn Serialize + Send>> {
        let all = get_proxies_from_providers(&self.providers, false).await;
        let mut m = HashMap::new();
        m.insert("type".to_string(), Box::new(self.proto()) as _);
        m.insert(
            "all".to_string(),
            Box::new(all.iter().map(|x| x.name().to_owned()).collect::<Vec<_>>())
                as _,
        );
        m
    }

    fn icon(&self) -> Option<String> {
        self.opts.common_opts.icon.clone()
    }
}
