use crate::{
    app::remote_content_manager::providers::{
        ThreadSafeProviderVehicle, fetcher::Fetcher,
    },
    config::internal::listener::InboundOpts,
};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::warn;

/// The YAML structure expected at the provider URL / file.
///
/// ```yaml
/// listeners:
///   - name: ss-node
///     type: shadowsocks
///     listen: 0.0.0.0
///     port: 8901
///     cipher: 2022-blake3-aes-256-gcm
///     password: "base64key"
///     udp: true
/// ```
#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    listeners: Option<Vec<HashMap<String, Value>>>,
}

type InboundUpdater =
    Box<dyn Fn(Vec<InboundOpts>) -> BoxFuture<'static, ()> + Send + Sync + 'static>;
type InboundParser =
    Box<dyn Fn(&[u8]) -> anyhow::Result<Vec<InboundOpts>> + Send + Sync + 'static>;

pub struct InboundSetProvider {
    fetcher: Fetcher<InboundUpdater, InboundParser>,
}

impl InboundSetProvider {
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        on_update: impl Fn(Vec<InboundOpts>) -> BoxFuture<'static, ()>
        + Send
        + Sync
        + 'static,
    ) -> anyhow::Result<Self> {
        let n = name.clone();
        let parser: InboundParser = Box::new(move |input: &[u8]| {
            let scheme: ProviderScheme =
                serde_yaml::from_slice(input).map_err(|e| {
                    anyhow::anyhow!("inbound provider {n} parse error: {e}")
                })?;
            let opts = scheme
                .listeners
                .unwrap_or_default()
                .into_iter()
                .filter_map(|m| {
                    InboundOpts::try_from(m)
                        .inspect_err(|e| warn!("skipping inbound entry: {e}"))
                        .ok()
                })
                .collect();
            Ok(opts)
        });

        let updater: InboundUpdater = Box::new(move |opts| on_update(opts));

        Ok(Self {
            fetcher: Fetcher::new(name, interval, vehicle, parser, Some(updater)),
        })
    }

    pub async fn initialize(&self) -> anyhow::Result<Vec<InboundOpts>> {
        self.fetcher.initial().await
    }
}

pub type ThreadSafeInboundProvider = Arc<InboundSetProvider>;
