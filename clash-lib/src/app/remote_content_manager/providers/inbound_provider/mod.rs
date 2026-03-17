use crate::{
    Error,
    app::remote_content_manager::providers::{
        Provider, ProviderType, ProviderVehicleType, ThreadSafeProviderVehicle,
        fetcher::Fetcher,
    },
    common::errors::map_io_error,
    config::internal::listener::InboundOpts,
};
use async_trait::async_trait;
use erased_serde::Serialize as ESerialize;
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::RwLock;
use tracing::debug;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct ProviderScheme {
    #[serde(rename = "listeners")]
    listeners: Option<Vec<HashMap<String, Value>>>,
}

struct Inner {
    inbounds: Vec<InboundOpts>,
}

type InboundUpdater = Box<
    dyn Fn(Vec<InboundOpts>) -> BoxFuture<'static, ()> + Send + Sync + 'static,
>;
type InboundParser =
    Box<dyn Fn(&[u8]) -> anyhow::Result<Vec<InboundOpts>> + Send + Sync + 'static>;

pub struct InboundSetProvider {
    fetcher: Fetcher<InboundUpdater, InboundParser>,
    inner: Arc<RwLock<Inner>>,
}

impl InboundSetProvider {
    /// Create a new `InboundSetProvider`.
    ///
    /// `on_update` is called every time the inbound set changes.  It receives
    /// the full new list of `InboundOpts` and is responsible for applying them
    /// to the `InboundManager` (or any other consumer).
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        on_update: Option<InboundUpdater>,
    ) -> anyhow::Result<Self> {
        let inner = Arc::new(RwLock::new(Inner { inbounds: vec![] }));
        let inner_clone = inner.clone();

        let on_update = on_update.map(Arc::new);
        let n = name.clone();

        let updater: InboundUpdater = Box::new(
            move |input: Vec<InboundOpts>| -> BoxFuture<'static, ()> {
                let n = n.clone();
                let inner = inner_clone.clone();
                let cb = on_update.clone();
                Box::pin(async move {
                    let mut guard = inner.write().await;
                    debug!("updating {} inbound listeners for: {}", input.len(), n);
                    guard.inbounds = input.clone();
                    drop(guard);
                    if let Some(cb) = cb {
                        cb(input).await;
                    }
                })
            },
        );

        let n = name.clone();
        let parser: InboundParser = Box::new(
            move |input: &[u8]| -> anyhow::Result<Vec<InboundOpts>> {
                let scheme: ProviderScheme =
                    serde_yaml::from_slice(input).map_err(|x| {
                        Error::InvalidConfig(format!(
                            "inbound provider parse error {n}: {x}"
                        ))
                    })?;
                let listeners = scheme.listeners.unwrap_or_default();
                listeners
                    .into_iter()
                    .map(|m| {
                        InboundOpts::try_from(m).map_err(|e| {
                            Error::InvalidConfig(format!(
                                "inbound provider {n} listener parse error: {e}"
                            ))
                            .into()
                        })
                    })
                    .collect()
            },
        );

        let fetcher = Fetcher::new(name, interval, vehicle, parser, Some(updater));
        Ok(Self { fetcher, inner })
    }

    /// Returns the currently loaded set of inbound options.
    pub async fn inbounds(&self) -> Vec<InboundOpts> {
        self.inner.read().await.inbounds.clone()
    }
}

#[async_trait]
impl Provider for InboundSetProvider {
    fn name(&self) -> &str {
        self.fetcher.name()
    }

    fn vehicle_type(&self) -> ProviderVehicleType {
        self.fetcher.vehicle_type()
    }

    fn typ(&self) -> ProviderType {
        ProviderType::Inbound
    }

    async fn initialize(&self) -> std::io::Result<()> {
        let ele = self.fetcher.initial().await.map_err(map_io_error)?;
        debug!(
            "{} initialized with {} inbound listeners",
            self.name(),
            ele.len()
        );
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(ele).await;
        }
        Ok(())
    }

    async fn update(&self) -> std::io::Result<()> {
        let (ele, same) = self.fetcher.update().await.map_err(map_io_error)?;
        debug!(
            "{} updated with {} inbound listeners, same? {}",
            self.name(),
            ele.len(),
            same
        );
        if !same {
            if let Some(updater) = self.fetcher.on_update.as_ref() {
                updater(ele).await;
            }
        }
        Ok(())
    }

    async fn as_map(&self) -> HashMap<String, Box<dyn ESerialize + Send>> {
        let mut m: HashMap<String, Box<dyn ESerialize + Send>> = HashMap::new();
        m.insert("name".to_owned(), Box::new(self.name().to_string()));
        m.insert("type".to_owned(), Box::new(self.typ().to_string()));
        m.insert(
            "vehicleType".to_owned(),
            Box::new(self.vehicle_type().to_string()),
        );
        m.insert(
            "updatedAt".to_owned(),
            Box::new(self.fetcher.updated_at().await),
        );
        m
    }
}
