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
                        .inspect_err(
                            |e| warn!(provider = %n, "skipping inbound entry: {e}"),
                        )
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
        let items = self.fetcher.initial().await?;
        if let Some(updater) = self.fetcher.on_update.as_ref() {
            updater(items.clone()).await;
        }
        Ok(items)
    }
}

pub type ThreadSafeInboundProvider = Arc<InboundSetProvider>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::remote_content_manager::providers::{
        MockProviderVehicle, ProviderVehicleType,
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;

    fn make_vehicle(content: &'static [u8]) -> Arc<MockProviderVehicle> {
        let tmp = std::env::temp_dir()
            .join(format!("inbound_provider_test_{}", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, content).unwrap();
        let mut mock = MockProviderVehicle::new();
        mock.expect_path()
            .return_const(tmp.to_str().unwrap().to_owned());
        mock.expect_read().returning(move || Ok(content.to_vec()));
        mock.expect_typ().return_const(ProviderVehicleType::File);
        Arc::new(mock)
    }

    #[tokio::test]
    async fn test_initialize_parses_opts_and_calls_on_update() {
        let yaml = b"\
listeners:
  - name: socks-test
    type: socks
    listen: 0.0.0.0
    port: 1080
    udp: true
";
        let vehicle = make_vehicle(yaml);
        let received: Arc<Mutex<Vec<InboundOpts>>> = Arc::new(Mutex::new(vec![]));
        let received_clone = received.clone();

        let provider = InboundSetProvider::new(
            "test".to_owned(),
            Duration::ZERO,
            vehicle,
            move |opts| {
                let received = received_clone.clone();
                Box::pin(async move {
                    received.lock().await.extend(opts);
                })
            },
        )
        .unwrap();

        let initial = provider.initialize().await.unwrap();
        assert_eq!(initial.len(), 1);

        let called = received.lock().await;
        assert_eq!(called.len(), 1);
        assert_eq!(called[0].common_opts().name, "socks-test");
        assert_eq!(called[0].common_opts().port, 1080);
    }

    #[tokio::test]
    async fn test_invalid_entries_are_skipped() {
        let yaml = b"\
listeners:
  - name: valid
    type: socks
    listen: 0.0.0.0
    port: 1080
    udp: true
  - name: invalid
    type: unknown-protocol
    listen: 0.0.0.0
    port: 9999
";
        let vehicle = make_vehicle(yaml);
        let received: Arc<Mutex<Vec<InboundOpts>>> = Arc::new(Mutex::new(vec![]));
        let received_clone = received.clone();

        let provider = InboundSetProvider::new(
            "test".to_owned(),
            Duration::ZERO,
            vehicle,
            move |opts| {
                let received = received_clone.clone();
                Box::pin(async move {
                    received.lock().await.extend(opts);
                })
            },
        )
        .unwrap();

        let initial = provider.initialize().await.unwrap();
        assert_eq!(initial.len(), 1);
        assert_eq!(initial[0].common_opts().name, "valid");
    }

    #[tokio::test]
    async fn test_empty_listeners_calls_on_update_with_empty_vec() {
        let yaml = b"listeners:\n";
        let vehicle = make_vehicle(yaml);
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        let provider = InboundSetProvider::new(
            "test".to_owned(),
            Duration::ZERO,
            vehicle,
            move |opts| {
                let called = called_clone.clone();
                Box::pin(async move {
                    assert!(opts.is_empty());
                    *called.lock().await = true;
                })
            },
        )
        .unwrap();

        let initial = provider.initialize().await.unwrap();
        assert!(initial.is_empty());
        assert!(*called.lock().await);
    }
}
