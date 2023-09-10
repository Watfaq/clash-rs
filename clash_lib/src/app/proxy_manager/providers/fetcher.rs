use std::{
    fs::{self, metadata},
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use tokio::{
    sync::{Mutex, RwLock},
    time::Instant,
};
use tracing::{info, trace, warn};

use crate::common::utils;

use super::{ProviderVehicleType, ThreadSafeProviderVehicle};

struct Inner {
    updated_at: SystemTime,
    hash: [u8; 16],
}

pub struct Fetcher<U, P> {
    name: String,
    interval: Duration,
    vehicle: ThreadSafeProviderVehicle,
    thread_handle: Option<tokio::task::JoinHandle<()>>,
    ticker: Option<tokio::time::Interval>,
    inner: std::sync::Arc<tokio::sync::RwLock<Inner>>,
    parser: Arc<Mutex<P>>,
    pub on_update: Option<Arc<Mutex<U>>>,
}

impl<T, U, P> Fetcher<U, P>
where
    T: Send + Sync + 'static,
    U: Fn(T) -> BoxFuture<'static, ()> + Send + Sync + 'static,
    P: Fn(&[u8]) -> anyhow::Result<T> + Send + Sync + 'static,
{
    pub fn new(
        name: String,
        interval: Duration,
        vehicle: ThreadSafeProviderVehicle,
        parser: P,
        on_update: Option<U>,
    ) -> Self {
        Self {
            name,
            interval,
            vehicle,
            thread_handle: None,
            ticker: match interval.as_secs() {
                0 => None,
                _ => Some(tokio::time::interval_at(
                    Instant::now() + interval,
                    interval,
                )),
            },
            inner: Arc::new(tokio::sync::RwLock::new(Inner {
                updated_at: SystemTime::UNIX_EPOCH,
                hash: [0; 16],
            })),
            parser: Arc::new(Mutex::new(parser)),
            on_update: on_update.map(|f| Arc::new(Mutex::new(f))),
        }
    }
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn vehicle_type(&self) -> super::ProviderVehicleType {
        self.vehicle.typ()
    }

    pub async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.read().await.updated_at.into()
    }

    pub async fn initial(&mut self) -> anyhow::Result<T> {
        let mut is_local = false;
        let mut immediately_update = false;

        let vehicle_path = self.vehicle.path().to_owned();

        let mut inner = self.inner.write().await;

        let content = match metadata(&vehicle_path) {
            Ok(meta) => {
                let content = fs::read(&vehicle_path)?;
                is_local = true;
                inner.updated_at = meta.modified()?;
                immediately_update = SystemTime::now()
                    .duration_since(inner.updated_at)
                    .expect("wrong system clock")
                    > self.interval;
                content
            }
            Err(_) => self.vehicle.read().await?,
        };

        let proxies = match (self.parser.lock().await)(&content) {
            Ok(proxies) => proxies,
            Err(e) => {
                if !is_local {
                    return Err(e);
                }
                let content = self.vehicle.read().await?;
                (self.parser.lock().await)(&content)?
            }
        };

        if self.vehicle_type() != ProviderVehicleType::File && !is_local {
            let p = self.vehicle.path().to_owned();
            let path = Path::new(p.as_str());
            let prefix = path.parent().unwrap();
            if !prefix.exists() {
                fs::create_dir_all(prefix)?;
            }
            fs::write(self.vehicle.path(), &content)?;
        }

        inner.hash = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        drop(inner);

        if let Some(ticker) = self.ticker.take() {
            self.pull_loop(immediately_update, ticker);
        }

        Ok(proxies)
    }

    pub async fn update(&self) -> anyhow::Result<(T, bool)> {
        Fetcher::<U, P>::update_inner(
            self.inner.clone(),
            self.vehicle.clone(),
            self.parser.clone(),
        )
        .await
    }

    async fn update_inner(
        inner: Arc<RwLock<Inner>>,
        vehicle: ThreadSafeProviderVehicle,
        parser: Arc<Mutex<P>>,
    ) -> anyhow::Result<(T, bool)> {
        let mut this = inner.write().await;
        let content = vehicle.read().await?;
        let proxies = (parser.lock().await)(&content)?;

        let now = SystemTime::now();
        let hash = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        if hash == this.hash {
            this.updated_at = now;
            filetime::set_file_times(vehicle.path(), now.into(), now.into())?;
            return Ok((proxies, true));
        }

        if vehicle.typ() != ProviderVehicleType::File {
            let p = vehicle.path().to_owned();
            let path = Path::new(p.as_str());
            let prefix = path.parent().unwrap();
            if !prefix.exists() {
                fs::create_dir_all(prefix)?;
            }

            fs::write(vehicle.path(), &content)?;
        }

        this.hash = hash;
        this.updated_at = now;

        Ok((proxies, false))
    }

    pub fn destroy(&mut self) {
        if let Some(handle) = self.thread_handle.take() {
            handle.abort();
        }
    }

    fn pull_loop(&mut self, immediately_update: bool, mut ticker: tokio::time::Interval) {
        let inner = self.inner.clone();
        let vehicle = self.vehicle.clone();
        let parser = self.parser.clone();
        let on_update = self.on_update.clone();
        let name = self.name.clone();
        let fire_immediately = immediately_update;

        self.thread_handle = Some(tokio::spawn(async move {
            info!("{} started", &name);
            loop {
                let inner = inner.clone();
                let vehicle = vehicle.clone();
                let parser = parser.clone();
                let name = name.clone();
                let on_update = on_update.clone();
                let update = || async move {
                    let (elm, same) =
                        match Fetcher::<U, P>::update_inner(inner, vehicle, parser).await {
                            Ok((elm, same)) => (elm, same),
                            Err(e) => {
                                warn!("{} update failed: {}", &name, e);
                                return;
                            }
                        };

                    if same {
                        trace!("fetcher {} no update", &name);
                        return;
                    }

                    if let Some(on_update) = on_update {
                        info!("fetcher {} updated", &name);
                        on_update.lock().await(elm).await;
                    }
                };

                if fire_immediately {
                    update().await;
                    ticker.tick().await;
                } else {
                    ticker.tick().await;
                    update().await;
                }
            }
        }));
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc, time::Duration};

    use futures::future::BoxFuture;
    use tokio::time::sleep;

    use crate::app::proxy_manager::providers::{MockProviderVehicle, ProviderVehicleType};

    use super::Fetcher;

    #[tokio::test]
    async fn test_fetcher() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let tx1 = tx.clone();

        let mut mock_vehicle = MockProviderVehicle::new();
        let mock_file = "/tmp/mock_provider_vehicle";
        if Path::new(mock_file).exists() {
            std::fs::remove_file(mock_file).unwrap();
        }
        std::fs::write(mock_file, vec![1, 2, 3]).unwrap();

        mock_vehicle
            .expect_path()
            .return_const(mock_file.to_owned());
        mock_vehicle.expect_read().returning(|| Ok(vec![4, 5, 6]));
        mock_vehicle
            .expect_typ()
            .return_const(ProviderVehicleType::File);

        let parser = move |i: &[u8]| -> anyhow::Result<String> {
            let copy = i.to_owned();
            tx1.try_send(copy).unwrap();
            Ok("parsed".to_owned())
        };

        let updater = move |input: String| -> BoxFuture<'static, ()> {
            Box::pin(async move {
                assert_eq!(input, "parsed".to_owned());
            })
        };

        let mut f = Fetcher::new(
            "test_fetcher".to_string(),
            Duration::from_secs(1),
            Arc::new(mock_vehicle),
            parser,
            Some(updater),
        );

        let _ = f.initial().await;

        sleep(Duration::from_secs_f64(5.5)).await;
        f.destroy();

        drop(tx);
        drop(f);

        let mut parsed = vec![];

        while let Some(message) = rx.recv().await {
            parsed.push(message);
        }

        assert!(parsed.len() > 5);
        assert_eq!(parsed[0], vec![1, 2, 3]);
        assert_eq!(parsed[1], vec![4, 5, 6]);
    }
}
