use std::{
    fs::{self, metadata},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use futures::future::BoxFuture;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
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
    ticker_interval: Duration,
    inner: Arc<RwLock<Inner>>,
    parser: Arc<P>,
    pub on_update: Option<Arc<U>>,
    /// Aborts the polling and file-watch tasks on drop so config reloads don't
    /// leak tasks or OS watches.
    cancel_token: CancellationToken,
}

impl<U, P> Drop for Fetcher<U, P> {
    fn drop(&mut self) {
        self.cancel_token.cancel();
    }
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
            ticker_interval: interval,
            inner: Arc::new(tokio::sync::RwLock::new(Inner {
                updated_at: SystemTime::UNIX_EPOCH,
                hash: [0; 16],
            })),
            parser: Arc::new(parser),
            on_update: on_update.map(|f| Arc::new(f)),
            cancel_token: CancellationToken::new(),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    pub fn vehicle_type(&self) -> ProviderVehicleType {
        self.vehicle.typ()
    }

    pub async fn updated_at(&self) -> DateTime<Utc> {
        self.inner.read().await.updated_at.into()
    }

    pub async fn initial(&self) -> anyhow::Result<T> {
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

        let parser_guard = &self.parser;

        let items = match (parser_guard)(&content) {
            Ok(proxies) => proxies,
            Err(e) => {
                if !is_local {
                    return Err(e);
                }
                let content = self.vehicle.read().await?;
                (parser_guard)(&content)?
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

        if !self.ticker_interval.is_zero() {
            self.pull_loop(
                immediately_update,
                tokio::time::interval(self.ticker_interval),
            )
            .await;
        }

        Ok(items)
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
        parser: Arc<P>,
    ) -> anyhow::Result<(T, bool)> {
        let mut this = inner.write().await;
        let content = vehicle.read().await?;
        let proxies = parser(&content)?;

        let now = SystemTime::now();
        let hash = utils::md5(&content)[..16]
            .try_into()
            .expect("md5 must be 16 bytes");

        if hash == this.hash {
            this.updated_at = now;
            // Only bump the mtime of an http cache file (for the staleness
            // check). Doing it to a watched `File` vehicle would re-trigger the
            // watcher in an endless read→touch→event loop.
            if vehicle.typ() != ProviderVehicleType::File {
                filetime::set_file_times(vehicle.path(), now.into(), now.into())?;
            }
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

    #[cfg(test)]
    pub async fn destroy(&mut self) {
        self.cancel_token.cancel();
    }

    /// Run one update cycle, invoking `on_update` when the content changed.
    /// Shared by the polling loop and the file watcher so they can't diverge.
    async fn run_update(
        inner: Arc<RwLock<Inner>>,
        vehicle: ThreadSafeProviderVehicle,
        parser: Arc<P>,
        on_update: Option<Arc<U>>,
        name: &str,
    ) {
        let (elm, same) =
            match Fetcher::<U, P>::update_inner(inner, vehicle, parser).await {
                Ok(result) => result,
                Err(e) => {
                    warn!("{} update failed: {}", name, e);
                    return;
                }
            };

        if same {
            trace!("fetcher {} no update", name);
            return;
        }

        if let Some(on_update) = on_update {
            info!("fetcher {} updated", name);
            on_update(elm).await;
        }
    }

    /// Watch the provider's local file and reload its content on change.
    ///
    /// Watches the parent directory (not the file itself) so atomic-save
    /// editors that replace the inode — vim, VS Code, `sed -i` — keep working,
    /// filtering events down to the target file name. No-op for non-`File`
    /// vehicles.
    pub async fn start_watch(&self) -> anyhow::Result<()> {
        use notify::{EventKind, RecursiveMode, Watcher, recommended_watcher};

        if self.vehicle_type() != ProviderVehicleType::File {
            return Ok(());
        }

        let file_path = PathBuf::from(self.vehicle.path());
        // Watch the parent dir so the watch survives inode replacement; fall
        // back to the file itself if it has no parent.
        let watch_dir = file_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| file_path.clone());
        let watch_name = file_path.file_name().map(ToOwned::to_owned);

        let inner = self.inner.clone();
        let vehicle = self.vehicle.clone();
        let parser = self.parser.clone();
        let on_update = self.on_update.clone();
        let name = self.name.clone();
        let cancel_token = self.cancel_token.clone();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<()>(1);

        let mut watcher =
            recommended_watcher(move |result: notify::Result<notify::Event>| {
                let Ok(event) = result else { return };
                // Accept any non-access event: macOS/Windows backends report
                // ordinary writes as `Modify(Any)`/`Modify(Metadata)`, so a
                // narrow filter would miss them. Over-triggering is harmless —
                // a same-hash reload is a no-op and no longer touches the mtime.
                if matches!(event.kind, EventKind::Access(_)) {
                    return;
                }
                // Filter to our file, but accept directory-scoped events that
                // carry no path rather than miss a change.
                if let Some(want) = &watch_name
                    && !event.paths.is_empty()
                    && !event.paths.iter().any(|p| p.file_name() == Some(want))
                {
                    return;
                }
                let _ = tx.try_send(());
            })
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to create file watcher for {}: {}",
                    file_path.display(),
                    e
                )
            })?;

        watcher
            .watch(&watch_dir, RecursiveMode::NonRecursive)
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to watch directory {}: {}",
                    watch_dir.display(),
                    e
                )
            })?;

        tokio::spawn(async move {
            // Keep the watcher alive in the task so events keep flowing.
            let _watcher = watcher;

            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    recv = rx.recv() => {
                        if recv.is_none() {
                            break;
                        }
                        // Debounce a burst of writes into a single reload.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        while rx.try_recv().is_ok() {}

                        Fetcher::<U, P>::run_update(
                            inner.clone(),
                            vehicle.clone(),
                            parser.clone(),
                            on_update.clone(),
                            &name,
                        )
                        .await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn pull_loop(
        &self,
        immediately_update: bool,
        mut ticker: tokio::time::Interval,
    ) {
        let inner = self.inner.clone();
        let vehicle = self.vehicle.clone();
        let parser = self.parser.clone();
        let on_update = self.on_update.clone();
        let name = self.name.clone();
        let cancel_token = self.cancel_token.clone();
        let fire_immediately = immediately_update;

        tokio::spawn(async move {
            let run = |()| {
                Fetcher::<U, P>::run_update(
                    inner.clone(),
                    vehicle.clone(),
                    parser.clone(),
                    on_update.clone(),
                    &name,
                )
            };

            if fire_immediately {
                run(()).await;
            }
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    _ = ticker.tick() => run(()).await,
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::{path::Path, sync::Arc, time::Duration};

    use futures::future::BoxFuture;
    use tokio::time::sleep;

    use crate::app::remote_content_manager::providers::{
        MockProviderVehicle, ProviderVehicleType,
    };

    use super::Fetcher;

    #[tokio::test]
    async fn test_fetcher() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(32);
        let tx1 = tx.clone();

        let mut mock_vehicle = MockProviderVehicle::new();
        let mock_file = std::env::temp_dir().join(format!(
            "{}-{}",
            "mock_provider_vehicle",
            uuid::Uuid::new_v4()
        ));
        if Path::new(mock_file.to_str().unwrap()).exists() {
            std::fs::remove_file(&mock_file).unwrap();
        }
        std::fs::write(&mock_file, vec![1, 2, 3]).unwrap();

        mock_vehicle
            .expect_path()
            .return_const(mock_file.to_str().unwrap().to_owned());
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
        f.destroy().await;

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
