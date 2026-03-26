use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};

use chrono::Utc;
use memory_stats::memory_stats;
use portable_atomic::AtomicU64;
use serde::Serialize;
use tokio::sync::{Mutex, RwLock, oneshot::Sender};

use crate::session::Session;

use super::tracked::Tracked;

/// Per-user traffic since the last drain.  Both upload and download are in
/// bytes.
#[derive(Serialize, Clone, Debug, Default)]
pub struct UserTraffic {
    pub upload: u64,
    pub download: u64,
}

#[derive(Default, Clone, Debug)]
pub struct ProxyChain(Arc<RwLock<Vec<String>>>);

impl ProxyChain {
    pub async fn push(&self, s: String) {
        let mut chain = self.0.write().await;
        chain.push(s);
    }
}

#[derive(Serialize, Default)]
pub struct TrackerInfo {
    #[serde(rename = "id")]
    pub uuid: uuid::Uuid,
    #[serde(rename = "metadata")]
    pub session: HashMap<String, Box<dyn erased_serde::Serialize + Send + Sync>>,
    #[serde(rename = "upload")]
    pub upload_total: AtomicU64,
    #[serde(rename = "download")]
    pub download_total: AtomicU64,
    #[serde(rename = "start")]
    pub start_time: chrono::DateTime<Utc>,
    #[serde(rename = "chains")]
    pub proxy_chain: Vec<String>,
    #[serde(rename = "rule")]
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,

    #[serde(skip)]
    pub proxy_chain_holder: ProxyChain,
    #[serde(skip)]
    pub session_holder: Session,

    /// Per-user byte counters, separate from `upload_total`/`download_total`.
    /// Only incremented when `session_holder.inbound_user` is set.
    /// Swapped to 0 on drain — never touched by `snapshot()`.
    #[serde(skip)]
    pub user_upload: AtomicU64,
    #[serde(skip)]
    pub user_download: AtomicU64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    download_total: u64,
    upload_total: u64,
    connections: Vec<TrackerInfo>,
    memory: usize,
}

type ConnectionMap = HashMap<uuid::Uuid, (Tracked, Sender<()>)>;

pub struct Manager {
    connections: Arc<Mutex<ConnectionMap>>,
    upload_temp: AtomicU64,
    download_temp: AtomicU64,
    upload_blip: AtomicU64,
    download_blip: AtomicU64,
    upload_total: AtomicU64,
    download_total: AtomicU64,
    /// Bytes accumulated from **closed** connections, keyed by inbound_user.
    /// Drained (and reset) by [`Manager::drain_user_stats`].
    user_period_stats: Arc<Mutex<HashMap<String, UserTraffic>>>,
}

impl Manager {
    pub fn new() -> Arc<Self> {
        let v = Arc::new(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            upload_temp: AtomicU64::new(0),
            download_temp: AtomicU64::new(0),
            upload_blip: AtomicU64::new(0),
            download_blip: AtomicU64::new(0),
            upload_total: AtomicU64::new(0),
            download_total: AtomicU64::new(0),
            user_period_stats: Arc::new(Mutex::new(HashMap::new())),
        });
        let c = v.clone();
        tokio::spawn(async move {
            c.kick_off().await;
        });
        v
    }

    pub async fn track(&self, item: Tracked, close_notify: Sender<()>) {
        let mut connections = self.connections.lock().await;

        connections.insert(item.id(), (item, close_notify));
    }

    /// Untrack a connection.
    /// This method is not async because it is called in Drop.
    /// When the connection has an inbound_user, its final byte counts are
    /// accumulated into `user_period_stats` so they survive connection close.
    pub fn untrack(&self, id: uuid::Uuid) {
        let connections = self.connections.clone();
        let user_period_stats = self.user_period_stats.clone();

        tokio::spawn(async move {
            let mut connections = connections.lock().await;
            if let Some((tracked, _)) = connections.remove(&id) {
                let info = tracked.tracker_info();
                // Atomically take the remaining user-accounting bytes.
                // upload_total/download_total are left intact for /connections.
                let upload = info.user_upload.swap(0, Ordering::AcqRel);
                let download = info.user_download.swap(0, Ordering::AcqRel);
                if let Some(ref user) = info.session_holder.inbound_user
                    && (upload > 0 || download > 0)
                {
                    let mut stats = user_period_stats.lock().await;
                    let entry = stats
                        .entry(user.clone())
                        .or_insert_with(UserTraffic::default);
                    entry.upload += upload;
                    entry.download += download;
                }
            }
        });
    }

    /// Return per-user traffic accumulated since the last call (for both closed
    /// and currently-active connections) and reset all counters.
    ///
    /// Called by the `/user-stats` REST endpoint so FAC can poll for deltas.
    pub async fn drain_user_stats(&self) -> HashMap<String, UserTraffic> {
        // Drain the closed-connection accumulator.
        let mut result: HashMap<String, UserTraffic> = {
            let mut stats = self.user_period_stats.lock().await;
            std::mem::take(&mut *stats)
        };

        // Include bytes from still-active connections by atomically swapping
        // their user counters to 0. upload_total/download_total are untouched
        // so /connections keeps seeing the correct cumulative values.
        let connections = self.connections.lock().await;
        for (_, (tracked, _)) in connections.iter() {
            let info = tracked.tracker_info();
            if let Some(ref user) = info.session_holder.inbound_user {
                let upload = info.user_upload.swap(0, Ordering::AcqRel);
                let download = info.user_download.swap(0, Ordering::AcqRel);
                if upload > 0 || download > 0 {
                    let entry = result.entry(user.clone()).or_default();
                    entry.upload += upload;
                    entry.download += download;
                }
            }
        }

        result
    }

    pub async fn close(&self, id: uuid::Uuid) {
        let connections = self.connections.clone();

        tokio::spawn(async move {
            let mut connections = connections.lock().await;
            if let Some((_, close_notify)) = connections.remove(&id) {
                let _ = close_notify.send(());
            }
        });
    }

    pub async fn close_all(&self) {
        let connections = self.connections.clone();

        let mut connections = connections.lock().await;
        for (_, (_, close_notify)) in connections.drain() {
            let _ = close_notify.send(());
        }
    }

    pub fn push_uploaded(&self, n: usize) {
        self.upload_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.upload_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn push_downloaded(&self, n: usize) {
        self.download_temp
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        self.download_total
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn now(&self) -> (u64, u64) {
        (
            self.upload_blip.load(std::sync::atomic::Ordering::Relaxed),
            self.download_blip
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }

    pub async fn snapshot(&self) -> Snapshot {
        let mut connections = vec![];
        let conns = self.connections.lock().await;
        for (_, v) in conns.iter() {
            let t = v.0.tracker_info();
            let chain = t.proxy_chain_holder.0.read().await;
            connections.push(TrackerInfo {
                uuid: t.uuid,
                upload_total: AtomicU64::new(t.upload_total.load(Ordering::Acquire)),
                download_total: AtomicU64::new(
                    t.download_total.load(Ordering::Acquire),
                ),
                start_time: t.start_time,
                proxy_chain: chain.clone(),
                rule: t.rule.clone(),
                rule_payload: t.rule_payload.clone(),
                session: t.session_holder.as_map(),
                ..Default::default()
            });
        }

        Snapshot {
            download_total: self
                .download_total
                .load(std::sync::atomic::Ordering::Relaxed),
            upload_total: self
                .upload_total
                .load(std::sync::atomic::Ordering::Relaxed),
            connections,
            memory: self.memory_usage(),
        }
    }

    #[allow(dead_code)]
    pub fn reset_statistic(&self) {
        self.upload_temp.store(0, Ordering::Relaxed);
        self.upload_blip.store(0, Ordering::Relaxed);
        self.upload_total.store(0, Ordering::Relaxed);
        self.download_temp.store(0, Ordering::Relaxed);
        self.download_blip.store(0, Ordering::Relaxed);
        self.download_total.store(0, Ordering::Relaxed);
    }

    pub fn memory_usage(&self) -> usize {
        memory_stats().map(|x| x.physical_mem).unwrap_or(0)
    }

    /// Test helper: directly populate `user_period_stats` to simulate closed
    /// connections without going through the full `Tracked` machinery.
    #[cfg(test)]
    pub async fn inject_closed_user_bytes(
        &self,
        user: &str,
        upload: u64,
        download: u64,
    ) {
        let mut stats = self.user_period_stats.lock().await;
        let entry = stats.entry(user.to_string()).or_default();
        entry.upload += upload;
        entry.download += download;
    }

    async fn kick_off(&self) {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            ticker.tick().await;
            self.upload_blip
                .store(self.upload_temp.load(Ordering::Relaxed), Ordering::Relaxed);
            self.upload_temp.store(0, Ordering::Relaxed);
            self.download_blip.store(
                self.download_temp.load(Ordering::Relaxed),
                Ordering::Relaxed,
            );
            self.download_temp.store(0, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_drain_user_stats_empty() {
        let mgr = Manager::new();
        let stats = mgr.drain_user_stats().await;
        assert!(stats.is_empty(), "fresh manager should have no user stats");
    }

    #[tokio::test]
    async fn test_drain_user_stats_returns_closed_connection_bytes() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 1000, 2000).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 1000);
        assert_eq!(u.download, 2000);
    }

    #[tokio::test]
    async fn test_drain_user_stats_resets_on_read() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("user1", 500, 750).await;

        let first = mgr.drain_user_stats().await;
        assert!(!first.is_empty());

        let second = mgr.drain_user_stats().await;
        assert!(
            second.is_empty(),
            "second drain should be empty after reset"
        );
    }

    #[tokio::test]
    async fn test_drain_user_stats_multiple_users() {
        let mgr = Manager::new();
        mgr.inject_closed_user_bytes("alice", 100, 200).await;
        mgr.inject_closed_user_bytes("bob", 300, 400).await;

        let stats = mgr.drain_user_stats().await;
        assert_eq!(stats.len(), 2);
        assert_eq!(stats["alice"].upload, 100);
        assert_eq!(stats["alice"].download, 200);
        assert_eq!(stats["bob"].upload, 300);
        assert_eq!(stats["bob"].download, 400);
    }

    #[tokio::test]
    async fn test_drain_user_stats_accumulates_across_connections() {
        let mgr = Manager::new();
        // Same user closes two separate connections before a drain.
        mgr.inject_closed_user_bytes("user1", 100, 200).await;
        mgr.inject_closed_user_bytes("user1", 50, 80).await;

        let stats = mgr.drain_user_stats().await;
        let u = stats.get("user1").expect("user1 not found");
        assert_eq!(u.upload, 150, "upload should be sum of both connections");
        assert_eq!(u.download, 280, "download should be sum of both connections");
    }
}
