use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
};

use chrono::Utc;
use serde::Serialize;
use tokio::sync::{oneshot::Sender, Mutex, RwLock};

use crate::session::Session;

use super::tracked::Tracked;

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
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    download_total: i64,
    upload_total: i64,
    connections: Vec<TrackerInfo>,
}

type ConnectionMap = HashMap<uuid::Uuid, (Tracked, Sender<()>)>;

pub struct Manager {
    connections: Arc<Mutex<ConnectionMap>>,
    upload_temp: AtomicI64,
    download_temp: AtomicI64,
    upload_blip: AtomicI64,
    download_blip: AtomicI64,
    upload_total: AtomicI64,
    download_total: AtomicI64,
}

impl Manager {
    pub fn new() -> Arc<Self> {
        let v = Arc::new(Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            upload_temp: AtomicI64::new(0),
            download_temp: AtomicI64::new(0),
            upload_blip: AtomicI64::new(0),
            download_blip: AtomicI64::new(0),
            upload_total: AtomicI64::new(0),
            download_total: AtomicI64::new(0),
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
    /// this method is not async because it is called in Drop.
    pub fn untrack(&self, id: uuid::Uuid) {
        let connections = self.connections.clone();

        tokio::spawn(async move {
            let mut connections = connections.lock().await;
            connections.remove(&id);
        });
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
            .fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
        self.upload_total
            .fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn push_downloaded(&self, n: usize) {
        self.download_temp
            .fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
        self.download_total
            .fetch_add(n as i64, std::sync::atomic::Ordering::Relaxed);
    }

    //TODO: make this u64
    pub fn now(&self) -> (i64, i64) {
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
                download_total: AtomicU64::new(t.download_total.load(Ordering::Acquire)),
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
            upload_total: self.upload_total.load(std::sync::atomic::Ordering::Relaxed),
            connections,
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
