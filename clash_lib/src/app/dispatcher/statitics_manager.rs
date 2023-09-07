use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicI64, AtomicU64, Ordering},
        Arc,
    },
};

use chrono::Utc;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::session::Session;

use super::tracked_conn::TrackedStream;

#[derive(Serialize, Default)]
pub struct TrackerInfo {
    pub uuid: uuid::Uuid,
    pub session: Session,
    pub upload_total: AtomicU64,
    pub download_total: AtomicU64,
    pub start_time: chrono::DateTime<Utc>,
    pub proxy_chain: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    download_total: i64,
    upload_total: i64,
    connections: Vec<TrackerInfo>,
}

pub struct Manager {
    connections: Arc<Mutex<HashMap<uuid::Uuid, Arc<TrackedStream>>>>,
    upload_temp: AtomicI64,
    download_temp: AtomicI64,
    upload_blip: AtomicI64,
    download_blip: AtomicI64,
    upload_total: AtomicI64,
    download_total: AtomicI64,
}

impl Manager {
    fn new() -> Arc<Self> {
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

    pub async fn track(&self, stream: Arc<TrackedStream>) {
        let mut connections = self.connections.lock().await;
        connections.insert(stream.id(), stream);
    }

    pub async fn untrack(&self, id: uuid::Uuid) {
        let mut connections = self.connections.lock().await;
        connections.remove(&id);
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
            let t = v.tracker_info();
            connections.push(TrackerInfo {
                uuid: t.uuid,
                upload_total: AtomicU64::new(t.upload_total.load(Ordering::Relaxed)),
                download_total: AtomicU64::new(t.download_total.load(Ordering::Relaxed)),
                start_time: t.start_time,
                proxy_chain: t.proxy_chain.clone(),
                rule: t.rule.clone(),
                rule_payload: t.rule_payload.clone(),
                session: t.session.clone(),
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
