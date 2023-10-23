use std::{collections::HashMap, sync::Arc};

use serde::{Deserialize, Serialize};
use tracing::{error, trace};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Db {
    selected: HashMap<String, String>,
    ip_to_host: HashMap<String, String>,
    host_to_ip: HashMap<String, String>,
}

#[derive(Clone)]
pub struct ThreadSafeCacheFile(Arc<tokio::sync::RwLock<CacheFile>>);

impl ThreadSafeCacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let store = Arc::new(tokio::sync::RwLock::new(CacheFile::new(
            path,
            store_selected,
        )));

        let path = path.to_string();
        let store_clone = store.clone();

        if store_selected {
            tokio::spawn(async move {
                let store = store_clone;
                loop {
                    tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    let r = store.read().await;
                    let db = r.db.clone();
                    drop(r);

                    let s = match serde_yaml::to_string(&db) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("failed to serialize cache file: {}", e);
                            continue;
                        }
                    };

                    if let Err(e) = tokio::fs::write(&path, s).await {
                        error!("failed to write cache file: {}", e);
                    } else {
                        trace!("cache file flushed to {}", path);
                    }
                }
            });
        }

        Self(store)
    }

    pub async fn set_selected(&self, group: &str, server: &str) {
        let mut g = self.0.write().await;
        if g.store_selected() {
            g.set_selected(group, server);
        }
    }

    pub async fn get_selected(&self, group: &str) -> Option<String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.db.selected.get(group).map(Clone::clone)
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub async fn get_selected_map(&self) -> HashMap<String, String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.get_selected_map()
        } else {
            HashMap::new()
        }
    }

    pub async fn set_ip_to_host(&self, ip: &str, host: &str) {
        self.0.write().await.set_ip_to_host(ip, host);
    }

    pub async fn set_host_to_ip(&self, host: &str, ip: &str) {
        self.0.write().await.set_host_to_ip(host, ip);
    }

    pub async fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        self.0.read().await.get_fake_ip(ip_or_host)
    }

    pub async fn delete_fake_ip_pair(&self, ip: &str, host: &str) {
        self.0.write().await.delete_fake_ip_pair(ip, host);
    }
}

struct CacheFile {
    db: Db,

    store_selected: bool,
}

impl CacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let db = match std::fs::read_to_string(path) {
            Ok(s) => match serde_yaml::from_str(&s) {
                Ok(db) => db,
                Err(e) => {
                    error!("failed to parse cache file: {}, initilizing a new one", e);
                    Db {
                        selected: HashMap::new(),
                        ip_to_host: HashMap::new(),
                        host_to_ip: HashMap::new(),
                    }
                }
            },
            Err(e) => {
                error!("failed to read cache file: {}, initializing a new one", e);
                Db {
                    selected: HashMap::new(),
                    ip_to_host: HashMap::new(),
                    host_to_ip: HashMap::new(),
                }
            }
        };

        Self { db, store_selected }
    }

    pub fn store_selected(&self) -> bool {
        self.store_selected
    }

    pub fn set_selected(&mut self, group: &str, server: &str) {
        self.db
            .selected
            .insert(group.to_string(), server.to_string());
    }

    pub fn get_selected_map(&self) -> HashMap<String, String> {
        self.db.selected.clone()
    }

    pub fn set_ip_to_host(&mut self, ip: &str, host: &str) {
        self.db.ip_to_host.insert(ip.to_string(), host.to_string());
    }

    pub fn set_host_to_ip(&mut self, host: &str, ip: &str) {
        self.db.host_to_ip.insert(host.to_string(), ip.to_string());
    }

    pub fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        self.db
            .ip_to_host
            .get(ip_or_host)
            .or_else(|| self.db.host_to_ip.get(ip_or_host))
            .map(Clone::clone)
    }

    pub fn delete_fake_ip_pair(&mut self, ip: &str, host: &str) {
        self.db.ip_to_host.remove(ip);
        self.db.host_to_ip.remove(host);
    }
}
