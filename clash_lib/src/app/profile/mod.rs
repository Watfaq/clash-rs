use bincode;
use std::{
    num::NonZeroUsize,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use lru::LruCache;
use redb::{Database, ReadableTable, TableDefinition};

use crate::proxy::group::smart::{
    penalty::ProxyPenalty, state::SmartStateData, stats::SiteStats,
};

const SELECTED_TABLE: TableDefinition<&str, &str> = TableDefinition::new("selected");
// Store (is_ip_key, corresponding_value, last_update_timestamp_secs)
const IP_HOST_MAPPING_TABLE: TableDefinition<&str, (bool, &str, u64)> =
    TableDefinition::new("ip_host_mapping");
const SMART_PENALTY_TABLE: TableDefinition<(&str, &str), (f64, u64)> =
    TableDefinition::new("smart_penalty");
// Store (serialized_compact_stats, last_attempt_timestamp_secs)
const SMART_SITE_STATS_TABLE: TableDefinition<(&str, &str), (&[u8], u64)> =
    TableDefinition::new("smart_site_stats");

// --- Cleanup Configuration ---
/// Max age for site statistics before cleanup (7 days).
const MAX_SITE_STATS_AGE_SECS: u64 = 7 * 24 * 3600;
/// Max age for IP-Host mappings before cleanup (1 day).
const MAX_IP_MAPPING_AGE_SECS: u64 = 24 * 3600;
/// Max history length stored per site stat entry.
pub const MAX_HISTORY_LENGTH: usize = 10;
/// Minimum interval between background cleanup runs (1 hour).
const MIN_CLEANUP_INTERVAL_SECS: u64 = 3600;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone)]
pub struct ThreadSafeCacheFile(Arc<tokio::sync::RwLock<CacheFile>>);

impl ThreadSafeCacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let store = Arc::new(tokio::sync::RwLock::new(CacheFile::new(
            path,
            store_selected,
        )));

        // Start background cleanup task.
        let store_clone = Arc::clone(&store);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_secs(MIN_CLEANUP_INTERVAL_SECS),
            );
            loop {
                interval.tick().await;
                // Use try_read to avoid blocking if a write lock is held.
                if let Ok(cache) = store_clone.try_read() {
                    if let Err(e) = cache.cleanup_old_data().await {
                        tracing::error!("Background cache cleanup failed: {}", e);
                    }
                } else {
                    tracing::debug!(
                        "Skipping cache cleanup due to lock contention."
                    );
                }
            }
        });

        Self(store)
    }

    pub async fn set_selected(&self, group: &str, server: &str) {
        if !self.0.read().await.store_selected() {
            return;
        }
        let g = self.0.read().await;
        if let Err(e) = g.set_selected(group, server).await {
            tracing::error!(
                "Failed to set selected server for group {}: {}",
                group,
                e
            );
        }
    }

    pub async fn get_selected(&self, group: &str) -> Option<String> {
        if !self.0.read().await.store_selected() {
            return None;
        }
        let g = self.0.read().await;
        match g.get_selected(group).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(
                    "Failed to get selected server for group {}: {}",
                    group,
                    e
                );
                None
            }
        }
    }

    pub async fn set_ip_host_mapping(&self, ip: &str, host: &str) {
        let g = self.0.read().await;
        if let Err(e) = g.set_ip_host_mapping(ip, host).await {
            tracing::error!("Failed to set IP-host mapping {}->{}: {}", ip, host, e);
        }
    }

    pub async fn set_ip_to_host(&self, ip: &str, host: &str) {
        self.set_ip_host_mapping(ip, host).await;
    }

    pub async fn set_host_to_ip(&self, host: &str, ip: &str) {
        self.set_ip_host_mapping(ip, host).await;
    }

    pub async fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        let g = self.0.read().await;
        match g.get_fake_ip(ip_or_host).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to get fake IP for {}: {}", ip_or_host, e);
                None
            }
        }
    }

    pub async fn delete_fake_ip_pair(&self, ip: &str, host: &str) {
        let g = self.0.read().await;
        if let Err(e) = g.delete_fake_ip_pair(ip, host).await {
            tracing::error!("Failed to delete IP-host pair {}->{}: {}", ip, host, e);
        }
    }

    pub async fn set_smart_stats(
        &self,
        group_name: &str,
        stats: SmartStateData,
    ) -> Result<()> {
        let g = self.0.read().await;
        g.set_smart_stats(group_name, stats).await
    }

    pub async fn get_smart_stats(&self, group_name: &str) -> Option<SmartStateData> {
        let g = self.0.read().await;
        match g.get_smart_stats(group_name).await {
            Ok(Some(stats)) => Some(stats),
            Ok(None) => None,
            Err(e) => {
                tracing::error!(
                    "Failed to get smart stats for group {}: {}",
                    group_name,
                    e
                );
                None
            }
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CompactSiteStats {
    delay_history: Vec<u16>, // Delays stored as milliseconds (u16 max = 65.535s).
    success_history: u64,    // Bit-packed boolean history (64 entries).
    last_attempt_secs: u64,  // Unix timestamp of the last attempt.
}

impl CompactSiteStats {
    fn from_site_stats(stats: &SiteStats, max_history: usize) -> Self {
        let delay_history: Vec<u16> = stats
            .delay_history
            .iter()
            .take(max_history)
            .map(|&delay| (delay * 1000.0).min(65535.0) as u16)
            .collect();

        let mut success_history = 0u64;
        for (i, &success) in stats.success_history.iter().take(64).enumerate() {
            if success {
                success_history |= 1u64 << i;
            }
        }

        Self {
            delay_history,
            success_history,
            last_attempt_secs: stats.last_attempt_secs(),
        }
    }

    /// Converts `CompactSiteStats` back to `SiteStats`.
    fn to_site_stats(&self, max_history: usize) -> SiteStats {
        // Convert milliseconds back to seconds.
        let delay_history: Vec<f64> = self
            .delay_history
            .iter()
            .map(|&ms| ms as f64 / 1000.0)
            .collect();

        // Unpack the success history from the u64 bitmask.
        let mut success_history_unpacked = Vec::new();
        for i in 0..64.min(max_history) {
            // Limit unpacking by max_history or 64 bits.
            success_history_unpacked.push((self.success_history & (1u64 << i)) != 0);
        }

        // Call the updated from_stored function (without max_history arg).
        SiteStats::from_stored(
            delay_history,
            success_history_unpacked,
            self.last_attempt_secs,
        )
    }
}

struct CacheFile {
    db: Arc<Database>,
    store_selected: bool,
    selected_cache: tokio::sync::RwLock<LruCache<String, String>>,
    mapping_cache: tokio::sync::RwLock<LruCache<String, String>>,
    last_cleanup: tokio::sync::RwLock<u64>,
}

impl CacheFile {
    pub fn new(path: &str, store_selected: bool) -> Self {
        let db = Database::create(path).expect("Failed to create redb database");
        Self::init_tables(&db).expect("Failed to initialize tables");

        // LRU cache for frequently accessed 'selected' entries.
        let selected_cache_cap = NonZeroUsize::new(15).unwrap();
        // LRU cache for frequently accessed IP/Host mappings. Reduced size.
        let mapping_cache_cap = NonZeroUsize::new(5_000).unwrap();

        Self {
            db: Arc::new(db),
            store_selected,
            selected_cache: tokio::sync::RwLock::new(LruCache::new(
                selected_cache_cap,
            )),
            mapping_cache: tokio::sync::RwLock::new(LruCache::new(
                mapping_cache_cap,
            )),
            last_cleanup: tokio::sync::RwLock::new(0),
        }
    }

    fn init_tables(db: &Database) -> Result<()> {
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(SELECTED_TABLE)?;
            write_txn.open_table(IP_HOST_MAPPING_TABLE)?;
            write_txn.open_table(SMART_PENALTY_TABLE)?;
            write_txn.open_table(SMART_SITE_STATS_TABLE)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn store_selected(&self) -> bool {
        self.store_selected
    }

    pub async fn set_selected(&self, group: &str, server: &str) -> Result<()> {
        self.selected_cache
            .write()
            .await
            .put(group.to_string(), server.to_string());

        let db = self.db.clone();
        let group = group.to_string();
        let server = server.to_string();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(SELECTED_TABLE)?;
                table.insert(group.as_str(), server.as_str())?;
            }
            write_txn.commit()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    pub async fn get_selected(&self, group: &str) -> Result<Option<String>> {
        {
            let mut cache = self.selected_cache.write().await;
            if let Some(val) = cache.get(group) {
                return Ok(Some(val.clone()));
            }
        }

        let db = self.db.clone();
        let group_clone = group.to_string();

        let result =
            tokio::task::spawn_blocking(move || -> Result<Option<String>> {
                let read_txn = db.begin_read()?;
                let table = read_txn.open_table(SELECTED_TABLE)?;
                match table.get(group_clone.as_str())? {
                    Some(guard) => Ok(Some(guard.value().to_string())),
                    None => Ok(None),
                }
            })
            .await??;

        if let Some(ref v) = result {
            let mut cache = self.selected_cache.write().await;
            cache.put(group.to_string(), v.clone());
        }

        Ok(result)
    }

    pub async fn set_ip_host_mapping(&self, ip: &str, host: &str) -> Result<()> {
        {
            let mut cache = self.mapping_cache.write().await;
            cache.put(ip.to_string(), host.to_string());
            cache.put(host.to_string(), ip.to_string());
        }

        let db = self.db.clone();
        let ip = ip.to_string();
        let host = host.to_string();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(IP_HOST_MAPPING_TABLE)?;
                // Store IP -> (is_ip=true, host, timestamp)
                table.insert(ip.as_str(), (true, host.as_str(), current_time))?;
                // Store Host -> (is_ip=false, ip, timestamp)
                table.insert(host.as_str(), (false, ip.as_str(), current_time))?;
            }
            write_txn.commit()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    pub async fn get_fake_ip(&self, ip_or_host: &str) -> Result<Option<String>> {
        {
            let mut cache = self.mapping_cache.write().await;
            if let Some(val) = cache.get(ip_or_host) {
                return Ok(Some(val.clone()));
            }
        }

        let db = self.db.clone();
        let key = ip_or_host.to_string();

        let result =
            tokio::task::spawn_blocking(move || -> Result<Option<String>> {
                let read_txn = db.begin_read()?;
                let table = read_txn.open_table(IP_HOST_MAPPING_TABLE)?;
                if let Some(guard) = table.get(key.as_str())? {
                    // Extract the actual value, ignoring is_ip flag and timestamp.
                    let (_, value, _) = guard.value();
                    return Ok(Some(value.to_string()));
                }
                Ok(None) // Not found.
            })
            .await??;

        if let Some(ref v) = result {
            let mut cache = self.mapping_cache.write().await;
            cache.put(ip_or_host.to_string(), v.clone());
        }

        Ok(result)
    }

    pub async fn delete_fake_ip_pair(&self, ip: &str, host: &str) -> Result<()> {
        {
            let mut cache = self.mapping_cache.write().await;
            cache.pop(ip);
            cache.pop(host);
        }

        let db = self.db.clone();
        let ip = ip.to_string();
        let host = host.to_string();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write()?;
            {
                let mut table = write_txn.open_table(IP_HOST_MAPPING_TABLE)?;
                let _ = table.remove(ip.as_str());
                let _ = table.remove(host.as_str());
            }
            write_txn.commit()?;
            Ok(())
        })
        .await??;

        Ok(())
    }

    pub async fn set_smart_stats(
        &self,
        group_name: &str,
        stats: SmartStateData,
    ) -> Result<()> {
        let db = self.db.clone();
        let group_name_owned = group_name.to_string();

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write()?;

            {
                let mut penalty_table = write_txn.open_table(SMART_PENALTY_TABLE)?;
                let keys_to_remove: Vec<(String, String)> = penalty_table
                    .iter()?
                    .filter_map(|result| {
                        if let Ok((key_guard, _)) = result {
                            let (group, proxy_name) = key_guard.value();
                            if *group == group_name_owned {
                                Some((group.to_string(), proxy_name.to_string()))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .collect();

                for (group, proxy_name) in keys_to_remove {
                    let _ =
                        penalty_table.remove((group.as_str(), proxy_name.as_str()));
                }

                for (proxy_name, penalty) in &stats.penalty {
                    let key = (group_name_owned.as_str(), proxy_name.as_str());
                    let value = (penalty.value(), penalty.last_update_secs());
                    penalty_table.insert(key, value)?;
                }
            }

            {
                let mut stats_table =
                    write_txn.open_table(SMART_SITE_STATS_TABLE)?;
                for (proxy_name, sites) in &stats.site_stats {
                    for (site, site_stats) in sites {
                        // Convert to compact format before serializing.
                        let compact_stats = CompactSiteStats::from_site_stats(
                            site_stats,
                            MAX_HISTORY_LENGTH,
                        );
                        // Serialize using bincode.
                        let serialized = bincode::serialize(&compact_stats)
                            .map_err(|e| {
                                Box::new(e)
                                    as Box<dyn std::error::Error + Send + Sync>
                            })?;

                        // Key: (proxy_name, site_name)
                        // Value: (serialized_data, last_attempt_timestamp) -
                        // timestamp used for cleanup.
                        let key = (proxy_name.as_str(), site.as_str());
                        let value =
                            (serialized.as_slice(), compact_stats.last_attempt_secs);
                        stats_table.insert(key, value)?;
                    }
                }
            }

            write_txn.commit()?;
            Ok(())
        })
        .await?
    }

    pub async fn get_smart_stats(
        &self,
        group_name: &str,
    ) -> Result<Option<SmartStateData>> {
        let db = self.db.clone();
        let group_name_clone = group_name.to_string();

        tokio::task::spawn_blocking(move || -> Result<Option<SmartStateData>> {
            let read_txn = db.begin_read()?;
            let mut state_data = SmartStateData::default();
            let mut found_penalty_data = false;

            {
                let penalty_table = read_txn.open_table(SMART_PENALTY_TABLE)?;
                for result in penalty_table.iter()? {
                    let (key_guard, value_guard) = result?;
                    let (group, proxy_name) = key_guard.value();
                    let (value, last_update_secs) = value_guard.value();

                    if *group == group_name_clone {
                        state_data.penalty.insert(
                            proxy_name.to_string(),
                            ProxyPenalty::from_stored(value, last_update_secs),
                        );
                        found_penalty_data = true;
                    }
                }
            }

            {
                let stats_table = read_txn.open_table(SMART_SITE_STATS_TABLE)?;
                for result in stats_table.iter()? {
                    let (key_guard, value_guard) = result?;
                    let (proxy_name, site) = key_guard.value();
                    // Value contains (serialized_data, timestamp) - we only need
                    // data here.
                    let (stats_blob, _) = value_guard.value();

                    // Deserialize the compact stats.
                    let compact_stats: CompactSiteStats =
                        match bincode::deserialize(stats_blob) {
                            Ok(stats) => stats,
                            Err(e) => {
                                tracing::warn!(
                                    "Failed to deserialize site stats for {}/{}: {}",
                                    proxy_name,
                                    site,
                                    e
                                );
                                continue; // Skip this entry if deserialization fails.
                            }
                        };

                    // Convert back to the full SiteStats struct.
                    let site_stats = compact_stats.to_site_stats(MAX_HISTORY_LENGTH);

                    // Insert into the result map.
                    state_data
                        .site_stats
                        .entry(proxy_name.to_string()) // Get or create entry for proxy.
                        .or_default()                  // Get default HashMap if new.
                        .insert(site.to_string(), site_stats); // Insert site stats.
                }
            }

            if found_penalty_data {
                Ok(Some(state_data))
            } else {
                Ok(None)
            }
        })
        .await?
    }

    /// Performs background cleanup of stale data in the database.
    async fn cleanup_old_data(&self) -> Result<()> {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        // Check if cleanup interval has passed.
        {
            let mut last_cleanup_guard = self.last_cleanup.write().await;
            if current_time.saturating_sub(*last_cleanup_guard)
                < MIN_CLEANUP_INTERVAL_SECS
            {
                return Ok(()); // Not time to clean up yet.
            }
            *last_cleanup_guard = current_time; // Update last cleanup time.
        }
        tracing::debug!("Running background cache cleanup...");

        let db = self.db.clone();
        let cutoff_site_stats = current_time.saturating_sub(MAX_SITE_STATS_AGE_SECS);
        let cutoff_ip_mapping = current_time.saturating_sub(MAX_IP_MAPPING_AGE_SECS);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let write_txn = db.begin_write()?;

            // --- Cleanup Site Stats ---
            {
                let mut stats_table =
                    write_txn.open_table(SMART_SITE_STATS_TABLE)?;
                let keys_to_remove: Vec<(String, String)> = stats_table
                    .iter()?
                    .filter_map(|result| match result {
                        Ok((key_guard, value_guard)) => {
                            let (proxy_name, site) = key_guard.value();
                            let (_, last_attempt_secs) = value_guard.value(); // Timestamp is the second element.
                            if last_attempt_secs < cutoff_site_stats {
                                Some((proxy_name.to_string(), site.to_string()))
                            } else {
                                None
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Error iterating site stats table during cleanup: \
                                 {}",
                                e
                            );
                            None
                        }
                    })
                    .collect();

                for (proxy_name, site) in keys_to_remove {
                    let _ = stats_table.remove((proxy_name.as_str(), site.as_str()));
                }
            }

            // --- Cleanup IP Mappings ---
            {
                let mut mapping_table =
                    write_txn.open_table(IP_HOST_MAPPING_TABLE)?;
                let keys_to_remove: Vec<String> = mapping_table
                    .iter()?
                    .filter_map(|result| match result {
                        Ok((key_guard, value_guard)) => {
                            let key = key_guard.value();
                            let (_, _, last_update_secs) = value_guard.value(); // Timestamp is the third element.
                            if last_update_secs < cutoff_ip_mapping {
                                Some(key.to_string())
                            } else {
                                None
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Error iterating IP mapping table during cleanup: \
                                 {}",
                                e
                            );
                            None
                        }
                    })
                    .collect();

                for key in keys_to_remove {
                    let _ = mapping_table.remove(key.as_str());
                }
            }

            write_txn.commit()?;
            Ok(())
        })
        .await??;

        Ok(())
    }
}
