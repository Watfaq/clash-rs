use bincode;
use std::{
    collections::HashMap,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
};

use lru::LruCache;
use rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};

use crate::proxy::group::smart::{
    penalty::ProxyPenalty, state::SmartStateData, stats::SiteStats,
};

#[derive(Clone)]
pub struct ThreadSafeCacheFile(Arc<tokio::sync::RwLock<CacheFile>>);

impl ThreadSafeCacheFile {
    /// Create a new thread-safe cache file.
    pub fn new(path: &str, store_selected: bool) -> Self {
        let store = Arc::new(tokio::sync::RwLock::new(CacheFile::new(
            path,
            store_selected,
        )));
        Self(store)
    }

    /// Set selected server for a group.
    pub async fn set_selected(&self, group: &str, server: &str) {
        let g = self.0.read().await;
        if g.store_selected() {
            let _ = g.set_selected(group, server).await;
        }
    }

    /// Get selected server for a group.
    pub async fn get_selected(&self, group: &str) -> Option<String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.get_selected(group).await.ok().flatten()
        } else {
            None
        }
    }

    /// Get all selected servers as a map.
    #[allow(dead_code)]
    pub async fn get_selected_map(&self) -> HashMap<String, String> {
        let g = self.0.read().await;
        if g.store_selected() {
            g.get_selected_map().await.unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    /// Set IP to host mapping.
    pub async fn set_ip_to_host(&self, ip: &str, host: &str) {
        let g = self.0.read().await;
        let _ = g.set_ip_to_host(ip, host).await;
    }

    /// Set host to IP mapping.
    pub async fn set_host_to_ip(&self, host: &str, ip: &str) {
        let g = self.0.read().await;
        let _ = g.set_host_to_ip(host, ip).await;
    }

    /// Get fake IP or host mapping.
    pub async fn get_fake_ip(&self, ip_or_host: &str) -> Option<String> {
        let g = self.0.read().await;
        g.get_fake_ip(ip_or_host).await.ok().flatten()
    }

    /// Delete fake IP and host mapping pair.
    pub async fn delete_fake_ip_pair(&self, ip: &str, host: &str) {
        let g = self.0.read().await;
        let _ = g.delete_fake_ip_pair(ip, host).await;
    }

    /// Store smart proxy group statistics.
    pub async fn set_smart_stats(
        &self,
        group_name: &str,
        stats: SmartStateData,
    ) -> SqlResult<()> {
        let g = self.0.read().await;
        g.set_smart_stats(group_name, stats).await
    }

    /// Get smart proxy group statistics.
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

struct CacheFile {
    conn: Arc<Mutex<Connection>>,
    store_selected: bool,
    // Caches wrapped in RwLock for concurrent access from the async layer via
    // blocking calls.
    selected_cache: tokio::sync::RwLock<LruCache<String, String>>,
    ip_to_host_cache: tokio::sync::RwLock<LruCache<String, String>>,
    host_to_ip_cache: tokio::sync::RwLock<LruCache<String, String>>,
}

impl CacheFile {
    /// Open or create a new cache file, ensuring all required tables exist.
    pub fn new(path: &str, store_selected: bool) -> Self {
        let conn = Connection::open(path).expect("Failed to open sqlite db");
        Self::migrate_schema(&conn);
        let cache_cap = NonZeroUsize::new(10_000).unwrap();
        Self {
            conn: Arc::new(Mutex::new(conn)),
            store_selected,
            selected_cache: tokio::sync::RwLock::new(LruCache::new(cache_cap)),
            ip_to_host_cache: tokio::sync::RwLock::new(LruCache::new(cache_cap)),
            host_to_ip_cache: tokio::sync::RwLock::new(LruCache::new(cache_cap)),
        }
    }

    /// Ensure all tables exist for backward and forward compatibility.
    fn migrate_schema(conn: &Connection) {
        let migrations = [
            // Use "IF NOT EXISTS" for compatibility
            r#"CREATE TABLE IF NOT EXISTS selected (group_name TEXT PRIMARY KEY, server TEXT);"#,
            r#"CREATE TABLE IF NOT EXISTS ip_to_host (ip TEXT PRIMARY KEY, host TEXT);"#,
            r#"CREATE TABLE IF NOT EXISTS host_to_ip (host TEXT PRIMARY KEY, ip TEXT);"#,
            r#"CREATE TABLE IF NOT EXISTS smart_penalty (
                group_name TEXT NOT NULL,
                proxy_name TEXT NOT NULL,
                value REAL NOT NULL,
                last_update_secs INTEGER NOT NULL,
                PRIMARY KEY (group_name, proxy_name)
            );"#,
            r#"CREATE TABLE IF NOT EXISTS smart_site_stats (
                proxy_name TEXT NOT NULL,
                site TEXT NOT NULL,
                delay_history BLOB NOT NULL,
                success_history BLOB NOT NULL,
                last_attempt_secs INTEGER NOT NULL,
                PRIMARY KEY (proxy_name, site)
            );"#,
        ];
        // Execute migrations one by one to better pinpoint failures
        for (i, sql) in migrations.iter().enumerate() {
            if let Err(e) = conn.execute_batch(sql) {
                // Log error but try to continue if possible (e.g., DROP TABLE might
                // fail harmlessly)
                tracing::warn!(
                    "Failed to execute migration #{}: {} (SQL: '{}')",
                    i + 1,
                    e,
                    sql
                );
                // For critical CREATE TABLE failures, we might want to panic or
                // return error
                if sql.starts_with("CREATE TABLE") {
                    panic!("Failed to create critical table: {}", e);
                }
            }
        }
    }

    /// Whether to store selected servers.
    pub fn store_selected(&self) -> bool {
        self.store_selected
    }

    /// Set selected server for a group.
    pub async fn set_selected(&self, group: &str, server: &str) -> SqlResult<()> {
        self.selected_cache
            .write()
            .await
            .put(group.to_string(), server.to_string());
        let conn = self.conn.clone();
        let group = group.to_string();
        let server = server.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "REPLACE INTO selected (group_name, server) VALUES (?1, ?2)",
                params![group, server],
            )
        })
        .await
        .unwrap()?;
        Ok(())
    }

    /// Get selected server for a group (with LRU cache).
    pub async fn get_selected(&self, group: &str) -> SqlResult<Option<String>> {
        {
            let mut cache = self.selected_cache.write().await;
            if let Some(val) = cache.get(group) {
                return Ok(Some(val.clone()));
            }
        }

        let conn = self.conn.clone();
        let group_clone = group.to_string();
        let res: SqlResult<Option<String>> =
            tokio::task::spawn_blocking(move || {
                let conn = conn.lock().unwrap();
                conn.query_row(
                    "SELECT server FROM selected WHERE group_name = ?1",
                    params![&group_clone],
                    |row| row.get(0),
                )
                .optional()
            })
            .await
            .unwrap();

        if let Ok(Some(v)) = &res {
            let mut cache = self.selected_cache.write().await;
            cache.put(group.to_string(), v.clone());
        }
        res
    }

    /// Get all selected servers as a map.
    pub async fn get_selected_map(&self) -> SqlResult<HashMap<String, String>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt =
                conn.prepare("SELECT group_name, server FROM selected")?;
            let rows = stmt.query_map([], |row| {
                let group: String = row.get(0)?;
                let server: String = row.get(1)?;
                Ok((group, server))
            })?;

            let mut map = HashMap::new();
            for row_result in rows {
                let (k, v) = row_result?;
                map.insert(k, v);
            }
            Ok(map)
        })
        .await
        .unwrap()
    }

    /// Set IP to host mapping.
    pub async fn set_ip_to_host(&self, ip: &str, host: &str) -> SqlResult<()> {
        self.ip_to_host_cache
            .write()
            .await
            .put(ip.to_string(), host.to_string());
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let host = host.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "REPLACE INTO ip_to_host (ip, host) VALUES (?1, ?2)",
                params![ip, host],
            )
        })
        .await
        .unwrap()?;
        Ok(())
    }

    /// Set host to IP mapping.
    pub async fn set_host_to_ip(&self, host: &str, ip: &str) -> SqlResult<()> {
        self.host_to_ip_cache
            .write()
            .await
            .put(host.to_string(), ip.to_string());
        let conn = self.conn.clone();
        let host = host.to_string();
        let ip = ip.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "REPLACE INTO host_to_ip (host, ip) VALUES (?1, ?2)",
                params![host, ip],
            )
        })
        .await
        .unwrap()?;
        Ok(())
    }

    /// Get fake IP or host mapping (with LRU cache for both directions).
    pub async fn get_fake_ip(&self, ip_or_host: &str) -> SqlResult<Option<String>> {
        {
            let mut ip_cache = self.ip_to_host_cache.write().await;
            if let Some(val) = ip_cache.get(ip_or_host) {
                return Ok(Some(val.clone()));
            }
        }
        {
            let mut host_cache = self.host_to_ip_cache.write().await;
            if let Some(val) = host_cache.get(ip_or_host) {
                return Ok(Some(val.clone()));
            }
        }

        let conn = self.conn.clone();
        let ip_or_host_clone = ip_or_host.to_string();
        let res: SqlResult<Option<String>> =
            tokio::task::spawn_blocking(move || {
                let conn = conn.lock().unwrap();
                let mut stmt = conn.prepare(
                    "SELECT host FROM ip_to_host WHERE ip = ?1 UNION SELECT ip \
                     FROM host_to_ip WHERE host = ?1 LIMIT 1",
                )?;
                stmt.query_row(
                    params![&ip_or_host_clone, &ip_or_host_clone],
                    |row| row.get(0),
                )
                .optional()
            })
            .await
            .unwrap();

        if let Ok(Some(v)) = &res {
            let key = ip_or_host.to_string();
            if ip_or_host.contains('.') || ip_or_host.contains(':') {
                let mut ip_cache = self.ip_to_host_cache.write().await;
                ip_cache.put(key, v.clone());
            } else {
                let mut host_cache = self.host_to_ip_cache.write().await;
                host_cache.put(key, v.clone());
            }
        }
        res
    }

    /// Delete fake IP and host mapping pair. (Sync version)
    pub async fn delete_fake_ip_pair(&self, ip: &str, host: &str) -> SqlResult<()> {
        self.ip_to_host_cache.write().await.pop(ip);
        self.host_to_ip_cache.write().await.pop(host);
        let conn = self.conn.clone();
        let ip = ip.to_string();
        let host = host.to_string();
        tokio::task::spawn_blocking(move || -> SqlResult<()> {
            let conn = conn.lock().unwrap();
            conn.execute("DELETE FROM ip_to_host WHERE ip = ?1", params![ip])?;
            conn.execute("DELETE FROM host_to_ip WHERE host = ?1", params![host])?;
            Ok(())
        })
        .await
        .unwrap()?;
        Ok(())
    }

    /// Store smart proxy group statistics into structured tables (group
    /// independent).
    pub async fn set_smart_stats(
        &self,
        group_name: &str, // Now explicitly used for penalty
        stats: SmartStateData,
    ) -> SqlResult<()> {
        let conn_arc = self.conn.clone();
        let group_name_owned = group_name.to_string();

        tokio::task::spawn_blocking(move || -> SqlResult<()> {
            let mut conn = conn_arc.lock().unwrap();
            let tx = conn.transaction()?;

            // Insert or Replace Penalties (Group Specific)
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO smart_penalty (group_name, proxy_name, \
                     value, last_update_secs) VALUES (?1, ?2, ?3, ?4)",
                )?;
                for (proxy_name, penalty) in &stats.penalty {
                    stmt.execute(params![
                        &group_name_owned, // Use the specific group name
                        proxy_name,
                        penalty.value(),
                        penalty.last_update_secs()
                    ])?;
                }
            }

            // Insert or Replace Site Stats (Global)
            {
                let mut stmt = tx.prepare_cached(
                    "INSERT OR REPLACE INTO smart_site_stats (proxy_name, site, \
                     delay_history, success_history, last_attempt_secs) VALUES \
                     (?1, ?2, ?3, ?4, ?5)",
                )?;
                for (proxy_name, sites) in &stats.site_stats {
                    for (site, site_stats) in sites {
                        let delay_history_blob = bincode::serialize(
                            &site_stats.delay_history,
                        )
                        .map_err(|e| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                        })?;
                        let success_history_blob =
                            bincode::serialize(&site_stats.success_history)
                                .map_err(|e| {
                                    rusqlite::Error::ToSqlConversionFailure(
                                        Box::new(e),
                                    )
                                })?;

                        stmt.execute(params![
                            proxy_name,
                            site,
                            delay_history_blob,
                            success_history_blob,
                            site_stats.last_attempt_secs(),
                        ])?;
                    }
                }
            }

            // Commit transaction
            tx.commit()?;

            Ok(())
        })
        .await
        .unwrap() // Propagate panic from spawn_blocking, return SqlResult
    }

    /// Get smart proxy group statistics by querying structured tables.
    /// Loads group-specific penalties and global site stats.
    pub async fn get_smart_stats(
        &self,
        group_name: &str, // Still needed for penalty
    ) -> SqlResult<Option<SmartStateData>> {
        let conn_arc = self.conn.clone();
        let group_name_clone = group_name.to_string(); // Clone for blocking task

        tokio::task::spawn_blocking(move || -> SqlResult<Option<SmartStateData>> {
            let conn = conn_arc.lock().unwrap();
            let mut state_data = SmartStateData::default();
            let mut found_penalty_data = false; // Track if group-specific data exists

            // Load Penalties (Group Specific)
            let mut stmt_penalty = conn.prepare(
                "SELECT proxy_name, value, last_update_secs FROM smart_penalty \
                 WHERE group_name = ?1",
            )?;
            let penalty_iter =
                stmt_penalty.query_map(params![&group_name_clone], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, f64>(1)?,
                        row.get::<_, u64>(2)?, // Changed type from i64 to u64
                    ))
                })?;

            for row_result in penalty_iter {
                let (proxy_name, value, last_update_secs) = row_result?;
                state_data.penalty.insert(
                    proxy_name,
                    ProxyPenalty::from_stored(value, last_update_secs),
                );
                found_penalty_data = true; // Mark that group-specific penalty data was found
            }

            // Load Site Stats (Global - No group filter)
            let mut stmt_stats = conn.prepare(
                "SELECT proxy_name, site, delay_history, success_history, \
                 last_attempt_secs FROM smart_site_stats",
            )?;
            let stats_iter = stmt_stats.query_map([], |row| {
                let deserialize_delay_history = |blob: Vec<u8>| -> Result<
                    Vec<f64>,
                    Box<dyn std::error::Error + Send + Sync>,
                > {
                    if blob.is_empty() {
                        Ok(Vec::new())
                    } else {
                        bincode::deserialize(&blob).map_err(Into::into)
                    }
                };
                let deserialize_success_history = |blob: Vec<u8>| -> Result<
                    Vec<bool>,
                    Box<dyn std::error::Error + Send + Sync>,
                > {
                    if blob.is_empty() {
                        Ok(Vec::new())
                    } else {
                        bincode::deserialize(&blob).map_err(Into::into)
                    }
                };

                let proxy_name: String = row.get(0)?;
                let site: String = row.get(1)?;
                let delay_history_blob: Vec<u8> = row.get(2)?;
                let success_history_blob: Vec<u8> = row.get(3)?;
                let last_attempt_secs: u64 = row.get(4)?;

                let delay_history = deserialize_delay_history(delay_history_blob)
                    .unwrap_or_else(|e| {
                        tracing::error!(
                            "Failed to deserialize delay_history for {}/{}: {}",
                            proxy_name,
                            site,
                            e
                        );
                        Vec::new()
                    });
                let success_history =
                    deserialize_success_history(success_history_blob)
                        .unwrap_or_else(|e| {
                            tracing::error!(
                                "Failed to deserialize success_history for {}/{}: \
                                 {}",
                                proxy_name,
                                site,
                                e
                            );
                            Vec::new()
                        });

                Ok((
                    proxy_name,
                    site,
                    delay_history,
                    success_history,
                    last_attempt_secs,
                ))
            })?;

            for row_result in stats_iter {
                match row_result {
                    Ok((
                        proxy_name,
                        site,
                        delay_history,
                        success_history,
                        last_attempt_secs,
                    )) => {
                        let site_stats = SiteStats::from_stored(
                            delay_history,
                            success_history,
                            last_attempt_secs,
                            10,
                        );
                        state_data
                            .site_stats
                            .entry(proxy_name)
                            .or_default()
                            .insert(site, site_stats);
                    }
                    Err(e) => {
                        tracing::error!("Error processing site stats row: {}", e);
                    }
                }
            }

            // Return Some only if penalty data for this specific group was found.
            // Site stats are global and loaded regardless.
            if found_penalty_data {
                Ok(Some(state_data))
            } else {
                Ok(None)
            }
        })
        .await
        .unwrap()
    }
}
