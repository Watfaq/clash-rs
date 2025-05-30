//! Site preference tracking for smart proxy group
//!
//! This module implements simple site stickiness functionality.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Deserialize, Serialize};
/// Simple site preference tracking for sticky behavior
#[derive(Debug, Clone)]
pub struct SitePreference {
    /// Preferred proxy name for this site
    pub preferred_proxy: String,
    /// Last used time
    pub last_used: Instant,
    /// Success rate with this proxy (0.0 - 1.0)
    pub success_rate: f64,
    /// Total connection attempts
    pub total_attempts: u32,
}

impl Serialize for SitePreference {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SitePreference", 4)?;
        state.serialize_field("preferred_proxy", &self.preferred_proxy)?;
        
        // Convert Instant to timestamp
        let duration = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let elapsed = self.last_used.elapsed();
        let timestamp = duration.saturating_sub(elapsed);
        state.serialize_field("last_used", &timestamp.as_secs())?;
        
        state.serialize_field("success_rate", &self.success_rate)?;
        state.serialize_field("total_attempts", &self.total_attempts)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for SitePreference {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SitePreferenceData {
            preferred_proxy: String,
            last_used: u64,
            success_rate: f64,
            total_attempts: u32,
        }
        
        let data = SitePreferenceData::deserialize(deserializer)?;
        
        // Convert timestamp back to Instant
        let timestamp = Duration::from_secs(data.last_used);
        let now_duration = SystemTime::now().duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        
        let last_used = if now_duration > timestamp {
            let elapsed = now_duration - timestamp;
            Instant::now() - elapsed
        } else {
            Instant::now()
        };
        
        Ok(SitePreference {
            preferred_proxy: data.preferred_proxy,
            last_used,
            success_rate: data.success_rate,
            total_attempts: data.total_attempts,
        })
    }
}

impl SitePreference {
    /// Create a new site preference for a proxy
    pub fn new(proxy_name: String) -> Self {
        Self {
            preferred_proxy: proxy_name,
            last_used: Instant::now(),
            success_rate: 1.0,
            total_attempts: 1,
        }
    }

    /// Update preference with a new connection result
    pub fn update_success(&mut self, success: bool) {
        self.total_attempts += 1;
        let success_count = (self.success_rate * (self.total_attempts - 1) as f64) + if success { 1.0 } else { 0.0 };
        self.success_rate = success_count / self.total_attempts as f64;
        self.last_used = Instant::now();
    }

    /// Check if preference is still valid
    pub fn is_valid(&self, min_success_rate: f64, max_age_secs: u64) -> bool {
        self.success_rate >= min_success_rate
            && self.last_used.elapsed().as_secs() < max_age_secs
    }
}