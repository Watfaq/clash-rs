//! Site preference tracking for smart proxy group
//!
//! This module implements simple site stickiness functionality.

use std::time::Instant;

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