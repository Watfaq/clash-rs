//! State management for smart proxy group
//!
//! This module provides centralized state management for the smart proxy
//! group, coordinating between different components like penalties,
//! statistics, and preferences.

use std::{
    collections::HashMap,
    time::Instant,
};
use tracing::debug;

use crate::{
    app::remote_content_manager::TrafficStats,
    session::Session,
};

use super::{
    config::WeightConfig,
    penalty::ProxyPenalty,
    preference::SitePreference,
    stats::{SiteStats, TrafficStatsCollector},
};

/// Centralized state manager for smart proxy group
///
/// Coordinates all stateful components of the smart proxy group including
/// penalties, site statistics, traffic monitoring, and preferences.
pub struct SmartState {
    /// Penalty tracking per proxy
    penalty: HashMap<String, ProxyPenalty>,
    /// Site-specific statistics per proxy
    pub site_stats: HashMap<String, HashMap<String, SiteStats>>, // Proxy name -> Site -> Stats
    /// Real-time traffic statistics collector
    traffic_collector: TrafficStatsCollector,
    /// Site preferences for sticky behavior
    site_preferences: HashMap<String, SitePreference>, // Site -> Preference
    /// Parsed weight configuration for custom proxy priorities
    weight_config: WeightConfig,
}

impl SmartState {
    /// Create a new SmartState with default configuration
    ///
    /// # Returns
    /// New SmartState instance with default settings
    pub fn new() -> Self {
        Self {
            penalty: HashMap::new(),
            site_stats: HashMap::new(),
            traffic_collector: TrafficStatsCollector::new(),
            site_preferences: HashMap::new(),
            weight_config: WeightConfig::default(),
        }
    }
    
    /// Create a new SmartState with weight configuration
    ///
    /// # Arguments
    /// * `policy_priority` - Optional policy priority configuration string
    ///
    /// # Returns
    /// New SmartState instance with specified weight configuration
    pub fn new_with_weight_config(policy_priority: Option<&str>) -> Self {
        let weight_config = if let Some(priority) = policy_priority {
            WeightConfig::parse(priority).unwrap_or_default()
        } else {
            WeightConfig::default()
        };
        
        Self {
            penalty: HashMap::new(),
            site_stats: HashMap::new(),
            traffic_collector: TrafficStatsCollector::new(),
            site_preferences: HashMap::new(),
            weight_config,
        }
    }

    /// Get or create penalty tracker for a proxy
    ///
    /// # Arguments
    /// * `proxy_name` - Name of the proxy
    ///
    /// # Returns
    /// Mutable reference to the proxy's penalty tracker
    pub fn get_penalty_mut(&mut self, proxy_name: &str) -> &mut ProxyPenalty {
        self.penalty.entry(proxy_name.to_string()).or_default()
    }

    /// Get penalty tracker for a proxy (read-only)
    ///
    /// # Arguments
    /// * `proxy_name` - Name of the proxy
    ///
    /// # Returns
    /// Reference to the proxy's penalty tracker, or None if not found
    pub fn get_penalty(&self, proxy_name: &str) -> Option<&ProxyPenalty> {
        self.penalty.get(proxy_name)
    }

    /// Get weight multiplier for a proxy from configuration
    ///
    /// # Arguments
    /// * `proxy_name` - Name of the proxy
    ///
    /// # Returns
    /// Weight multiplier (default: 1.0)
    pub fn get_weight(&self, proxy_name: &str) -> f64 {
        self.weight_config.get_weight(proxy_name)
    }

    /// Get or create site statistics for a proxy-site combination
    ///
    /// # Arguments
    /// * `proxy_name` - Name of the proxy
    /// * `site` - Site identifier (hostname or IP)
    ///
    /// # Returns
    /// Mutable reference to the site statistics
    pub fn get_site_stats_mut(&mut self, proxy_name: &str, site: &str) -> &mut SiteStats {
        self.site_stats
            .entry(proxy_name.to_string())
            .or_default()
            .entry(site.to_string())
            .or_default()
    }

    /// Get site statistics for a proxy-site combination (read-only)
    ///
    /// # Arguments
    /// * `proxy_name` - Name of the proxy
    /// * `site` - Site identifier (hostname or IP)
    ///
    /// # Returns
    /// Reference to site statistics, or None if not found
    pub fn get_site_stats(&self, proxy_name: &str, site: &str) -> Option<&SiteStats> {
        self.site_stats
            .get(proxy_name)
            .and_then(|sites| sites.get(site))
    }

    /// Record a connection result for penalty and statistics tracking
    ///
    /// # Arguments
    /// * `proxy_name` - Name of the proxy used
    /// * `site` - Site that was accessed
    /// * `dest_ip` - Optional destination IP address
    /// * `delay` - Connection delay in milliseconds
    /// * `success` - Whether the connection was successful
    pub fn record_connection_result(
        &mut self,
        proxy_name: &str,
        site: &str,
        dest_ip: Option<&str>,
        delay: f64,
        success: bool,
    ) {
        // Update penalty
        let penalty = self.get_penalty_mut(proxy_name);
        if success {
            penalty.reward();
        } else {
            penalty.add_penalty();
        }

        // Update site statistics
        let site_stats = self.get_site_stats_mut(proxy_name, site);
        site_stats.add_result(delay, success, None);

        // Update IP statistics if available
        if let Some(ip) = dest_ip {
            let ip_stats = self.get_site_stats_mut(proxy_name, ip);
            ip_stats.add_result(delay, success, None);
        }

    }

    /// Get site preference for a site
    ///
    /// # Arguments
    /// * `site` - Site identifier
    ///
    /// # Returns
    /// Reference to site preference, or None if not found
    pub fn get_site_preference(&self, site: &str) -> Option<&SitePreference> {
        self.site_preferences.get(site)
    }

    /// Update site preference based on connection result
    ///
    /// # Arguments
    /// * `site` - Site identifier
    /// * `proxy_name` - Name of the proxy used
    /// * `success` - Whether the connection was successful
    /// * `site_stickiness` - Site stickiness configuration (0.0-1.0)
    pub fn update_site_preference(&mut self, site: &str, proxy_name: &str, success: bool, site_stickiness: f64) {
        if site_stickiness <= 0.0 {
            return;
        }

        if let Some(preference) = self.site_preferences.get_mut(site) {
            if preference.preferred_proxy == proxy_name {
                preference.update_success(success);
                if !success && preference.success_rate < 0.5 {
                    debug!("Removing site preference for {} from {} (poor performance)", site, proxy_name);
                    self.site_preferences.remove(site);
                }
            } else if success && preference.success_rate < 0.8 {
                // Switch to this better performing proxy
                debug!("Switching site preference for {} from {} to {} (better performance)",
                       site, preference.preferred_proxy, proxy_name);
                *preference = SitePreference::new(proxy_name.to_string());
            }
        } else if success {
            self.site_preferences.insert(
                site.to_string(),
                SitePreference::new(proxy_name.to_string())
            );
        }
    }

    /// Generate session ID from session information
    ///
    /// # Arguments
    /// * `sess` - Session information
    ///
    /// # Returns
    /// Unique session identifier string
    pub fn generate_session_id(sess: &Session) -> String {
        format!("{}:{}->{}", sess.network, sess.source, sess.destination)
    }

    /// Start tracking traffic for a session
    ///
    /// # Arguments
    /// * `sess` - Session to start tracking
    pub fn start_traffic_tracking(&mut self, sess: &Session) {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector.start_session(&session_id);
    }

    /// Record traffic data for a session
    ///
    /// # Arguments
    /// * `sess` - Session information
    /// * `uploaded` - Bytes uploaded
    /// * `downloaded` - Bytes downloaded
    pub fn record_traffic(&mut self, sess: &Session, uploaded: u64, downloaded: u64) {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector.record_transfer(&session_id, uploaded, downloaded);
    }

    /// Record a request event for a session
    ///
    /// # Arguments
    /// * `sess` - Session information
    pub fn record_request(&mut self, sess: &Session) {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector.record_request(&session_id);
    }

    /// Get traffic statistics for a session
    ///
    /// # Arguments
    /// * `sess` - Session information
    ///
    /// # Returns
    /// Traffic statistics if available
    pub fn get_traffic_stats(&self, sess: &Session) -> Option<TrafficStats> {
        let session_id = Self::generate_session_id(sess);
        self.traffic_collector.get_stats(&session_id)
    }

    /// Clean up stale data to prevent memory leaks
    ///
    /// Removes outdated statistics, preferences, and other data
    /// that is no longer relevant or useful.
    pub fn cleanup_stale(&mut self) {
        // Clean up stale site statistics
        for stats in self.site_stats.values_mut() {
            stats.retain(|_, site_stat| !site_stat.is_stale());
        }

        // Clean up old traffic data
        self.traffic_collector.cleanup_old_sessions();

        // Clean up old site preferences (older than 1 hour with poor performance)
        let cutoff = Instant::now().checked_sub(std::time::Duration::from_secs(3600));
        if let Some(cutoff) = cutoff {
            self.site_preferences.retain(|_, pref| {
                pref.last_used > cutoff || pref.success_rate > 0.7
            });
        }

        // Decay penalties for all proxies and clean up negligible or very old ones
        self.penalty.retain(|_, penalty| {
            penalty.decay();
            // Keep penalty if it's significant and not too old (less than 1 hour)
            !penalty.is_negligible() && penalty.age().as_secs() < 3600
        });
    }

    /// Get comprehensive statistics for monitoring and debugging
    ///
    /// # Returns
    /// (tracked_proxies, active_sites, active_sessions, avg_success_rate)
    pub fn get_statistics(&self) -> (usize, usize, usize, f64) {
        let tracked_proxies = self.penalty.len();
        let active_sites = self.site_preferences.len();
        let active_sessions = self.traffic_collector.active_session_count();
        
        // Calculate average success rate across all site preferences
        let avg_success_rate = if !self.site_preferences.is_empty() {
            self.site_preferences.values()
                .map(|pref| pref.success_rate)
                .sum::<f64>() / self.site_preferences.len() as f64
        } else {
            0.0
        };

        (tracked_proxies, active_sites, active_sessions, avg_success_rate)
    }
}

impl Default for SmartState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smart_state_creation() {
        let state = SmartState::new();
        let (proxies, sites, sessions, _) = state.get_statistics();
        assert_eq!(proxies, 0);
        assert_eq!(sites, 0);
        assert_eq!(sessions, 0);
    }

    #[test]
    fn test_penalty_tracking() {
        let mut state = SmartState::new();
        
        // Record a failure
        state.record_connection_result("proxy1", "example.com", None, 1000.0, false);
        
        let penalty = state.get_penalty("proxy1");
        assert!(penalty.is_some());
        assert!(penalty.unwrap().value() > 0.0);
    }

    #[test]
    fn test_site_preference() {
        let mut state = SmartState::new();
        
        // Record successful connection
        state.update_site_preference("example.com", "proxy1", true, 0.8);
        
        let preference = state.get_site_preference("example.com");
        assert!(preference.is_some());
        assert_eq!(preference.unwrap().preferred_proxy, "proxy1");
    }

    #[test]
    fn test_weight_config() {
        let state = SmartState::new_with_weight_config(Some("proxy1:0.5"));
        assert_eq!(state.get_weight("proxy1"), 0.5);
        assert_eq!(state.get_weight("proxy2"), 1.0); // default
    }
}