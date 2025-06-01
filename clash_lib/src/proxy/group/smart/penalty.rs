//! Penalty mechanism for smart proxy group
//!
//! This module implements a penalty system that tracks proxy performance
//! and applies exponential penalties for failures with time-based decay.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Tracks and manages the penalty score for a proxy
///
/// The penalty system uses exponential growth for failures and exponential
/// decay over time to allow recovery. Higher penalty values indicate worse
/// performance and lower selection priority.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProxyPenalty {
    /// Current penalty value (higher = worse performance)
    value: f64,
    /// When the penalty was last updated (as duration since UNIX_EPOCH)
    #[serde(with = "instant_serde")]
    last_update: Instant,
}

mod instant_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    // Serialize Instant as UNIX timestamp (seconds)
    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let elapsed = instant.elapsed();
        let timestamp = duration.saturating_sub(elapsed);
        serializer.serialize_u64(timestamp.as_secs())
    }

    // Deserialize UNIX timestamp to Instant, fallback to now if overflow
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp_secs = u64::deserialize(deserializer)?;
        let timestamp = Duration::from_secs(timestamp_secs);
        let now_duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        if now_duration > timestamp {
            let elapsed = now_duration - timestamp;
            if let Some(inst) = Instant::now().checked_sub(elapsed) {
                Ok(inst)
            } else {
                Ok(Instant::now())
            }
        } else {
            Ok(Instant::now())
        }
    }
}

impl ProxyPenalty {
    /// Create a new ProxyPenalty with initial score 0
    ///
    /// # Returns
    /// A new penalty tracker with zero penalty
    #[inline]
    pub fn new() -> Self {
        Self {
            value: 0.0,
            last_update: Instant::now(),
        }
    }

    /// Get the current penalty value
    ///
    /// # Returns
    /// Current penalty score
    #[inline]
    pub fn value(&self) -> f64 {
        self.value
    }

    /// Increase penalty exponentially after a failure
    ///
    /// Penalty grows more severely with consecutive failures to quickly
    /// identify and deprioritize problematic proxies. Uses exponential
    /// growth: penalty = (penalty + 1) * 2
    #[inline]
    pub fn add_penalty(&mut self) {
        self.value = (self.value + 1.0) * 2.0; // Exponential growth
        self.last_update = Instant::now();
    }

    /// Decay penalty over time when not used
    ///
    /// Uses exponential decay based on elapsed time to allow proxies
    /// to recover from temporary issues. The half-life is approximately
    /// 10 seconds, meaning penalty is halved every 10 seconds.
    #[inline]
    pub fn decay(&mut self) {
        let elapsed = self.last_update.elapsed().as_secs_f64();
        // Reset to zero if penalty becomes negligible to avoid floating-point
        // underflow
        if self.value < 0.01 || elapsed > 300.0 {
            // 5-minute timeout
            self.value = 0.0;
        } else if elapsed > 0.0 {
            // Exponential decay with half-life of 10 seconds
            self.value *= 0.5f64.powf(elapsed / 10.0);
        }
        self.last_update = Instant::now();
    }

    /// Reduce penalty significantly after a success
    ///
    /// Quick recovery mechanism to allow retrying previously failed
    /// proxies. Reduces penalty by 80% to rapidly restore confidence
    /// in recovering proxies.
    #[inline]
    pub fn reward(&mut self) {
        self.value *= 0.2; // 80% reduction
        self.last_update = Instant::now();
    }
}

impl Default for ProxyPenalty {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_penalty_creation() {
        let penalty = ProxyPenalty::new();
        assert_eq!(penalty.value(), 0.0);
    }

    #[test]
    fn test_penalty_growth() {
        let mut penalty = ProxyPenalty::new();

        penalty.add_penalty();
        assert_eq!(penalty.value(), 2.0); // (0 + 1) * 2

        penalty.add_penalty();
        assert_eq!(penalty.value(), 6.0); // (2 + 1) * 2

        penalty.add_penalty();
        assert_eq!(penalty.value(), 14.0); // (6 + 1) * 2
    }

    #[test]
    fn test_penalty_reward() {
        let mut penalty: ProxyPenalty = ProxyPenalty::new();
        penalty.add_penalty(); // value = 2.0
        penalty.add_penalty(); // value = 6.0

        penalty.reward();
        assert!((penalty.value() - 1.2).abs() < 1e-6); // 6.0 * 0.2

        penalty.reward();
        assert!((penalty.value() - 0.24).abs() < 1e-6); // 1.2 * 0.2
    }

    #[test]
    fn test_penalty_decay() {
        let mut penalty = ProxyPenalty::new();
        penalty.add_penalty(); // value = 2.0

        // Simulate time passage by manually setting last_update
        penalty.last_update = Instant::now() - Duration::from_secs(10);
        penalty.decay();

        // After 10 seconds (one half-life), penalty should be ~1.0
        assert!((penalty.value() - 1.0).abs() < 0.1);
    }
}
