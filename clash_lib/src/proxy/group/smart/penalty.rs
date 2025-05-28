//! Penalty mechanism for smart proxy group
//!
//! This module implements a penalty system that tracks proxy performance
//! and applies exponential penalties for failures with time-based decay.

use std::time::Instant;

/// Tracks and manages the penalty score for a proxy
///
/// The penalty system uses exponential growth for failures and exponential
/// decay over time to allow recovery. Higher penalty values indicate worse
/// performance and lower selection priority.
pub struct ProxyPenalty {
    /// Current penalty value (higher = worse performance)
    value: f64,
    /// When the penalty was last updated
    last_update: Instant,
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
        if self.value > 0.0 && elapsed > 0.0 {
            // Half-life of ~10 seconds
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

    /// Check if penalty has decayed to negligible levels
    ///
    /// # Returns
    /// `true` if penalty is effectively zero (< 0.01)
    pub fn is_negligible(&self) -> bool {
        self.value < 0.01
    }

    /// Get the age of the last penalty update
    ///
    /// # Returns
    /// Duration since last penalty update
    pub fn age(&self) -> std::time::Duration {
        self.last_update.elapsed()
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
        assert!(penalty.is_negligible());
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
        let mut penalty = ProxyPenalty::new();
        penalty.add_penalty(); // value = 2.0
        penalty.add_penalty(); // value = 6.0
        
        penalty.reward();
        assert_eq!(penalty.value(), 1.2); // 6.0 * 0.2
        
        penalty.reward();
        assert_eq!(penalty.value(), 0.24); // 1.2 * 0.2
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