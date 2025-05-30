//! Configuration management for smart proxy group
//!
//! This module handles configuration options, weight rules, and
//! policy priority parsing for the smart proxy group.

use crate::proxy::HandlerCommonOptions;

/// Configuration options for the smart proxy group handler
#[derive(Default, Clone)]
pub struct HandlerOptions {
    /// Common proxy handler options
    pub common_opts: HandlerCommonOptions,
    /// Name of this proxy group
    pub name: String,
    /// Whether UDP is supported
    pub udp: bool,
    /// Maximum retries for failed connections
    pub max_retries: Option<u32>,
    /// Site stickiness factor (0.0-1.0)
    pub site_stickiness: Option<f64>,
    /// Bandwidth consideration weight
    pub bandwidth_weight: Option<f64>,
}

/// Custom weight rule for proxy selection
///
/// Weight rules allow fine-tuning of proxy selection by applying
/// multipliers to specific proxies based on regex patterns.
#[derive(Debug, Clone)]
pub struct WeightRule {
    /// Regex pattern to match proxy names
    pub pattern: regex::Regex,
    /// Weight multiplier (< 1.0 increases priority, > 1.0 decreases)
    pub weight: f64,
}

/// Parsed weight configuration container
///
/// This structure holds all parsed weight rules and provides
/// methods to calculate weights for specific proxy names.
#[derive(Debug, Default)]
pub struct WeightConfig {
    /// List of weight rules to apply
    pub rules: Vec<WeightRule>,
}

impl WeightConfig {
    /// Parse policy priority string into weight rules
    ///
    /// The policy priority string format is:
    /// "pattern1:weight1;pattern2:weight2;..." where patterns are regex
    /// expressions and weights are floating point numbers.
    ///
    /// # Arguments
    /// * `policy_priority` - The policy priority configuration string
    ///
    /// # Returns
    /// * `Ok(WeightConfig)` - Successfully parsed configuration
    /// * `Err(Box<dyn std::error::Error>)` - Parse error
    ///
    /// # Example
    /// ```
    /// let config = WeightConfig::parse("US.*:0.8;.*HK.*:1.2")?;
    /// ```
    pub fn parse(policy_priority: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rules = Vec::new();

        for rule_str in policy_priority.split(';') {
            let parts: Vec<&str> = rule_str.splitn(2, ':').collect();
            if parts.len() == 2 {
                let pattern = regex::Regex::new(parts[0].trim())?;
                let weight: f64 = parts[1].trim().parse()?;
                rules.push(WeightRule { pattern, weight });
            }
        }

        Ok(WeightConfig { rules })
    }

    /// Get weight multiplier for a proxy name
    ///
    /// Iterates through all weight rules and returns the weight
    /// of the first matching rule, or 1.0 if no rules match.
    ///
    /// # Arguments
    /// * `proxy_name` - The name of the proxy to get weight for
    ///
    /// # Returns
    /// Weight multiplier for the proxy (default: 1.0)
    pub fn get_weight(&self, proxy_name: &str) -> f64 {
        for rule in &self.rules {
            if rule.pattern.is_match(proxy_name) {
                return rule.weight;
            }
        }
        1.0 // Default weight
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_config_parse() {
        let config = WeightConfig::parse("US.*:0.8;.*HK.*:1.2").unwrap();
        assert_eq!(config.rules.len(), 2);

        assert_eq!(config.get_weight("US-Server-1"), 0.8);
        assert_eq!(config.get_weight("HK-Server-1"), 1.2);
        assert_eq!(config.get_weight("JP-Server-1"), 1.0);
    }

    #[test]
    fn test_weight_config_invalid() {
        let result = WeightConfig::parse("invalid:pattern");
        assert!(result.is_err());
    }
}
