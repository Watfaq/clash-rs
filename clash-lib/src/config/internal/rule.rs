use crate::{Error, print_and_exit};
use std::{fmt::Display, str::FromStr};

pub enum RuleType {
    Domain {
        domain: String,
        target: String,
    },
    DomainSuffix {
        domain_suffix: String,
        target: String,
    },
    DomainRegex {
        regex: regex::Regex,
        target: String,
    },
    DomainKeyword {
        domain_keyword: String,
        target: String,
    },
    GeoIP {
        target: String,
        country_code: String,
        no_resolve: bool,
    },
    GeoSite {
        target: String,
        country_code: String,
    },
    IpCidr {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
    },
    SrcCidr {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
    },
    SRCPort {
        target: String,
        port: u16,
    },
    DSTPort {
        target: String,
        port: u16,
    },
    ProcessName {
        process_name: String,
        target: String,
    },
    ProcessPath {
        process_path: String,
        target: String,
    },
    RuleSet {
        rule_set: String,
        target: String,
    },
    Match {
        target: String,
    },
    Network {
        network: crate::session::Network,
        target: String,
    },
    Composite {
        operator: String,
        expression: String,
        target: String,
    },
    WithInterface {
        rule: Box<RuleType>,
        interface: String,
    },
}

fn split_rule_tokens(line: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    for (idx, ch) in line.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                tokens.push(line[start..idx].trim());
                start = idx + 1;
            }
            _ => {}
        }
    }
    tokens.push(line[start..].trim());
    tokens
}

fn split_rule_options(
    params: Option<Vec<&str>>,
) -> Result<(Option<String>, Option<Vec<&str>>), Error> {
    let Some(params) = params else {
        return Ok((None, None));
    };

    let mut interface = None;
    let mut rest = Vec::new();
    for param in params {
        if let Some(v) = param.strip_prefix("interface=") {
            if v.is_empty() {
                return Err(Error::InvalidConfig(
                    "rule interface cannot be empty".to_string(),
                ));
            }
            if interface.replace(v.to_string()).is_some() {
                return Err(Error::InvalidConfig(
                    "rule interface can only be specified once".to_string(),
                ));
            }
        } else {
            rest.push(param);
        }
    }

    Ok((interface, (!rest.is_empty()).then_some(rest)))
}

impl RuleType {
    pub fn target(&self) -> &str {
        match self {
            RuleType::Domain { target, .. } => target,
            RuleType::DomainSuffix { target, .. } => target,
            RuleType::DomainRegex { target, .. } => target,
            RuleType::DomainKeyword { target, .. } => target,
            RuleType::GeoIP { target, .. } => target,
            RuleType::GeoSite { target, .. } => target,
            RuleType::IpCidr { target, .. } => target,
            RuleType::SrcCidr { target, .. } => target,
            RuleType::SRCPort { target, .. } => target,
            RuleType::DSTPort { target, .. } => target,
            RuleType::ProcessName { target, .. } => target,
            RuleType::ProcessPath { target, .. } => target,
            RuleType::RuleSet { target, .. } => target,
            RuleType::Match { target, .. } => target,
            RuleType::Network { target, .. } => target,
            RuleType::Composite { target, .. } => target,
            RuleType::WithInterface { rule, .. } => rule.target(),
        }
    }

    pub fn interface(&self) -> Option<&str> {
        match self {
            RuleType::WithInterface { interface, .. } => Some(interface),
            _ => None,
        }
    }
}

impl Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::Domain { domain, target, .. } => {
                write!(f, "DOMAIN,{domain},{target}")
            }
            RuleType::DomainRegex { regex, target, .. } => {
                write!(f, "DOMAIN-REGEX,{regex},{target}")
            }
            RuleType::DomainSuffix { .. } => write!(f, "DOMAIN-SUFFIX"),
            RuleType::DomainKeyword { .. } => write!(f, "DOMAIN-KEYWORD"),
            RuleType::GeoIP { .. } => write!(f, "GEOIP"),
            RuleType::GeoSite { .. } => write!(f, "GEOSITE"),
            RuleType::IpCidr { .. } => write!(f, "IP-CIDR"),
            RuleType::SrcCidr { .. } => write!(f, "SRC-IP-CIDR"),
            RuleType::SRCPort { .. } => write!(f, "SRC-PORT"),
            RuleType::DSTPort { .. } => write!(f, "DST-PORT"),
            RuleType::ProcessName { .. } => write!(f, "PROCESS-NAME"),
            RuleType::ProcessPath { .. } => write!(f, "PROCESS-PATH"),
            RuleType::RuleSet { .. } => write!(f, "RULE-SET"),
            RuleType::Match { .. } => write!(f, "MATCH"),
            RuleType::Network { .. } => write!(f, "NETWORK"),
            RuleType::Composite { .. } => write!(f, "COMPOSITE"),
            RuleType::WithInterface { rule, interface } => {
                write!(f, "{rule},interface={interface}")
            }
        }
    }
}

impl RuleType {
    pub fn new(
        proto: &str,
        payload: &str,
        target: &str,
        params: Option<Vec<&str>>,
    ) -> Result<Self, Error> {
        let (interface, params) = split_rule_options(params)?;
        let no_resolve = params
            .as_ref()
            .is_some_and(|params| params.contains(&"no-resolve"));

        let rule = match proto {
            "DOMAIN" => Ok(RuleType::Domain {
                domain: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-REGEX" => Ok(RuleType::DomainRegex {
                regex: regex::Regex::new(payload)
                    .map_err(|e| Error::InvalidConfig(e.to_string()))?,
                target: target.to_string(),
            }),
            "DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix {
                domain_suffix: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword {
                domain_keyword: payload.to_string(),
                target: target.to_string(),
            }),
            "GEOSITE" => Ok(RuleType::GeoSite {
                target: target.to_string(),
                country_code: payload.to_string(),
            }),
            "GEOIP" => Ok(RuleType::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
                no_resolve,
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleType::IpCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve,
            }),
            "SRC-IP-CIDR" => Ok(RuleType::SrcCidr {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve,
            }),
            "SRC-PORT" => Ok(RuleType::SRCPort {
                target: target.to_string(),
                port: payload.parse().unwrap_or_else(|_| {
                    print_and_exit!("invalid port: {}", payload)
                }),
            }),
            "DST-PORT" => Ok(RuleType::DSTPort {
                target: target.to_string(),
                port: payload.parse().unwrap_or_else(|_| {
                    print_and_exit!("invalid port: {}", payload)
                }),
            }),
            "PROCESS-NAME" => Ok(RuleType::ProcessName {
                process_name: payload.to_string(),
                target: target.to_string(),
            }),
            "PROCESS-PATH" => Ok(RuleType::ProcessPath {
                process_path: payload.to_string(),
                target: target.to_string(),
            }),
            "RULE-SET" => Ok(RuleType::RuleSet {
                rule_set: payload.to_string(),
                target: target.to_string(),
            }),
            "MATCH" => Ok(RuleType::Match {
                target: target.to_string(),
            }),
            "NETWORK" => {
                let network = match payload {
                    "TCP" | "tcp" => crate::session::Network::Tcp,
                    "UDP" | "udp" => crate::session::Network::Udp,
                    _ => {
                        return Err(Error::InvalidConfig(format!(
                            "invalid network type: {}, expected TCP or UDP",
                            payload
                        )));
                    }
                };
                Ok(RuleType::Network {
                    network,
                    target: target.to_string(),
                })
            }
            "AND" | "OR" | "NOT" => Ok(RuleType::Composite {
                operator: proto.to_string(),
                expression: payload.to_string(),
                target: target.to_string(),
            }),

            _ => Err(Error::InvalidConfig(format!(
                "unsupported rule type: {proto}"
            ))),
        }?;

        Ok(match interface {
            Some(interface) => RuleType::WithInterface {
                rule: Box::new(rule),
                interface,
            },
            None => rule,
        })
    }
}

impl TryFrom<String> for RuleType {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let parts = split_rule_tokens(&line);

        match parts.as_slice() {
            [proto, target] => RuleType::new(proto, "", target, None),
            ["MATCH", target, params @ ..] => {
                RuleType::new("MATCH", "", target, Some(params.to_vec()))
            }
            [proto, payload, target] => RuleType::new(proto, payload, target, None),
            [proto, payload, target, params @ ..] => {
                RuleType::new(proto, payload, target, Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {line}"))),
        }
    }
}

impl FromStr for RuleType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_rule_parsing() {
        // Test TCP network rule
        let rule = RuleType::try_from("NETWORK,TCP,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network {
                network, target, ..
            } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test UDP network rule
        let rule = RuleType::try_from("NETWORK,UDP,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network {
                network, target, ..
            } => {
                assert_eq!(network, crate::session::Network::Udp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test lowercase network types
        let rule = RuleType::try_from("NETWORK,tcp,PROXY".to_string()).unwrap();
        match rule {
            RuleType::Network {
                network, target, ..
            } => {
                assert_eq!(network, crate::session::Network::Tcp);
                assert_eq!(target, "PROXY");
            }
            _ => panic!("Expected Network rule"),
        }

        // Test invalid network type
        let rule = RuleType::try_from("NETWORK,INVALID,PROXY".to_string());
        assert!(rule.is_err());
    }

    #[test]
    fn test_interface_option_does_not_change_target() {
        let rule = RuleType::try_from(
            "DOMAIN,google.com,IFACE_en0,interface=pdp_ip0".to_string(),
        )
        .unwrap();

        assert_eq!(rule.target(), "IFACE_en0");
        assert_eq!(rule.interface(), Some("pdp_ip0"));

        let rule = RuleType::try_from("DOMAIN,google.com,interface=en0".to_string())
            .unwrap();
        assert_eq!(rule.target(), "interface=en0");
        assert_eq!(rule.interface(), None);
    }

    #[test]
    fn test_match_interface_option() {
        let rule =
            RuleType::try_from("MATCH,DIRECT,interface=en0".to_string()).unwrap();

        assert_eq!(rule.target(), "DIRECT");
        assert_eq!(rule.interface(), Some("en0"));
    }

    #[test]
    fn test_composite_interface_option() {
        let rule = RuleType::try_from(
            "AND,((DOMAIN,google.com),(NETWORK,TCP)),PROXY,interface=en0"
                .to_string(),
        )
        .unwrap();

        assert_eq!(rule.target(), "PROXY");
        assert_eq!(rule.interface(), Some("en0"));
    }
}
