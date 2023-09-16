use crate::Error;
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
    DomainKeyword {
        domain_keyword: String,
        target: String,
    },
    GeoIP {
        target: String,
        country_code: String,
        no_resolve: bool,
    },
    IPCIDR {
        ipnet: ipnet::IpNet,
        target: String,
        no_resolve: bool,
    },
    SRCIPCIDR {
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
}

impl RuleType {
    pub fn target(&self) -> &str {
        match self {
            RuleType::Domain { target, .. } => target,
            RuleType::DomainSuffix { target, .. } => target,
            RuleType::DomainKeyword { target, .. } => target,
            RuleType::GeoIP { target, .. } => target,
            RuleType::IPCIDR { target, .. } => target,
            RuleType::SRCIPCIDR { target, .. } => target,
            RuleType::SRCPort { target, .. } => target,
            RuleType::DSTPort { target, .. } => target,
            RuleType::ProcessName { target, .. } => target,
            RuleType::ProcessPath { target, .. } => target,
            RuleType::RuleSet { target, .. } => target,
            RuleType::Match { target } => target,
        }
    }
}

impl Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::Domain { domain, target } => write!(f, "DOMAIN,{},{}", domain, target),
            RuleType::DomainSuffix { .. } => write!(f, "DOMAIN-SUFFIX"),
            RuleType::DomainKeyword { .. } => write!(f, "DOMAIN-KEYWORD"),
            RuleType::GeoIP { .. } => write!(f, "GEOIP"),
            RuleType::IPCIDR { .. } => write!(f, "IP-CIDR"),
            RuleType::SRCIPCIDR { .. } => write!(f, "SRC-IP-CIDR"),
            RuleType::SRCPort { .. } => write!(f, "SRC-PORT"),
            RuleType::DSTPort { .. } => write!(f, "DST-PORT"),
            RuleType::ProcessName { .. } => write!(f, "PROCESS-NAME"),
            RuleType::ProcessPath { .. } => write!(f, "PROCESS-PATH"),
            RuleType::RuleSet { .. } => write!(f, "RULE-SET"),
            RuleType::Match { .. } => write!(f, "MATCH"),
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
        match proto {
            "DOMAIN" => Ok(RuleType::Domain {
                domain: payload.to_string(),
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
            "GEOIP" => Ok(RuleType::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleType::IPCIDR {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "SRC-IP-CIDR" => Ok(RuleType::SRCIPCIDR {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "SRC-PORT" => Ok(RuleType::SRCPort {
                target: target.to_string(),
                port: payload
                    .parse()
                    .expect(format!("invalid port: {}", payload).as_str()),
            }),
            "DST-PORT" => Ok(RuleType::DSTPort {
                target: target.to_string(),
                port: payload
                    .parse()
                    .expect(format!("invalid port: {}", payload).as_str()),
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
            _ => Err(Error::InvalidConfig(format!(
                "unsupported rule type: {}",
                proto
            ))),
        }
    }
}

impl TryFrom<String> for RuleType {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let parts = line.split(",").map(str::trim).collect::<Vec<&str>>();

        match parts.as_slice() {
            [proto, target] => RuleType::new(proto, "", target, None),
            [proto, payload, target] => RuleType::new(proto, payload, target, None),
            [proto, payload, target, params @ ..] => {
                RuleType::new(proto, payload, target, Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {}", line))),
        }
    }
}

impl FromStr for RuleType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}
