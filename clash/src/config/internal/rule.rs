use crate::Error;
use std::str::FromStr;

pub enum Rule {
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
    ProcessName,
    ProcessPath,
    RuleSet {
        rule_set: String,
        target: String,
    },
    Match {
        target: String,
    },
}

impl Rule {
    pub fn new(
        proto: &str,
        payload: &str,
        target: &str,
        params: Option<Vec<&str>>,
    ) -> Result<Self, Error> {
        match proto {
            "DOMAIN" => Ok(Rule::Domain {
                domain: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-SUFFIX" => Ok(Rule::DomainSuffix {
                domain_suffix: payload.to_string(),
                target: target.to_string(),
            }),
            "DOMAIN-KEYWORD" => Ok(Rule::DomainKeyword {
                domain_keyword: payload.to_string(),
                target: target.to_string(),
            }),
            "GEOIP" => Ok(Rule::GeoIP {
                target: target.to_string(),
                country_code: payload.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "IP-CIDR" | "IP-CIDR6" => Ok(Rule::IPCIDR {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "SRC-IP-CIDR" => Ok(Rule::SRCIPCIDR {
                ipnet: payload.parse()?,
                target: target.to_string(),
                no_resolve: if let Some(params) = params {
                    params.contains(&"no-resolve")
                } else {
                    false
                },
            }),
            "SRC-PORT" => Ok(Rule::SRCPort {
                target: target.to_string(),
                port: payload
                    .parse()
                    .expect(format!("invalid port: {}", payload).as_str()),
            }),
            "DST-PORT" => Ok(Rule::DSTPort {
                target: target.to_string(),
                port: payload
                    .parse()
                    .expect(format!("invalid port: {}", payload).as_str()),
            }),
            "PROCESS-NAME" => todo!(),
            "PROCESS-PATH" => todo!(),
            "RULE-SET" => Ok(Rule::RuleSet {
                rule_set: payload.to_string(),
                target: target.to_string(),
            }),
            "MATCH" => Ok(Rule::Match {
                target: target.to_string(),
            }),
            _ => Err(Error::InvalidConfig(format!(
                "unsupported rule type: {}",
                proto
            ))),
        }
    }
}

impl TryFrom<String> for Rule {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let parts = line.split(",").map(str::trim).collect::<Vec<&str>>();

        match parts.as_slice() {
            [proto, target] => Rule::new(proto, "", target, None),
            [proto, payload, target] => Rule::new(proto, payload, target, None),
            [proto, payload, target, params @ ..] => {
                Rule::new(proto, payload, target, Some(params.to_vec()))
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {}", line))),
        }
    }
}

impl FromStr for Rule {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}
