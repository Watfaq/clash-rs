use crate::Error;
use futures::StreamExt;

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
    GeoIP(),
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
    SRCPort,
    DSTPort,
    ProcessName,
    ProcessPath,
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
    ) -> anyhow::Result<Self> {
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
            "GEOIP" => Ok(Rule::GeoIP()),
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
            "SRC-PORT" => todo!(),
            "DST-PORT" => todo!(),
            "PROCESS-NAME" => todo!(),
            "PROCESS-PATH" => todo!(),
            "MATCH" => Ok(Rule::Match {
                target: target.to_string(),
            }),
            _ => Err(anyhow!("unsupported rule type: {}", proto)),
        }
    }
}

impl TryFrom<String> for Rule {
    type Error = crate::Error;

    fn try_from(line: String) -> Result<Self, Self::Error> {
        let parts = line.split(",").map(str::trim).collect::<Vec<&str>>();

        match parts[..] {
            [proto, target] => Rule::new(proto, "", target, None).into(),
            [proto, payload, target] => Rule::new(proto, payload, target, None).into(),
            [proto, payload, target, params @ ..] => {
                Rule::new(proto, payload, target, Some(params)).into()
            }
            _ => Err(Error::InvalidConfig(format!("invalid rule line: {}", line))),
        }
    }
}
