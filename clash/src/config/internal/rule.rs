pub enum Rule {
    Domain { domain: String, target: String },
    DomainSuffix{domain_suffix: String , target: String},
    DomainKeyword{domain_keyword: String, target: String},
    GeoIP(),
    IPCIDR{ipnet: ipnet::IpNet, target: String, no_resolve:bool},
    SRCIPCIDR{ ipnet: ipnet::IpNet, target: String, no_resolve: bool},
    SRCPort,
    DSTPort,
    ProcessName,
    ProcessPath,
    Match,
}