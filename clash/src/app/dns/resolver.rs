use std::{io, net, rc::Rc, sync::Arc};

use async_trait::async_trait;

use crate::{common::trie, Error};

use super::{
    dns_client::{DnsClient, Opts},
    filters::{DomainFilter, FallbackDomainFilter, FallbackIPFilter, GeoIPFilter, IPNetFilter},
    Client, Config, NameServer,
};
/// Application Resolver, will consult hosts, etc.
/// it returns Result<Option, E> as a DNS can have
/// no A record setup
#[async_trait]
pub trait ClashResolver: Sync + Send {
    async fn resolve(&self, host: &str) -> Result<Option<net::IpAddr>, io::Error>;
    async fn resolve_v4(&self, host: &str) -> Result<Option<net::IpAddr>, io::Error>;
    async fn resolve_v6(&self, host: &str) -> Result<Option<net::Ipv6Addr>, io::Error>;
}

struct Resolver {
    ipv6: bool,
    hosts: Option<trie::DomainTrie>,
    main: Vec<Box<dyn Client>>,

    fallback: Option<Vec<Box<dyn Client>>>,
    fallback_domain_filters: Option<Vec<Box<dyn FallbackDomainFilter>>>,
    fallback_ip_filters: Option<Vec<Box<dyn FallbackIPFilter>>>,

    group: Option<async_singleflight::Group<trust_dns_client::op::Message, Error>>,
    lru_cache: Option<lru_cache::LruCache<String, trust_dns_client::op::Message>>,
    policy: Option<trie::DomainTrie>,
}

#[async_trait]
impl ClashResolver for Resolver {
    async fn resolve(&self, host: &str) -> Result<Option<net::IpAddr>, io::Error> {
        todo!();
    }
    async fn resolve_v4(&self, host: &str) -> Result<Option<net::IpAddr>, io::Error> {
        todo!();
    }
    async fn resolve_v6(&self, host: &str) -> Result<Option<net::Ipv6Addr>, io::Error> {
        todo!();
    }
}

impl Resolver {
    pub async fn new(cfg: Config) -> Self {
        let default_resolver = Arc::new(Resolver {
            ipv6: false,
            hosts: None,
            main: Resolver::make_clients(cfg.default_nameserver, None).await,
            fallback: None,
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            group: None,
            lru_cache: None,
            policy: None,
        });

        let r = Resolver {
            ipv6: cfg.ipv6,
            main: Resolver::make_clients(cfg.nameserver, Some(default_resolver.clone())).await,
            hosts: cfg.hosts,
            fallback: if cfg.fallback.len() > 0 {
                Some(Resolver::make_clients(cfg.fallback, Some(default_resolver.clone())).await)
            } else {
                None
            },
            fallback_domain_filters: if cfg.fallback_filter.domain.len() > 0 {
                Some(vec![Box::new(DomainFilter::new(
                    cfg.fallback_filter
                        .domain
                        .iter()
                        .map(|x| x.as_str())
                        .collect(),
                )) as Box<dyn FallbackDomainFilter>])
            } else {
                None
            },
            fallback_ip_filters: if cfg.fallback_filter.ip_cidr.is_some()
                || cfg.fallback_filter.geo_ip
            {
                let mut filters = vec![];

                filters.push(Box::new(GeoIPFilter::new(&cfg.fallback_filter.geo_ip_code))
                    as Box<dyn FallbackIPFilter>);

                if let Some(ipcidr) = cfg.fallback_filter.ip_cidr {
                    for subnet in ipcidr {
                        filters
                            .push(Box::new(IPNetFilter::new(subnet)) as Box<dyn FallbackIPFilter>)
                    }
                }

                Some(filters)
            } else {
                None
            },
            group: Some(async_singleflight::Group::new()),
            lru_cache: Some(lru_cache::LruCache::new(4096)),
            policy: if cfg.nameserver_policy.len() > 0 {
                let mut p = trie::DomainTrie::new();
                for (domain, ns) in cfg.nameserver_policy {
                    p.insert(
                        domain.as_str(),
                        Arc::new(
                            Resolver::make_clients(vec![ns], Some(default_resolver.clone())).await,
                        ),
                    );
                }
                Some(p)
            } else {
                None
            },
        };

        r
    }

    async fn make_clients(
        servers: Vec<NameServer>,
        resolver: Option<Arc<dyn ClashResolver>>,
    ) -> Vec<Box<dyn Client>> {
        let mut rv = Vec::new();

        for s in servers {
            match s.net.as_str() {
                "https" => todo!(),
                "dhcp" => todo!(),
                _ => {
                    let port = s.address.split(":").last().unwrap();
                    let host = s.address.strip_suffix(port).unwrap();

                    if let Ok(c) = DnsClient::new(Opts {
                        r: resolver.as_ref().map(|x| x.clone()),
                        host: host.to_string(),
                        port: port.parse::<u16>().unwrap(),
                        net: s.net,
                        iface: s.interface.map(|iface| {
                            net::SocketAddr::new(
                                get_if_addrs::get_if_addrs()
                                    .ok()
                                    .expect("failed to lookup local ip")
                                    .into_iter()
                                    .find(|x| x.name == iface)
                                    .map(|x| x.addr.ip())
                                    .expect("no ip address on interface"),
                                0,
                            )
                        }),
                    })
                    .await
                    {
                        rv.push(Box::new(c) as Box<dyn Client>);
                    }
                }
            }
        }

        rv
    }
}
