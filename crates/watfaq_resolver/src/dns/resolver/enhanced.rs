use async_trait::async_trait;
use futures::{FutureExt, TryFutureExt};
use rand::seq::{IteratorRandom, SliceRandom as _};
use watfaq_state::Context;

use std::{
    net::{self, IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{debug, error, instrument, trace, warn};
use watfaq_error::anyhow;
use watfaq_types::{DNSMode, StackPrefer, StringTrie};
use watfaq_utils::Mmdb;

use hickory_proto::{op, rr};

use crate::{
    AbstractResolver, DnsClient,
    dns::{
        DnsConfig,
        fakeip::{self, InMemStore, ThreadSafeFakeDns},
        filters::{
            DomainFilter, FallbackDomainFilter, FallbackIPFilter, GeoIPFilter,
            IPNetFilter,
        },
        helper::build_dns_clients,
    },
};
use watfaq_error::Result;

use super::{SystemResolver, batch_exchange};

static TTL: Duration = Duration::from_secs(60);

pub struct EnhancedResolver {
    ipv6: AtomicBool,
    hosts: Option<StringTrie<net::IpAddr>>,
    main: Vec<DnsClient>,

    fallback: Option<Vec<DnsClient>>,
    fallback_domain_filters: Option<Vec<Box<dyn FallbackDomainFilter>>>,
    fallback_ip_filters: Option<Vec<Box<dyn FallbackIPFilter>>>,

    lru_cache: Option<Arc<RwLock<lru_time_cache::LruCache<String, op::Message>>>>,
    policy: Option<StringTrie<Vec<DnsClient>>>,

    fake_dns: Option<ThreadSafeFakeDns>,

    reverse_lookup_cache:
        Option<Arc<RwLock<lru_time_cache::LruCache<net::IpAddr, String>>>>,
    ctx: Arc<Context>,
}

impl EnhancedResolver {
    /// For testing purpose
    #[cfg(test)]
    pub async fn new_default() -> Self {
        use crate::dns::{
            config::NameServer, dns_client::DNSNetMode, helper::build_dns_clients,
            resolver::dummy::DummyResolver,
        };

        EnhancedResolver {
            ipv6: AtomicBool::new(false),
            hosts: None,
            main: build_dns_clients(
                vec![NameServer {
                    net: DNSNetMode::Udp,
                    address: "8.8.8.8:53".to_string(),
                    opts: None,
                }],
                &DummyResolver.into(),
            )
            .await,
            fallback: None,
            fallback_domain_filters: None,
            fallback_ip_filters: None,
            lru_cache: None,
            policy: None,

            fake_dns: None,

            reverse_lookup_cache: None,
            ctx: Context::new_test().into(),
        }
    }

    pub async fn new(
        ctx: Arc<Context>,
        cfg: DnsConfig,
        mmdb: Arc<Mmdb>,
    ) -> Result<Self> {
        let dummy_resolver = SystemResolver::new(false)?.into();
        let default_resolver = Arc::new(
            EnhancedResolver {
                ipv6: AtomicBool::new(false),
                hosts: None,
                main: build_dns_clients(
                    cfg.default_nameserver.clone(),
                    &dummy_resolver,
                )
                .await,
                fallback: None,
                fallback_domain_filters: None,
                fallback_ip_filters: None,
                lru_cache: None,
                policy: None,

                fake_dns: None,

                reverse_lookup_cache: None,
                ctx: ctx.clone(),
            }
            .into(),
        );

        let res = Self {
            ipv6: AtomicBool::new(cfg.ipv6),
            main: build_dns_clients(cfg.nameserver.clone(), &default_resolver).await,
            hosts: cfg.hosts,
            fallback: if !cfg.fallback.is_empty() {
                Some(
                    build_dns_clients(cfg.fallback.clone(), &default_resolver).await,
                )
            } else {
                None
            },
            fallback_domain_filters: if !cfg.fallback_filter.domain.is_empty() {
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

                filters.push(Box::new(GeoIPFilter::new(
                    &cfg.fallback_filter.geo_ip_code,
                    mmdb,
                )) as Box<dyn FallbackIPFilter>);

                if let Some(ipcidr) = &cfg.fallback_filter.ip_cidr {
                    for subnet in ipcidr {
                        filters.push(Box::new(IPNetFilter::new(*subnet))
                            as Box<dyn FallbackIPFilter>)
                    }
                }

                Some(filters)
            } else {
                None
            },
            lru_cache: Some(Arc::new(RwLock::new(
                lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                    TTL, 4096,
                ),
            ))),
            policy: if !cfg.nameserver_policy.is_empty() {
                let mut p = StringTrie::new();
                for (domain, ns) in &cfg.nameserver_policy {
                    p.insert(
                        domain.as_str(),
                        Arc::new(
                            build_dns_clients(
                                vec![ns.to_owned()],
                                &default_resolver,
                            )
                            .await,
                        ),
                    );
                }
                Some(p)
            } else {
                None
            },
            fake_dns: match cfg.enhance_mode {
                DNSMode::FakeIp => Some(Arc::new(RwLock::new(
                    fakeip::FakeDns::new(fakeip::Opts {
                        ipnet: cfg.fake_ip_range,
                        skipped_hostnames: if !cfg.fake_ip_filter.is_empty() {
                            let mut host = StringTrie::new();
                            for domain in cfg.fake_ip_filter.iter() {
                                host.insert(domain.as_str(), Arc::new(true));
                            }
                            Some(host)
                        } else {
                            None
                        },
                        store: if cfg.store_fake_ip {
                            Box::new(InMemStore::new(1000))
                        } else {
                            Box::new(InMemStore::new(1000))
                        },
                    })
                    .unwrap(),
                ))),
                DNSMode::RedirHost => {
                    warn!(
                        "dns redir-host is not supported and will not do anything"
                    );
                    None
                }
                _ => None,
            },

            reverse_lookup_cache: Some(Arc::new(RwLock::new(
                lru_time_cache::LruCache::with_expiry_duration_and_capacity(
                    Duration::from_secs(3), /* should be shorter than TTL so
                                             * client won't be connecting to a
                                             * different server after the ip is
                                             * reverse mapped to hostname and
                                             * being resolved again */
                    4096,
                ),
            ))),
            ctx,
        };
        Ok(res)
    }

    /// guaranteed to return at least 1 IP address when Ok
    async fn lookup_ip(
        &self,
        host: &str,
        record_type: rr::record_type::RecordType,
    ) -> Result<Vec<net::IpAddr>> {
        let mut m = op::Message::new();
        let mut q = op::Query::new();
        let name = rr::Name::from_str_relaxed(host)
            .map_err(|_| anyhow!("invalid domain: {}", host))?
            .append_domain(&rr::Name::root())?; // makes it FQDN
        q.set_name(name);
        q.set_query_type(record_type);
        m.add_query(q);
        m.set_recursion_desired(true);

        match self.exchange(&m).await {
            Ok(result) => {
                let ip_list = EnhancedResolver::ip_list_of_message(&result);
                if !ip_list.is_empty() {
                    Ok(ip_list)
                } else {
                    Err(anyhow!("no record for hostname: {}", host))
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn exchange(&self, message: &op::Message) -> Result<op::Message> {
        if let Some(q) = message.query() {
            if let Some(lru) = &self.lru_cache {
                if let Some(cached) = lru.read().await.peek(q.to_string().as_str()) {
                    trace!("dns query {} hit lru cache", q.to_string());
                    let mut cached = cached.clone();
                    cached.set_id(message.id());
                    return Ok(cached);
                }
            }
            self.exchange_no_cache(message).await
        } else {
            Err(anyhow!("invalid query"))
        }
    }

    async fn exchange_no_cache(&self, message: &op::Message) -> Result<op::Message> {
        let q = message.query().unwrap();

        let query = async move {
            if EnhancedResolver::is_ip_request(q) {
                return self.ip_exchange(message).await;
            }

            if let Some(matched) = self.match_policy(message) {
                return batch_exchange(matched, message).await;
            }

            batch_exchange(&self.main, message).await
        };

        let rv = query.await;

        if let Ok(msg) = &rv {
            if let Some(lru) = &self.lru_cache {
                if !(q.query_type() == rr::RecordType::TXT
                    && q.name().to_ascii().starts_with("_acme-challenge."))
                {
                    // TODO: make this TTL wired to LRU cache
                    #[allow(unused_variables)]
                    let ttl = if msg.answer_count() != 0 {
                        msg.answers()
                            .iter()
                            .map(|x| x.ttl())
                            .min()
                            .unwrap_or_default()
                    } else if msg.name_server_count() != 0 {
                        msg.name_servers()
                            .iter()
                            .map(|x| x.ttl())
                            .min()
                            .unwrap_or_default()
                    } else {
                        msg.additionals()
                            .iter()
                            .map(|x| x.ttl())
                            .min()
                            .unwrap_or_default()
                    };

                    lru.write().await.insert(q.to_string(), msg.clone());
                }
            }
        }

        rv
    }

    fn match_policy(&self, m: &op::Message) -> Option<&Vec<DnsClient>> {
        if let (Some(_fallback), Some(_fallback_domain_filters), Some(policy)) =
            (&self.fallback, &self.fallback_domain_filters, &self.policy)
        {
            if let Some(domain) = EnhancedResolver::domain_name_of_message(m) {
                return policy.search(&domain).map(|n| n.get_data().unwrap());
            }
        }
        None
    }

    async fn ip_exchange(&self, message: &op::Message) -> Result<op::Message> {
        if let Some(matched) = self.match_policy(message) {
            return batch_exchange(matched, message).await;
        }

        if self.should_only_query_fallback(message) {
            // self.fallback guaranteed in the above check
            return batch_exchange(self.fallback.as_ref().unwrap(), message).await;
        }

        let main_query = batch_exchange(&self.main, message);

        if self.fallback.is_none() {
            return main_query.await;
        }

        let fallback_query =
            batch_exchange(self.fallback.as_ref().unwrap(), message);

        if let Ok(main_result) = main_query.await {
            let ip_list = EnhancedResolver::ip_list_of_message(&main_result);
            if !ip_list.is_empty() {
                // TODO: only check 1st?
                if !self.should_ip_fallback(&ip_list[0]) {
                    return Ok(main_result);
                }
            }
        }

        fallback_query.await
    }

    fn should_only_query_fallback(&self, message: &op::Message) -> bool {
        if let (Some(_), Some(fallback_domain_filters)) =
            (&self.fallback, &self.fallback_domain_filters)
        {
            if let Some(domain) = EnhancedResolver::domain_name_of_message(message) {
                for f in fallback_domain_filters.iter() {
                    if f.apply(domain.as_str()) {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn should_ip_fallback(&self, ip: &net::IpAddr) -> bool {
        if let Some(filers) = &self.fallback_ip_filters {
            for f in filers.iter() {
                if f.apply(ip) {
                    return true;
                }
            }
        }
        false
    }

    // helpers
    fn is_ip_request(q: &op::Query) -> bool {
        q.query_class() == rr::DNSClass::IN
            && (q.query_type() == rr::RecordType::A
                || q.query_type() == rr::RecordType::AAAA)
    }

    fn domain_name_of_message(m: &op::Message) -> Option<String> {
        m.query()
            .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
    }

    pub(crate) fn ip_list_of_message(m: &op::Message) -> Vec<net::IpAddr> {
        m.answers()
            .iter()
            .filter(|r| {
                r.record_type() == rr::RecordType::A
                    || r.record_type() == rr::RecordType::AAAA
            })
            .map(|r| match r.data() {
                rr::RData::A(v4) => net::IpAddr::V4(**v4),
                rr::RData::AAAA(v6) => net::IpAddr::V6(**v6),
                _ => unreachable!("should be only A/AAAA"),
            })
            .collect()
    }

    async fn save_reverse_lookup(&self, ip: net::IpAddr, domain: String) {
        if let Some(lru) = &self.reverse_lookup_cache {
            trace!("reverse lookup cache insert: {} -> {}", ip, domain);
            lru.write().await.insert(ip, domain);
        }
    }
}

impl AbstractResolver for EnhancedResolver {
    #[instrument(skip(self))]
    async fn resolve(
        &self,
        host: &str,
        enhanced: bool,
    ) -> Result<(Option<Ipv4Addr>, Option<Ipv6Addr>)> {
        if enhanced
            && let Some(hosts) = &self.hosts
            && let Some(ip) = hosts.search(host)
        {
            match ip.get_data() {
                Some(IpAddr::V4(v4)) => return Ok((Some(*v4), None)),
                Some(IpAddr::V6(v6)) => return Ok((None, Some(*v6))),
                None => {}
            }
        }
        if let Ok(ip) = host.parse::<net::IpAddr>() {
            match ip {
                IpAddr::V4(v4) => return Ok((Some(v4), None)),
                IpAddr::V6(v6) => return Ok((None, Some(v6))),
            }
        }

        if enhanced
            && self.fake_ip_enabled()
            && let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await
            && !fake_dns.should_skip(host)
        {
            let ip = fake_dns.lookup(host).await;
            debug!("fake dns lookup: {} -> {:?}", host, ip);
            match ip {
                IpAddr::V4(v4) => return Ok((Some(v4), None)),
                IpAddr::V6(v6) => return Ok((None, Some(v6))),
            }
        }
        let fut1 = self.lookup_ip(host, rr::RecordType::A);
        let fut2 = self.lookup_ip(host, rr::RecordType::AAAA);
        let (res_v4, res_v6) = tokio::join!(fut1, fut2);
        let res_v4 = res_v4?
            .into_iter()
            .filter_map(|v| match v {
                IpAddr::V4(addr) => Some(addr),
                IpAddr::V6(_) => None,
            })
            .choose(&mut rand::thread_rng());
        let res_v6 = res_v6?
            .into_iter()
            .filter_map(|v| match v {
                IpAddr::V4(_) => None,
                IpAddr::V6(addr) => Some(addr),
            })
            .choose(&mut rand::thread_rng());
        if res_v4.is_none() && res_v6.is_none() {
            Err(anyhow!("can't resolve default DNS: {host}"))
        } else {
            Ok((res_v4, res_v6))
        }
    }

    async fn cached_for(&self, ip: net::IpAddr) -> Option<String> {
        if let Some(lru) = &self.reverse_lookup_cache {
            if let Some(cached) = lru.read().await.peek(&ip) {
                trace!("reverse lookup cache hit: {} -> {}", ip, cached);
                return Some(cached.clone());
            }
        }

        None
    }

    async fn exchange(&self, message: &op::Message) -> Result<op::Message> {
        let rv = self.exchange(message).await?;
        let hostname = message
            .query()
            .unwrap()
            .name()
            .to_utf8()
            .trim_end_matches('.')
            .to_owned();
        let ip_list = EnhancedResolver::ip_list_of_message(&rv);
        if !ip_list.is_empty() {
            for ip in ip_list {
                self.save_reverse_lookup(ip, hostname.clone()).await;
            }
        }
        Ok(rv)
    }

    fn stack_prefer(&self) -> StackPrefer {
        todo!()
    }

    fn fake_ip_enabled(&self) -> bool {
        self.fake_dns.is_some()
    }

    async fn is_fake_ip(&self, ip: std::net::IpAddr) -> bool {
        if !self.fake_ip_enabled() {
            return false;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        fake_dns.is_fake_ip(ip).await
    }

    async fn reverse_lookup(&self, ip: net::IpAddr) -> Option<String> {
        debug!("reverse lookup: {}", ip);
        if !self.fake_ip_enabled() {
            return None;
        }

        let mut fake_dns = self.fake_dns.as_ref().unwrap().write().await;
        fake_dns.reverse_lookup(ip).await
    }

    fn ctx(&self) -> Arc<Context> {
        todo!()
    }

    fn set_stack_perfer(&self, prefer: StackPrefer) {
        todo!()
    }
}
