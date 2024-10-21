use std::{future::Future, net::IpAddr};

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        RData, Record,
    },
};

use tracing::{debug, error};
use watfaq_dns::DNSListenAddr;

use crate::Runner;

use super::ThreadSafeDNSResolver;

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

struct DnsMessageExchanger {
    resolver: ThreadSafeDNSResolver,
}

impl watfaq_dns::DnsMessageExchanger for DnsMessageExchanger {
    fn ipv6(&self) -> bool {
        self.resolver.ipv6()
    }

    fn exchange(
        &self,
        message: &Message,
    ) -> impl Future<Output = Result<Message, watfaq_dns::DNSError>> + Send {
        async {
            if self.resolver.fake_ip_enabled() {
                let name = message
                    .query()
                    .ok_or(watfaq_dns::DNSError::InvalidOpQuery(
                        "malformed query message".to_string(),
                    ))?
                    .name();

                let host = message
                    .query()
                    .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
                    .unwrap();

                let mut message = Message::new();
                message.set_recursion_available(false);
                message.set_authoritative(true);

                match self.resolver.resolve(&host, true).await {
                    Ok(resp) => match resp {
                        Some(ip) => {
                            let rdata = match ip {
                                IpAddr::V4(a) => RData::A(A(a)),
                                IpAddr::V6(aaaa) => RData::AAAA(AAAA(aaaa)),
                            };

                            let records = vec![Record::from_rdata(
                                name.clone(),
                                DEFAULT_DNS_SERVER_TTL,
                                rdata,
                            )];

                            message.set_response_code(ResponseCode::NoError);
                            message.set_answer_count(records.len() as u16);

                            message.add_answers(records);

                            return Ok(message);
                        }
                        None => {
                            message.set_response_code(ResponseCode::NXDomain);
                            return Ok(message);
                        }
                    },
                    Err(e) => {
                        debug!("dns resolve error: {}", e);
                        return Err(watfaq_dns::DNSError::QueryFailed(
                            e.to_string(),
                        ));
                    }
                }
            }
            match self.resolver.exchange(message).await {
                Ok(m) => Ok(m),
                Err(e) => {
                    debug!("dns resolve error: {}", e);
                    Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
                }
            }
        }
    }
}

pub async fn get_dns_listener(
    listen: DNSListenAddr,
    resolver: ThreadSafeDNSResolver,
    cwd: &std::path::Path,
) -> Option<Runner> {
    let h = DnsMessageExchanger { resolver };
    let r = watfaq_dns::get_dns_listener(listen, h, cwd).await;
    if let Some(r) = r {
        Some(Box::pin(async move {
            match r.await {
                Ok(()) => Ok(()),
                Err(err) => {
                    error!("dns listener error: {}", err);
                    Err(err.into())
                }
            }
        }))
    } else {
        None
    }
}
