use std::future::Future;

use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, rdata::A},
};
use tracing::debug;

use crate::app::dns::ThreadSafeDNSResolver;

use super::DEFAULT_DNS_SERVER_TTL;

pub fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a Message,
    enhanced: bool,
) -> impl Future<Output = Result<Message, watfaq_dns::DNSError>> + use<'a> {
    async move {
        if resolver.fake_ip_enabled() {
            let name = req
                .query()
                .ok_or(watfaq_dns::DNSError::InvalidOpQuery(
                    "malformed query message".to_string(),
                ))?
                .name();

            let host = req
                .query()
                .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
                .unwrap();

            let mut res = Message::new();
            res.set_id(req.id());
            res.set_message_type(hickory_proto::op::MessageType::Response);
            res.add_queries(req.queries().iter().map(|x| x.to_owned()));
            res.set_recursion_available(false);
            res.set_authoritative(true);
            res.set_recursion_desired(req.recursion_desired());
            res.set_checking_disabled(req.checking_disabled());
            if let Some(edns) = req.extensions().clone() {
                res.set_edns(edns);
            }

            match resolver.resolve_v4(&host, enhanced).await {
                Ok(resp) => match resp {
                    Some(ip) => {
                        let rdata = RData::A(A(ip));

                        let records = vec![Record::from_rdata(
                            name.clone(),
                            DEFAULT_DNS_SERVER_TTL,
                            rdata,
                        )];

                        res.set_response_code(ResponseCode::NoError);
                        res.set_answer_count(records.len() as u16);

                        res.add_answers(records);

                        return Ok(res);
                    }
                    None => {
                        res.set_response_code(ResponseCode::NXDomain);
                        return Ok(res);
                    }
                },
                Err(e) => {
                    debug!("dns resolve error: {}", e);
                    return Err(watfaq_dns::DNSError::QueryFailed(e.to_string()));
                }
            }
        }
        match resolver.exchange(req).await {
            Ok(m) => Ok(m),
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
            }
        }
    }
}
