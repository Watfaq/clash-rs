use super::DEFAULT_DNS_SERVER_TTL;
use crate::app::dns::{ThreadSafeDNSResolver, helper::build_dns_response_message};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, rdata::A},
};
use tracing::debug;

pub async fn exchange_with_resolver<'a>(
    resolver: &'a ThreadSafeDNSResolver,
    req: &'a Message,
    enhanced: bool,
) -> Result<Message, watfaq_dns::DNSError> {
    if req.queries.first().map(|q| q.query_type())
        == Some(hickory_proto::rr::RecordType::AAAA)
        || !resolver.fake_ip_enabled()
    {
        return match resolver.exchange(req).await {
            Ok(m) => Ok(m),
            Err(e) => {
                debug!("dns resolve error: {}", e);
                Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
            }
        };
    }

    let name = req
        .queries
        .first()
        .ok_or(watfaq_dns::DNSError::InvalidOpQuery(
            "malformed query message".to_string(),
        ))?
        .name()
        .clone();

    let host = req
        .queries
        .first()
        .map(|x| x.name().to_ascii().trim_end_matches('.').to_owned())
        .unwrap();

    let mut res = build_dns_response_message(req, false, false);

    match resolver.resolve_v4(&host, enhanced).await {
        Ok(resp) => match resp {
            Some(ip) => {
                let rdata = RData::A(A(ip));

                let records =
                    vec![Record::from_rdata(name, DEFAULT_DNS_SERVER_TTL, rdata)];

                res.metadata.response_code = ResponseCode::NoError;
                res.add_answers(records);

                Ok(res)
            }
            None => {
                res.metadata.response_code = ResponseCode::NXDomain;
                Ok(res)
            }
        },
        Err(e) => {
            debug!("dns resolve error: {}", e);
            Err(watfaq_dns::DNSError::QueryFailed(e.to_string()))
        }
    }
}
