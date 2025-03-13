use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{RData, Record, rdata::A},
};
use tracing::debug;

use crate::{AbstractResolver, Resolver};

static DEFAULT_DNS_SERVER_TTL: u32 = 60;

pub async fn exchange_with_resolver<'a>(
    resolver: &'a Resolver,
    req: &'a Message,
    enhanced: bool,
) -> Result<Message, watfaq_dns::DNSError> {
    // TODO maybe should move fakeip logic to somewhere else
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

        match resolver.resolve(&host, enhanced).await {
            Ok((Some(ip), _)) => {
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
            Ok(_) => {
                // FIXME not sure
                res.set_response_code(ResponseCode::NXDomain);
                return Ok(res);
            }
            Err(e) => {
                debug!("dns resolve error: {}", e);
                return Err(watfaq_dns::DNSError::QueryFailed(e.to_string()));
            }
        }
    }
    resolver.exchange(req).await.map_err(|e| {
        debug!("dns resolve error: {}", e);
        watfaq_dns::DNSError::QueryFailed(e.to_string())
    })
}
