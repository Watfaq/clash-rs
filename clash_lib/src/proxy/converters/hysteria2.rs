use std::sync::Arc;

use crate::{
    config::internal::proxy::OutboundHysteria2,
    proxy::{
        hysteria2::{HystClient, HystOption},
        AnyOutboundHandler,
    },
    session::SocksAddr,
};

impl TryFrom<OutboundHysteria2> for AnyOutboundHandler {
    type Error = crate::Error;
    fn try_from(value: OutboundHysteria2) -> Result<Self, Self::Error> {
        let addr = SocksAddr::try_from((value.server, value.port))?;
        let obfs_passwd = match value.obfs {
            Some(_) => value
                .obfs_password
                .ok_or(crate::Error::InvalidConfig(
                    "hysteria2 found obfs enable, but obfs password is none".to_owned(),
                ))?
                .into(),
            None => None,
        };

        let opts = HystOption {
            sni: value.sni.or(addr.domain().map(|s| s.to_owned())),
            addr,
            alpn: value.alpn.unwrap_or_default(),
            ca: value.ca.map(|s| s.into()),
            fingerprint: value.fingerprint,
            skip_cert_verify: value.skip_cert_verify,
            passwd: value.password,
            ports: value.ports,
            salamander: obfs_passwd,
            up_down: value.up.zip(value.down),
            ca_str: value.ca_str,
            cwnd: value.cwnd,
        };

        let c = HystClient::new(opts).unwrap();
        Ok(Arc::new(c))
    }
}
