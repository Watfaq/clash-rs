use crate::{
    config::internal::proxy::OutboundVmess,
    proxy::{
        options::{Http2Option, WsOption},
        transport::TLSOptions,
        vmess::{Handler, HandlerOptions, VmessTransport},
        AnyOutboundHandler, CommonOption,
    },
    Error,
};

impl TryFrom<OutboundVmess> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundVmess) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVmess> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVmess) -> Result<Self, Self::Error> {
        let h = Handler::new(HandlerOptions {
            name: s.name.to_owned(),
            common_opts: CommonOption::default(),
            server: s.server.to_owned(),
            port: s.port,
            uuid: s.uuid.clone(),
            alter_id: s.alter_id,
            security: s.cipher.as_ref().map(Clone::clone).unwrap_or_default(),
            udp: s.udp.unwrap_or(true),
            transport: s
                .network
                .clone()
                .map(|x| match x.as_str() {
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            VmessTransport::Ws(WsOption {
                                path: x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default(),
                                headers: x
                                    .headers
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or_default(),
                                max_early_data: x.max_early_data.unwrap_or_default() as usize,
                                early_data_header_name: x
                                    .early_data_header_name
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or_default(),
                            })
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "h2" => s
                        .h2_opts
                        .as_ref()
                        .map(|x| {
                            VmessTransport::H2(Http2Option {
                                host: x.host.as_ref().map(|x| x.to_owned()).unwrap_or_default(),
                                path: x.path.as_ref().map(|x| x.to_owned()).unwrap_or_default(),
                            })
                        })
                        .ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        )),
                    _ => {
                        return Err(Error::InvalidConfig(format!("unsupported network: {}", x)));
                    }
                })
                .transpose()?,
            tls: match s.tls.unwrap_or_default() {
                true => Some(TLSOptions {
                    skip_cert_verify: s.skip_cert_verify.unwrap_or_default(),
                    sni: s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                        s.ws_opts
                            .as_ref()
                            .map(|x| {
                                x.headers
                                    .as_ref()
                                    .map(Clone::clone)
                                    .map(|x| {
                                        let h = x.get("Host");
                                        h.map(Clone::clone)
                                    })
                                    .flatten()
                            })
                            .flatten()
                            .unwrap_or(s.server.to_owned())
                            .to_owned(),
                    ),
                    alpn: s
                        .network
                        .as_ref()
                        .map(|x| match x.as_str() {
                            "ws" => Ok(vec!["http/1.1".to_owned()]),
                            "http" => Ok(vec![]),
                            "h2" => Ok(vec!["h2".to_owned()]),
                            _ => Err(Error::InvalidConfig(format!("unsupported network: {}", x))),
                        })
                        .transpose()?,
                }),
                false => None,
            },
        });
        Ok(h)
    }
}
