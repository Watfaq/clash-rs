use tracing::warn;

use crate::{
    config::internal::proxy::OutboundVmess,
    proxy::{
        options::{GrpcOption, Http2Option, WsOption},
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
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: Default::default(),
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            alter_id: s.alter_id,
            security: s.cipher.clone().unwrap_or_default(),
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
                                path: x
                                    .path
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or_default(),
                                headers: x
                                    .headers
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or_default(),
                                max_early_data: x.max_early_data.unwrap_or_default()
                                    as usize,
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
                                host: x
                                    .host
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or(vec![s
                                        .common_opts
                                        .server
                                        .to_owned()]),
                                path: x
                                    .path
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or_default(),
                            })
                        })
                        .ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            VmessTransport::Grpc(GrpcOption {
                                host: s
                                    .server_name
                                    .as_ref()
                                    .unwrap_or(&s.common_opts.server)
                                    .to_owned(),
                                service_name: x
                                    .grpc_service_name
                                    .as_ref()
                                    .to_owned()
                                    .unwrap_or(&"GunService".to_owned())
                                    .to_owned(),
                            })
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {}",
                        x
                    ))),
                })
                .transpose()?,
            tls: match s.tls.unwrap_or_default() {
                true => Some(TLSOptions {
                    skip_cert_verify: s.skip_cert_verify.unwrap_or_default(),
                    sni: s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                        s.ws_opts
                            .as_ref()
                            .and_then(|x| {
                                x.headers.clone().and_then(|x| {
                                    let h = x.get("Host");
                                    h.cloned()
                                })
                            })
                            .unwrap_or(s.common_opts.server.to_owned())
                            .to_owned(),
                    ),
                    alpn: s
                        .network
                        .as_ref()
                        .map(|x| match x.as_str() {
                            "ws" => Ok(vec!["http/1.1".to_owned()]),
                            "http" => Ok(vec![]),
                            "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                            _ => Err(Error::InvalidConfig(format!(
                                "unsupported network: {}",
                                x
                            ))),
                        })
                        .transpose()?,
                }),
                false => None,
            },
        });
        Ok(h)
    }
}
