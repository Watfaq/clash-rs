use tracing::warn;

use crate::{
    config::internal::proxy::OutboundTrojan,
    proxy::{
        options::{GrpcOption, WsOption},
        trojan::{Handler, Opts, Transport},
        AnyOutboundHandler, CommonOption,
    },
    Error,
};

impl TryFrom<OutboundTrojan> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(value: OutboundTrojan) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTrojan> for AnyOutboundHandler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTrojan) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!("skipping TLS cert verification for {}", s.server);
        }

        let h = Handler::new(Opts {
            name: s.name.to_owned(),
            common_opts: CommonOption::default(),
            server: s.server.to_owned(),
            port: s.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            sni: s
                .sni
                .as_ref()
                .map(|x| x.to_owned())
                .unwrap_or(s.server.to_owned()),
            alpn: s.alpn.as_ref().map(|x| x.to_owned()),
            skip_cert_verify,
            transport: s
                .network
                .as_ref()
                .map(|x| match x.as_str() {
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            Transport::Ws(WsOption {
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
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            Transport::Grpc(GrpcOption {
                                host: s.sni.as_ref().unwrap_or(&s.server).to_owned(),
                                service_name: x
                                    .grpc_service_name
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or_default(),
                            })
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported trojan network: {}",
                        x
                    ))),
                })
                .transpose()?,
        });
        Ok(h)
    }
}
