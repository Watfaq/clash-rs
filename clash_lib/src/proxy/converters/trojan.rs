use tracing::warn;

use crate::{
    Error,
    config::internal::proxy::OutboundTrojan,
    proxy::{
        HandlerCommonOptions, transport,
        trojan::{Handler, HandlerOptions},
    },
};

impl TryFrom<OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTrojan) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundTrojan> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundTrojan) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        let h = Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            sni: s
                .sni
                .as_ref()
                .map(|x| x.to_owned())
                .unwrap_or(s.common_opts.server.to_owned()),
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
                            let path = x
                                .path
                                .as_ref()
                                .map(|x| x.to_owned())
                                .unwrap_or_default();
                            let headers = x
                                .headers
                                .as_ref()
                                .map(|x| x.to_owned())
                                .unwrap_or_default();
                            let max_early_data =
                                x.max_early_data.unwrap_or_default() as usize;
                            let early_data_header_name = x
                                .early_data_header_name
                                .as_ref()
                                .map(|x| x.to_owned())
                                .unwrap_or_default();

                            let client = transport::WsClient::new(
                                s.common_opts.server.to_owned(),
                                s.common_opts.port,
                                path,
                                headers,
                                None,
                                max_early_data,
                                early_data_header_name,
                            );
                            Box::new(client) as _
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client = transport::GrpcClient::new(
                                s.sni
                                    .as_ref()
                                    .unwrap_or(&s.common_opts.server)
                                    .to_owned(),
                                x.grpc_service_name
                                    .as_ref()
                                    .map(|x| x.to_owned())
                                    .unwrap_or_default()
                                    .try_into()
                                    .expect("invalid gRPC service path"),
                            );
                            Box::new(client) as _
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
