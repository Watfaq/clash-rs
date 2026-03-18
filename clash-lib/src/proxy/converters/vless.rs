use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::{
            GrpcClient, H2Client, RealityClient, TlsClient, Transport, WsClient,
        },
        vless::{Handler, HandlerOptions},
    },
};
use tracing::warn;

impl TryFrom<OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundVless) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundVless> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundVless) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }

        if s.client_fingerprint.is_some() {
            warn!(
                "client-fingerprint (uTLS) is not yet implemented, ignored for {}",
                s.common_opts.name
            );
        }

        let tls: Option<Box<dyn Transport>> = if let Some(ref reality_opts) =
            s.reality_opts
        {
            // vless with reality

            // reality public-key bytes
            let pk_bytes =
                super::utils::decode_base64_public_key(&reality_opts.public_key)?;

            // reality short id bytes
            let short_id = super::utils::decode_short_id(&reality_opts.short_id)?;

            // SNI
            let sni = s
                .server_name
                .clone()
                .unwrap_or_else(|| s.common_opts.server.clone());

            Some(Box::new(RealityClient::new(sni, pk_bytes, short_id)))
        } else {
            // vless without reality
            match s.tls.unwrap_or_default() {
                true => {
                    let client = TlsClient::new(
                        s.skip_cert_verify.unwrap_or_default(),
                        s.server_name.as_ref().map(|x| x.to_owned()).unwrap_or(
                            s.ws_opts
                                .as_ref()
                                .and_then(|x| {
                                    x.headers.clone().and_then(|x| {
                                        let h = x.get("Host");
                                        h.cloned()
                                    })
                                })
                                .unwrap_or(s.common_opts.server.to_owned()),
                        ),
                        s.network
                            .as_ref()
                            .map(|x| match x.as_str() {
                                "tcp" => Ok(vec![]),
                                "ws" => Ok(vec!["http/1.1".to_owned()]),
                                "http" => Ok(vec![]),
                                "h2" | "grpc" => Ok(vec!["h2".to_owned()]),
                                _ => Err(Error::InvalidConfig(format!(
                                    "unsupported network: {x}"
                                ))),
                            })
                            .transpose()?,
                        None,
                    );
                    Some(Box::new(client))
                }
                false => None,
            }
        };

        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            uuid: s.uuid.clone(),
            udp: s.udp.unwrap_or(true),
            transport: s
                .network
                .clone()
                .map(|x| match x.as_str() {
                    "tcp" => Ok(None),
                    "ws" => s
                        .ws_opts
                        .as_ref()
                        .map(|x| {
                            let client: WsClient = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid ws options");
                            Some(Box::new(client) as _)
                        })
                        .ok_or(Error::InvalidConfig(
                            "ws_opts is required for ws".to_owned(),
                        )),
                    "h2" => s
                        .h2_opts
                        .as_ref()
                        .map(|x| {
                            let client: H2Client = (x, &s.common_opts)
                                .try_into()
                                .expect("invalid h2 options");
                            Some(Box::new(client) as _)
                        })
                        .ok_or(Error::InvalidConfig(
                            "h2_opts is required for h2".to_owned(),
                        )),
                    "grpc" => s
                        .grpc_opts
                        .as_ref()
                        .map(|x| {
                            let client: GrpcClient =
                                (s.server_name.clone(), x, &s.common_opts)
                                    .try_into()
                                    .expect("invalid grpc options");
                            Some(Box::new(client) as _)
                        })
                        .ok_or(Error::InvalidConfig(
                            "grpc_opts is required for grpc".to_owned(),
                        )),
                    _ => Err(Error::InvalidConfig(format!(
                        "unsupported network: {x}"
                    ))),
                })
                .transpose()?
                .flatten(),
            tls,
            flow: s.flow.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::internal::proxy::CommonConfigOptions;

    #[test]
    fn test_vless_network_tcp() {
        // Test that network: tcp is accepted and results in successful parsing
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-tcp".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("tcp".to_string()),
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLess handler with network: tcp should parse successfully"
        );
    }

    #[test]
    fn test_vless_network_none() {
        // Test that omitting network field also results in successful parsing
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-none".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: None,
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_ok(),
            "VLess handler without network field should parse successfully"
        );
    }

    #[test]
    fn test_vless_network_invalid() {
        // Test that invalid network types are rejected
        let config = OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test-invalid".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "test-uuid".to_string(),
            udp: Some(true),
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("invalid-network".to_string()),
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            ..Default::default()
        };

        let handler = Handler::try_from(&config);
        assert!(
            handler.is_err(),
            "VLess handler with invalid network should fail"
        );
        let err = handler.unwrap_err();
        assert!(
            err.to_string().contains("unsupported network"),
            "Error should mention unsupported network"
        );
    }
}
