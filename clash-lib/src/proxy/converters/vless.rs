use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use tracing::warn;

use crate::{
    Error,
    config::internal::proxy::OutboundVless,
    proxy::{
        HandlerCommonOptions,
        transport::{GrpcClient, H2Client, RealityClient, TlsClient, WsClient},
        vless::{Handler, HandlerOptions},
    },
};

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

        let tls: Option<Box<dyn crate::proxy::transport::Transport>> = if let Some(
            reality_opts,
        ) =
            &s.reality_opts
        {
            if s.skip_cert_verify.unwrap_or_default() {
                warn!(
                    "skip-cert-verify is ignored when reality-opts is set for {}",
                    s.common_opts.name
                );
            }
            let client_fingerprint = s.client_fingerprint.clone();
            if let Some(fp) = client_fingerprint.as_deref() {
                watfaq_rustls::client::ClientFingerprint::from_name(fp).map_err(
                    |e| {
                        Error::InvalidConfig(format!(
                            "reality client-fingerprint: {e}"
                        ))
                    },
                )?;
            }
            let pk_bytes: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&reality_opts.public_key)
                .map_err(|e| {
                    Error::InvalidConfig(format!("reality public-key base64: {e}"))
                })?
                .try_into()
                .map_err(|_| {
                    Error::InvalidConfig(
                        "reality public-key must decode to 32 bytes".into(),
                    )
                })?;
            let short_id = hex::decode(&reality_opts.short_id).map_err(|e| {
                Error::InvalidConfig(format!("reality short-id hex: {e}"))
            })?;
            let sni = s
                .server_name
                .clone()
                .unwrap_or_else(|| s.common_opts.server.clone());
            let alpn = s
                .network
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
                .transpose()?;
            Some(Box::new(RealityClient::new(
                sni,
                pk_bytes,
                short_id,
                alpn,
                client_fingerprint,
            )) as _)
        } else {
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
    use crate::config::internal::proxy::{CommonConfigOptions, RealityOpt};

    fn base_config() -> OutboundVless {
        OutboundVless {
            common_opts: CommonConfigOptions {
                name: "test".to_string(),
                server: "example.com".to_string(),
                port: 443,
                ..Default::default()
            },
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".to_string(),
            udp: Some(true),
            tls: None,
            skip_cert_verify: None,
            server_name: None,
            network: None,
            ws_opts: None,
            h2_opts: None,
            grpc_opts: None,
            reality_opts: None,
            flow: None,
            client_fingerprint: None,
        }
    }

    #[test]
    fn test_vless_network_tcp() {
        let config = OutboundVless {
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            network: Some("tcp".to_string()),
            ..base_config()
        };
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn test_vless_network_none() {
        let config = OutboundVless {
            tls: Some(true),
            skip_cert_verify: Some(true),
            server_name: Some("example.com".to_string()),
            ..base_config()
        };
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn test_vless_network_invalid() {
        let config = OutboundVless {
            network: Some("invalid-network".to_string()),
            ..base_config()
        };
        let err = Handler::try_from(&config).unwrap_err();
        assert!(err.to_string().contains("unsupported network"));
    }

    #[test]
    fn test_vless_reality_valid() {
        // Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs decodes to 32 bytes
        let config = OutboundVless {
            reality_opts: Some(RealityOpt {
                public_key: "Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs"
                    .to_string(),
                short_id: "1bc2c1ef1c".to_string(),
            }),
            server_name: Some("www.microsoft.com".to_string()),
            ..base_config()
        };
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn test_vless_reality_bad_pubkey_base64() {
        let config = OutboundVless {
            reality_opts: Some(RealityOpt {
                public_key: "not!valid!base64!!!".to_string(),
                short_id: "1bc2c1ef1c".to_string(),
            }),
            ..base_config()
        };
        let err = Handler::try_from(&config).unwrap_err();
        assert!(err.to_string().contains("reality public-key base64"));
    }

    #[test]
    fn test_vless_reality_pubkey_wrong_length() {
        // "AAAA" decodes to 3 bytes, not 32
        let config = OutboundVless {
            reality_opts: Some(RealityOpt {
                public_key: "AAAA".to_string(),
                short_id: "1bc2c1ef1c".to_string(),
            }),
            ..base_config()
        };
        let err = Handler::try_from(&config).unwrap_err();
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn test_vless_reality_bad_short_id_hex() {
        let config = OutboundVless {
            reality_opts: Some(RealityOpt {
                public_key: "Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs"
                    .to_string(),
                short_id: "not-hex!!".to_string(),
            }),
            ..base_config()
        };
        let err = Handler::try_from(&config).unwrap_err();
        assert!(err.to_string().contains("reality short-id hex"));
    }

    #[test]
    fn test_vless_reality_bad_client_fingerprint() {
        let config = OutboundVless {
            reality_opts: Some(RealityOpt {
                public_key: "Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs"
                    .to_string(),
                short_id: "1bc2c1ef1c".to_string(),
            }),
            client_fingerprint: Some("not-a-fingerprint".to_string()),
            ..base_config()
        };
        let err = Handler::try_from(&config).unwrap_err();
        assert!(err.to_string().contains("reality client-fingerprint"));
    }

    #[test]
    fn test_vless_reality_overrides_tls() {
        // When reality_opts is set, TlsClient should NOT be constructed
        // (we use RealityClient instead, tls: true is irrelevant)
        let config = OutboundVless {
            tls: Some(true),
            reality_opts: Some(RealityOpt {
                public_key: "Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs"
                    .to_string(),
                short_id: "1bc2c1ef1c".to_string(),
            }),
            server_name: Some("www.microsoft.com".to_string()),
            ..base_config()
        };
        // Should succeed (RealityClient replaces TlsClient)
        assert!(Handler::try_from(&config).is_ok());
    }

    #[test]
    fn test_vless_reality_with_flow() {
        let config = OutboundVless {
            reality_opts: Some(RealityOpt {
                public_key: "Vc8ycAgKqfRvtXjvGP0ry_U91o5wgrQlqOhHq72HYRs"
                    .to_string(),
                short_id: "1bc2c1ef1c".to_string(),
            }),
            server_name: Some("www.microsoft.com".to_string()),
            flow: Some("xtls-rprx-vision".to_string()),
            ..base_config()
        };
        assert!(Handler::try_from(&config).is_ok());
    }
}
