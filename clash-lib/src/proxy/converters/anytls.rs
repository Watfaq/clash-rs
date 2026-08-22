use tracing::warn;

use crate::{
    common::tls_fingerprint::parse_client_fingerprint,
    config::internal::proxy::OutboundAnytls,
    proxy::{
        HandlerCommonOptions,
        anytls::{Handler, HandlerOptions},
        transport::{TlsClient, TransportLayer},
    },
};

const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

impl TryFrom<OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundAnytls) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundAnytls> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundAnytls) -> Result<Self, Self::Error> {
        let skip_cert_verify = s.skip_cert_verify.unwrap_or_default();
        if skip_cert_verify {
            warn!(
                "skipping TLS cert verification for {}",
                s.common_opts.server
            );
        }
        // `fingerprint` pins the server certificate and is a different thing
        // from `client-fingerprint`, which shapes our own hello. The first is
        // still unimplemented here; the second is applied below.
        if s.fingerprint.is_some() {
            warn!(
                "anytls certificate fingerprint pinning is parsed but not applied \
                 yet for {}",
                s.common_opts.name
            );
        }
        let client_fingerprint = s
            .client_fingerprint
            .as_deref()
            .map(|value| parse_client_fingerprint(value, &s.common_opts.name));
        if s.idle_session_check_interval.is_some()
            || s.idle_session_timeout.is_some()
            || s.min_idle_session.is_some()
        {
            warn!(
                "anytls idle-session fields are parsed but not applied yet for {}",
                s.common_opts.name
            );
        }
        Ok(Handler::new(HandlerOptions {
            name: s.common_opts.name.to_owned(),
            common_opts: HandlerCommonOptions {
                connector: s.common_opts.connect_via.clone(),
                ..Default::default()
            },
            server: s.common_opts.server.to_owned(),
            port: s.common_opts.port,
            password: s.password.clone(),
            udp: s.udp.unwrap_or_default(),
            tls: {
                let client = TlsClient::new_with_fingerprint(
                    skip_cert_verify,
                    s.sni
                        .clone()
                        .unwrap_or_else(|| s.common_opts.server.clone()),
                    s.alpn
                        .clone()
                        .or(Some(DEFAULT_ALPN.map(str::to_owned).to_vec())),
                    None,
                    s.tls_cert.as_deref(),
                    s.tls_key.as_deref(),
                    client_fingerprint,
                )?;
                Some(TransportLayer::Tls(client))
            },
            transport: None,
        }))
    }
}
