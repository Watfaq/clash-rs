use tracing::warn;

use crate::{
    config::internal::proxy::OutboundAnytls,
    proxy::{
        HandlerCommonOptions,
        anytls::{Handler, HandlerOptions},
        transport::TlsClient,
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
        if s.fingerprint.is_some() || s.client_fingerprint.is_some() {
            warn!(
                "anytls fingerprint fields are parsed but not applied yet for {}",
                s.common_opts.name
            );
        }
        if s.idle_session_check_interval.is_some()
            || s.idle_session_timeout.is_some()
            || s.min_idle_session.is_some()
        {
            warn!(
                "anytls idle-session fields are parsed but not applied yet for {}",
                s.common_opts.name
            );
        }
        if s.udp.unwrap_or_default() {
            warn!(
                "anytls UDP outbound is not implemented yet for {}",
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
                let client = TlsClient::new(
                    skip_cert_verify,
                    s.sni
                        .as_ref()
                        .map(|x| x.to_owned())
                        .unwrap_or(s.common_opts.server.to_owned()),
                    s.alpn.clone().or(Some(
                        DEFAULT_ALPN
                            .iter()
                            .copied()
                            .map(|x| x.to_owned())
                            .collect::<Vec<String>>(),
                    )),
                    None,
                );
                Some(Box::new(client))
            },
            transport: None,
        }))
    }
}
