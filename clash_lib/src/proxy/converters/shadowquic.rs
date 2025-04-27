use shadowquic::config::{
    default_alpn, default_congestion_control, default_initial_mtu, default_min_mtu,
    default_over_stream, default_zero_rtt,
};

use crate::{
    config::proxy::OutboundShadowQuic,
    proxy::shadowquic::{Handler, HandlerOptions},
};

impl TryFrom<OutboundShadowQuic> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundShadowQuic) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OutboundShadowQuic> for Handler {
    type Error = crate::Error;

    fn try_from(s: &OutboundShadowQuic) -> Result<Self, Self::Error> {
        Ok(Handler::new(HandlerOptions {
            addr: format!(
                "{}:{}",
                s.common_opts.server.to_owned(),
                s.common_opts.port
            ),
            jls_pwd: s.jls_pwd.clone(),
            jls_iv: s.jls_iv.clone(),
            server_name: s.server_name.clone(),
            alpn: s.alpn.clone().unwrap_or(default_alpn()),
            initial_mtu: s.initial_mtu.unwrap_or(default_initial_mtu()),
            congestion_control: s
                .congestion_control
                .clone()
                .unwrap_or(default_congestion_control()),
            zero_rtt: s.zero_rtt.unwrap_or(default_zero_rtt()),
            over_stream: s.over_stream.unwrap_or(default_over_stream()),
            min_mtu: s.min_mtu.unwrap_or(default_min_mtu()),
        }))
    }
}
