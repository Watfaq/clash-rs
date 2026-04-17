use crate::{
    config::internal::proxy::OutboundTailscale,
    proxy::tailscale::{Handler, HandlerOptions},
};
use tracing::warn;

impl TryFrom<OutboundTailscale> for Handler {
    type Error = crate::Error;

    fn try_from(value: OutboundTailscale) -> Result<Self, Self::Error> {
        if value.state_dir.is_some()
            || value.auth_key.is_some()
            || value.hostname.is_some()
            || value.control_url.is_some()
            || value.ephemeral
        {
            warn!(
                "tailscale config auth/runtime fields are parsed but tsnet auth bootstrap is not enabled in this build; {} will use host network tailscale state",
                value.name
            );
        }
        Ok(Handler::new(HandlerOptions {
            name: value.name,
            state_dir: value.state_dir,
            auth_key: value.auth_key,
            hostname: value.hostname,
            control_url: value.control_url,
            ephemeral: value.ephemeral,
        }))
    }
}
