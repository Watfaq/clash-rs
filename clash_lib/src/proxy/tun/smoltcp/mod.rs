use std::sync::Arc;

use url::Url;

use crate::{
    app::{dispatcher::Dispatcher, dns::ThreadSafeDNSResolver},
    config::internal::config::TunConfig,
    Error, Runner,
};

pub fn get_runner(
    cfg: TunConfig,
    dispatcher: Arc<Dispatcher>,
    resolver: ThreadSafeDNSResolver,
) -> Result<Option<Runner>, Error> {
    let device_id = cfg.device_id;

    let u =
        Url::parse(&device_id).map_err(|x| Error::InvalidConfig(format!("tun device {}", x)))?;

    let device = match u.scheme() {
        "fd" => {
            let fd = u
                .host()
                .expect("tun fd must be provided")
                .to_string()
                .parse()
                .map_err(|x| Error::InvalidConfig(format!("tun fd {}", x)))?;
            TunTapInterface::from_fd(fd)?
        }
        "dev" => {
            let dev = u.host().expect("tun dev must be provided").to_string();
            tun_cfg.name(dev);
        }
        _ => {
            return Err(Error::InvalidConfig(format!(
                "invalid device id: {}",
                device_id
            )));
        }
    };
}
