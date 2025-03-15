use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

pub use crate::modules::error::ErrContext;
use network_interface::NetworkInterfaceConfig as _;
use tokio::net::TcpStream;

use crate::modules::{
    error::Result,
    state::Context,
    types::{DualIpAddr, Iface, Stack, StackPrefer, TargetStack},
};

pub fn which_ip_decision<T: Into<DualIpAddr>>(
    ctx: &Context,
    iface: Option<&Iface>,
    stack_prefer: Option<StackPrefer>,
    remote: T,
) -> Result<IpAddr> {
    let remote: DualIpAddr = remote.into();
    let iface = match iface {
        Some(v) => v,
        None => &ctx.default_iface.load(),
    };

    let stack_prefer = stack_prefer.unwrap_or_else(|| ctx.stack_prefer);
    let stack = which_stack_decision(iface, stack_prefer, &remote)?;
    match (stack, remote.v4, remote.v6) {
        (Stack::V4, Some(v4), _) => Ok(v4.into()),
        (Stack::V6, _, Some(v6)) => Ok(v6.into()),
        _ => unreachable!("pattern filtered in `which_stack_decision`"),
    }
}

pub fn which_stack_decision<T: Into<TargetStack>>(
    iface: &Iface,
    stack_prefer: StackPrefer,
    target: T,
) -> Result<Stack> {
    let (iface_v4, iface_v6) = (iface.ipv4.is_some(), iface.ipv6.is_some());
    let target: TargetStack = target.into();
    let (target_v4, target_v6) = (target.0, target.1);

    // Check for incompatible single stack scenarios
    match (iface_v4, iface_v6) {
        (true, false) if !target_v4 => {
            return Err(anyhow!(
                "Cannot dicide which stack to use, cause of interface{} only \
                 support v4 but target only support v6",
                iface.name
            ))?;
        }
        (false, true) if !target_v6 => {
            return Err(anyhow!(
                "Cannot dicide which stack to use, cause of interface{} only \
                 support v6 but target only support v4",
                iface.name
            ))?;
        }
        _ => (),
    }

    // Decision logic based on stack preference
    match stack_prefer {
        StackPrefer::V4 if iface_v4 && target_v4 => Ok(Stack::V4),
        StackPrefer::V6 if iface_v6 && target_v6 => Ok(Stack::V6),
        StackPrefer::V4V6 => {
            if iface_v4 && target_v4 {
                Ok(Stack::V4)
            } else if iface_v6 && target_v6 {
                Ok(Stack::V6)
            } else {
                unreachable!()
            }
        }

        StackPrefer::V6V4 => {
            if iface_v6 && target_v6 {
                Ok(Stack::V6)
            } else if iface_v4 && target_v4 {
                Ok(Stack::V4)
            } else {
                unreachable!()
            }
        }

        _ => unreachable!(),
    }
}
const DEFAULT_OUTBOUND_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SocketAddrArg(Option<SocketAddrV4>, Option<SocketAddrV6>);

impl From<&SocketAddrArg> for TargetStack {
    fn from(value: &SocketAddrArg) -> Self {
        Self(value.0.is_some(), value.1.is_some())
    }
}
impl From<(Option<Ipv4Addr>, Option<Ipv6Addr>, u16)> for SocketAddrArg {
    fn from(value: (Option<Ipv4Addr>, Option<Ipv6Addr>, u16)) -> Self {
        let v4 = value.0.map(|v| SocketAddrV4::new(v, value.2));
        let v6 = value.1.map(|v| SocketAddrV6::new(v, value.2, 0, 0));
        Self(v4, v6)
    }
}

pub async fn new_tcp(
    ctx: &Context,
    remote: SocketAddrArg,
) -> anyhow::Result<TcpStream> {
    let stack =
        which_stack_decision(&ctx.default_iface.load(), ctx.stack_prefer, &remote)?;
    let addr: SocketAddr = match (stack, (remote.0, remote.1)) {
        (Stack::V4, (Some(addr), _)) => addr.into(),
        (Stack::V6, (_, Some(addr))) => addr.into(),
        _ => unreachable!(),
    };
    ctx.protector
        .new_tcp(addr, Some(DEFAULT_OUTBOUND_TIMEOUT))
        .await
}
pub fn search_iface(name: &str) -> anyhow::Result<Iface> {
    let iface = network_interface::NetworkInterface::show()?
        .into_iter()
        .find_map(|iface| {
            if &iface.name == name {
                Some(iface)
            } else {
                None
            }
        })
        .with_context(|| format!("Iface named:{name} not found"))?;

    let iface = Iface {
        name: name.to_owned(),
        ipv4: iface.addr.iter().find_map(|v| match v {
            network_interface::Addr::V4(addr) => Some(addr.ip),
            _ => None,
        }),
        ipv6: iface.addr.iter().find_map(|v| match v {
            network_interface::Addr::V6(addr) => Some(addr.ip),
            _ => None,
        }),
        index: iface.index,
    };
    Ok(iface)
}
