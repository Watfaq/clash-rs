use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    time::Duration,
};

use tokio::net::TcpStream;
use watfaq_error::{ErrContext, Result, anyhow};
use watfaq_state::Context;
use watfaq_types::{DualIpAddr, Iface, Stack, StackPrefer, TargetStack};

// TODO change function name
// 1. socket helper的new_tcp 与 new_udp 传入 用于覆盖全局的出口网卡，
//    远端地址的可空v4 + 可空v6，用户的v4v6偏好
// 2. 检查出口网卡的网络栈能力 仅支持v4，
//    bind到v4::UNSPECIFIED，但若远端v4空则panic
//    仅支持v6，bind到v6::UNSPECIFIED，但若远端v6空则panic
//    其他情况（出口支持双栈): 若v4v6 = 4、46 ，远端v4不为空 或 v4v6 = 64，
//    远端v6为空 则bind到v4::UNSPECIFIED connect到远端v4 若v4v6 = 6、64
//    ，远端v6不为空 或 v4v6 = 46， 远端v4为空 则bind到v6::UNSPECIFIED
//    connect到远端v6

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
            ));
        }
        (false, true) if !target_v6 => {
            return Err(anyhow!(
                "Cannot dicide which stack to use, cause of interface{} only \
                 support v6 but target only support v4",
                iface.name
            ));
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

pub async fn new_tcp(ctx: &Context, remote: SocketAddrArg) -> Result<TcpStream> {
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
pub fn search_iface(name: &str) -> Iface {
    todo!()
}
