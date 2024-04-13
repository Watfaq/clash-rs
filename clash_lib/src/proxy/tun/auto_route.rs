use crate::config::internal::config::TunConfig;

#[cfg(target_os = "linux")]
pub fn setup(cfg: &TunConfig, tun_name: &str) -> anyhow::Result<()> {
    use cmd_lib::run_cmd;

    use crate::listen_shutdown;

    if !cfg.auto_route.unwrap_or(false) {
        return Ok(());
    }
    let mark = 6969;
    let table = "2233";

    let ipv6 = false; // TODO read from conf
    // TODO chen perm
    run_cmd! {
        ip route add default dev $tun_name table $table;
        ip rule add ipproto icmp table main;
        ip rule add not fwmark $mark table $table;
        ip rule add table main suppress_prefixlength 0;
    }?;
    if ipv6 {
        run_cmd! {
            ip -6 route add default dev $tun_name table $table;
            ip -6 rule add ipproto icmp table main;
            ip -6 rule add not fwmark $mark table $table;
            ip -6 rule add table main suppress_prefixlength 0;
        }?;
    }
    tokio::spawn(async move {
        listen_shutdown().await.unwrap();
        tracing::info!("cleaning routes");
        run_cmd!{
            ip rule del not from all fwmark $mark lookup $table;
            ip rule del from all lookup main suppress_prefixlength 0;
            ip rule del from all ipproto icmp lookup main;
        }.unwrap();
        if ipv6 {
            run_cmd!{
                ip -6 rule del not from all fwmark $mark lookup $table;
                ip -6 rule del from all lookup main suppress_prefixlength 0;
                ip -6 rule del from all ipproto icmp lookup main;
            }.unwrap();
        }
    });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn setup(cfg: &mut TunConfig, tun_name: &str) -> anyhow::Result<()> {
    tracing::error!("Auto route not impl!");
    Ok(())
}
