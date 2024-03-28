use crate::config::internal::config::TunConfig;

#[cfg(target_os = "linux")]
pub async fn setup(cfg: &mut TunConfig, tun_name: &str) -> anyhow::Result<()>{
    if !cfg.auto_route.unwrap_or(false) {
        return Ok(());
    }
    let mark = cfg.mark.unwrap_or(6969);
    cfg.mark = Some(mark);
    let table = cfg.table.take().unwrap_or("CLASH_RS".into());
    cfg.table = Some(table);
    // TODO
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn setup(cfg: &mut TunConfig, tun_name: &str) -> anyhow::Result<()>{
    tracing::error!("Auto route not impl!");
    Ok(())
}