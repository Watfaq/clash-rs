use clash_lib::{ClashConfigDef, ClashDNSListen, ClashTunConfig, Config, Port};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FFIError {
    #[error("parse config: {0}")]
    ParseConfig(String),
    #[error("start clash error: {0}")]
    StartClash(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(uniffi::Record)]
pub struct GeneralConfig {
    pub port: u16,
    pub socks_port: u16,
    pub mixed_port: u16,

    pub secret: String,

    pub tun_enabled: bool,
    pub dns_enabled: bool,
    pub ipv6_enabled: bool,
}

impl From<ClashConfigDef> for GeneralConfig {
    fn from(cfg: ClashConfigDef) -> Self {
        Self {
            port: cfg.port.map(Into::into).unwrap_or_default(),
            socks_port: cfg.socks_port.map(Into::into).unwrap_or_default(),
            mixed_port: cfg.mixed_port.map(Into::into).unwrap_or_default(),
            secret: cfg.secret.unwrap_or_default(),
            tun_enabled: cfg.tun.map(|tun| tun.enable).unwrap_or_default(),
            dns_enabled: cfg.dns.enable,
            ipv6_enabled: cfg.ipv6,
        }
    }
}

#[derive(uniffi::Record)]
pub struct ConfigOverride {
    pub tun_fd: Option<i32>,
    pub http_port: Option<u16>,
    pub dns_server: Option<String>,
    pub bind_address: Option<String>,
    pub external_controller: Option<String>,
    pub rules_list: Vec<String>,
    /// yaml string
    /// ```
    ///  - name: "socks5-noauth"
    ///    type: socks5
    ///    server: 10.0.0.13
    ///    port: 10800
    ///    udp: true
    /// ```
    pub outbounds: Option<String>,
}

fn apply_config_override(
    cfg_override: &ConfigOverride,
    cfg_def: &mut ClashConfigDef,
) -> Result<(), FFIError> {
    if let Some(tun_fd) = cfg_override.tun_fd {
        let tun_cfg = ClashTunConfig {
            enable: true,
            gateway: "192.19.0.1/24".into(),
            device_id: format!("fd://{}", tun_fd),
            ..Default::default()
        };
        cfg_def.tun = Some(tun_cfg);
    }

    if cfg_def.port.is_none() && cfg_def.mixed_port.is_none() {
        cfg_def.port = Some(Port(cfg_override.http_port.unwrap_or(7890)));
    }

    if let Some(bind_address) = cfg_override.bind_address.as_ref() {
        cfg_def.bind_address = bind_address.parse().expect("invalid bind address");
    }

    if let Some(dns_server) = cfg_override.dns_server.as_ref() {
        cfg_def.dns.listen = Some(ClashDNSListen::Udp(dns_server.clone()));
    }

    if let Some(external_controller) = cfg_override.external_controller.as_ref() {
        cfg_def.external_controller = Some(external_controller.clone());
    }

    if !cfg_override.rules_list.is_empty() {
        if let Some(ref mut rule) = cfg_def.rule {
            rule.append(&mut cfg_override.rules_list.clone());
        } else {
            cfg_def.rule = Some(cfg_override.rules_list.clone());
        }
    }

    if let Some(outbounds) = cfg_override.outbounds.as_ref() {
        match &mut serde_yaml::from_str::<_>(&outbounds) {
            Ok(outbounds) => {
                if let Some(proxy) = cfg_def.proxy.as_mut() {
                    proxy.append(outbounds);
                } else {
                    cfg_def.proxy = Some(outbounds.clone());
                }
            }
            _ => {
                return Err(FFIError::ParseConfig(
                    "invalid outbounds yaml string".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[uniffi::export]
pub fn test_clash_config(cfg_str: &str) -> Result<(), FFIError> {
    let cfg_def = cfg_str.parse::<ClashConfigDef>();

    match cfg_def {
        Ok(_) => Ok(()),
        Err(err) => Err(FFIError::ParseConfig(err.to_string())),
    }
}

#[uniffi::export]
pub fn start_clash_with_config(
    cfg_dir: &str,
    cfg_str: &str,
    log_file: Option<String>,
    cfg_override: Option<ConfigOverride>,
) -> Result<(), FFIError> {
    let cfg_def = cfg_str.parse::<ClashConfigDef>();
    match cfg_def {
        Ok(mut cfg_def) => {
            if let Some(cfg_override) = cfg_override {
                if let Err(err) = apply_config_override(&cfg_override, &mut cfg_def)
                {
                    return Err(err);
                }
            }

            let opts = clash_lib::Options {
                config: Config::Def(cfg_def),
                cwd: Some(cfg_dir.into()),
                rt: Some(clash_lib::TokioRuntime::SingleThread),
                log_file,
            };

            match clash_lib::start_scaffold(opts) {
                Ok(_) => Ok(()),
                Err(e) => Err(FFIError::StartClash(e.to_string())),
            }
        }
        Err(err) => Err(FFIError::ParseConfig(err.to_string())),
    }
}

#[uniffi::export]
pub fn shutdown_clash() -> bool {
    clash_lib::shutdown()
}

#[uniffi::export]
pub fn parse_general_config(cfg_str: &str) -> Result<GeneralConfig, FFIError> {
    cfg_str
        .parse::<ClashConfigDef>()
        .map(|cfg| cfg.into())
        .map_err(|e| FFIError::ParseConfig(e.to_string()))
}

#[uniffi::export]
pub fn parse_proxy_list(cfg_str: &str) -> Result<String, FFIError> {
    match cfg_str.parse::<ClashConfigDef>() {
        Ok(cfg) => {
            let proxy_list = serde_json::to_string(&cfg.proxy);
            match proxy_list {
                Ok(s) => Ok(s),
                Err(e) => Err(FFIError::ParseConfig(e.to_string())),
            }
        }
        Err(err) => Err(FFIError::ParseConfig(err.to_string())),
    }
}

#[uniffi::export]
pub fn parse_proxy_group(cfg_str: &str) -> Result<String, FFIError> {
    match cfg_str.parse::<ClashConfigDef>() {
        Ok(cfg) => {
            let proxy_group = serde_json::to_string(&cfg.proxy_group);
            match proxy_group {
                Ok(s) => Ok(s),
                Err(e) => Err(FFIError::ParseConfig(e.to_string())),
            }
        }
        Err(err) => Err(FFIError::ParseConfig(err.to_string())),
    }
}

#[uniffi::export]
pub fn parse_rule_list(cfg_str: &str) -> Result<String, FFIError> {
    match cfg_str.parse::<ClashConfigDef>() {
        Ok(cfg) => {
            let rule_list = serde_json::to_string(&cfg.rule);
            match rule_list {
                Ok(s) => Ok(s),
                Err(e) => Err(FFIError::ParseConfig(e.to_string())),
            }
        }
        Err(err) => Err(FFIError::ParseConfig(err.to_string())),
    }
}

#[uniffi::export]
pub fn get_clash_version() -> String {
    static VERSION: &str = env!("CARGO_PKG_VERSION");

    VERSION.to_string()
}

#[cfg(test)]
mod tests {
    use std::vec;

    use clash_lib::{ClashConfigDef, ClashDNSListen};

    #[test]
    fn test_parse_config() {
        let i = "port: 7890\nexternal-controller: 127.0.0.1:9090\n\0".as_ptr() as _;
        let s = unsafe { std::ffi::CStr::from_ptr(i) };

        let mut cfg_def = s
            .to_string_lossy()
            .to_string()
            .parse::<ClashConfigDef>()
            .unwrap();

        let cfg_override = super::ConfigOverride {
            tun_fd: Some(1989),
            http_port: Some(7891),
            dns_server: Some("127.0.0.1:53".to_string()),
            bind_address: Some("240.0.0.2".to_string()),
            external_controller: None,
            rules_list: vec![
                "DOMAIN-KEYWORD,example.com,DIRECT".to_string(),
                "DOMAIN-SUFFIX,example.org,DIRECT".to_string(),
            ],
            outbounds: Some(
                r#"
              - name: "socks5-noauth"
                type: socks5
                server: 10.0.0.13
                port: 10800
                udp: true
            "#
                .to_string(),
            ),
        };

        assert!(super::apply_config_override(&cfg_override, &mut cfg_def).is_ok());

        assert_eq!(cfg_def.bind_address, "240.0.0.2".parse().unwrap());
        assert!(!cfg_def.dns.enable);
        assert_eq!(
            cfg_def.dns.listen.unwrap(),
            ClashDNSListen::Udp("127.0.0.1:53".into())
        );
        assert_eq!(
            cfg_def.dns.default_nameserver,
            vec!["114.114.114.114", "8.8.8.8"]
        );
        assert!(cfg_def.tun.as_ref().unwrap().enable);
        assert_eq!(cfg_def.tun.unwrap().device_id, "fd://1989");

        assert!(
            cfg_def
                .rule
                .unwrap()
                .contains(&"DOMAIN-KEYWORD,example.com,DIRECT".to_string())
        );
        assert!(cfg_def.proxy.unwrap().iter().any(|p| p.get("name")
            == Some(&serde_yaml::Value::String("socks5-noauth".to_string()))));
    }
}
