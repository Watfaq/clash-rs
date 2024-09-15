use std::{
    ffi::{c_int, CString},
    os::raw::c_char,
    ptr,
};

use clash_lib::{ClashConfigDef, ClashDNSListen, ClashTunConfig, Config, Error};
use error::LAST_ERROR;

mod error;

pub const ERR_OK: c_int = 0;
pub const ERR_START: c_int = 1;
pub const ERR_CONFIG: c_int = 2;

#[repr(C)]
pub struct GeneralConfig {
    pub port: u16,
    pub socks_port: u16,
    pub mixed_port: u16,

    pub secret: *const c_char,

    pub tun_enabled: bool,
    pub dns_enabled: bool,
    pub ipv6_enabled: bool,
}

#[repr(C)]
pub struct ConfigOverride {
    pub tun_fd: i32,
    pub http_port: u16,
    pub dns_server: *const c_char,
    pub bind_address: *const c_char,
    pub external_controller: *const c_char,
    /// \n separated rules list
    /// TODO: use a better way to pass rules list, like a list of strings
    pub rules_list: *const c_char,
    /// yaml string
    /// ```
    ///  - name: "socks5-noauth"
    ///    type: socks5
    ///    server: 10.0.0.13
    ///    port: 10800
    ///    udp: true
    /// ```
    pub outbounds: *const c_char,
}

fn apply_config_override(
    cfg_override: &ConfigOverride,
    cfg_def: &mut ClashConfigDef,
) -> Option<String> {
    if cfg_override.tun_fd != 0 {
        let mut tun_cfg = ClashTunConfig::default();
        tun_cfg.enable = true;
        tun_cfg.device_id = format!("fd://{}", cfg_override.tun_fd);

        cfg_def.tun = Some(tun_cfg);
    }

    if cfg_override.bind_address != ptr::null() {
        let bind_address =
            unsafe { std::ffi::CStr::from_ptr(cfg_override.bind_address) }
                .to_string_lossy()
                .to_string();
        cfg_def.bind_address = bind_address;
    }

    if cfg_override.dns_server != ptr::null() {
        let dns_server =
            unsafe { std::ffi::CStr::from_ptr(cfg_override.dns_server) }
                .to_string_lossy()
                .to_string();
        cfg_def.dns.listen = Some(ClashDNSListen::Udp(dns_server));
    }

    if cfg_override.external_controller != ptr::null() {
        let external_controller =
            unsafe { std::ffi::CStr::from_ptr(cfg_override.external_controller) }
                .to_string_lossy()
                .to_string();
        cfg_def.external_controller = Some(external_controller);
    }

    if cfg_def.port.is_none() && cfg_def.mixed_port.is_none() {
        cfg_def.port = Some(cfg_override.http_port);
    }

    if cfg_override.rules_list != ptr::null() {
        let mut rules_list = unsafe {
            std::ffi::CStr::from_ptr(cfg_override.rules_list)
                .to_string_lossy()
                .to_string()
        }
        .split("\n")
        .filter_map(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        })
        .collect::<Vec<String>>();

        cfg_def.rule.append(&mut rules_list);
    }

    if cfg_override.outbounds != ptr::null() {
        let outbounds = unsafe {
            std::ffi::CStr::from_ptr(cfg_override.outbounds)
                .to_string_lossy()
                .to_string()
        };

        match &mut serde_yaml::from_str::<_>(&outbounds) {
            Ok(outbounds) => cfg_def.proxy.append(outbounds),
            _ => {
                return Some(format!(
                    "couldn't parse outbounds: {}",
                    outbounds.replace("\n", ""),
                ));
            }
        }
    }

    None
}

#[no_mangle]
pub extern "C" fn get_last_error() -> *const c_char {
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => err.as_ptr() as *const c_char,
        None => ptr::null(),
    })
}

#[no_mangle]
pub extern "C" fn test_clash_config(cfg_str: *const c_char) -> *const c_char {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    let cfg_def = s.to_string_lossy().to_string().parse::<ClashConfigDef>();

    match cfg_def {
        Ok(_) => ptr::null(),
        Err(err) => {
            let err = CString::new(format!("{}", err)).unwrap();
            err.into_raw()
        }
    }
}

#[no_mangle]
pub extern "C" fn start_clash_with_config(
    cfg_dir: *const c_char,
    cfg_str: *const c_char,
    log_file: *const c_char,
    cfg_override: *const ConfigOverride,
) -> c_int {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    let cfg_def = s.to_string_lossy().to_string().parse::<ClashConfigDef>();
    match cfg_def {
        Ok(mut cfg_def) => {
            if !cfg_override.is_null() {
                match apply_config_override(unsafe { &*cfg_override }, &mut cfg_def)
                {
                    Some(err) => {
                        error::update_last_error(Error::InvalidConfig(err));
                        return ERR_CONFIG;
                    }
                    None => {}
                }
            }

            let opts = clash_lib::Options {
                config: Config::Def(cfg_def),
                cwd: Some(
                    unsafe { std::ffi::CStr::from_ptr(cfg_dir) }
                        .to_string_lossy()
                        .to_string(),
                ),
                rt: Some(clash_lib::TokioRuntime::SingleThread),
                log_file: if log_file != ptr::null() {
                    Some(
                        unsafe { std::ffi::CStr::from_ptr(log_file) }
                            .to_string_lossy()
                            .to_string(),
                    )
                } else {
                    None
                },
            };

            match clash_lib::start(opts) {
                Ok(_) => ERR_OK,
                Err(e) => {
                    error::update_last_error(Error::Operation(format!(
                        "start clash error: {}",
                        e
                    )));
                    ERR_START
                }
            }
        }
        Err(err) => {
            error::update_last_error(err);
            ERR_CONFIG
        }
    }
}

#[no_mangle]
pub extern "C" fn shutdown_clash() -> bool {
    clash_lib::shutdown()
}

#[no_mangle]
pub extern "C" fn parse_general_config(
    cfg_str: *const c_char,
    general: *mut GeneralConfig,
) -> c_int {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    match s
        .to_string_lossy()
        .to_string()
        .as_str()
        .parse::<ClashConfigDef>()
    {
        Ok(cfg) => {
            #[allow(deprecated)]
            unsafe {
                (*general).port = cfg.port.unwrap_or_default();
                (*general).socks_port = cfg.socks_port.unwrap_or_default();
                (*general).mixed_port = cfg.mixed_port.unwrap_or_default();
                // this is a memory leak, but we don't care
                (*general).secret = CString::new(cfg.secret.unwrap_or_default())
                    .expect("invalid secret")
                    .into_raw();
                (*general).tun_enabled =
                    cfg.tun.map(|tun| tun.enable).unwrap_or_default();
                (*general).dns_enabled = cfg.dns.enable;
                (*general).ipv6_enabled = cfg.ipv6;
            }
            ERR_OK
        }
        Err(err) => {
            error::update_last_error(err);
            ERR_CONFIG
        }
    }
}

#[no_mangle]
pub extern "C" fn parse_proxy_list(cfg_str: *const c_char) -> *mut c_char {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    match s
        .to_string_lossy()
        .to_string()
        .as_str()
        .parse::<ClashConfigDef>()
    {
        Ok(cfg) => {
            let proxy_list = serde_json::to_string(&cfg.proxy);
            match proxy_list {
                Ok(s) => CString::new(s).unwrap().into_raw(),
                Err(e) => {
                    error::update_last_error(Error::Operation(format!(
                        "parse proxy list error: {}",
                        e
                    )));
                    return ptr::null_mut();
                }
            }
        }
        Err(err) => {
            error::update_last_error(err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn free_string(ptr: *mut c_char) {
    unsafe {
        if !ptr.is_null() {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[no_mangle]
pub extern "C" fn parse_proxy_group(cfg_str: *const c_char) -> *mut c_char {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    match s
        .to_string_lossy()
        .to_string()
        .as_str()
        .parse::<ClashConfigDef>()
    {
        Ok(cfg) => {
            let proxy_group = serde_json::to_string(&cfg.proxy_group);
            match proxy_group {
                Ok(s) => CString::new(s).unwrap().into_raw(),
                Err(e) => {
                    error::update_last_error(Error::Operation(format!(
                        "parse proxy group error: {}",
                        e
                    )));
                    return ptr::null_mut();
                }
            }
        }
        Err(err) => {
            error::update_last_error(err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn parse_rule_list(cfg_str: *const c_char) -> *mut c_char {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    match s
        .to_string_lossy()
        .to_string()
        .as_str()
        .parse::<ClashConfigDef>()
    {
        Ok(cfg) => {
            let rule_list = serde_json::to_string(&cfg.rule);
            match rule_list {
                Ok(s) => CString::new(s).unwrap().into_raw(),
                Err(e) => {
                    error::update_last_error(Error::Operation(format!(
                        "parse rule list error: {}",
                        e
                    )));
                    return ptr::null_mut();
                }
            }
        }
        Err(err) => {
            error::update_last_error(err);
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn get_clash_version() -> *mut c_char {
    static VERSION: &str = env!("CARGO_PKG_VERSION");

    CString::new(VERSION).unwrap().into_raw()
}

#[cfg(test)]
mod tests {
    use std::{ptr, vec};

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
            tun_fd: 1989,
            http_port: 7891,
            dns_server: "127.0.0.1:53\0".as_ptr() as _,
            bind_address: "240.0.0.2\0".as_ptr() as _,
            external_controller: ptr::null(),
            rules_list: "DOMAIN-KEYWORD,example.com,DIRECT\nDOMAIN-SUFFIX,example.\
                         org,DIRECT\n\0"
                .as_ptr() as _,
            outbounds: r#"
              - name: "socks5-noauth"
                type: socks5
                server: 10.0.0.13
                port: 10800
                udp: true
            "#
            .as_ptr() as _,
        };

        assert_eq!(
            super::apply_config_override(&cfg_override, &mut cfg_def),
            None
        );

        assert_eq!(cfg_def.bind_address, "240.0.0.2");
        assert_eq!(cfg_def.dns.enable, false);
        assert_eq!(
            cfg_def.dns.listen.unwrap(),
            ClashDNSListen::Udp("127.0.0.1:53".into())
        );
        assert_eq!(
            cfg_def.dns.default_nameserver,
            vec!["114.114.114.114", "8.8.8.8"]
        );
        assert_eq!(cfg_def.tun.as_ref().unwrap().enable, true);
        assert_eq!(cfg_def.tun.unwrap().device_id, "fd://1989");

        assert!(cfg_def
            .rule
            .contains(&"DOMAIN-KEYWORD,example.com,DIRECT".to_string()));
        assert!(cfg_def.proxy.iter().any(|p| p.get("name")
            == Some(&serde_yaml::Value::String("socks5-noauth".to_string()))));
    }
}
