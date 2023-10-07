use std::{collections::HashMap, ffi::c_int, os::raw::c_char, ptr};

use clash_lib::{ClashConfigDef, ClashDNSListen, Config, Error};
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
    pub dns_server: *const c_char,
    pub bind_address: *const c_char,
}

#[no_mangle]
pub extern "C" fn get_last_error() -> *const c_char {
    LAST_ERROR.with(|prev| match *prev.borrow() {
        Some(ref err) => err.as_ptr() as *const c_char,
        None => ptr::null(),
    })
}

#[no_mangle]
pub extern "C" fn start_clash_with_config(
    cfg_dir: *const c_char,
    cfg_str: *const c_char,
    cfg_override: *const ConfigOverride,
) -> c_int {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    let cfg_def = s.to_string_lossy().to_string().parse::<ClashConfigDef>();
    match cfg_def {
        Ok(mut cfg_def) => {
            let cfg_override = if cfg_override.is_null() {
                None
            } else {
                unsafe { Some(&*cfg_override) }
            };

            if let Some(cfg_override) = cfg_override {
                if cfg_override.tun_fd != 0 {
                    let mut tun_cfg = HashMap::new();
                    tun_cfg.insert("enable".to_string(), serde_yaml::Value::Bool(true));
                    tun_cfg.insert(
                        "device-id".to_string(),
                        serde_yaml::Value::String(format!("fd://{}", cfg_override.tun_fd)),
                    );
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
                    let dns_server = unsafe { std::ffi::CStr::from_ptr(cfg_override.dns_server) }
                        .to_string_lossy()
                        .to_string();
                    cfg_def.dns.listen = Some(ClashDNSListen::Udp(dns_server));
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
            };

            match clash_lib::start(opts) {
                Ok(_) => ERR_OK,
                Err(e) => {
                    error::update_last_error(Error::Operation(format!("start clash error: {}", e)));
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
                (*general).secret = cfg.secret.unwrap_or_default().as_ptr() as _;
                (*general).tun_enabled = cfg
                    .tun
                    .and_then(|tun| {
                        tun.get("enable")
                            .cloned()
                            .map(|v| v.as_str() == Some("true"))
                    })
                    .unwrap_or_default();
                (*general).dns_enabled = cfg.dns.enable;
                (*general).ipv6_enabled = cfg.ipv6.unwrap_or_default();
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
pub extern "C" fn parse_proxy_list(cfg_str: *const c_char, rv: *mut c_char) -> c_int {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    match s
        .to_string_lossy()
        .to_string()
        .as_str()
        .parse::<ClashConfigDef>()
    {
        Ok(cfg) => {
            unsafe {
                let proxy_list = serde_json::to_string(&cfg.proxy);
                match proxy_list {
                    Ok(s) => *rv = s.as_ptr() as _,
                    Err(e) => {
                        error::update_last_error(Error::Operation(format!(
                            "parse proxy list error: {}",
                            e
                        )));
                        return ERR_CONFIG;
                    }
                }
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
pub extern "C" fn parse_proxy_group(cfg_str: *const c_char, rv: *mut c_char) -> c_int {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    match s
        .to_string_lossy()
        .to_string()
        .as_str()
        .parse::<ClashConfigDef>()
    {
        Ok(cfg) => {
            unsafe {
                let proxy_group = serde_json::to_string(&cfg.proxy_group);
                match proxy_group {
                    Ok(s) => *rv = s.as_ptr() as _,
                    Err(e) => {
                        error::update_last_error(Error::Operation(format!(
                            "parse proxy group error: {}",
                            e
                        )));
                        return ERR_CONFIG;
                    }
                }
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
pub extern "C" fn parse_rule_list(cfg_str: *const c_char, rv: *mut c_char) -> c_int {
    let s = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    match s
        .to_string_lossy()
        .to_string()
        .as_str()
        .parse::<ClashConfigDef>()
    {
        Ok(cfg) => {
            unsafe {
                let rule_list = serde_json::to_string(&cfg.rule);
                match rule_list {
                    Ok(s) => *rv = s.as_ptr() as _,
                    Err(e) => {
                        error::update_last_error(Error::Operation(format!(
                            "parse rule list error: {}",
                            e
                        )));
                        return ERR_CONFIG;
                    }
                }
            }
            ERR_OK
        }
        Err(err) => {
            error::update_last_error(err);
            ERR_CONFIG
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, ptr, vec};

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

        let cfg_override = Some(super::ConfigOverride {
            tun_fd: 1989,
            dns_server: "127.0.0.1:53\0".as_ptr() as _,
            bind_address: "240.0.0.2\0".as_ptr() as _,
        });

        if let Some(cfg_override) = cfg_override {
            if cfg_override.tun_fd != 0 {
                let mut tun_cfg = HashMap::new();
                tun_cfg.insert("enable".to_string(), serde_yaml::Value::Bool(true));
                tun_cfg.insert(
                    "device-id".to_string(),
                    serde_yaml::Value::String(format!("fd://{}", cfg_override.tun_fd)),
                );
                cfg_def.tun = Some(tun_cfg);
            }

            if cfg_override.bind_address != ptr::null() {
                let bind_address = unsafe { std::ffi::CStr::from_ptr(cfg_override.bind_address) }
                    .to_string_lossy()
                    .to_string();
                cfg_def.bind_address = bind_address;
            }

            if cfg_override.dns_server != ptr::null() {
                let dns_server = unsafe { std::ffi::CStr::from_ptr(cfg_override.dns_server) }
                    .to_string_lossy()
                    .to_string();
                cfg_def.dns.listen = Some(ClashDNSListen::Udp(dns_server));
            }
        }

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
        assert_eq!(cfg_def.tun.as_ref().unwrap()["enable"], true);
        assert_eq!(cfg_def.tun.unwrap()["device-id"], "fd://1989");
    }
}
