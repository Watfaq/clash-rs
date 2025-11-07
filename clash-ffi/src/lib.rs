use clash_lib::{Config, Options, TokioRuntime, shutdown, start_scaffold};
use tracing_oslog::OsLogger;
use tracing_subscriber::{self, layer::SubscriberExt as _};
use std::{
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
};

fn init_logging() {
    let oslog = OsLogger::new("com.flhcc.clashrs", "default");
    let collector = tracing_subscriber::registry().with(oslog);
    tracing::subscriber::set_global_default(collector).expect("failed to set global subscriber");
}
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clash_start(
    config: *const c_char,
    log: *const c_char,
    cwd: *const c_char,
    multithread: c_int,
) -> *mut c_char {
    init_logging();

    unsafe {
        let config_str = CStr::from_ptr(config)
            .to_str()
            .unwrap_or_default()
            .to_string();
        let log_str = CStr::from_ptr(log).to_str().unwrap_or_default().to_string();
        let cwd_str = CStr::from_ptr(cwd).to_str().unwrap_or_default().to_string();

        let rt = if multithread != 0 {
            Some(TokioRuntime::MultiThread)
        } else {
            Some(TokioRuntime::SingleThread)
        };

        let options = Options {
            config: Config::Str(config_str),
            cwd: Some(cwd_str),
            rt,
            log_file: Some(log_str),
        };

        match start_scaffold(options) {
            Ok(_) => CString::new("").unwrap().into_raw(),
            Err(e) => CString::new(format!("Error: {e}")).unwrap().into_raw(),
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn clash_shutdown() -> c_int {
    if shutdown() {
        1 // Success
    } else {
        0 // Failure
    }
}

/// # Safety
/// This function is unsafe because it dereferences raw pointers.
#[unsafe(no_mangle)]
#[allow(unused_must_use)]
pub unsafe extern "C" fn clash_free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        CString::from_raw(s);
    }
}
