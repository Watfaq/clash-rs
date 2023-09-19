use std::os::raw::c_char;

use clash_lib::Config;

#[no_mangle]
pub extern "C" fn start_clash(cfg_str: *const c_char) {
    println!("start clash");
    let c_str = unsafe { std::ffi::CStr::from_ptr(cfg_str) };
    let cfg = Config::Str(c_str.to_string_lossy().to_string());
    clash_lib::start(clash_lib::Options { config: cfg }).unwrap();
}
