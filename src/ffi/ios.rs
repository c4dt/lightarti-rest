use libc::c_char;
use core_foundation::{
    base::TCFType,
    string::{CFString, CFStringRef},
};
use crate::{Request, DirectoryCache};
use log::LevelFilter;

#[no_mangle]
pub unsafe extern "C" fn call_tls_get(domain_cc: *const c_char) -> CFStringRef {
    simple_logging::log_to_stderr(LevelFilter::Debug);
    let domain = cstring_to_str(&domain_cc);
    let req = &Request{
        method: "GET".to_string(),
        url: format!("https://{}/index.html", domain),
        headers: Default::default(),
        body: None
    };
    match req.send(&DirectoryCache{
        tmp_dir: None,
        nodes: None,
        relays: None
    }){
        Ok(s) => to_cf_str(format!("Result is: {:?}", s.body.unwrap())),
        Err(e) => to_cf_str(format!("Error while getting result: {}", e)),
    }
}

fn to_cf_str(str: String) -> CFStringRef {
    let cf_string = CFString::new(&str);
    let cf_string_ref = cf_string.as_concrete_TypeRef();
    ::std::mem::forget(cf_string);
    cf_string_ref
}

// Convert C string to Rust string slice
unsafe fn cstring_to_str<'a>(cstring: &'a *const c_char) -> &str {
    if cstring.is_null() {
        // Of course in a real project you'd return Result instead
        panic!("cstring is null")
    }

    let raw = ::std::ffi::CStr::from_ptr(*cstring);
    raw.to_str().expect("Couldn't convert c string to slice")
}
