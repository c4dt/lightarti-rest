#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "ios")]
mod ios;

#[cfg(any(target_os = "android", target_os = "ios"))]
mod structs;
#[cfg(any(target_os = "android", target_os = "ios"))]
pub(self) use structs::{Request, Response, RuntimeAndClient};
