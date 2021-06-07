use anyhow::{Result, bail};
use log::{info};

mod arti;
mod ffi;

/// Request for the different REST methods. Here we don't differentiate between
/// the url and the parameters passed to the remote end.
/// Only http and https URLs are supported for the moment.
pub struct Request {
    pub url: String,
    pub user_agent: Option<String>,
    pub body: Option<String>,
}

/// Response from the REST call. If an error happened during the call,
/// no Response will be sent.
/// The 'code' is parsed from the response.
pub struct Response {
    pub code: i32,
    pub body: Option<String>,
}

/// Sends a GET request to the given URL. It returns the response.
pub fn send_get(req: Request) -> Result<Response> {
    info!("Sending GET request to {}", req.url);
    bail!("Not yet implemented")
}

/// Sends a POST request to the given URL. It returns the response.
pub fn send_post(req: Request) -> Result<Response> {
    info!("Sending POST request to {}", req.url);
    bail!("Not yet implemented")
}

/// Sends a PUT request to the given URL. It returns the response.
pub fn send_put(req: Request) -> Result<Response> {
    info!("Sending PUT request to {}", req.url);
    bail!("Not yet implemented")
}

/// Sends a DELETE request to the given URL. It returns the response.
pub fn send_delete(req: Request) -> Result<Response> {
    info!("Sending DELETE request to {}", req.url);
    bail!("Not yet implemented")
}

#[test]
fn test_get() {
    match send_get(Request{
        url: "https://www.c4dt.org/index.html".into(),
        user_agent: None,
        body: None,
    }){
        Ok(resp) => {
            info!("Sent GET to c4dt.org and got code {}", resp.code);
            if let Some(body) = resp.body {
                info!("Body is: {}", body);
            }
        },
        Err(e) => {
            panic!("Encountered error: {}", e);
        }
    }
}