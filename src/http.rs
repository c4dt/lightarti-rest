use std::io::Write;

use anyhow::{bail, Context, Result};
use http::{Request, Response};

/// Serialize a [`Request`] as an raw HTTP request
pub fn request_to_raw(req: Request<Vec<u8>>) -> Result<Vec<u8>> {
    const EOL: &str = "\n";

    let (parts, mut body) = req.into_parts();

    let mut ret = Vec::new();

    write!(
        &mut ret,
        "{} {} {:?}{}",
        parts.method,
        parts
            .uri
            .path_and_query()
            .context("uri without path or query")?,
        parts.version,
        EOL,
    )
    .context("write status line")?;

    for (key, value) in &parts.headers {
        write!(
            &mut ret,
            "{}: {}{}",
            key,
            value.to_str().context("serialize header value as string")?,
            EOL,
        )
        .context("write header")?;
    }

    write!(&mut ret, "{}", EOL).context("write last EOL")?;

    ret.append(&mut body);

    Ok(ret)
}

/// Deserialize an raw HTTP response to an [`Response`]
pub fn raw_to_response(mut raw_resp: Vec<u8>) -> Result<Response<Vec<u8>>> {
    const MAX_HEADERS: usize = 16;

    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];

    let mut http_resp = httparse::Response::new(&mut headers);
    let parsed = http_resp
        .parse(raw_resp.as_slice())
        .context("parse response")?;
    if parsed.is_partial() {
        bail!("unfinished response");
    }

    let mut builder = Response::builder()
        .status(http_resp.code.context("no status")?)
        .version(if http_resp.version.context("no version")? == 0 {
            http::Version::HTTP_10
        } else {
            http::Version::HTTP_11
        });
    for header in http_resp.headers {
        builder = builder.header(header.name, header.value)
    }
    builder
        .body(raw_resp.split_off(parsed.unwrap()))
        .context("create response")
}
