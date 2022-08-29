use http::request::{Builder, Parts};
use http::Request;
use lightarti_rest::Client;
use url::Url;

mod utils;

const MAX_TRIES: u32 = 4;

#[tokio::test]
pub async fn test_get_short() {
    test_get("https://www.example.com").await;
}

#[tokio::test]
pub async fn test_get_long_response() {
    test_get("https://www.admin.ch/gov/de/start.html").await;
}

#[tokio::test]
pub async fn test_get_many_headers() {
    test_get("https://www.sunrise.ch/en/home").await;
}

#[tokio::test]
pub async fn test_post() {
    test_client(
        Request::post("https://httpbin.org/post")
            .header("Host", "httpbin.org")
            .version(http::Version::HTTP_10)
            .body(Vec::from("key1=val1&key2=val2"))
            .expect("Couldn't build request"),
    )
    .await;
}

// Creates a GET request from an URI and calls test_client on it.
async fn test_get(uri: &str) {
    let url = Url::parse(uri).unwrap();

    test_client(
        Request::get(uri)
            .header("Host", url.host_str().unwrap())
            .version(http::Version::HTTP_10)
            .body(vec![])
            .map_err(|e| anyhow::anyhow!("Error in request: {}", e))
            .expect("Couldn't build request"),
    )
    .await;
}

// Calls the lightarti-rest code up to MAX_TRIES to get a correct answer.
// Returns on the first correct answer, or throws a panic if all MAX_TRIES failed.
// This is necessary due to the sometimes erratic behaviour of the tor-nodes.
async fn test_client(req: Request<Vec<u8>>) {
    utils::setup_tracing();
    let (header, body) = req.into_parts();
    let host = header.uri.clone();

    for i in 1..=MAX_TRIES {
        let request = clone_request(&header, &body);
        let cache = utils::setup_cache();

        let res = Client::new(cache.path())
            .await
            .expect("create client")
            .send(request)
            .await
            .and_then(|r| {
                (r.status() == 200)
                    .then_some(())
                    .ok_or_else(|| anyhow::anyhow!("wrong status"))
            });

        if let Err(e) = res {
            tracing::warn!("Call failed in step {} / {}: {:?}", i, MAX_TRIES, e)
        } else {
            return;
        }
    }

    panic!(
        "Didn't manage to pass in {} steps for domain {}",
        MAX_TRIES, host
    )
}

fn clone_request(header: &Parts, body: &[u8]) -> Request<Vec<u8>> {
    let mut builder = Builder::new()
        .method(header.method.clone())
        .uri(header.uri.clone())
        .version(header.version);
    let builder_header = builder.headers_mut().unwrap();
    for header in header.headers.clone() {
        builder_header.insert(header.0.unwrap(), header.1);
    }

    builder.body(body.to_vec()).unwrap()
}
