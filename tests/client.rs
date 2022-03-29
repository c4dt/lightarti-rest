use http::Request;
use lightarti_rest::Client;

mod utils;

#[tokio::test]
pub async fn test_get() {
    utils::setup_tracing();
    let cache = utils::setup_cache();

    let resp = Client::new(cache.path())
        .await
        .expect("create client")
        .send(
            Request::get("https://www.example.com")
                .header("Host", "www.example.com")
                .version(http::Version::HTTP_10)
                .body(vec![])
                .expect("create get request"),
        )
        .await
        .expect("send request");

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
pub async fn test_post() {
    utils::setup_tracing();
    let cache = utils::setup_cache();

    let resp = Client::new(cache.path())
        .await
        .expect("create client")
        .send(
            Request::post("https://httpbin.org/post")
                .header("Host", "httpbin.org")
                .version(http::Version::HTTP_10)
                .body(Vec::from("key1=val1&key2=val2"))
                .expect("create post request"),
        )
        .await
        .expect("send request");

    assert_eq!(resp.status(), 200);
}
