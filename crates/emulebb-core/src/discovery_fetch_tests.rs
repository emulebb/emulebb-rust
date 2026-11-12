use super::*;
use crate::tests::discovery_fixture::{Reply, Server, server};
use std::sync::atomic::Ordering;

mod tls_fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/tls_fixture.rs"
    ));
}

fn client(policy: DiscoveryUrlPolicy) -> Client {
    discovery_client_builder(policy)
        .unwrap()
        .no_proxy()
        .build()
        .unwrap()
}

async fn fetch(server: &Server, cap: usize) -> Result<Vec<u8>> {
    fetch_discovery_bytes(
        &client(DiscoveryUrlPolicy::OperatorImport),
        &server.url,
        cap,
        Duration::from_secs(5),
        DiscoveryUrlPolicy::OperatorImport,
    )
    .await
}

#[tokio::test]
async fn exact_limits_and_streamed_length_variants_are_bounded() {
    for raw in [
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcde".as_slice(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\na\r\n1\r\nb\r\n3\r\ncde\r\n0\r\n\r\n".as_slice(),
    ] {
        let source = server(vec![Reply::raw(raw)]).await;
        assert_eq!(fetch(&source, 5).await.unwrap(), b"abcde");
    }
    let exact = server(vec![Reply::body(b"abcde")]).await;
    assert_eq!(fetch(&exact, 5).await.unwrap(), b"abcde");
    let excess = server(vec![Reply::raw(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\nabcdef\r\n0\r\n\r\n")]).await;
    assert!(
        fetch(&excess, 5)
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds 5 bytes")
    );
}

#[tokio::test]
async fn absent_lengths_and_many_small_chunks_cannot_bypass_the_cap() {
    let absent = server(vec![Reply::raw(
        b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcdef",
    )])
    .await;
    assert!(
        fetch(&absent, 5)
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds 5 bytes")
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{}0\r\n\r\n",
        "1\r\na\r\n".repeat(17)
    );
    let chunked = server(vec![Reply::raw(response.as_bytes())]).await;
    assert!(
        fetch(&chunked, 16)
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds 16 bytes")
    );
}

#[tokio::test]
async fn declared_oversize_is_rejected_before_waiting_for_body() {
    let source = server(vec![Reply::raw(
        b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n",
    )])
    .await;
    assert!(
        fetch(&source, 5)
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds 5 bytes")
    );
}

#[tokio::test]
async fn encoded_body_remains_raw_and_within_the_same_limit() {
    let source = server(vec![Reply::raw(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde")]).await;
    assert_eq!(fetch(&source, 5).await.unwrap(), b"abcde");
}

#[tokio::test]
async fn relative_and_cross_host_redirects_preserve_operator_loopback_access() {
    let destination = server(vec![Reply::body(b"ok")]).await;
    let redirected = destination.url.replace("127.0.0.1", "localhost");
    let source = server(vec![Reply::redirect("/next"), Reply::redirect(&redirected)]).await;
    assert_eq!(fetch(&source, 2).await.unwrap(), b"ok");
    assert_eq!(source.hits.load(Ordering::SeqCst), 2);
    assert_eq!(destination.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_fourth_redirect_and_redirect_loops_stop_before_the_next_contact() {
    for target in ["/next", "/"] {
        let source = server((0..5).map(|_| Reply::redirect(target)).collect()).await;
        let error = fetch(&source, 2).await.unwrap_err();
        assert!(
            error
                .downcast_ref::<reqwest::Error>()
                .unwrap()
                .is_redirect()
        );
        assert_eq!(source.hits.load(Ordering::SeqCst), 4);
    }
    let source = server(vec![
        Reply::redirect("/1"),
        Reply::redirect("/2"),
        Reply::redirect("/3"),
        Reply::body(b"ok"),
    ])
    .await;
    assert_eq!(fetch(&source, 2).await.unwrap(), b"ok");
    assert_eq!(source.hits.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn invalid_initial_and_redirect_schemes_fail_without_an_extra_request() {
    for policy in [
        DiscoveryUrlPolicy::OperatorImport,
        DiscoveryUrlPolicy::TrustedBootstrap,
    ] {
        assert!(
            fetch_discovery_bytes(
                &client(policy),
                "file:///synthetic",
                2,
                Duration::from_secs(1),
                policy
            )
            .await
            .is_err()
        );
    }
    let sentinel = server(vec![Reply::body(b"unused")]).await;
    let error = fetch_discovery_bytes(
        &client(DiscoveryUrlPolicy::TrustedBootstrap),
        &sentinel.url,
        2,
        Duration::from_secs(1),
        DiscoveryUrlPolicy::TrustedBootstrap,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("unsupported scheme"));
    assert_eq!(sentinel.hits.load(Ordering::SeqCst), 0);
    let source = server(vec![Reply::redirect("file:///synthetic")]).await;
    assert!(fetch(&source, 2).await.is_err());
    assert_eq!(source.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn https_bootstrap_downgrade_is_rejected_before_http_contact() {
    let sentinel = server(vec![Reply::body(b"unused")]).await;
    let response = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        sentinel.url
    );
    let (address, tls) =
        tls_fixture::serve_response(tls_fixture::VALID, response.into_bytes()).await;
    let root =
        reqwest::Certificate::from_der(include_bytes!("../tests/tls-fixtures/root.der")).unwrap();
    let client = discovery_client_builder(DiscoveryUrlPolicy::TrustedBootstrap)
        .unwrap()
        .tls_certs_only([root])
        .no_proxy()
        .build()
        .unwrap();
    let error = fetch_discovery_bytes(
        &client,
        &format!("https://{address}/"),
        2,
        Duration::from_secs(5),
        DiscoveryUrlPolicy::TrustedBootstrap,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .downcast_ref::<reqwest::Error>()
            .unwrap()
            .is_redirect()
    );
    assert_eq!(tls.await.unwrap(), tls_fixture::Outcome::Served);
    assert_eq!(sentinel.hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn trusted_bootstrap_accepts_verified_https_before_streaming() {
    let (address, tls) = tls_fixture::serve(tls_fixture::VALID).await;
    let root =
        reqwest::Certificate::from_der(include_bytes!("../tests/tls-fixtures/root.der")).unwrap();
    let client = discovery_client_builder(DiscoveryUrlPolicy::TrustedBootstrap)
        .unwrap()
        .tls_certs_only([root])
        .no_proxy()
        .build()
        .unwrap();
    let body = fetch_discovery_bytes(
        &client,
        &format!("https://{address}/"),
        2,
        Duration::from_secs(5),
        DiscoveryUrlPolicy::TrustedBootstrap,
    )
    .await
    .unwrap();
    assert_eq!(body, b"ok");
    assert_eq!(tls.await.unwrap(), tls_fixture::Outcome::Served);
}

#[tokio::test]
async fn one_deadline_covers_slow_headers_redirects_and_drip_fed_body() {
    for replies in [
        vec![Reply {
            before: Duration::from_secs(1),
            ..Reply::body(b"ok")
        }],
        vec![Reply {
            parts: std::iter::once(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n".to_vec())
                .chain(std::iter::repeat_n(vec![b'a'], 100))
                .collect(),
            before: Duration::ZERO,
            between: Duration::from_millis(50),
        }],
        vec![
            Reply {
                before: Duration::from_millis(180),
                ..Reply::redirect("/next")
            },
            Reply {
                before: Duration::from_millis(180),
                ..Reply::body(b"ok")
            },
        ],
    ] {
        let source = server(replies).await;
        let error = fetch_discovery_bytes(
            &client(DiscoveryUrlPolicy::OperatorImport),
            &source.url,
            100,
            Duration::from_millis(250),
            DiscoveryUrlPolicy::OperatorImport,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("elapsed-time budget"));
        assert!(source.hits.load(Ordering::SeqCst) > 0);
    }
}

#[tokio::test]
async fn operator_import_preserves_explicit_proxy_selection() {
    let proxy = server(vec![Reply::body(b"ok")]).await;
    let client = discovery_client_builder(DiscoveryUrlPolicy::OperatorImport)
        .unwrap()
        .proxy(reqwest::Proxy::http(&proxy.url).unwrap())
        .build()
        .unwrap();
    let bytes = fetch_discovery_bytes(
        &client,
        "http://synthetic-unresolvable.invalid/discovery",
        2,
        Duration::from_secs(5),
        DiscoveryUrlPolicy::OperatorImport,
    )
    .await
    .unwrap();
    assert_eq!(bytes, b"ok");
    assert_eq!(proxy.hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_request_diagnostics_omit_url_credentials_and_query() {
    let source = server(vec![Reply::raw(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )])
    .await;
    let url = source
        .url
        .replace("http://", "http://synthetic-user:synthetic-secret@")
        + "/?token=synthetic-token";
    let error = fetch_discovery_bytes(
        &client(DiscoveryUrlPolicy::OperatorImport),
        &url,
        2,
        Duration::from_secs(5),
        DiscoveryUrlPolicy::OperatorImport,
    )
    .await
    .unwrap_err();
    let diagnostic = format!("{error:#}");
    for secret in ["synthetic-user", "synthetic-secret", "synthetic-token"] {
        assert!(!diagnostic.contains(secret));
    }
}
