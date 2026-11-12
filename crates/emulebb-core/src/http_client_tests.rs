use super::*;

mod fixture {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/tls_fixture.rs"
    ));
}

const ROOT: &[u8] = include_bytes!("../tests/tls-fixtures/root.der");
const EXPIRED: &[u8] = include_bytes!("../tests/tls-fixtures/expired.der");

#[test]
fn packaged_android_roots_are_nonempty_and_build_without_platform_initialization() {
    assert!(!webpki_root_certs::TLS_SERVER_ROOT_CERTS.is_empty());
    packaged_root_client_builder().unwrap().build().unwrap();
}

#[test]
fn missing_or_malformed_roots_fail_without_platform_fallback() {
    assert!(root_client_builder(Vec::new()).is_err());
    let malformed = reqwest::Certificate::from_der(b"not a DER certificate").unwrap();
    assert!(
        root_client_builder(vec![malformed])
            .unwrap()
            .build()
            .is_err()
    );
}

#[tokio::test]
async fn controlled_ca_accepts_valid_tls_but_rejects_wrong_hostname_and_expiry() {
    for (certificate, host, accepted) in [
        (fixture::VALID, "fixture.test", true),
        (fixture::VALID, "other.test", false),
        (EXPIRED, "fixture.test", false),
    ] {
        let (address, server) = fixture::serve(certificate).await;
        let root = reqwest::Certificate::from_der(ROOT).unwrap();
        // Controlled roots are injected only into this private test boundary.
        // No production API accepts caller-supplied Android roots.
        let client = root_client_builder(vec![root])
            .unwrap()
            .no_proxy()
            .resolve(host, address)
            .timeout(fixture::TIMEOUT)
            .build()
            .unwrap();
        let result = client
            .get(format!("https://{host}:{}/", address.port()))
            .send()
            .await;
        if accepted {
            assert_eq!(result.unwrap().text().await.unwrap(), "ok");
        } else {
            let error = result.unwrap_err();
            assert!(
                !error.is_timeout(),
                "timeout is not proof of certificate validation"
            );
        }
        assert_eq!(
            server.await.unwrap(),
            if accepted {
                fixture::Outcome::Served
            } else {
                fixture::Outcome::CertificateRejected
            }
        );
    }
}

#[tokio::test]
async fn packaged_android_roots_do_not_trust_private_fixture_ca() {
    let (address, server) = fixture::serve(fixture::VALID).await;
    let client = packaged_root_client_builder()
        .unwrap()
        .no_proxy()
        .timeout(fixture::TIMEOUT)
        .build()
        .unwrap();
    let error = client
        .get(format!("https://{address}/"))
        .send()
        .await
        .unwrap_err();
    assert!(!error.is_timeout());
    assert_eq!(server.await.unwrap(), fixture::Outcome::CertificateRejected);
}
