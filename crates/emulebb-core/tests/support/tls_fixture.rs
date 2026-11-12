// Synthetic, test-only ECDSA P-256 fixtures generated offline with OpenSSL 3.5.9.
// The leaf's fixed validity is 2020-01-01..2099-01-01; the expired variant is
// 2019-01-01..2020-01-01. Both name only fixture.test and 127.0.0.1. The private
// key is deliberately public test material, never an operator credential.
// The CA private key was discarded; no system trust store is modified.
use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_rustls::TlsAcceptor;

pub const VALID: &[u8] = include_bytes!("../tls-fixtures/valid.der");
const KEY: &[u8] = include_bytes!("../tls-fixtures/leaf-key.der");
pub const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Served,
    CertificateRejected,
}

/// Serve one bounded loopback TLS connection; handshake rejection is expected
/// for negative cases, so it ends the fixture without a server-side panic.
pub async fn serve(certificate: &[u8]) -> (SocketAddr, JoinHandle<Outcome>) {
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.to_vec())],
            PrivatePkcs8KeyDer::from(KEY.to_vec()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let exchange = async {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = match TlsAcceptor::from(Arc::new(config)).accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    let alert = error
                        .get_ref()
                        .and_then(|inner| inner.downcast_ref::<rustls::Error>());
                    assert!(
                        matches!(alert, Some(rustls::Error::AlertReceived(alert)) if matches!(*alert,
                        rustls::AlertDescription::BadCertificate | rustls::AlertDescription::CertificateExpired
                        | rustls::AlertDescription::CertificateUnknown | rustls::AlertDescription::UnknownCA)),
                        "expected a peer certificate rejection, got {error:?}"
                    );
                    return Outcome::CertificateRejected;
                }
            };
            let mut request = [0; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
            Outcome::Served
        };
        tokio::time::timeout(TIMEOUT, exchange)
            .await
            .expect("loopback TLS fixture timed out")
    });
    (address, task)
}
