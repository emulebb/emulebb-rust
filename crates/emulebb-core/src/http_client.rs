//! Trust selection for outbound HTTP, shared by discovery and URL imports.

use anyhow::Result;
use reqwest::ClientBuilder;

/// Create a verified HTTP builder without changing caller-specific request policy.
///
/// Desktop clients retain platform verification. Android CLI uses the compiled
/// Mozilla CA set: Android/Termux private CAs and SSL_CERT_FILE are not consulted.
/// Updating that root set requires a dependency update and a rebuilt executable.
pub fn http_client_builder() -> Result<ClientBuilder> {
    #[cfg(target_os = "android")]
    {
        packaged_root_client_builder()
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(reqwest::Client::builder())
    }
}

#[cfg(any(target_os = "android", test))]
fn packaged_root_client_builder() -> Result<ClientBuilder> {
    use anyhow::Context as _;

    let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|root| reqwest::Certificate::from_der(root.as_ref()))
        .collect::<reqwest::Result<Vec<_>>>()
        .context("invalid packaged Android TLS roots")?;
    root_client_builder(roots)
}

#[cfg(any(target_os = "android", test))]
fn root_client_builder(roots: Vec<reqwest::Certificate>) -> Result<ClientBuilder> {
    anyhow::ensure!(
        !roots.is_empty(),
        "packaged Android TLS roots must not be empty"
    );
    // WHY: reqwest 0.13's default verifier needs an initialized Android JVM.
    // tls_certs_only selects ordinary Rustls root/hostname/validity verification
    // without that platform verifier; merging roots would retain the JVM path.
    Ok(reqwest::Client::builder().tls_certs_only(roots))
}

#[cfg(test)]
#[path = "http_client_tests.rs"]
mod tests;
