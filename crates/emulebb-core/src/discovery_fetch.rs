//! Resource and destination bounds shared by discovery bootstrap and imports.

use std::time::Duration;

use anyhow::{Result, bail, ensure};
use reqwest::{Client, ClientBuilder, Url, redirect::Policy};

pub const SERVER_MET_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const NODES_DAT_MAX_BYTES: usize = 2 * 1024 * 1024;

/// Scheme contract for an operator-selected import or automatic trusted bootstrap.
#[derive(Clone, Copy)]
pub enum DiscoveryUrlPolicy {
    OperatorImport,
    TrustedBootstrap,
}

impl DiscoveryUrlPolicy {
    fn accepts(self, url: &Url) -> bool {
        match self {
            Self::OperatorImport => matches!(url.scheme(), "http" | "https"),
            Self::TrustedBootstrap => url.scheme() == "https",
        }
    }
}

pub(crate) fn parse_discovery_url(url: &str, policy: DiscoveryUrlPolicy) -> Result<Url> {
    let parsed = Url::parse(url).map_err(|_| anyhow::anyhow!("invalid discovery URL"))?;
    ensure!(
        policy.accepts(&parsed),
        "discovery URL uses an unsupported scheme"
    );
    Ok(parsed)
}

/// Preserve normal proxy/trust selection while constraining redirects and decoding.
pub fn discovery_client_builder(policy: DiscoveryUrlPolicy) -> Result<ClientBuilder> {
    Ok(crate::http_client_builder()?
        .redirect(Policy::custom(move |attempt| {
            // WHY: checking only the final response permits an HTTP bootstrap
            // hop to be contacted before its eventual HTTPS response is rejected.
            if !policy.accepts(attempt.url()) {
                attempt.error("discovery redirect uses an unsupported scheme")
            } else {
                Policy::limited(3).redirect(attempt)
            }
        }))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd())
}

/// Fetch a complete bounded document before callers parse or publish any state.
///
/// The single elapsed budget includes redirects, headers and all body chunks.
/// Caller-supplied clients must come from `discovery_client_builder` so every
/// redirect has the same pre-contact scheme policy and raw-body contract.
pub async fn fetch_discovery_bytes(
    client: &Client,
    url: &str,
    max_bytes: usize,
    budget: Duration,
    policy: DiscoveryUrlPolicy,
) -> Result<Vec<u8>> {
    let operation = async {
        let url = parse_discovery_url(url, policy)?;
        let mut response = client
            .get(url)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?
            .error_for_status()
            .map_err(reqwest::Error::without_url)?;
        // WHY: reqwest can return the original 3xx without calling the custom
        // policy for an unsupported target. Such a response is not a document.
        ensure!(
            !response.status().is_redirection(),
            "discovery redirect did not reach a supported destination"
        );
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
        {
            bail!("discovery response exceeds {max_bytes} bytes");
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(reqwest::Error::without_url)?
        {
            ensure!(
                chunk.len() <= max_bytes.saturating_sub(body.len()),
                "discovery response exceeds {max_bytes} bytes"
            );
            // WHY: ordinary Vec growth can reserve beyond the fixed document
            // ceiling even when the received byte count is still within it.
            body.try_reserve_exact(chunk.len())
                .map_err(|_| anyhow::anyhow!("cannot allocate bounded discovery response"))?;
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    };
    tokio::time::timeout(budget, operation)
        .await
        .map_err(|_| anyhow::anyhow!("discovery fetch exceeded its elapsed-time budget"))?
}

#[cfg(test)]
#[path = "discovery_fetch_tests.rs"]
mod tests;
