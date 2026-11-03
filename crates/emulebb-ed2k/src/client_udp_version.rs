//! Process-wide eD2K client-UDP capability advertised in peer handshakes.
//!
//! Production builds always advertise the current stock-compatible version.
//! Diagnostics builds may select an older supported version before networking
//! starts so deterministic parity campaigns exercise the real negotiated wire
//! path instead of mutating an already-registered peer.

use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::Result;

/// Current client-UDP protocol capability advertised by normal builds.
pub const CURRENT_CLIENT_UDP_VERSION: u8 = 4;

#[cfg(feature = "packet-diagnostics")]
const DIAGNOSTIC_CLIENT_UDP_VERSION_ENV: &str = "EMULEBB_DIAGNOSTIC_CLIENT_UDP_VERSION";

static LOCAL_CLIENT_UDP_VERSION: AtomicU8 = AtomicU8::new(CURRENT_CLIENT_UDP_VERSION);

/// Return the process-wide client-UDP capability used by hello and UDP ingress.
pub fn local_client_udp_version() -> u8 {
    LOCAL_CLIENT_UDP_VERSION.load(Ordering::Relaxed)
}

/// Resolve and install the client-UDP capability before eD2K networking starts.
///
/// The diagnostics-only environment control is deliberately strict. Normal
/// builds neither read nor honor it and remain fixed at version 4.
pub fn configure_local_client_udp_version() -> Result<u8> {
    #[cfg(feature = "packet-diagnostics")]
    let version = match std::env::var(DIAGNOSTIC_CLIENT_UDP_VERSION_ENV) {
        Ok(raw) => parse_diagnostic_client_udp_version(&raw)?,
        Err(std::env::VarError::NotPresent) => CURRENT_CLIENT_UDP_VERSION,
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!(
            "{DIAGNOSTIC_CLIENT_UDP_VERSION_ENV} must be an integer in the range 1..=4"
        ),
    };

    #[cfg(not(feature = "packet-diagnostics"))]
    let version = CURRENT_CLIENT_UDP_VERSION;

    LOCAL_CLIENT_UDP_VERSION.store(version, Ordering::Relaxed);
    Ok(version)
}

#[cfg(feature = "packet-diagnostics")]
fn parse_diagnostic_client_udp_version(raw: &str) -> Result<u8> {
    let bytes = raw.as_bytes();
    anyhow::ensure!(
        bytes.len() == 1 && (b'1'..=b'0' + CURRENT_CLIENT_UDP_VERSION).contains(&bytes[0]),
        "{DIAGNOSTIC_CLIENT_UDP_VERSION_ENV} must be an integer in the range 1..=4"
    );
    Ok(bytes[0] - b'0')
}

#[cfg(all(test, feature = "packet-diagnostics"))]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_client_udp_version_accepts_supported_exact_values() {
        for version in 1..=CURRENT_CLIENT_UDP_VERSION {
            assert_eq!(
                parse_diagnostic_client_udp_version(&version.to_string()).unwrap(),
                version
            );
        }
    }

    #[test]
    fn diagnostic_client_udp_version_rejects_invalid_values() {
        for raw in ["", "0", "5", "03", " 3", "3 ", "v3", "256"] {
            let error = parse_diagnostic_client_udp_version(raw).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("must be an integer in the range 1..=4"),
                "unexpected error for {raw:?}: {error}"
            );
        }
    }
}
