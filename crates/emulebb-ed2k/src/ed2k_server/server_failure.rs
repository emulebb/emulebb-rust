use std::{fmt, io};

/// Stage of an ED2K server connection at which an attempt failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kServerFailurePhase {
    Resolve,
    SocketSetup,
    Connect,
    Handshake,
    Established,
}

impl Ed2kServerFailurePhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::SocketSetup => "socket_setup",
            Self::Connect => "connect",
            Self::Handshake => "handshake",
            Self::Established => "established",
        }
    }
}

/// Cause used by dead-server accounting and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed2kServerFailureReason {
    ConnectionRefused,
    DnsResolution,
    LocalBindInterface,
    TimeoutUnreachable,
    ProtocolRejection,
    EstablishedDisconnect,
    TransportOther,
}

impl Ed2kServerFailureReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionRefused => "connection_refused",
            Self::DnsResolution => "dns_resolution",
            Self::LocalBindInterface => "local_bind_interface",
            Self::TimeoutUnreachable => "timeout_unreachable",
            Self::ProtocolRejection => "protocol_rejection",
            Self::EstablishedDisconnect => "established_disconnect",
            Self::TransportOther => "transport_other",
        }
    }
}

/// Classified ED2K server failure carried from the network loop to the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed2kServerFailure {
    pub phase: Ed2kServerFailurePhase,
    pub reason: Ed2kServerFailureReason,
    pub detail: String,
}

impl Ed2kServerFailure {
    #[must_use]
    pub fn new(
        phase: Ed2kServerFailurePhase,
        reason: Ed2kServerFailureReason,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            phase,
            reason,
            detail: detail.into(),
        }
    }

    /// Only an explicit refusal by the remote TCP endpoint proves that the
    /// configured server is dead. Local/VPN and ambiguous network failures must
    /// remain retryable even when the configured threshold is one.
    #[must_use]
    pub const fn counts_toward_dead_server(&self) -> bool {
        matches!(
            (self.phase, self.reason),
            (
                Ed2kServerFailurePhase::Connect,
                Ed2kServerFailureReason::ConnectionRefused
            )
        )
    }

    pub(super) fn dns(detail: impl Into<String>) -> Self {
        Self::new(
            Ed2kServerFailurePhase::Resolve,
            Ed2kServerFailureReason::DnsResolution,
            detail,
        )
    }

    pub(super) fn local_socket(detail: impl Into<String>) -> Self {
        Self::new(
            Ed2kServerFailurePhase::SocketSetup,
            Ed2kServerFailureReason::LocalBindInterface,
            detail,
        )
    }

    pub(super) fn connect_timeout(detail: impl Into<String>) -> Self {
        Self::new(
            Ed2kServerFailurePhase::Connect,
            Ed2kServerFailureReason::TimeoutUnreachable,
            detail,
        )
    }

    pub(super) fn connect_io(endpoint: impl fmt::Display, error: &io::Error) -> Self {
        let reason = match error.kind() {
            io::ErrorKind::ConnectionRefused => Ed2kServerFailureReason::ConnectionRefused,
            io::ErrorKind::TimedOut
            | io::ErrorKind::NetworkUnreachable
            | io::ErrorKind::HostUnreachable => Ed2kServerFailureReason::TimeoutUnreachable,
            io::ErrorKind::AddrInUse
            | io::ErrorKind::AddrNotAvailable
            | io::ErrorKind::PermissionDenied => Ed2kServerFailureReason::LocalBindInterface,
            _ => Ed2kServerFailureReason::TransportOther,
        };
        Self::new(
            Ed2kServerFailurePhase::Connect,
            reason,
            format!("failed to connect to ED2K server {endpoint}: {error}"),
        )
    }

    pub(super) fn protocol_rejection(detail: impl Into<String>) -> Self {
        Self::new(
            Ed2kServerFailurePhase::Handshake,
            Ed2kServerFailureReason::ProtocolRejection,
            detail,
        )
    }

    pub(super) fn from_session_error(error: &anyhow::Error, was_connected: bool) -> Self {
        if was_connected {
            return Self::new(
                Ed2kServerFailurePhase::Established,
                Ed2kServerFailureReason::EstablishedDisconnect,
                error.to_string(),
            );
        }
        if let Some(classified) = error.chain().find_map(|cause| cause.downcast_ref::<Self>()) {
            return classified.clone();
        }
        Self::new(
            Ed2kServerFailurePhase::Handshake,
            Ed2kServerFailureReason::TransportOther,
            error.to_string(),
        )
    }
}

impl fmt::Display for Ed2kServerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "phase={} reason={} detail={}",
            self.phase.as_str(),
            self.reason.as_str(),
            self.detail
        )
    }
}

impl std::error::Error for Ed2kServerFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_connect_refusal_counts_toward_dead_server() {
        let phases = [
            Ed2kServerFailurePhase::Resolve,
            Ed2kServerFailurePhase::SocketSetup,
            Ed2kServerFailurePhase::Connect,
            Ed2kServerFailurePhase::Handshake,
            Ed2kServerFailurePhase::Established,
        ];
        let reasons = [
            Ed2kServerFailureReason::ConnectionRefused,
            Ed2kServerFailureReason::DnsResolution,
            Ed2kServerFailureReason::LocalBindInterface,
            Ed2kServerFailureReason::TimeoutUnreachable,
            Ed2kServerFailureReason::ProtocolRejection,
            Ed2kServerFailureReason::EstablishedDisconnect,
            Ed2kServerFailureReason::TransportOther,
        ];
        for phase in phases {
            for reason in reasons {
                let failure = Ed2kServerFailure::new(phase, reason, "test");
                assert_eq!(
                    failure.counts_toward_dead_server(),
                    phase == Ed2kServerFailurePhase::Connect
                        && reason == Ed2kServerFailureReason::ConnectionRefused,
                    "unexpected policy for {failure}"
                );
            }
        }
    }

    #[test]
    fn connect_io_classification_is_stable() {
        let cases = [
            (
                io::ErrorKind::ConnectionRefused,
                Ed2kServerFailureReason::ConnectionRefused,
            ),
            (
                io::ErrorKind::TimedOut,
                Ed2kServerFailureReason::TimeoutUnreachable,
            ),
            (
                io::ErrorKind::NetworkUnreachable,
                Ed2kServerFailureReason::TimeoutUnreachable,
            ),
            (
                io::ErrorKind::AddrNotAvailable,
                Ed2kServerFailureReason::LocalBindInterface,
            ),
            (
                io::ErrorKind::ConnectionReset,
                Ed2kServerFailureReason::TransportOther,
            ),
        ];
        for (kind, expected) in cases {
            let failure = Ed2kServerFailure::connect_io("127.0.0.1:4661", &io::Error::from(kind));
            assert_eq!(failure.reason, expected);
        }
    }

    #[test]
    fn established_state_overrides_nested_connect_classification() {
        let error = anyhow::Error::new(Ed2kServerFailure::connect_io(
            "127.0.0.1:4661",
            &io::Error::from(io::ErrorKind::ConnectionRefused),
        ));
        let failure = Ed2kServerFailure::from_session_error(&error, true);
        assert_eq!(failure.phase, Ed2kServerFailurePhase::Established);
        assert_eq!(
            failure.reason,
            Ed2kServerFailureReason::EstablishedDisconnect
        );
        assert!(!failure.counts_toward_dead_server());
    }
}
