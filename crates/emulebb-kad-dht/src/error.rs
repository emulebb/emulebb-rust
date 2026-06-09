#[derive(Debug, thiserror::Error)]
pub enum DhtError {
    #[error("Kad bind address is required")]
    MissingBindAddr,
    #[error("network error: {0}")]
    Net(#[from] emulebb_kad_net::NetError),
    #[error("no bootstrap nodes available")]
    NoBootstrapNodes,
    #[error("bootstrap failed - no node responded")]
    BootstrapFailed,
    #[error("search timed out")]
    SearchTimeout,
    #[error("publish failed - no node accepted")]
    PublishFailed,
    #[error("routing error: {0}")]
    Routing(#[from] emulebb_kad_routing::RoutingError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("nodes.dat parse error")]
    NodesDatParse,
    #[error("search semaphore closed")]
    SemaphoreClosed,
    #[error("unexpected packet type")]
    UnexpectedPacket,
}

#[cfg(test)]
mod tests {
    use super::DhtError;

    #[test]
    fn runtime_error_messages_are_ascii_only() {
        assert!(DhtError::MissingBindAddr.to_string().is_ascii());
        assert!(DhtError::BootstrapFailed.to_string().is_ascii());
        assert!(DhtError::PublishFailed.to_string().is_ascii());
    }
}
