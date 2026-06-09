/// Scope of a routing-table subnet-limit rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingSubnetLimitScope {
    /// The table-wide `/24` cap rejected the contact.
    Global,
    /// The destination bin already has the oracle-local `/24` allotment.
    BinLocal,
}

/// Why a full leaf bin was not allowed to split further.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingSplitDeniedReason {
    /// The routing tree already reached the hard Kad depth ceiling.
    DepthLimit,
    /// The local table-size ceiling blocked further expansion.
    MaxTableSize,
    /// Oracle `CanSplit` no longer allows this zone index to split at this depth.
    ZoneIndexCap,
}

/// Routing-table insertion or split failures that matter for oracle parity.
#[derive(Debug, thiserror::Error)]
pub enum RoutingError {
    /// The table-level hard cap blocked further growth.
    #[error("routing table is full (max {max} contacts)")]
    TableFull { max: usize },
    /// The oracle one-per-IP rule rejected this contact.
    #[error("duplicate IP: {ip}")]
    IpLimitExceeded { ip: std::net::Ipv4Addr },
    /// A `/24` clustering limit rejected this contact.
    #[error("subnet /{prefix} limit exceeded in {scope:?} scope")]
    SubnetLimitExceeded {
        prefix: u8,
        scope: RoutingSubnetLimitScope,
    },
    /// A full leaf bin could not be split under the oracle `CanSplit` rules.
    #[error("routing leaf could not split because of {reason:?}")]
    SplitDenied { reason: RoutingSplitDeniedReason },
}
