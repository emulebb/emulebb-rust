//! Stable entry points for the separate `cargo-fuzz` package.
//!
//! Keeping the entry points here lets libFuzzer exercise private hand-written
//! codecs without making their intermediate types part of the normal public
//! API. The feature is absent from release builds.

/// Exercise one ED2K server binary parser selected by the first input byte.
pub fn server_binary_parsers(data: &[u8]) {
    crate::ed2k_server::fuzz_binary_parsers(data);
}

/// Exercise one ED2K peer-TCP binary parser selected by the first input byte.
pub fn peer_tcp_binary_parsers(data: &[u8]) {
    crate::ed2k_tcp::fuzz_binary_parsers(data);
}

/// Exercise the clear/encrypted client-UDP parser and its versioned bodies.
pub fn client_udp_binary_parser(data: &[u8]) {
    crate::ed2k_client_udp::fuzz_binary_parser(data);
}
