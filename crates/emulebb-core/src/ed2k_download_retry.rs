//! eD2K download retry-state decisions.

pub(crate) fn should_retry_after_exhausted_direct_sources(
    had_direct_sources: bool,
    has_last_direct_error: bool,
) -> bool {
    had_direct_sources && has_last_direct_error
}

#[cfg(test)]
mod tests {
    use super::should_retry_after_exhausted_direct_sources;

    #[test]
    fn direct_peer_failures_keep_active_transfer_retrying() {
        assert!(should_retry_after_exhausted_direct_sources(true, true));
        assert!(!should_retry_after_exhausted_direct_sources(false, true));
        assert!(!should_retry_after_exhausted_direct_sources(true, false));
    }
}
