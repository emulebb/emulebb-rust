//! GPL-evildoer mod-version detection for inbound peers (eMule
//! `CUpDownClient::CheckForGPLEvilDoer`).

/// Whether a peer's `CT_MOD_VERSION` string matches the known major GPL-breaker
/// prefixes (eMule `CheckForGPLEvilDoer`: case-insensitive `LH`, `LIO`, or
/// `PLUS PLUS`, after skipping leading spaces). A GPL-breaker's upload score is
/// zeroed by the upload-queue score path.
pub(super) fn is_gpl_evildoer_mod_version(mod_version: &str) -> bool {
    let trimmed = mod_version.trim_start_matches(' ');
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("lh") || lower.starts_with("lio") || lower.starts_with("plus plus")
}

#[cfg(test)]
mod tests {
    use super::is_gpl_evildoer_mod_version;

    #[test]
    fn flags_known_gpl_breaker_prefixes() {
        assert!(is_gpl_evildoer_mod_version("LH"));
        assert!(is_gpl_evildoer_mod_version("lio mod"));
        assert!(is_gpl_evildoer_mod_version("  PLUS PLUS 1.0"));
        // Case-insensitive, after skipping leading spaces.
        assert!(is_gpl_evildoer_mod_version("  lh-x"));
    }

    #[test]
    fn allows_unrelated_mod_versions() {
        assert!(!is_gpl_evildoer_mod_version("emule-rust"));
        assert!(!is_gpl_evildoer_mod_version(""));
        assert!(!is_gpl_evildoer_mod_version("Xtreme 8.1"));
    }
}
