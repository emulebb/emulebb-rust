//! Decoder for the eMule `CT_EMULE_MISCOPTIONS1` hello tag bitfield.
//!
//! `CT_EMULE_MISCOPTIONS1` is a packed `u32` of capability sub-fields that a
//! peer advertises in its OP_HELLO / OP_HELLOANSWER eMule tag set. The exact
//! bit layout mirrors the oracle `CUpDownClient::ProcessHelloTypePacket`
//! (`BaseClient.cpp:515-533`):
//!
//! ```text
//!   bits 29-31 (3)  AICH version          (m_fSupportsAICH)
//!   bit  28    (1)  Unicode support       (m_bUnicodeSupport)
//!   bits 24-27 (4)  UDP version           (m_byUDPVer)
//!   bits 20-23 (4)  Data compression ver  (m_byDataCompVer)
//!   bits 16-19 (4)  Secure ident          (m_bySupportSecIdent)
//!   bits 12-15 (4)  Source Exchange ver   (deprecated and ignored by the oracle)
//!   bits  8-11 (4)  Ext. requests ver     (m_byExtendedRequestsVer)
//!   bits  4-7  (4)  Accept comment ver    (m_byAcceptCommentVer)
//!   bit  2     (1)  No 'View Shared Files' (m_fNoViewSharedFiles)
//!   bit  1     (1)  MultiPacket           (m_bMultiPacket)
//!   bit  0     (1)  Preview               (m_fSupportsPreview)
//! ```
//!
//! Oracle reference (do not modify): `srchybrid/BaseClient.cpp`
//! `CUpDownClient::ProcessHelloTypePacket` `case CT_EMULE_MISCOPTIONS1`.

/// Fully-decoded `CT_EMULE_MISCOPTIONS1` capability bitfield.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct MiscOptions1 {
    /// AICH version (`m_fSupportsAICH`), the full 3-bit field (bits 29-31). The
    /// oracle keeps the whole value, not just the low bit; AICH is supported when
    /// this is non-zero.
    pub(super) aich_version: u8,
    /// Unicode support (`m_bUnicodeSupport`, bit 28).
    pub(super) unicode_support: bool,
    /// eD2k UDP version (`m_byUDPVer`, bits 24-27).
    pub(super) udp_version: u8,
    /// Data compression version (`m_byDataCompVer`, bits 20-23).
    pub(super) data_compression_version: u8,
    /// Secure-identification level (`m_bySupportSecIdent`, bits 16-19).
    pub(super) secure_ident: u8,
    /// Extended-requests version (`m_byExtendedRequestsVer`, bits 8-11).
    pub(super) extended_requests_version: u8,
    /// Accepted-comment version (`m_byAcceptCommentVer`, bits 4-7).
    pub(super) accept_comment_version: u8,
    /// Peer does not permit a "View Shared Files" browse (`m_fNoViewSharedFiles`,
    /// bit 2).
    pub(super) no_view_shared_files: bool,
    /// MultiPacket support (`m_bMultiPacket`, bit 1).
    pub(super) multipacket: bool,
    /// Preview support (`m_fSupportsPreview`, bit 0).
    pub(super) preview: bool,
}

impl MiscOptions1 {
    /// AICH is supported when the 3-bit version field is non-zero (oracle treats
    /// `m_fSupportsAICH` as a truthy version, not a single flag bit).
    pub(super) fn supports_aich(self) -> bool {
        self.aich_version != 0
    }

    /// Secure identification is supported when its sub-field is non-zero.
    pub(super) fn supports_secure_ident(self) -> bool {
        self.secure_ident != 0
    }
}

/// Decode every `CT_EMULE_MISCOPTIONS1` sub-field from the packed `u32`, matching
/// `BaseClient.cpp:515-533` shift/mask widths exactly.
pub(super) fn decode_misc_options1(value: u32) -> MiscOptions1 {
    MiscOptions1 {
        aich_version: ((value >> 29) & 0x07) as u8,
        unicode_support: ((value >> 28) & 0x01) != 0,
        udp_version: ((value >> 24) & 0x0F) as u8,
        data_compression_version: ((value >> 20) & 0x0F) as u8,
        secure_ident: ((value >> 16) & 0x0F) as u8,
        extended_requests_version: ((value >> 8) & 0x0F) as u8,
        accept_comment_version: ((value >> 4) & 0x0F) as u8,
        no_view_shared_files: ((value >> 2) & 0x01) != 0,
        multipacket: ((value >> 1) & 0x01) != 0,
        preview: (value & 0x01) != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_all_subfields_from_oracle_layout() {
        // Build a value with a distinct pattern in each field so a wrong shift or
        // mask shows up. Widths: AICH 3, Unicode 1, UDP 4, DataComp 4, SecIdent 4,
        // SX 4 (ignored), ExtReq 4, Comment 4, NoView 1, Multi 1, Preview 1.
        let value = (0b101u32 << 29) // AICH version = 5
            | (1u32 << 28)            // Unicode
            | (0x4u32 << 24)          // UDP version 4
            | (0x6u32 << 20)          // data compression 6
            | (0x3u32 << 16)          // secure ident 3
            | (0xFu32 << 12)          // SX (ignored) — must not leak into others
            | (0x2u32 << 8)           // ext requests 2
            | (0x7u32 << 4)           // accept comment 7
            | (1u32 << 2)             // no view shared files
            | (1u32 << 1)             // multipacket
            | 1u32; // preview

        let decoded = decode_misc_options1(value);
        assert_eq!(decoded.aich_version, 5);
        assert!(decoded.supports_aich());
        assert!(decoded.unicode_support);
        assert_eq!(decoded.udp_version, 4);
        assert_eq!(decoded.data_compression_version, 6);
        assert_eq!(decoded.secure_ident, 3);
        assert!(decoded.supports_secure_ident());
        assert_eq!(decoded.extended_requests_version, 2);
        assert_eq!(decoded.accept_comment_version, 7);
        assert!(decoded.no_view_shared_files);
        assert!(decoded.multipacket);
        assert!(decoded.preview);
    }

    #[test]
    fn full_aich_version_is_not_collapsed_to_one_bit() {
        // AICH version 0b110 (=6): the low bit is 0, so a `& 0x01` collapse would
        // wrongly report "no AICH". The full 3-bit field must survive.
        let value = 0b110u32 << 29;
        let decoded = decode_misc_options1(value);
        assert_eq!(decoded.aich_version, 6);
        assert!(
            decoded.supports_aich(),
            "non-zero AICH version means supported"
        );
    }

    #[test]
    fn zero_value_is_all_unset() {
        let decoded = decode_misc_options1(0);
        assert_eq!(decoded, MiscOptions1::default());
        assert!(!decoded.supports_aich());
        assert!(!decoded.supports_secure_ident());
        assert!(!decoded.preview);
    }

    #[test]
    fn fields_do_not_bleed_across_boundaries() {
        // Only UDP version set to its max (0xF): nothing else should be non-zero.
        let decoded = decode_misc_options1(0xFu32 << 24);
        assert_eq!(decoded.udp_version, 0xF);
        assert_eq!(decoded.data_compression_version, 0);
        assert_eq!(decoded.secure_ident, 0);
        assert_eq!(decoded.aich_version, 0);
        assert!(!decoded.unicode_support);
    }
}
