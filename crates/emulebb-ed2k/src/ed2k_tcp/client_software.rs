//! eMule "compatible client" software identification.
//!
//! Derives a human-readable client-software string (e.g. `eMule v0.60.0`,
//! `aMule v2.3.1`) from the peer's `CT_EMULE_VERSION` handshake tag, mirroring
//! eMule's `CUpDownClient` handling in `BaseClient.cpp`: the tag's top byte is
//! the compatible-client id (`Constants.h` `SO_*`) and the low three bytes pack
//! the version as `major:minor:update:build` bitfields. Read/display only -- this
//! never affects what we put on the wire, so it does not touch protocol parity.

/// eMule compatible-client identifiers: the top byte of `CT_EMULE_VERSION` (also
/// carried standalone in the `ET_COMPATIBLECLIENT` tag). Values match eMule
/// `Constants.h`.
const SO_EMULE: u8 = 0;
const SO_CDONKEY: u8 = 1;
const SO_XMULE: u8 = 2;
const SO_AMULE: u8 = 3;
const SO_SHAREAZA: u8 = 4;
const SO_LPHANT: u8 = 0x14;
const SO_SHAREAZA_NEW2: u8 = 0x28;
const SO_NEW2_MLDONKEY: u8 = 0x0a;
const SO_MLDONKEY: u8 = 0x34;
const SO_NEW_MLDONKEY: u8 = 0x98;

/// Map an eMule compatible-client id to its software name (eMule
/// `BaseClient.cpp` `m_byCompatibleClient` switch).
fn compatible_client_name(compatible: u8) -> &'static str {
    match compatible {
        SO_CDONKEY => "cDonkey",
        SO_XMULE => "xMule",
        SO_AMULE => "aMule",
        SO_SHAREAZA | SO_SHAREAZA_NEW2 => "Shareaza",
        SO_LPHANT => "lphant",
        SO_NEW2_MLDONKEY | SO_MLDONKEY | SO_NEW_MLDONKEY => "MLdonkey",
        SO_EMULE => "eMule",
        // Any other non-zero compatible id is an eMule-protocol-compatible client.
        _ => "eMule Compat",
    }
}

/// Build a client-software string from a decoded `CT_EMULE_VERSION` tag value.
///
/// eMule packs the tag as `(compatible_client << 24) | (major << 17) |
/// (minor << 10) | (update << 7) | build`. We render `name vMAJOR.MINOR.UPDATE`,
/// or just the name when the tag carries no version.
pub(crate) fn client_software_from_emule_version(tag: u32) -> String {
    let compatible = ((tag >> 24) & 0xff) as u8;
    let name = compatible_client_name(compatible);
    let version = tag & 0x00ff_ffff;
    if version == 0 {
        return name.to_string();
    }
    let major = (version >> 17) & 0x7f;
    let minor = (version >> 10) & 0x7f;
    let update = (version >> 7) & 0x07;
    format!("{name} v{major}.{minor}.{update}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(compatible: u8, major: u32, minor: u32, update: u32) -> u32 {
        ((compatible as u32) << 24) | (major << 17) | (minor << 10) | (update << 7)
    }

    #[test]
    fn emule_with_version() {
        assert_eq!(
            client_software_from_emule_version(pack(SO_EMULE, 0, 60, 0)),
            "eMule v0.60.0"
        );
    }

    #[test]
    fn named_clients_map_and_format() {
        assert_eq!(
            client_software_from_emule_version(pack(SO_AMULE, 2, 3, 1)),
            "aMule v2.3.1"
        );
        assert_eq!(
            client_software_from_emule_version(pack(SO_SHAREAZA_NEW2, 1, 0, 0)),
            "Shareaza v1.0.0"
        );
        assert_eq!(
            client_software_from_emule_version(pack(SO_MLDONKEY, 3, 0, 0)),
            "MLdonkey v3.0.0"
        );
    }

    #[test]
    fn unknown_compatible_is_emule_compat() {
        assert_eq!(
            client_software_from_emule_version(pack(0x77, 1, 0, 0)),
            "eMule Compat v1.0.0"
        );
    }

    #[test]
    fn zero_version_is_bare_name() {
        assert_eq!(client_software_from_emule_version(0), "eMule");
        assert_eq!(
            client_software_from_emule_version(pack(SO_AMULE, 0, 0, 0)),
            "aMule"
        );
    }
}
