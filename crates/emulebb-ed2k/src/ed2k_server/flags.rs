use super::{
    SERVER_TCP_FLAG_COMPRESSION, SERVER_TCP_FLAG_LARGEFILES, SERVER_TCP_FLAG_NEWTAGS,
    SERVER_TCP_FLAG_RELATEDSEARCH, SERVER_TCP_FLAG_TCPOBFUSCATION, SERVER_TCP_FLAG_TYPETAGINTEGER,
    SERVER_TCP_FLAG_UNICODE,
};

pub(super) fn format_server_flags(flags: u32) -> String {
    let mut enabled = Vec::new();
    if flags & SERVER_TCP_FLAG_COMPRESSION != 0 {
        enabled.push("compression");
    }
    if flags & SERVER_TCP_FLAG_NEWTAGS != 0 {
        enabled.push("newtags");
    }
    if flags & SERVER_TCP_FLAG_UNICODE != 0 {
        enabled.push("unicode");
    }
    if flags & SERVER_TCP_FLAG_RELATEDSEARCH != 0 {
        enabled.push("related_search");
    }
    if flags & SERVER_TCP_FLAG_TYPETAGINTEGER != 0 {
        enabled.push("int_tags");
    }
    if flags & SERVER_TCP_FLAG_LARGEFILES != 0 {
        enabled.push("large_files");
    }
    if flags & SERVER_TCP_FLAG_TCPOBFUSCATION != 0 {
        enabled.push("tcp_obfuscation");
    }
    if enabled.is_empty() {
        format!("0x{flags:08X}")
    } else {
        format!("0x{flags:08X} [{}]", enabled.join(","))
    }
}

pub(super) fn format_connect_options(connect_options: u8) -> String {
    let mut parts = Vec::new();
    if connect_options & 0x01 != 0 {
        parts.push("supports_crypt");
    }
    if connect_options & 0x02 != 0 {
        parts.push("requests_crypt");
    }
    if connect_options & 0x04 != 0 {
        parts.push("requires_crypt");
    }
    if parts.is_empty() {
        return format!("0x{connect_options:02X}");
    }
    format!("0x{connect_options:02X} ({})", parts.join("|"))
}

pub(super) fn is_low_id(client_id: u32) -> bool {
    client_id < 0x0100_0000
}
