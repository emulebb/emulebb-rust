//! Causal `diag_event_v2` records for authoritative ED2K server UDP metadata
//! mutations. Wire capture lives in `emulebb-ed2k`; these applied records live
//! here because the core owns the persisted server store.

use emulebb_ed2k::{
    diag_event::emit,
    ed2k_server::{
        Ed2kServerUdpDescriptionEvidence, Ed2kServerUdpEvidence, Ed2kServerUdpStatusEvidence,
    },
};
use serde_json::{Map, Value, json};

const FAMILY: &str = "ed2k_server_udp";
const OP_EDONKEYPROT: u8 = 0xE3;
const OP_GLOBSERVSTATRES: u8 = 0x97;
const OP_SERVER_DESC_RES: u8 = 0xA3;

fn applied_parts(
    evidence: Ed2kServerUdpEvidence,
    challenge: u32,
    server_endpoint: &str,
    opcode: u8,
    opcode_name: &str,
    fields: Value,
) -> (Value, Value) {
    let peer = evidence.peer().to_string();
    let trace_id = evidence.trace_id();
    let transport = evidence.transport();
    let mut body = fields.as_object().cloned().unwrap_or_default();
    body.extend(Map::from_iter([
        ("direction".to_string(), json!("meta")),
        ("outcome".to_string(), json!("applied")),
        ("protocolMarker".to_string(), json!(OP_EDONKEYPROT)),
        ("protocolName".to_string(), json!("ed2k")),
        ("opcode".to_string(), json!(opcode)),
        ("opcodeName".to_string(), json!(opcode_name)),
        ("challenge".to_string(), json!(challenge)),
        ("obfuscated".to_string(), json!(transport.obfuscated())),
        ("transportMode".to_string(), json!(transport.as_str())),
        ("flow".to_string(), json!("server")),
        ("phase".to_string(), json!("udp")),
        ("role".to_string(), json!("udp")),
        ("traceId".to_string(), json!(trace_id)),
        (
            "traceKey".to_string(),
            json!(format!("server:udp:{trace_id}:{peer}")),
        ),
        ("stateId".to_string(), json!("server.udp.applied")),
        ("stateLabel".to_string(), json!("applied")),
        ("serverEndpoint".to_string(), json!(server_endpoint)),
    ]));
    (
        json!({
            "peer": peer,
            "traceId": trace_id,
            "protocolMarker": OP_EDONKEYPROT,
            "opcode": opcode,
            "challenge": challenge,
        }),
        Value::Object(body),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "flat decoded server-status fields are the parity evidence contract"
)]
pub(crate) fn server_status_applied(
    evidence: Ed2kServerUdpStatusEvidence,
    server_endpoint: &str,
    users: u32,
    files: u32,
    max_users: u32,
    low_id_users: u32,
    ping_ms: u32,
    soft_files: u32,
    hard_files: u32,
    udp_flags: u32,
    udp_key: u32,
    udp_key_ip: u32,
    obfuscation_port_tcp: u16,
    obfuscation_port_udp: u16,
) {
    let (keys, body) = server_status_applied_parts(
        evidence,
        server_endpoint,
        users,
        files,
        max_users,
        low_id_users,
        ping_ms,
        soft_files,
        hard_files,
        udp_flags,
        udp_key,
        udp_key_ip,
        obfuscation_port_tcp,
        obfuscation_port_udp,
    );
    emit(FAMILY, "server_status_applied", "info", keys, body);
}

#[expect(
    clippy::too_many_arguments,
    reason = "flat decoded server-status fields are the parity evidence contract"
)]
fn server_status_applied_parts(
    evidence: Ed2kServerUdpStatusEvidence,
    server_endpoint: &str,
    users: u32,
    files: u32,
    max_users: u32,
    low_id_users: u32,
    ping_ms: u32,
    soft_files: u32,
    hard_files: u32,
    udp_flags: u32,
    udp_key: u32,
    udp_key_ip: u32,
    obfuscation_port_tcp: u16,
    obfuscation_port_udp: u16,
) -> (Value, Value) {
    applied_parts(
        evidence.receive(),
        evidence.challenge(),
        server_endpoint,
        OP_GLOBSERVSTATRES,
        "OP_GLOBSERVSTATRES",
        json!({
            "users": users,
            "files": files,
            "maxUsers": max_users,
            "lowIdUsers": low_id_users,
            "pingMs": ping_ms,
            "softFiles": soft_files,
            "hardFiles": hard_files,
            "udpFlags": udp_flags,
            "udpKey": udp_key,
            "udpKeyIp": udp_key_ip,
            "obfuscationPortTcp": obfuscation_port_tcp,
            "obfuscationPortUdp": obfuscation_port_udp,
        }),
    )
}

pub(crate) fn server_description_applied(
    evidence: Ed2kServerUdpDescriptionEvidence,
    server_endpoint: &str,
    name: Option<&str>,
    description: Option<&str>,
    dynamic_host: Option<&str>,
    version: Option<&str>,
    auxiliary_ports: &[u16],
) {
    let (keys, body) = server_description_applied_parts(
        evidence,
        server_endpoint,
        name,
        description,
        dynamic_host,
        version,
        auxiliary_ports,
    );
    emit(FAMILY, "server_description_applied", "info", keys, body);
}

fn server_description_applied_parts(
    evidence: Ed2kServerUdpDescriptionEvidence,
    server_endpoint: &str,
    name: Option<&str>,
    description: Option<&str>,
    dynamic_host: Option<&str>,
    version: Option<&str>,
    auxiliary_ports: &[u16],
) -> (Value, Value) {
    applied_parts(
        evidence.receive(),
        evidence.challenge(),
        server_endpoint,
        OP_SERVER_DESC_RES,
        "OP_SERVER_DESC_RES",
        json!({
            "responseFormat": evidence.response_format().as_str(),
            "name": name,
            "description": description,
            "dynamicHost": dynamic_host,
            "version": version,
            "auxiliaryPorts": auxiliary_ports,
        }),
    )
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use emulebb_ed2k::ed2k_server::{
        Ed2kServerDescriptionResponseFormat, Ed2kServerUdpDescriptionEvidence,
        Ed2kServerUdpEvidence, Ed2kServerUdpStatusEvidence, Ed2kServerUdpTransport,
    };

    use super::*;

    #[test]
    fn status_applied_preserves_correlation_transport_and_exact_fields() {
        let peer: SocketAddr = "198.51.100.7:4673".parse().unwrap();
        let receive = Ed2kServerUdpEvidence::new(41, Ed2kServerUdpTransport::Obfuscated, peer);
        let evidence = Ed2kServerUdpStatusEvidence::new(receive, 0x55AA_1234);
        let (keys, body) = server_status_applied_parts(
            evidence,
            "198.51.100.7:4661",
            11,
            22,
            33,
            44,
            55,
            66,
            77,
            0x1234,
            0x5566_7788,
            0x0102_0304,
            4711,
            4723,
        );

        assert_eq!(
            keys,
            json!({
                "peer": peer.to_string(),
                "traceId": 41,
                "protocolMarker": OP_EDONKEYPROT,
                "opcode": OP_GLOBSERVSTATRES,
                "challenge": 0x55AA_1234u32,
            })
        );
        assert_eq!(
            body,
            json!({
                "direction": "meta",
                "outcome": "applied",
                "protocolMarker": OP_EDONKEYPROT,
                "protocolName": "ed2k",
                "opcode": OP_GLOBSERVSTATRES,
                "opcodeName": "OP_GLOBSERVSTATRES",
                "challenge": 0x55AA_1234u32,
                "serverEndpoint": "198.51.100.7:4661",
                "obfuscated": true,
                "transportMode": "obfuscated",
                "flow": "server",
                "phase": "udp",
                "role": "udp",
                "traceId": 41,
                "traceKey": format!("server:udp:41:{peer}"),
                "stateId": "server.udp.applied",
                "stateLabel": "applied",
                "users": 11,
                "files": 22,
                "maxUsers": 33,
                "softFiles": 66,
                "hardFiles": 77,
                "udpFlags": 0x1234,
                "lowIdUsers": 44,
                "obfuscationPortUdp": 4723,
                "obfuscationPortTcp": 4711,
                "udpKey": 0x5566_7788u32,
                "udpKeyIp": 0x0102_0304u32,
                "pingMs": 55,
            })
        );
    }

    #[test]
    fn description_applied_preserves_plaintext_and_optional_metadata() {
        let peer: SocketAddr = "192.0.2.10:4665".parse().unwrap();
        let receive = Ed2kServerUdpEvidence::new(73, Ed2kServerUdpTransport::Plaintext, peer);
        let evidence = Ed2kServerUdpDescriptionEvidence::new(
            receive,
            0x1234_F0FF,
            Ed2kServerDescriptionResponseFormat::Tagged,
        );
        let (keys, body) = server_description_applied_parts(
            evidence,
            "192.0.2.10:4661",
            Some("Server"),
            Some("Description"),
            Some("server.example.test"),
            Some("17.06"),
            &[4662, 4663],
        );

        assert_eq!(
            keys,
            json!({
                "peer": peer.to_string(),
                "traceId": 73,
                "protocolMarker": OP_EDONKEYPROT,
                "opcode": OP_SERVER_DESC_RES,
                "challenge": 0x1234_F0FFu32,
            })
        );
        assert_eq!(
            body,
            json!({
                "direction": "meta",
                "outcome": "applied",
                "protocolMarker": OP_EDONKEYPROT,
                "protocolName": "ed2k",
                "opcode": OP_SERVER_DESC_RES,
                "opcodeName": "OP_SERVER_DESC_RES",
                "challenge": 0x1234_F0FFu32,
                "serverEndpoint": "192.0.2.10:4661",
                "obfuscated": false,
                "transportMode": "plaintext",
                "flow": "server",
                "phase": "udp",
                "role": "udp",
                "traceId": 73,
                "traceKey": format!("server:udp:73:{peer}"),
                "stateId": "server.udp.applied",
                "stateLabel": "applied",
                "responseFormat": "tagged",
                "name": "Server",
                "description": "Description",
                "dynamicHost": "server.example.test",
                "version": "17.06",
                "auxiliaryPorts": [4662, 4663],
            })
        );
    }
}
