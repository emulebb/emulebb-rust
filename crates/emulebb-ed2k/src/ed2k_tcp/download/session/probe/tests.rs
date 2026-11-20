use super::*;

fn reply(opcode: u8, payload: Vec<u8>) -> EmuleTcpPacket {
    EmuleTcpPacket {
        protocol: OP_EDONKEYPROT,
        opcode,
        payload,
    }
}

#[test]
fn availability_requires_matching_hash_and_valid_geometry() {
    let hash = Ed2kHash([0x11; 16]);
    let mut name = None;
    let mut payload = hash.0.to_vec();
    payload.extend_from_slice(&[2, 0, 1]);
    let packet = reply(OP_FILESTATUS, payload.clone());
    assert_eq!(
        decode_probe_reply(&packet, hash, ED2K_PART_SIZE + 1, 2, true, &mut name).unwrap(),
        ProbeReply::Parts(vec![true, false])
    );
    assert!(
        decode_probe_reply(
            &packet,
            Ed2kHash([0x22; 16]),
            ED2K_PART_SIZE + 1,
            2,
            true,
            &mut name
        )
        .is_err()
    );
    assert!(decode_probe_reply(&packet, hash, ED2K_PART_SIZE * 2, 2, true, &mut name).is_err());
    payload.truncate(17);
    assert!(
        decode_probe_reply(
            &reply(OP_FILESTATUS, payload),
            hash,
            ED2K_PART_SIZE + 1,
            2,
            true,
            &mut name
        )
        .is_err()
    );
}

#[test]
fn complete_status_and_protocol_eof_are_normalized_to_data_parts() {
    let hash = Ed2kHash([0x33; 16]);
    let mut payload = hash.0.to_vec();
    payload.extend_from_slice(&[0, 0]);
    assert_eq!(
        decode_probe_reply(
            &reply(OP_FILESTATUS, payload),
            hash,
            ED2K_PART_SIZE * 2,
            2,
            true,
            &mut None
        )
        .unwrap(),
        ProbeReply::Parts(vec![true, true])
    );
    let mut payload = hash.0.to_vec();
    payload.extend_from_slice(&[3, 0, 0b101]);
    assert_eq!(
        decode_probe_reply(
            &reply(OP_FILESTATUS, payload),
            hash,
            ED2K_PART_SIZE * 2,
            2,
            true,
            &mut None
        )
        .unwrap(),
        ProbeReply::Parts(vec![true, false])
    );
}

#[test]
fn filename_proves_only_single_part_availability() {
    let hash = Ed2kHash([0x44; 16]);
    let packet = crate::ed2k_tcp::encode_request_filename_answer(
        &hash,
        "Sample.bin",
        Ed2kStringEncoding::Utf8,
    )
    .unwrap();
    let packet = reply(OP_REQFILENAMEANSWER, packet[6..].to_vec());
    let mut name = None;
    assert_eq!(
        decode_probe_reply(&packet, hash, 100, 1, true, &mut name).unwrap(),
        ProbeReply::Parts(vec![true])
    );
    assert_eq!(name.as_deref(), Some("Sample.bin"));
    assert_eq!(
        decode_probe_reply(&packet, hash, ED2K_PART_SIZE + 1, 2, true, &mut name).unwrap(),
        ProbeReply::Continue
    );
}

#[test]
fn multipacket_rejects_conflicting_size_and_unrecognized_subpackets() {
    let hash = Ed2kHash([0x55; 16]);
    let frame = crate::ed2k_tcp::encode_multipacket_ext2_answer(
        &Ed2kFileIdentifier {
            file_hash: hash,
            file_size: Some(ED2K_PART_SIZE * 3),
            aich_root: None,
        },
        "Sample.bin",
        Ed2kStringEncoding::Utf8,
        true,
        Some(&[0, 0]),
    )
    .unwrap();
    let packet = EmuleTcpPacket {
        protocol: OP_EMULEPROT,
        opcode: OP_MULTIPACKETANSWER_EXT2,
        payload: frame[6..].to_vec(),
    };
    assert!(decode_probe_reply(&packet, hash, ED2K_PART_SIZE + 1, 2, true, &mut None).is_err());
    let mut payload = hash.0.to_vec();
    payload.push(0xff);
    let packet = EmuleTcpPacket {
        protocol: OP_EMULEPROT,
        opcode: OP_MULTIPACKETANSWER,
        payload,
    };
    assert!(decode_probe_reply(&packet, hash, ED2K_PART_SIZE + 1, 2, true, &mut None).is_err());
}
