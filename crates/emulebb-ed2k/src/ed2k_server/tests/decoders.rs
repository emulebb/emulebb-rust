use super::*;

#[test]
fn server_ident_parser_extracts_name_and_description() {
    let mut payload = vec![0u8; 22];
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
    payload.push(ST_SERVERNAME);
    payload.extend_from_slice(b"test");
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
    payload.push(ST_DESCRIPTION);
    payload.extend_from_slice(b"desc");

    let (name, description) = decode_server_ident(&payload).unwrap();

    assert_eq!(name.as_deref(), Some("test"));
    assert_eq!(description.as_deref(), Some("desc"));
}

#[test]
fn server_ident_parser_skips_non_short_named_tags() {
    let mut payload = vec![0u8; 22];
    payload.extend_from_slice(&2u32.to_le_bytes());
    payload.push(TAGTYPE_UINT32);
    payload.extend_from_slice(&4u16.to_le_bytes());
    payload.extend_from_slice(b"misc");
    payload.extend_from_slice(&7u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 3));
    payload.push(ST_SERVERNAME);
    payload.extend_from_slice(b"test");

    let (name, description) = decode_server_ident(&payload).unwrap();

    assert_eq!(name.as_deref(), Some("test"));
    assert_eq!(description, None);
}

#[test]
fn search_results_decoder_extracts_count_and_names() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&[0x11; 16]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 9));
    payload.push(FT_FILENAME);
    payload.extend_from_slice(b"ubuntu.iso");
    payload.push(0x00);

    let summary = decode_search_results(&payload).unwrap();

    assert_eq!(summary.count, 1);
    assert_eq!(summary.sample_names, vec!["ubuntu.iso".to_string()]);
}

#[test]
fn search_results_decoder_extracts_size_type_and_sources() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(&[0x22; 16]);
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.extend_from_slice(&4u32.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 9));
    payload.push(FT_FILENAME);
    payload.extend_from_slice(b"ubuntu.iso");
    payload.push(super::TAGTYPE_UINT64);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(FT_FILESIZE);
    payload.extend_from_slice(&4_294_967_300u64.to_le_bytes());
    payload.push(TAG_SHORT_NAME_MASK | (super::TAGTYPE_STR1 + 4));
    payload.push(FT_FILETYPE);
    payload.extend_from_slice(b"Video");
    payload.push(TAGTYPE_UINT32);
    payload.extend_from_slice(&1u16.to_le_bytes());
    payload.push(FT_SOURCES);
    payload.extend_from_slice(&12u32.to_le_bytes());
    payload.push(0x01);

    let page = decode_search_result_page(&payload).unwrap();
    let files = page.files;

    assert_eq!(files.len(), 1);
    assert_eq!(files[0].file_name.as_deref(), Some("ubuntu.iso"));
    assert_eq!(files[0].file_size, Some(4_294_967_300));
    assert_eq!(files[0].file_type.as_deref(), Some("Video"));
    assert_eq!(files[0].source_count, Some(12));
    assert!(page.more_results_available);
}

#[test]
fn search_results_decoder_rejects_invalid_more_marker() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.push(0x7F);

    let error = decode_search_result_page(&payload).unwrap_err().to_string();

    assert!(error.contains("More marker"));
}

#[test]
fn found_sources_decoder_extracts_plain_sources() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xAA; 16]);
    payload.push(1);
    payload.extend_from_slice(&[10, 20, 30, 40]);
    payload.extend_from_slice(&4662u16.to_le_bytes());

    let sources = decode_found_sources(&payload, false).unwrap();
    let client_id = u32::from_le_bytes([10, 20, 30, 40]);

    assert_eq!(
        sources,
        vec![Ed2kFoundSource {
            file_hash: Ed2kHash([0xAA; 16]),
            ip: Ipv4Addr::new(10, 20, 30, 40),
            tcp_port: 4662,
            client_id,
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        }]
    );
}

#[test]
fn found_sources_decoder_marks_low_id_sources_as_callback_only() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xAB; 16]);
    payload.push(1);
    payload.extend_from_slice(&34254u32.to_le_bytes());
    payload.extend_from_slice(&4662u16.to_le_bytes());

    let sources = decode_found_sources(&payload, false).unwrap();
    let client_id = 34254u32;

    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].client_id, client_id);
    assert_eq!(sources[0].ip, ipv4_from_client_id(client_id));
    assert!(sources[0].low_id);
    assert!(!sources[0].is_direct_dialable());
}

#[test]
fn found_sources_decoder_extracts_obfuscated_sources_with_user_hash() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0xCC; 16]);
    payload.push(1);
    payload.extend_from_slice(&[10, 20, 30, 40]);
    payload.extend_from_slice(&4662u16.to_le_bytes());
    payload.push(SOURCE_OBFUSCATION_USER_HASH_PRESENT | 0x03);
    payload.extend_from_slice(&[0x61; 16]);

    let sources = decode_found_sources(&payload, true).unwrap();
    let client_id = u32::from_le_bytes([10, 20, 30, 40]);

    assert_eq!(
        sources,
        vec![Ed2kFoundSource {
            file_hash: Ed2kHash([0xCC; 16]),
            ip: Ipv4Addr::new(10, 20, 30, 40),
            tcp_port: 4662,
            client_id,
            low_id: false,
            obfuscated: true,
            obfuscation_options: Some(SOURCE_OBFUSCATION_USER_HASH_PRESENT | 0x03),
            user_hash: Some([0x61; 16]),
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        }]
    );
}

#[test]
fn found_sources_validation_rejects_hash_mismatch() {
    let error = validate_found_sources(
        &[Ed2kFoundSource {
            file_hash: Ed2kHash([0xAA; 16]),
            ip: Ipv4Addr::new(1, 2, 3, 4),
            tcp_port: 4662,
            client_id: u32::from(Ipv4Addr::new(1, 2, 3, 4)),
            low_id: false,
            obfuscated: false,
            obfuscation_options: None,
            user_hash: None,
            source_server: None,
            buddy_id: None,
            buddy_endpoint: None,
            source_udp_port: None,
        }],
        Ed2kHash([0xBB; 16]),
    )
    .unwrap_err()
    .to_string();

    assert!(error.contains("unexpected file hash"));
}
