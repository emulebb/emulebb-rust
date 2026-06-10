use super::*;

#[test]
fn secident_state_roundtrip_matches_wire_shape() {
    let packet = encode_secident_state(ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436EEAC);

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_SECIDENTSTATE);
    assert_eq!(
        decode_secident_state(&packet[6..]).unwrap(),
        (ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED, 0x4436EEAC)
    );
}

#[test]
fn public_key_payload_rejects_mismatched_length_prefix() {
    assert!(decode_public_key_payload(&[5, 1, 2, 3]).is_err());
}

#[test]
fn signature_payload_rejects_non_stock_length_prefixes() {
    let signature = decode_signature_payload(&peer_signature_payload()).unwrap();
    assert_eq!(signature.signature_len, 48);
    assert_eq!(signature.challenge_ip_kind, None);

    let mut v2_signature = peer_signature_payload();
    v2_signature.push(2);
    let signature = decode_signature_payload(&v2_signature).unwrap();
    assert_eq!(signature.signature_len, 48);
    assert_eq!(signature.challenge_ip_kind, Some(2));

    assert!(decode_signature_payload(&[]).is_err());
    assert!(decode_signature_payload(&[0xAA; 49]).is_err());
}

#[test]
fn secure_ident_probe_requests_key_and_signature() {
    let mut state = Ed2kPeerSecureIdentState::default();
    let packet = begin_secure_ident_probe(&mut state);
    let (request_state, challenge) = decode_secident_state(&packet[6..]).unwrap();

    assert_eq!(packet[0], OP_EMULEPROT);
    assert_eq!(packet[5], OP_SECIDENTSTATE);
    assert_eq!(request_state, ED2K_SECURE_IDENT_KEY_AND_SIGNATURE_NEEDED);
    assert_ne!(challenge, 0);
    assert_eq!(state.challenge_for, Some(challenge));
    assert!(state.requested_peer_key);
}

#[test]
fn secure_ident_signature_matches_oracle_message_shape() {
    let identity =
        Ed2kSecureIdent::from_private_key(RsaPrivateKey::new(&mut OsRng, 384).unwrap()).unwrap();
    let peer_public_key = RsaPublicKey::from(&RsaPrivateKey::new(&mut OsRng, 384).unwrap())
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let challenge = 0x4436EEAC;

    let payload = identity
        .signature_payload(&peer_public_key, challenge)
        .unwrap();
    let signature = Signature::try_from(&payload[1..]).unwrap();
    let mut message = peer_public_key.clone();
    message.extend_from_slice(&challenge.to_le_bytes());

    assert_eq!(usize::from(payload[0]), payload.len() - 1);
    assert!(
        VerifyingKey::<Sha1>::new(RsaPublicKey::from(&identity.private_key))
            .verify(&message, &signature)
            .is_ok()
    );
}
