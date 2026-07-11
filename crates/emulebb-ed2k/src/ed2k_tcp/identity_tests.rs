//! Unit tests for the eD2k secure-ident signing/verification in
//! [`super`][`crate::ed2k_tcp::identity`]. Kept in a sibling file so the
//! production module remains focused on the secure-ident implementation.

use super::*;

fn ident() -> Ed2kSecureIdent {
    Ed2kSecureIdent::generate().expect("keypair")
}

/// A peer signs `our_pubkey ‖ challenge` (+ optional V2 ip-kind trailer) with
/// its own RSA key, exactly as `CClientCreditsList::CreateSignature` does.
fn peer_sign(
    peer: &Ed2kSecureIdent,
    our_public_key_der: &[u8],
    challenge: u32,
    v2: Option<(u8, [u8; 4])>,
) -> SecureIdentSignature {
    use rsa::signature::SignatureEncoding;
    let mut message = Vec::new();
    message.extend_from_slice(our_public_key_der);
    message.extend_from_slice(&challenge.to_le_bytes());
    if let Some((ip_kind, ip)) = v2 {
        message.extend_from_slice(&ip);
        message.push(ip_kind);
    }
    let signing_key = SigningKey::<Sha1>::new(peer.private_key.clone());
    let bytes = signing_key.sign_with_rng(&mut OsRng, &message).to_bytes();
    SecureIdentSignature {
        signature_len: bytes.len() as u8,
        challenge_ip_kind: v2.map(|(kind, _)| kind),
        signature: bytes.to_vec(),
    }
}

#[test]
fn v1_valid_signature_verifies() {
    let us = ident();
    let peer = ident();
    let challenge = 0xDEAD_BEEF;
    let sig = peer_sign(&peer, us.public_key_der(), challenge, None);
    let ok = verify_inbound_signature(
        us.public_key_der(),
        challenge,
        peer.public_key_der(),
        &sig,
        Ipv4Addr::new(198, 51, 100, 7),
        None,
    )
    .expect("verify ran");
    assert!(ok, "a valid V1 signature must verify");
}

#[test]
fn tampered_signature_fails() {
    let us = ident();
    let peer = ident();
    let challenge = 0x0102_0304;
    let mut sig = peer_sign(&peer, us.public_key_der(), challenge, None);
    sig.signature[5] ^= 0xFF; // flip a byte
    let ok = verify_inbound_signature(
        us.public_key_der(),
        challenge,
        peer.public_key_der(),
        &sig,
        Ipv4Addr::new(198, 51, 100, 7),
        None,
    )
    .expect("verify ran");
    assert!(!ok, "a tampered signature must not verify");
}

#[test]
fn wrong_challenge_fails() {
    let us = ident();
    let peer = ident();
    let sig = peer_sign(&peer, us.public_key_der(), 0xAAAA_AAAA, None);
    // Verify with a different challenge than the one the peer signed over.
    let ok = verify_inbound_signature(
        us.public_key_der(),
        0xBBBB_BBBB,
        peer.public_key_der(),
        &sig,
        Ipv4Addr::new(198, 51, 100, 7),
        None,
    )
    .expect("verify ran");
    assert!(
        !ok,
        "a signature over a different challenge must not verify"
    );
}

#[test]
fn wrong_signer_key_fails() {
    let us = ident();
    let peer = ident();
    let impostor = ident();
    let challenge = 0x1111_2222;
    let sig = peer_sign(&peer, us.public_key_der(), challenge, None);
    // Verify the peer's signature against an impostor's public key.
    let ok = verify_inbound_signature(
        us.public_key_der(),
        challenge,
        impostor.public_key_der(),
        &sig,
        Ipv4Addr::new(198, 51, 100, 7),
        None,
    )
    .expect("verify ran");
    assert!(!ok, "a signature must not verify under a different key");
}

#[test]
fn v2_localclient_signature_binds_peer_ip() {
    let us = ident();
    let peer = ident();
    let challenge = 0x3333_4444;
    let peer_ip = Ipv4Addr::new(203, 0, 113, 42);
    let sig = peer_sign(
        &peer,
        us.public_key_der(),
        challenge,
        Some((CRYPT_CIP_LOCALCLIENT, peer_ip.octets())),
    );
    assert!(
        verify_inbound_signature(
            us.public_key_der(),
            challenge,
            peer.public_key_der(),
            &sig,
            peer_ip,
            None,
        )
        .expect("verify ran"),
        "V2 LOCALCLIENT verifies against the peer IP"
    );
    // Same signature replayed against a different endpoint IP must fail.
    assert!(
        !verify_inbound_signature(
            us.public_key_der(),
            challenge,
            peer.public_key_der(),
            &sig,
            Ipv4Addr::new(203, 0, 113, 99),
            None,
        )
        .expect("verify ran"),
        "V2 LOCALCLIENT must not verify when replayed to another IP"
    );
}

#[test]
fn v2_outbound_signature_round_trips_through_verify() {
    // B4: our V2 signing (challenge IP + ip-kind) must produce a payload our
    // own verify path accepts, with the ip-kind trailer on the wire.
    let signer = ident();
    let recipient = ident();
    let challenge = 0x7777_8888;
    let signer_ip = Ipv4Addr::new(192, 0, 2, 33);
    // Signer signs the recipient's public key + challenge + its own IP (V2
    // LOCALCLIENT), exactly as CreateSignature(byChaIPKind=LOCALCLIENT).
    let payload = signer
        .signature_payload_with_challenge_ip(
            recipient.public_key_der(),
            challenge,
            Some((CRYPT_CIP_LOCALCLIENT, signer_ip)),
        )
        .unwrap();
    let decoded = decode_signature_payload(&payload).unwrap();
    assert_eq!(decoded.challenge_ip_kind, Some(CRYPT_CIP_LOCALCLIENT));

    // The recipient verifies over its own public key + the challenge it
    // issued; LOCALCLIENT maps the challenge IP to the signer's (peer's) IP.
    let ok = verify_inbound_signature(
        recipient.public_key_der(),
        challenge,
        signer.public_key_der(),
        &decoded,
        signer_ip,
        None,
    )
    .expect("verify ran");
    assert!(ok, "our V2 signature verifies through our own verify path");
}

#[test]
fn verify_without_issued_challenge_errors() {
    let us = ident();
    let peer = ident();
    let sig = peer_sign(&peer, us.public_key_der(), 1, None);
    assert!(
        verify_inbound_signature(
            us.public_key_der(),
            0, // no challenge issued
            peer.public_key_der(),
            &sig,
            Ipv4Addr::new(198, 51, 100, 7),
            None,
        )
        .is_err()
    );
}

#[test]
fn emitted_public_key_is_pkcs1_within_stock_cap() {
    // A1: stock eMule (`CClientCredits::SetSecureIdent`) rejects any key longer
    // than MAXPUBKEYSIZE (80 bytes) and parses it as a bare PKCS#1 RSAPublicKey,
    // so our emitted OP_PUBLICKEY bytes must be PKCS#1 DER and fit the cap.
    let us = ident();
    let payload = us.public_key_payload().expect("public-key payload");
    let key_len = payload[0] as usize;
    assert_eq!(
        key_len,
        payload.len() - 1,
        "length prefix must match key bytes"
    );
    let key_bytes = &payload[1..];
    assert_eq!(
        key_bytes,
        us.public_key_der(),
        "wire bytes == public_key_der"
    );
    assert!(
        key_bytes.len() <= 80,
        "emitted key {} bytes must fit MAXPUBKEYSIZE",
        key_bytes.len()
    );

    // The emitted bytes must round-trip as a bare PKCS#1 RSAPublicKey (what
    // stock eMule feeds to its Crypto++ verifier), not an SPKI wrapper.
    let parsed = RsaPublicKey::from_pkcs1_der(key_bytes)
        .expect("emitted key must decode as PKCS#1 RSAPublicKey");
    assert_eq!(
        parsed,
        RsaPublicKey::from(&us.private_key),
        "round-tripped key must equal our own public key"
    );

    // A signature produced over the PKCS#1 bytes must verify against the same
    // PKCS#1 bytes (sign -> verify parity over the on-wire key form).
    let peer = ident();
    let challenge = 0x4242_4242;
    let sig = peer_sign(&peer, us.public_key_der(), challenge, None);
    assert!(
        verify_inbound_signature(
            us.public_key_der(),
            challenge,
            peer.public_key_der(),
            &sig,
            Ipv4Addr::new(198, 51, 100, 7),
            None,
        )
        .expect("verify ran"),
        "sign->verify must pass over the PKCS#1 public-key bytes"
    );
}

#[test]
fn helper_sets_verified_only_on_valid_signature() {
    let us = ident();
    let peer = ident();
    let challenge = 0x5555_6666;
    let peer_addr: SocketAddr = "198.51.100.7:4662".parse().unwrap();

    let mut state = Ed2kPeerSecureIdentState {
        peer_public_key: Some(peer.public_key_der().to_vec()),
        challenge_for: Some(challenge),
        ..Default::default()
    };
    let good = peer_sign(&peer, us.public_key_der(), challenge, None);
    assert!(verify_peer_secure_ident_signature(
        &us, &mut state, &good, peer_addr, None
    ));
    assert!(state.peer_ident_verified);
    assert!(state.peer_signature_received);

    // A subsequent tampered signature clears the verified flag.
    let mut bad = good.clone();
    bad.signature[3] ^= 0xFF;
    assert!(!verify_peer_secure_ident_signature(
        &us, &mut state, &bad, peer_addr, None
    ));
    assert!(!state.peer_ident_verified);
    assert!(state.peer_signature_received);
}

#[test]
fn outbound_signature_v2_selected_for_v2_only_peer() {
    let our_ip = Ipv4Addr::new(203, 0, 113, 9);
    let peer_ip = Ipv4Addr::new(198, 51, 100, 7);

    // secIdent=2 (bit 0 clear) -> V2. HighID (our IP known) signs LOCALCLIENT with
    // our own public IP (master GetClientID()).
    assert_eq!(
        select_outbound_challenge_ip(2, Some(our_ip), Some(peer_ip)),
        Some((CRYPT_CIP_LOCALCLIENT, our_ip)),
    );
    // secIdent=2 + LowID (our IP unknown) -> V2 REMOTECLIENT with the peer's IP.
    assert_eq!(
        select_outbound_challenge_ip(2, None, Some(peer_ip)),
        Some((CRYPT_CIP_REMOTECLIENT, peer_ip)),
    );

    // secIdent=3 (bit 0 set) -> V1 (no challenge-IP trailer), the common case.
    assert_eq!(
        select_outbound_challenge_ip(3, Some(our_ip), Some(peer_ip)),
        None
    );
    // Unknown level (0) stays on the safe V1 path.
    assert_eq!(
        select_outbound_challenge_ip(0, Some(our_ip), Some(peer_ip)),
        None
    );
}

#[test]
fn outbound_v2_payload_differs_from_v1() {
    // A V2 payload carries an extra ip-kind trailer byte after the signature, so a
    // V2-only peer (secIdent=2) and a V1 peer (secIdent=3) produce different wire
    // payloads from the same challenge.
    let us = ident();
    let peer = ident();
    let challenge = 0x1234_5678u32;
    let our_ip = Ipv4Addr::new(203, 0, 113, 9);

    let v2_sel = select_outbound_challenge_ip(2, Some(our_ip), None);
    let v1_sel = select_outbound_challenge_ip(3, Some(our_ip), None);
    let v2 = us
        .signature_payload_with_challenge_ip(peer.public_key_der(), challenge, v2_sel)
        .expect("v2 payload");
    let v1 = us
        .signature_payload_with_challenge_ip(peer.public_key_der(), challenge, v1_sel)
        .expect("v1 payload");
    assert_eq!(
        v2.len(),
        v1.len() + 1,
        "V2 appends the ip-kind trailer byte"
    );
    assert_eq!(*v2.last().unwrap(), CRYPT_CIP_LOCALCLIENT);
}

#[test]
fn credit_accrual_gate_matches_oracle_ident_states() {
    // eMule CClientCredits::AddUploaded/AddDownloaded (ClientCredits.cpp:83-113).
    // Verified peer (IS_IDENTIFIED): accrue, regardless of advertised support.
    assert!(credit_accrual_allowed(true, true));
    assert!(credit_accrual_allowed(true, false));
    // Legacy peer with no secure-ident support (IS_NOTAVAILABLE): still accrue.
    assert!(credit_accrual_allowed(false, false));
    // Crypto-capable peer that has not verified yet (IS_IDNEEDED/IDFAILED/
    // IDBADGUY): skip -- its user hash is spoofable.
    assert!(!credit_accrual_allowed(false, true));
}
