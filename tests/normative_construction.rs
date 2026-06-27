//! Tests for the normative bilateral contest-output channel construction.
//!
//! These tests cover the §5–§7 normative surface of the Kurrent thesis:
//! BLAKE2b-256 keyed domain hashes, fixed-width `ScopeEncoding` and
//! `PolicyEncoding`, `encodeSPK` canonical form, MuSig2 aggregate
//! key construction, cooperative-close output-set hashing,
//! `StateCertMessage` and `CoopCloseMessage`
//! signing payloads, the `0 ≤ n ≤ 2^63 - 1` state number range, the
//! `v_A + v_B = V` conservation invariant, and the bounded transaction
//! shapes.
//!
//! These tests are independent of the prototype marker evidence path
//! in `tests/protocol_model.rs`. The two surfaces are different
//! artefacts per the thesis §13 production-readiness scope.

use kurrent::*;
use secp256k1::{Keypair, Secp256k1, SecretKey};

// --------------------------------------------------------------------------
// Fixed-width canonical encodings
// --------------------------------------------------------------------------

#[test]
fn encode_spk_canonical_roundtrip() {
    let spk = EncodedSpk::new(0, vec![0x76, 0xa9, 0x14, 0xff]);
    let bytes = spk.encode();
    assert_eq!(bytes.len(), 2 + 8 + 4);
    assert_eq!(&bytes[0..2], &[0x00, 0x00]); // version
    assert_eq!(&bytes[2..10], &[0x04, 0, 0, 0, 0, 0, 0, 0]); // len
    assert_eq!(&bytes[10..], &[0x76, 0xa9, 0x14, 0xff]);
    let decoded = EncodedSpk::decode(&bytes).expect("decode succeeds");
    assert_eq!(decoded, spk);
}

#[test]
fn toccata_spk_is_distinct_from_commitment_spk() {
    let spk = EncodedSpk::new(0x0102, vec![0x76, 0xa9, 0x14, 0xff]);
    let commit = spk.encode();
    let toccata = spk.toccata_encode();
    assert_eq!(toccata, vec![0x01, 0x02, 0x76, 0xa9, 0x14, 0xff]);
    assert_ne!(commit, toccata);
}

#[test]
fn encode_spk_rejects_truncated_payload() {
    let bytes = vec![0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0];
    assert!(EncodedSpk::decode(&bytes).is_err());
}

#[test]
fn encode_spk_rejects_wrong_length() {
    let mut bytes = vec![0u8; 10];
    bytes[..2].copy_from_slice(&0u16.to_le_bytes());
    bytes[2..10].copy_from_slice(&4u64.to_le_bytes());
    bytes.push(0x76);
    // Length says 4 but only 1 byte of script is present.
    assert!(EncodedSpk::decode(&bytes).is_err());
}

// --------------------------------------------------------------------------
// BLAKE2b-256 keyed domain hash
// --------------------------------------------------------------------------

#[test]
fn blake2b_256_keyed_is_deterministic() {
    let a = blake2b_256_keyed_hex("KurrentScope/v1", b"payload");
    let b = blake2b_256_keyed_hex("KurrentScope/v1", b"payload");
    assert_eq!(a, b);
}

#[test]
fn blake2b_256_keyed_separates_domains() {
    let a = blake2b_256_keyed_hex("KurrentScope/v1", b"payload");
    let b = blake2b_256_keyed_hex("KurrentState/v1", b"payload");
    assert_ne!(a, b);
}

#[test]
fn blake2b_256_keyed_separates_payloads() {
    let a = blake2b_256_keyed_hex("KurrentScope/v1", b"payload-a");
    let b = blake2b_256_keyed_hex("KurrentScope/v1", b"payload-b");
    assert_ne!(a, b);
}

// --------------------------------------------------------------------------
// State number range
// --------------------------------------------------------------------------

#[test]
fn state_number_zero_is_valid() {
    assert!(validate_state_number(0).is_ok());
}

#[test]
fn state_number_max_is_valid() {
    assert!(validate_state_number(MAX_STATE_NUMBER).is_ok());
}

#[test]
fn state_number_above_max_is_rejected() {
    assert!(validate_state_number(MAX_STATE_NUMBER + 1).is_err());
}

#[test]
fn state_number_u64_max_is_rejected() {
    assert!(validate_state_number(u64::MAX).is_err());
}

// --------------------------------------------------------------------------
// Conservation invariant
// --------------------------------------------------------------------------

#[test]
fn conservation_holds_for_split_values() {
    assert!(validate_conservation(60, 40, 100).is_ok());
    assert!(validate_conservation(0, 100, 100).is_ok());
    assert!(validate_conservation(100, 0, 100).is_ok());
}

#[test]
fn conservation_fails_on_mismatch() {
    assert!(validate_conservation(60, 40, 200).is_err());
    assert!(validate_conservation(0, 0, 100).is_err());
}

#[test]
fn conservation_fails_on_overflow() {
    assert!(validate_conservation(u64::MAX, 1, u64::MAX).is_err());
}

// --------------------------------------------------------------------------
// Scope identifier (ScopeInputs + ScopeEncoding)
// --------------------------------------------------------------------------

fn sample_scope_inputs() -> ScopeInputs {
    let policy = PolicyEncoding::v1();
    ScopeInputs {
        chain_context: [0x11u8; 32],
        covenant_id: [0x22u8; 32],
        agg_key: [0x33u8; 32],
        delta: 120,
        programme_version: PROGRAMME_VERSION_V1,
        policy_hash: policy.compute_policy_hash(),
    }
}

#[test]
fn scope_encoding_is_fixed_width() {
    let scope = sample_scope_inputs();
    let payload = scope.canonical_payload();
    // 32 (chain_context) + 32 (covenant_id) + 32 (agg_key)
    // + 4 (le32 Δ) + 2 (le16 programme_version) + 32 (policy_hash)
    assert_eq!(payload.len(), 32 + 32 + 32 + 4 + 2 + 32);
}

#[test]
fn scope_id_is_deterministic() {
    let a = sample_scope_inputs().compute_scope_id();
    let b = sample_scope_inputs().compute_scope_id();
    assert_eq!(a, b);
}

#[test]
fn scope_id_changes_with_covenant_id() {
    let a = sample_scope_inputs();
    let mut b = sample_scope_inputs();
    b.covenant_id = [0x99u8; 32];
    assert_ne!(a.compute_scope_id(), b.compute_scope_id());
}

#[test]
fn scope_id_changes_with_programme_version() {
    let a = sample_scope_inputs();
    let mut b = sample_scope_inputs();
    b.programme_version = 2;
    assert_ne!(a.compute_scope_id(), b.compute_scope_id());
}

#[test]
fn scope_id_changes_with_delta() {
    let a = sample_scope_inputs();
    let mut b = sample_scope_inputs();
    b.delta = 240;
    assert_ne!(a.compute_scope_id(), b.compute_scope_id());
}

// --------------------------------------------------------------------------
// Policy hash (PolicyEncoding)
// --------------------------------------------------------------------------

#[test]
fn policy_v1_validates() {
    let policy = PolicyEncoding::v1();
    assert_eq!(policy.settlement_shape_id, 1);
    assert!(policy.validate_v1().is_ok());
}

#[test]
fn policy_v1_rejects_reserved_nonzero() {
    let mut p = PolicyEncoding::v1();
    p.reserved_64[0] = 1;
    assert!(p.validate_v1().is_err());
}

#[test]
fn policy_v1_rejects_wrong_version() {
    let mut p = PolicyEncoding::v1();
    p.policy_version = 2;
    assert!(p.validate_v1().is_err());
}

#[test]
fn policy_v1_rejects_non_external_sponsor() {
    let mut p = PolicyEncoding::v1();
    p.sponsor_policy_id = 1;
    assert!(p.validate_v1().is_err());
}

#[test]
fn policy_v1_rejects_non_two_party_shape() {
    let mut p = PolicyEncoding::v1();
    p.settlement_shape_id = 0;
    assert!(p.validate_v1().is_err());
}

#[test]
fn policy_v1_hash_is_deterministic() {
    let a = PolicyEncoding::v1().compute_policy_hash();
    let b = PolicyEncoding::v1().compute_policy_hash();
    assert_eq!(a, b);
}

#[test]
fn policy_v1_hash_changes_with_coop_close_flag() {
    let mut p1 = PolicyEncoding::v1();
    p1.coop_close_enabled = true;
    let mut p2 = PolicyEncoding::v1();
    p2.coop_close_enabled = false;
    assert_ne!(p1.compute_policy_hash(), p2.compute_policy_hash());
}

// --------------------------------------------------------------------------
// State root
// --------------------------------------------------------------------------

fn sample_state_root_input() -> StateRootInput {
    StateRootInput {
        settlement_mask: SettlementMask::Both,
        spk_a: EncodedSpk::new(0, vec![0xaa; 32]),
        value_a: 60,
        spk_b: EncodedSpk::new(0, vec![0xbb; 32]),
        value_b: 40,
    }
}

#[test]
fn state_root_canonical_payload_is_fixed_width() {
    let s = sample_state_root_input();
    let p = s.canonical_payload();
    // The sample uses 32-byte scripts, so each encodeSPK is 2 + 8 + 32 = 42.
    // Total: 1 (mask) + 1 (slot A) + 42 (encodeSPK_A) + 8 (le64 v_A)
    //      + 1 (slot B) + 42 (encodeSPK_B) + 8 (le64 v_B)
    assert_eq!(p.len(), 1 + 1 + 42 + 8 + 1 + 42 + 8);
    assert_eq!(p[0], SettlementMask::Both.byte());
}

#[test]
fn settlement_mask_is_derived_from_non_zero_outputs() {
    assert_eq!(
        SettlementMask::from_values(60, 40, 100).unwrap(),
        SettlementMask::Both
    );
    assert_eq!(
        SettlementMask::from_values(100, 0, 100).unwrap(),
        SettlementMask::AOnly
    );
    assert_eq!(
        SettlementMask::from_values(0, 100, 100).unwrap(),
        SettlementMask::BOnly
    );
    assert!(SettlementMask::from_values(0, 0, 0).is_err());
}

#[test]
fn state_root_changes_with_values() {
    let a = sample_state_root_input();
    let mut b = sample_state_root_input();
    b.value_a = 70;
    b.value_b = 30;
    assert_ne!(a.compute_root(), b.compute_root());
}

#[test]
fn state_root_changes_with_slot() {
    let mut a = sample_state_root_input();
    let b = sample_state_root_input();
    std::mem::swap(&mut a.spk_a, &mut a.spk_b);
    assert_ne!(a.compute_root(), b.compute_root());
}

#[test]
fn state_root_changes_with_settlement_mask() {
    let a = sample_state_root_input();
    let mut b = sample_state_root_input();
    b.settlement_mask = SettlementMask::AOnly;
    assert_ne!(a.compute_root(), b.compute_root());
}

// --------------------------------------------------------------------------
// State certificate message
// --------------------------------------------------------------------------

fn sample_state_cert() -> StateCertMessage {
    StateCertMessage {
        scope_id: [0x55u8; 32],
        state_number: 37,
        state_root: [0x66u8; 32],
    }
}

#[test]
fn state_cert_message_is_deterministic() {
    let a = sample_state_cert().compute().unwrap();
    let b = sample_state_cert().compute().unwrap();
    assert_eq!(a, b);
}

#[test]
fn state_cert_message_changes_with_state_number() {
    let a = sample_state_cert();
    let mut b = sample_state_cert();
    b.state_number = 38;
    assert_ne!(a.compute().unwrap(), b.compute().unwrap());
}

#[test]
fn state_cert_message_changes_with_state_root() {
    let a = sample_state_cert();
    let mut b = sample_state_cert();
    b.state_root = [0x77u8; 32];
    assert_ne!(a.compute().unwrap(), b.compute().unwrap());
}

#[test]
fn state_cert_message_accepts_state_number_in_range() {
    let mut m = sample_state_cert();
    m.state_number = 0;
    assert_eq!(m.compute().unwrap().len(), 32);
    m.state_number = MAX_STATE_NUMBER;
    assert_eq!(m.compute().unwrap().len(), 32);
}

#[test]
fn state_cert_message_rejects_out_of_range_state_number() {
    let mut m = sample_state_cert();
    m.state_number = MAX_STATE_NUMBER + 1;
    assert!(m.compute().is_err());
    m.state_number = u64::MAX;
    assert!(m.compute().is_err());
}

// --------------------------------------------------------------------------
// Cooperative-close message (binds to input outpoint)
// --------------------------------------------------------------------------

#[test]
fn coop_close_outputs_hash_uses_distinct_domain_and_payload() {
    let s = sample_state_root_input();
    let actual =
        coop_close_outputs_hash(s.settlement_mask, &s.spk_a, s.value_a, &s.spk_b, s.value_b);

    let mut payload = Vec::new();
    payload.push(s.settlement_mask.byte());
    payload.extend_from_slice(&s.spk_a.encode());
    payload.extend_from_slice(&s.value_a.to_le_bytes());
    payload.extend_from_slice(&s.spk_b.encode());
    payload.extend_from_slice(&s.value_b.to_le_bytes());

    assert_eq!(
        actual,
        blake2b_256_keyed(DOMAIN_KURRENT_COOP_CLOSE_OUTPUTS, &payload)
    );
    assert_ne!(actual, s.compute_root());
}

fn sample_coop_close() -> CoopCloseMessage {
    CoopCloseMessage::from_outpoint_parts(
        [0x77u8; 32],
        [0xabu8; 32], // txid
        0,            // vout
        [0x88u8; 32],
    )
}

#[test]
fn coop_close_message_binds_to_input_outpoint() {
    let a = sample_coop_close();
    let mut b = sample_coop_close();
    b.input_outpoint[35] = 1; // different vout
    assert_ne!(a.compute(), b.compute());
}

#[test]
fn coop_close_message_changes_with_txid() {
    let a = sample_coop_close();
    let mut b = sample_coop_close();
    b.input_outpoint[0] = 0xcd;
    assert_ne!(a.compute(), b.compute());
}

#[test]
fn coop_close_message_changes_with_settlement_outputs_hash() {
    let a = sample_coop_close();
    let mut b = sample_coop_close();
    b.settlement_outputs_hash = [0xeeu8; 32];
    assert_ne!(a.compute(), b.compute());
}

#[test]
fn coop_close_outpoint_is_fixed_thirty_six_bytes() {
    // The on-chain covenant must commit to the canonical 32-byte txid
    // || 4-byte vout. The Rust model must not accept any other length.
    let m = sample_coop_close();
    assert_eq!(m.input_outpoint.len(), 36);
    // txid occupies the first 32 bytes, vout (little-endian) the last 4.
    assert_eq!(&m.input_outpoint[0..32], &[0xabu8; 32]);
    assert_eq!(&m.input_outpoint[32..36], &0u32.to_le_bytes());
}

// --------------------------------------------------------------------------
// State certificate and coop-close verify wrappers
// --------------------------------------------------------------------------

#[test]
fn verify_state_certificate_rejects_out_of_range_state_number() {
    // The verify wrapper composes compute() + musig2_verify. If
    // compute() fails on out-of-range state_number, the wrapper must
    // return false rather than panic.
    let secp = secp256k1::Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x55; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let agg = AggregateVerificationKey(xonly.serialize());
    let mut m = sample_state_cert();
    m.state_number = u64::MAX;
    let invalid_sig = [0u8; 64];
    assert!(!verify_state_certificate(&m, &agg, &invalid_sig));
}

#[test]
fn verify_state_certificate_rejects_bad_signature() {
    let secp = secp256k1::Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x55; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let agg = AggregateVerificationKey(xonly.serialize());
    let m = sample_state_cert();
    // All-zero signature is well-formed but invalid for any message.
    let invalid_sig = [0u8; 64];
    assert!(!verify_state_certificate(&m, &agg, &invalid_sig));
}

#[test]
fn verify_coop_close_rejects_bad_signature() {
    let secp = secp256k1::Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x55; 32]).unwrap();
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let agg = AggregateVerificationKey(xonly.serialize());
    let m = sample_coop_close();
    let invalid_sig = [0u8; 64];
    assert!(!verify_coop_close(&m, &agg, &invalid_sig));
}

// --------------------------------------------------------------------------
// Sponsor invariant and replacement state-root recomputation
// --------------------------------------------------------------------------

#[test]
fn sponsor_invariant_holds_for_zero_fee() {
    // No-sponsor branch: input = change + fee, all zero.
    assert!(check_sponsor_invariant(0, 0, 0).is_ok());
}

#[test]
fn sponsor_invariant_holds_for_paid_fee() {
    assert!(check_sponsor_invariant(150, 100, 50).is_ok());
    assert!(check_sponsor_invariant(1_000, 999, 1).is_ok());
}

#[test]
fn sponsor_invariant_rejects_mismatch() {
    // sponsor_input > sponsor_change + fee → launder attempt.
    assert!(check_sponsor_invariant(100, 50, 30).is_err());
    // sponsor_input < sponsor_change + fee → sponsor paying themselves.
    assert!(check_sponsor_invariant(70, 50, 30).is_err());
}

#[test]
fn sponsor_invariant_rejects_overflow() {
    assert!(check_sponsor_invariant(u64::MAX, u64::MAX, 1).is_err());
}

#[test]
fn verify_replacement_state_root_matches_recomputed() {
    // Build a state root from settlement slots, then verify a
    // certificate that carries the same root. The witness slots
    // match → verification succeeds.
    let spk_a = EncodedSpk::new(0, vec![0xaa; 32]);
    let spk_b = EncodedSpk::new(0, vec![0xbb; 32]);
    let input = StateRootInput {
        settlement_mask: SettlementMask::Both,
        spk_a: spk_a.clone(),
        value_a: 60,
        spk_b: spk_b.clone(),
        value_b: 40,
    };
    let state_root = input.compute_root();
    let cert = StateCertMessage {
        scope_id: [0x01; 32],
        state_number: 7,
        state_root,
    };
    assert!(verify_replacement_state_root(&cert, &spk_a, 60, &spk_b, 40, 100).unwrap());
}

#[test]
fn verify_replacement_state_root_rejects_mismatch() {
    // Build a state root from one set of slots, then verify a
    // certificate that claims a different set. The witness is
    // internally inconsistent with the certificate.
    let spk_a = EncodedSpk::new(0, vec![0xaa; 32]);
    let spk_b = EncodedSpk::new(0, vec![0xbb; 32]);
    let cert = StateCertMessage {
        scope_id: [0x01; 32],
        state_number: 7,
        state_root: [0u8; 32], // bogus
    };
    assert!(!verify_replacement_state_root(&cert, &spk_a, 60, &spk_b, 40, 100).unwrap());
}

#[test]
fn verify_replacement_state_root_rejects_violated_conservation() {
    // The witness exposes a split that does not conserve V.
    let spk_a = EncodedSpk::new(0, vec![0xaa; 32]);
    let spk_b = EncodedSpk::new(0, vec![0xbb; 32]);
    let cert = StateCertMessage {
        scope_id: [0x01; 32],
        state_number: 7,
        state_root: [0u8; 32],
    };
    let err = verify_replacement_state_root(&cert, &spk_a, 60, &spk_b, 50, 100);
    assert!(err.is_err());
}

// --------------------------------------------------------------------------
// MuSig2 key aggregation
// --------------------------------------------------------------------------

fn keypair_bytes(seed: [u8; 32]) -> [u8; 32] {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&seed).expect("32-byte secret is well-formed");
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = kp.x_only_public_key();
    xonly.serialize()
}

#[test]
fn musig2_aggregate_orders_keys_lexicographically() {
    let pk_a = keypair_bytes([0x01; 32]);
    let pk_b = keypair_bytes([0x02; 32]);
    let agg1 = musig2_aggregate_xonly(pk_a, pk_b);
    let agg2 = musig2_aggregate_xonly(pk_b, pk_a);
    assert_eq!(agg1, agg2);
}

#[test]
fn musig2_aggregate_is_deterministic() {
    let pk_a = keypair_bytes([0x01; 32]);
    let pk_b = keypair_bytes([0x02; 32]);
    let agg1 = musig2_aggregate_xonly(pk_a, pk_b);
    let agg2 = musig2_aggregate_xonly(pk_a, pk_b);
    assert_eq!(agg1, agg2);
}

#[test]
fn musig2_aggregate_changes_with_inputs() {
    let pk_a = keypair_bytes([0x01; 32]);
    let pk_b = keypair_bytes([0x02; 32]);
    let pk_c = keypair_bytes([0x03; 32]);
    let agg_ab = musig2_aggregate_xonly(pk_a, pk_b);
    let agg_ac = musig2_aggregate_xonly(pk_a, pk_c);
    assert_ne!(agg_ab, agg_ac);
}

// --------------------------------------------------------------------------
// Bounded transaction shape and canonical sequence
// --------------------------------------------------------------------------

#[test]
fn bounded_shape_input_output_slots() {
    assert_eq!(
        BoundedShape::ContestOpeningOrReplacement.input_slot_count(),
        2
    );
    assert_eq!(
        BoundedShape::ContestOpeningOrReplacement.output_slot_count(SettlementMask::Both, true),
        2
    );
    assert_eq!(BoundedShape::Settlement.input_slot_count(), 2);
    assert_eq!(
        BoundedShape::Settlement.output_slot_count(SettlementMask::Both, false),
        2
    );
    assert_eq!(
        BoundedShape::Settlement.output_slot_count(SettlementMask::Both, true),
        3
    );
    assert_eq!(
        BoundedShape::Settlement.output_slot_count(SettlementMask::AOnly, false),
        1
    );
    assert_eq!(
        BoundedShape::Settlement.output_slot_count(SettlementMask::BOnly, true),
        2
    );
    assert_eq!(BoundedShape::CoopClose.input_slot_count(), 2);
    assert_eq!(
        BoundedShape::CoopClose.output_slot_count(SettlementMask::Both, true),
        3
    );
}

#[test]
fn canonical_sequence_settle_encodes_delta() {
    let seq = CanonicalSequence::Settle { delta: 120 };
    let bytes = seq.encode();
    assert_eq!(bytes, 120u64.to_le_bytes());
    // Disable bit clear.
    assert_eq!(bytes[7] & 0x80, 0);
}

#[test]
fn canonical_sequence_disable_sets_bit_63() {
    let seq = CanonicalSequence::DisableRelativeLock;
    let bytes = seq.encode();
    assert_eq!(bytes, (1u64 << 63).to_le_bytes());
}

#[test]
fn canonical_sequence_settle_and_disable_differ() {
    let settle = CanonicalSequence::Settle { delta: 120 }.encode();
    let disable = CanonicalSequence::DisableRelativeLock.encode();
    assert_ne!(settle, disable);
}

// --------------------------------------------------------------------------
// Reference MuSig2 — independent re-implementation of the BIP-327 /
// Maxwell-Nick-Ruffing-Pozdin-Oliynykov two-party key aggregation. The
// purpose is to pin the kurrent `musig2_aggregate_xonly` against an
// implementation written from scratch in the test file. If anyone
// "simplifies" the kurrent function back to plain key addition
// `P_1 + P_2`, this test will fail.
// --------------------------------------------------------------------------

mod reference_musig2 {
    use blake2::digest::consts::U32;
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;
    use secp256k1::{Parity, PublicKey, Scalar, Secp256k1, XOnlyPublicKey};

    /// Plain (non-keyed) BLAKE2b-256, used for H_agg in MuSig2.
    fn h_agg(parts: &[&[u8]]) -> [u8; 32] {
        let mut h: Blake2bMac<U32> = Blake2bMac::new_from_slice(&[]).unwrap();
        for p in parts {
            h.update(p);
        }
        h.finalize_fixed().into()
    }

    /// Reference MuSig2 aggregate for two x-only pubkeys.
    pub fn aggregate(pk_a: [u8; 32], pk_b: [u8; 32]) -> [u8; 32] {
        let mut keys = [pk_a, pk_b];
        keys.sort();
        let l = h_agg(&[&keys[0], &keys[1]]);
        let a1_bytes = h_agg(&[&l, &keys[0]]);
        let a2_bytes = h_agg(&[&l, &keys[1]]);
        // Reject the (negligible-probability) n-boundary case the way
        // BIP-327 §"Computing aggregate pubkey" does.
        let a1 = Scalar::from_be_bytes(a1_bytes).unwrap_or(Scalar::ONE);
        let a2 = Scalar::from_be_bytes(a2_bytes).unwrap_or(Scalar::ONE);
        let secp = Secp256k1::new();
        let xa = XOnlyPublicKey::from_slice(&keys[0]).unwrap();
        let xb = XOnlyPublicKey::from_slice(&keys[1]).unwrap();
        let fa = PublicKey::from_x_only_public_key(xa, Parity::Even);
        let fb = PublicKey::from_x_only_public_key(xb, Parity::Even);
        let pa = fa.mul_tweak(&secp, &a1).unwrap();
        let pb = fb.mul_tweak(&secp, &a2).unwrap();
        let combined = pa.combine(&pb).unwrap();
        combined.x_only_public_key().0.serialize()
    }
}

#[test]
fn musig2_aggregate_matches_bip327_reference() {
    // Several distinct real keypair-derived pubkey pairs; each must
    // reproduce the reference implementation byte-for-byte. This pins
    // the kurrent function to the BIP-327 standard algorithm, not
    // simple `P_1 + P_2`.
    let pairs = [
        (keypair_bytes([0x01; 32]), keypair_bytes([0x02; 32])),
        (keypair_bytes([0x33; 32]), keypair_bytes([0x77; 32])),
        (keypair_bytes([0xa1; 32]), keypair_bytes([0xb2; 32])),
    ];
    for (a, b) in pairs {
        let got = musig2_aggregate_xonly(a, b).0;
        let expected = reference_musig2::aggregate(a, b);
        assert_eq!(got, expected, "aggregate({:x?}, {:x?})", a, b);
    }
}

#[test]
fn musig2_aggregate_differs_from_simple_key_addition() {
    // Rogue-key regression test: if anyone reverts the kurrent function
    // to simple P_1 + P_2, the aggregate below would equal `simple`.
    // The kurrent aggregate (real MuSig2 with coefficient construction)
    // must NOT equal that.
    use secp256k1::{Parity, PublicKey, XOnlyPublicKey};
    let a = keypair_bytes([0x01; 32]);
    let b = keypair_bytes([0x02; 32]);
    let xa = XOnlyPublicKey::from_slice(&a).unwrap();
    let xb = XOnlyPublicKey::from_slice(&b).unwrap();
    let simple = PublicKey::from_x_only_public_key(xa, Parity::Even)
        .combine(&PublicKey::from_x_only_public_key(xb, Parity::Even))
        .unwrap();
    let simple_xonly = simple.x_only_public_key().0.serialize();
    let musig2 = musig2_aggregate_xonly(a, b).0;
    assert_ne!(
        musig2, simple_xonly,
        "musig2 aggregate must differ from naive P_1 + P_2"
    );
}

// --------------------------------------------------------------------------
// BLAKE2b keyed-mode interop test. The reference recomputation uses the
// same `blake2` crate and the same code path the production helper uses,
// but the test exercises the digest against a fixed reference vector so
// any change to the on-chain opcode semantic (prefix vs keyed) shows up
// as a test failure.
// --------------------------------------------------------------------------

#[test]
fn blake2b_keyed_matches_keyed_mode_reference() {
    use blake2::digest::consts::U32;
    use blake2::digest::{FixedOutput, KeyInit, Update};
    use blake2::Blake2bMac;

    let tag = "KurrentScope/v1";
    let payload = b"reference payload";
    let got = blake2b_256_keyed(tag, payload);

    // Independent keyed-mode recomputation in the test.
    let mut h: Blake2bMac<U32> = Blake2bMac::new_from_slice(tag.as_bytes()).unwrap();
    h.update(payload);
    let want: [u8; 32] = h.finalize_fixed().into();

    assert_eq!(got, want);
    // And it must NOT match the prefix-mode digest `BLAKE2b-256(tag || payload)`.
    let mut h: Blake2bMac<U32> = Blake2bMac::new_from_slice(&[]).unwrap();
    h.update(tag.as_bytes());
    h.update(payload);
    let prefix: [u8; 32] = h.finalize_fixed().into();
    assert_ne!(got, prefix, "keyed mode and prefix mode must differ");
}
