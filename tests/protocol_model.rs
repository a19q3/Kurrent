use kurrent::client::*;
use kurrent::*;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn map(entries: &[(&str, u64)]) -> BTreeMap<String, u64> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), *v))
        .collect()
}

fn template() -> SettlementTemplate {
    SettlementTemplate {
        template_id: "settle-v1".to_string(),
        outputs: map(&[("alice", 600), ("bob", 400)]),
        refund_after_daa: Some(120),
        script_covenant_hash: "script-hash".to_string(),
    }
}

fn participants() -> Vec<String> {
    vec!["alice".to_string(), "bob".to_string()]
}

fn keypair_for(participant: &str) -> Keypair {
    let byte = match participant {
        "alice" => 1,
        "bob" => 2,
        _ => 42,
    };
    let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
    Keypair::from_secret_key(secp256k1::SECP256K1, &secret)
}

fn participant_public_keys() -> BTreeMap<String, String> {
    participants()
        .into_iter()
        .map(|participant| {
            let keypair = keypair_for(&participant);
            let (public_key, _) = keypair.x_only_public_key();
            (participant, hex::encode(public_key.serialize()))
        })
        .collect()
}

fn sign_update_for(participant: &str, update: &StateUpdate) -> String {
    let keypair = keypair_for(participant);
    let message = Message::from_digest(state_update_signing_digest(update));
    let secp = Secp256k1::new();
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    hex::encode(signature.as_ref())
}

fn channel_config() -> KurrentChannelConfig {
    KurrentChannelConfig {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        genesis_or_devnet_id: Some("devnet-1".to_string()),
        channel_id: "channel-a".to_string(),
        participants: participants(),
        challenge_policy: ChallengePolicy {
            mode: "latest-state".to_string(),
            challenge_window_daa: 120,
            same_number_conflict_rule: "reject-conflict".to_string(),
        },
        access_manifest: AccessManifest {
            authorised_participants: participants(),
            participant_public_keys: participant_public_keys(),
            required_signatures: 2,
        },
    }
}

fn funding() -> FundingState {
    FundingState {
        funding_outpoint: "funding:0".to_string(),
        total_principal: 1_000,
        principal_by_participant: map(&[("alice", 600), ("bob", 400)]),
        fee_reserve: 10,
        script_covenant_hash: "script-hash".to_string(),
    }
}

fn update(number: u64, commitment: &str, template_hash: String) -> StateUpdate {
    let mut state = StateUpdate {
        header: LatestStateHeader {
            network_profile: "local-toccata-devnet".to_string(),
            genesis_or_devnet_id: Some("devnet-1".to_string()),
            funding_outpoint: "funding:0".to_string(),
            channel_id: "channel-a".to_string(),
            factory_id: None,
            virtual_channel_id: None,
            state_number: number,
            previous_state_commitment: format!("state-{}", number.saturating_sub(1)),
            new_state_commitment: commitment.to_string(),
            settlement_template_hash: template_hash,
            challenge_policy_hash: "challenge-hash".to_string(),
            participant_set_hash: participant_set_hash(&participants()),
            script_covenant_hash: "script-hash".to_string(),
            protocol_version: 1,
            domain_separator: DOMAIN_STATE.to_string(),
        },
        balances: map(&[("alice", 600), ("bob", 400)]),
        participant_signatures: BTreeMap::new(),
    };
    for participant in participants() {
        let signature = sign_update_for(&participant, &state);
        state.participant_signatures.insert(participant, signature);
    }
    state
}

#[test]
fn state_number_0_to_1_update_succeeds() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    registry
        .accept_update(update(0, "state-0", t.hash()))
        .unwrap();
    registry
        .accept_update(update(1, "state-1", t.hash()))
        .unwrap();
}

#[test]
fn state_number_1_to_2_update_succeeds() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    registry
        .accept_update(update(0, "state-0", t.hash()))
        .unwrap();
    registry
        .accept_update(update(1, "state-1", t.hash()))
        .unwrap();
    registry
        .accept_update(update(2, "state-2", t.hash()))
        .unwrap();
}

#[test]
fn settlement_of_stale_state_number_0_fails_after_state_number_2_is_accepted() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    let s0 = update(0, "state-0", t.hash());
    registry.accept_update(s0.clone()).unwrap();
    registry
        .accept_update(update(1, "state-1", t.hash()))
        .unwrap();
    registry
        .accept_update(update(2, "state-2", t.hash()))
        .unwrap();
    assert!(matches!(
        registry.settle(&s0, &t),
        Err(KurrentError::StaleState {
            latest: 2,
            attempted: 0
        })
    ));
}

#[test]
fn settlement_of_stale_state_number_1_fails_after_state_number_2_is_accepted() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    registry
        .accept_update(update(0, "state-0", t.hash()))
        .unwrap();
    let s1 = update(1, "state-1", t.hash());
    registry.accept_update(s1.clone()).unwrap();
    registry
        .accept_update(update(2, "state-2", t.hash()))
        .unwrap();
    assert!(matches!(
        registry.settle(&s1, &t),
        Err(KurrentError::StaleState {
            latest: 2,
            attempted: 1
        })
    ));
}

#[test]
fn same_number_conflicting_state_rejection() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    registry
        .accept_update(update(0, "state-0", t.hash()))
        .unwrap();
    registry
        .accept_update(update(1, "state-1a", t.hash()))
        .unwrap();
    assert!(matches!(
        registry.accept_update(update(1, "state-1b", t.hash())),
        Err(KurrentError::SameNumberConflict { state_number: 1 })
    ));
}

#[test]
fn settlement_template_mismatch_fails() {
    let t = template();
    let mut wrong = template();
    wrong.template_id = "wrong".to_string();
    let mut registry = SettlementRegistry::default();
    let s0 = update(0, "state-0", t.hash());
    registry.accept_update(s0.clone()).unwrap();
    assert!(matches!(
        registry.settle(&s0, &wrong),
        Err(KurrentError::SettlementTemplateMismatch)
    ));
}

#[test]
fn wrong_channel_id_fails() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    let mut s0 = update(0, "state-0", t.hash());
    registry.accept_update(s0.clone()).unwrap();
    s0.header.channel_id = "wrong-channel".to_string();
    assert!(matches!(
        registry.settle(&s0, &t),
        Err(KurrentError::UnknownChannel(_))
    ));
}

#[test]
fn state_update_wrong_previous_commitment_fails() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    registry
        .accept_update(update(0, "state-0", t.hash()))
        .unwrap();
    let mut s1 = update(1, "state-1", t.hash());
    s1.header.previous_state_commitment = "foreign-state".to_string();
    assert!(matches!(
        registry.accept_update(s1),
        Err(KurrentError::PreviousStateMismatch { .. })
    ));
}

#[test]
fn channel_update_config_funding_and_signature_scope_passes() {
    let t = template();
    validate_channel_update(
        &channel_config(),
        &funding(),
        &update(0, "state-0", t.hash()),
        &t,
    )
    .unwrap();
}

#[test]
fn channel_update_rejects_under_signed_state() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.participant_signatures.remove("bob");
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::InsufficientSignatures {
            required: 2,
            actual: 1
        })
    ));
}

#[test]
fn channel_update_rejects_forged_signature() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    let forged = sign_update_for("alice", &state);
    state
        .participant_signatures
        .insert("bob".to_string(), forged);
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::InvalidParticipantSignature(participant)) if participant == "bob"
    ));
}

#[test]
fn channel_update_rejects_malformed_participant_public_key() {
    let t = template();
    let state = update(0, "state-0", t.hash());
    let mut config = channel_config();
    config
        .access_manifest
        .participant_public_keys
        .insert("alice".to_string(), "not-a-public-key".to_string());
    assert!(matches!(
        validate_channel_update(&config, &funding(), &state, &t),
        Err(KurrentError::InvalidParticipantPublicKey(participant)) if participant == "alice"
    ));
}

#[test]
fn channel_update_rejects_foreign_balance_participant() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.balances.insert("mallory".to_string(), 1);
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::UnauthorizedParticipant(participant)) if participant == "mallory"
    ));
}

#[test]
fn channel_update_rejects_wrong_funding_outpoint() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.header.funding_outpoint = "foreign-funding:0".to_string();
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::WrongFundingOutpoint { .. })
    ));
}

fn factory() -> FactoryState {
    let vc1 = VirtualChannelState {
        virtual_channel_id: "vc-1".to_string(),
        channel_id: "channel-vc-1".to_string(),
        balance_by_participant: map(&[("alice", 300), ("bob", 200)]),
        state_number: 2,
        state_commitment: "vc-1-state".to_string(),
    };
    let vc2 = VirtualChannelState {
        virtual_channel_id: "vc-2".to_string(),
        channel_id: "channel-vc-2".to_string(),
        balance_by_participant: map(&[("carol", 250), ("dave", 250)]),
        state_number: 0,
        state_commitment: "vc-2-state".to_string(),
    };
    FactoryState {
        factory_id: "factory-1".to_string(),
        network_profile: "local-toccata-devnet".to_string(),
        total_principal: 1_000,
        fee_reserve: 10,
        virtual_channels: BTreeMap::from([
            (vc1.virtual_channel_id.clone(), vc1),
            (vc2.virtual_channel_id.clone(), vc2),
        ]),
        materialised_receipts: BTreeSet::new(),
    }
}

fn materialisation_plan() -> MaterialisationPlan {
    MaterialisationPlan {
        materialisation_id: "mat-1".to_string(),
        factory_id: "factory-1".to_string(),
        virtual_channel_id: "vc-1".to_string(),
        touched_leaves: TouchedLeaves {
            virtual_channel_ids: BTreeSet::from(["vc-1".to_string()]),
        },
        principal_input_ids: BTreeSet::from(["principal-in".to_string()]),
        fee_input_ids: BTreeSet::from(["fee-in".to_string()]),
        principal_amount: 500,
        fee_amount: 10,
        output_amounts: map(&[("alice", 300), ("bob", 200), ("fee", 10)]),
    }
}

fn after_factory_materialisation(before: &FactoryState) -> FactoryState {
    let mut after = before.clone();
    after.total_principal = 500;
    after.fee_reserve = 0;
    after.virtual_channels.remove("vc-1");
    after
}

#[test]
fn wrong_factory_id_fails() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    let mut plan = materialisation_plan();
    plan.factory_id = "wrong-factory".to_string();
    assert!(matches!(
        validate_materialisation(&before, &after, &plan),
        Err(KurrentError::WrongFactoryId { .. })
    ));
}

#[test]
fn wrong_virtual_channel_id_fails() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    let mut plan = materialisation_plan();
    plan.virtual_channel_id = "missing-vc".to_string();
    assert!(matches!(
        validate_materialisation(&before, &after, &plan),
        Err(KurrentError::WrongVirtualChannelId(_))
    ));
}

#[test]
fn double_materialisation_fails() {
    let mut before = factory();
    before.materialised_receipts.insert("mat-1".to_string());
    let after = after_factory_materialisation(&before);
    assert!(matches!(
        validate_materialisation(&before, &after, &materialisation_plan()),
        Err(KurrentError::DoubleMaterialisation(_))
    ));
}

#[test]
fn factory_materialisation_cannot_mutate_untouched_virtual_channels() {
    let before = factory();
    let mut after = after_factory_materialisation(&before);
    after
        .virtual_channels
        .get_mut("vc-2")
        .unwrap()
        .state_commitment = "mutated".to_string();
    assert!(matches!(
        validate_materialisation(&before, &after, &materialisation_plan()),
        Err(KurrentError::MutatedUntouchedVirtualChannel(id)) if id == "vc-2"
    ));
}

#[test]
fn fee_principal_accounting_stays_separate() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    let mut plan = materialisation_plan();
    plan.fee_input_ids.insert("principal-in".to_string());
    assert!(matches!(
        validate_materialisation(&before, &after, &plan),
        Err(KurrentError::FeePrincipalNotSeparated)
    ));
}

#[test]
fn conservation_holds_for_valid_factory_materialisation() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    validate_materialisation(&before, &after, &materialisation_plan()).unwrap();
}

#[test]
fn factory_materialisation_removes_touched_virtual_channel() {
    let before = factory();
    let mut after = after_factory_materialisation(&before);
    after
        .virtual_channels
        .insert("vc-1".to_string(), before.virtual_channels["vc-1"].clone());
    assert!(matches!(
        validate_materialisation(&before, &after, &materialisation_plan()),
        Err(KurrentError::MaterialisedChannelStillActive(id)) if id == "vc-1"
    ));
}

#[test]
fn factory_materialisation_rejects_wrong_principal_amount() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    let mut plan = materialisation_plan();
    plan.principal_amount = 499;
    assert!(matches!(
        validate_materialisation(&before, &after, &plan),
        Err(KurrentError::MaterialisationAmountMismatch {
            expected: 500,
            actual: 499
        })
    ));
}

#[test]
fn factory_materialisation_rejects_wrong_fee_reserve_consumption() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    let mut plan = materialisation_plan();
    plan.fee_amount = 9;
    assert!(matches!(
        validate_materialisation(&before, &after, &plan),
        Err(KurrentError::MaterialisationAmountMismatch {
            expected: 10,
            actual: 9
        })
    ));
}

#[test]
fn wrong_ln_preimage_fails() {
    let hash = sha256_hex(b"correct-preimage");
    assert!(matches!(
        validate_preimage("wrong-preimage", &hash),
        Err(KurrentError::WrongPreimage)
    ));
}

#[test]
fn ln_hex_preimage_validates_against_decoded_bytes_hash() {
    let preimage = "0001020304050607080900010203040506070809000102030405060708090001";
    let bytes = hex::decode(preimage).unwrap();
    let hash = sha256_hex(&bytes);
    validate_preimage(preimage, &hash).unwrap();
}

#[test]
fn ln_swap_accepts_hex_preimage_from_lnd_evidence() {
    let preimage = "0001020304050607080900010203040506070809000102030405060708090001";
    let hash = sha256_hex(&hex::decode(preimage).unwrap());
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-hex".to_string(),
        direction: "ln-to-kaspa".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: preimage.to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "alice".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-hex".to_string());
    receipt.direction = Some("ln-to-kaspa".to_string());
    receipt.refresh_hash();
    validate_ln_swap(&evidence, &receipt).unwrap();
}

#[test]
fn ln_to_kaspa_receipt_replay_fails() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-1".to_string(),
        direction: "ln-to-kaspa".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "alice".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-1".to_string());
    receipt.direction = Some("kaspa-to-ln".to_string());
    receipt.refresh_hash();
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::ReceiptReplay)
    ));
}

#[test]
fn kaspa_to_ln_receipt_replay_fails() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-2".to_string(),
        direction: "kaspa-to-ln".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "bob".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "wrong-network",
        "channel-a",
        "funding:0",
        "settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-2".to_string());
    receipt.direction = Some("kaspa-to-ln".to_string());
    receipt.refresh_hash();
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::WrongNetworkProfile { .. })
    ));
}

#[test]
fn ln_swap_rejects_stale_receipt_hash_after_scope_mutation() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-stale-hash".to_string(),
        direction: "ln-to-kaspa".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "alice".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-stale-hash".to_string());
    receipt.direction = Some("ln-to-kaspa".to_string());
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::ReceiptHashMismatch)
    ));
}

#[test]
fn ln_swap_rejects_wrong_kaspa_funding_outpoint() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-funding".to_string(),
        direction: "ln-to-kaspa".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "alice".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "foreign-funding:0",
        "settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-funding".to_string());
    receipt.direction = Some("ln-to-kaspa".to_string());
    receipt.refresh_hash();
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::WrongFundingOutpoint { .. })
    ));
}

#[test]
fn ln_swap_rejects_wrong_kaspa_settlement_outpoint() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-settlement".to_string(),
        direction: "kaspa-to-ln".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "bob".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "foreign-settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-settlement".to_string());
    receipt.direction = Some("kaspa-to-ln".to_string());
    receipt.refresh_hash();
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::WrongSettlementOutpoint { .. })
    ));
}

#[test]
fn ln_swap_rejects_wrong_script_hash() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-script".to_string(),
        direction: "ln-to-kaspa".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "alice".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "settlement:0",
        2,
        "foreign-script-hash",
    );
    receipt.swap_id = Some("swap-script".to_string());
    receipt.direction = Some("ln-to-kaspa".to_string());
    receipt.refresh_hash();
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::WrongScriptHash { .. })
    ));
}

#[test]
fn ln_swap_rejects_wrong_protocol_version() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 2,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-protocol".to_string(),
        direction: "ln-to-kaspa".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 100,
        recipient: "alice".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-protocol".to_string());
    receipt.direction = Some("ln-to-kaspa".to_string());
    receipt.refresh_hash();
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::WrongProtocolVersion {
            expected: 2,
            actual: 1
        })
    ));
}

#[test]
fn ln_swap_rejects_zero_amount_evidence() {
    let hash = sha256_hex(b"preimage");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: "swap-zero".to_string(),
        direction: "ln-to-kaspa".to_string(),
        ln_payment_hash: hash.clone(),
        preimage: "preimage".to_string(),
        preimage_hash: hash,
        kaspa_funding_outpoint: "funding:0".to_string(),
        kaspa_settlement_outpoint: "settlement:0".to_string(),
        amount: 0,
        recipient: "alice".to_string(),
        script_hash: "script-hash".to_string(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "settlement:0",
        2,
        "script-hash",
    );
    receipt.swap_id = Some("swap-zero".to_string());
    receipt.direction = Some("ln-to-kaspa".to_string());
    receipt.refresh_hash();
    assert!(matches!(
        validate_ln_swap(&evidence, &receipt),
        Err(KurrentError::InvalidSwapEvidence(_))
    ));
}

#[test]
fn refund_before_maturity_fails() {
    let mut registry = SettlementRegistry::default();
    assert!(matches!(
        registry.refund_claim("swap-1", 119, 120),
        Err(KurrentError::RefundNotMature {
            current_daa: 119,
            required_daa: 120
        })
    ));
}

#[test]
fn refund_after_maturity_succeeds() {
    let mut registry = SettlementRegistry::default();
    registry.refund_claim("swap-1", 120, 120).unwrap();
}

#[test]
fn settlement_plus_refund_double_claim_fails() {
    let mut registry = SettlementRegistry::default();
    registry.settle_claim("swap-1").unwrap();
    assert!(
        matches!(registry.refund_claim("swap-1", 120, 120), Err(KurrentError::DoubleClaim(id)) if id == "swap-1")
    );
}

fn claim_scope(funding_outpoint: &str) -> ClaimScope {
    ClaimScope {
        network_profile: "local-toccata-devnet".to_string(),
        funding_outpoint: funding_outpoint.to_string(),
        output_id: "settlement:0".to_string(),
        claim_subject: "swap-1".to_string(),
    }
}

#[test]
fn scoped_settlement_and_refund_are_mutually_exclusive() {
    let mut registry = SettlementRegistry::default();
    let scope = claim_scope("funding:0");
    registry.settle_scoped_claim(&scope).unwrap();
    assert!(matches!(
        registry.refund_scoped_claim(&scope, 120, 120),
        Err(KurrentError::DoubleClaim(id)) if id == scope.exclusive_key()
    ));
}

#[test]
fn scoped_claims_do_not_collide_across_funding_outputs() {
    let mut registry = SettlementRegistry::default();
    let first = claim_scope("funding:0");
    let second = claim_scope("funding:1");
    registry.settle_scoped_claim(&first).unwrap();
    registry.refund_scoped_claim(&second, 120, 120).unwrap();
}

#[test]
fn evidence_verifier_rejects_missing_files() {
    let root = unique_temp_dir("missing");
    fs::create_dir_all(&root).unwrap();
    let bundle = EvidenceBundle {
        acceptance_json: "evidence/kurrent-acceptance.json".to_string(),
        referenced_files: vec![EvidenceFile {
            path: "missing.txt".to_string(),
            sha256: sha256_hex(b"missing"),
        }],
    };
    assert!(matches!(
        verify_evidence_bundle(&root, &bundle),
        Err(KurrentError::MissingEvidenceFile(_))
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn evidence_verifier_rejects_mismatched_file_hashes() {
    let root = unique_temp_dir("mismatch");
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("file.txt"), b"actual").unwrap();
    let bundle = EvidenceBundle {
        acceptance_json: "evidence/kurrent-acceptance.json".to_string(),
        referenced_files: vec![EvidenceFile {
            path: "file.txt".to_string(),
            sha256: sha256_hex(b"expected"),
        }],
    };
    assert!(matches!(
        verify_evidence_bundle(&root, &bundle),
        Err(KurrentError::EvidenceHashMismatch { .. })
    ));
    let _ = fs::remove_dir_all(root);
}

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("kurrent-{label}-{nanos}"))
}

#[test]
fn client_readiness_requires_all_business_flow_evidence() {
    let tools = ToolPaths {
        kaspad: "/bin/sh".into(),
        kaspa_cli: "/bin/sh".into(),
        kaspa_wallet: "/bin/sh".into(),
        lnd: "/bin/sh".into(),
        lncli: "/bin/sh".into(),
        bitcoind: "/bin/sh".into(),
        bitcoin_cli: "/bin/sh".into(),
    };
    let client = KurrentClient::new(
        tools,
        DevnetProfile::default(),
        unique_temp_dir("client-readiness"),
    );
    let audit = client.audit_readiness(&[]);
    assert_eq!(audit.status, "failed/blocked");
    assert_eq!(audit.missing_flow_evidence.len(), 6);
}

#[test]
fn client_detects_missing_tool_paths() {
    let tools = ToolPaths {
        kaspad: "/definitely/missing/kaspad".into(),
        kaspa_cli: "/bin/sh".into(),
        kaspa_wallet: "/bin/sh".into(),
        lnd: "/bin/sh".into(),
        lncli: "/bin/sh".into(),
        bitcoind: "/bin/sh".into(),
        bitcoin_cli: "/bin/sh".into(),
    };
    assert_eq!(tools.missing(), vec!["kaspad".to_string()]);
}
