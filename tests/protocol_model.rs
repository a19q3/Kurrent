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

fn resign_update(update: &mut StateUpdate) {
    update.participant_signatures.clear();
    for participant in participants() {
        let signature = sign_update_for(&participant, update);
        update.participant_signatures.insert(participant, signature);
    }
}

fn channel_config() -> KurrentChannelConfig {
    let channel_id = "channel-a".to_string();
    KurrentChannelConfig {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        genesis_or_devnet_id: Some("devnet-1".to_string()),
        expected_lane_id: Some(derive_kurrent_channel_lane_id(&channel_id)),
        channel_id,
        participants: participants(),
        challenge_policy: ChallengePolicy {
            mode: "latest-state".to_string(),
            challenge_window_daa: 120,
            same_number_conflict_rule: SameNumberConflictRule::RejectConflict,
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
        covenant_id: Some("covenant-id".to_string()),
        expected_lane_id: Some(derive_kurrent_channel_lane_id("channel-a")),
        script_covenant_hash: "script-hash".to_string(),
    }
}

fn challenge_policy_hash() -> String {
    hash_json(DOMAIN_STATE, &channel_config().challenge_policy)
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
            fee_policy_hash: None,
            challenge_policy_hash: challenge_policy_hash(),
            participant_set_hash: participant_set_hash(&participants()),
            covenant_id: Some("covenant-id".to_string()),
            expected_lane_id: Some(derive_kurrent_channel_lane_id("channel-a")),
            script_covenant_hash: "script-hash".to_string(),
            protocol_version: 1,
            domain_separator: DOMAIN_STATE.to_string(),
        },
        balances: map(&[("alice", 600), ("bob", 400)]),
        participant_signatures: BTreeMap::new(),
    };
    resign_update(&mut state);
    state
}

fn candidate(
    state: StateUpdate,
    txid: &str,
    accepted_order_index: u64,
    daa_score: u64,
) -> SettlementEligibilityCandidate {
    SettlementEligibilityCandidate {
        evidence: SettlementCandidateEvidence {
            network_profile: state.header.network_profile.clone(),
            funding_outpoint: state.header.funding_outpoint.clone(),
            channel_id: state.header.channel_id.clone(),
            factory_id: state.header.factory_id.clone(),
            virtual_channel_id: state.header.virtual_channel_id.clone(),
            state_number: state.header.state_number,
            state_header_hash: state.header.hash(),
            lane_id: state.header.expected_lane_id.clone().unwrap(),
            candidate_txid: txid.to_string(),
            accepted_order_index,
            accepting_chain_block_hash: format!("block-{accepted_order_index}"),
            daa_score,
            blue_score: daa_score,
        },
        update: state,
    }
}

fn eligibility_policy(window: u64) -> SettlementEligibilityPolicy {
    SettlementEligibilityPolicy {
        response_window_daa: window,
    }
}

fn fee_policy(max_sponsor_fee: u64) -> SettlementFeePolicy {
    SettlementFeePolicy {
        policy_id: "sponsor-policy-v1".to_string(),
        max_sponsor_fee,
        sponsor_mode: "external-sponsor-input".to_string(),
    }
}

fn sponsored_update(number: u64, commitment: &str, template_hash: String) -> StateUpdate {
    let policy = fee_policy(100);
    let mut state = update(number, commitment, template_hash);
    state.header.fee_policy_hash = Some(policy.hash());
    resign_update(&mut state);
    state
}

fn sponsored_candidate(
    state: StateUpdate,
    txid: &str,
    accepted_order_index: u64,
    daa_score: u64,
    sponsor_fee: u64,
) -> FeeSponsoredSettlementCandidate {
    let template = template();
    FeeSponsoredSettlementCandidate {
        eligibility: candidate(state, txid, accepted_order_index, daa_score),
        sponsor: SettlementSponsorEvidence {
            candidate_txid: txid.to_string(),
            sponsor_input_outpoints: vec![format!("sponsor-{txid}:0")],
            sponsor_input_total: sponsor_fee.saturating_add(1_000),
            sponsor_change_total: 1_000,
            sponsor_fee,
            settlement_template_hash: template.hash(),
            settlement_distribution_hash: settlement_distribution_hash(&template),
        },
    }
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
fn lane_derivation_is_deterministic_and_valid_user_lane() {
    let first = derive_kurrent_channel_lane_id("channel-a");
    let second = derive_kurrent_channel_lane_id("channel-a");
    assert_eq!(first, second);
    assert_eq!(first.len(), 40);
    assert!(is_valid_kurrent_user_lane_id(&first));
    assert_ne!(first, "0000000000000000000000000000000000000000");
}

#[test]
fn channel_update_without_lane_binding_validates_when_unconfigured() {
    let t = template();
    let mut config = channel_config();
    let mut funding = funding();
    let mut state = update(0, "state-0", t.hash());
    config.expected_lane_id = None;
    funding.expected_lane_id = None;
    state.header.expected_lane_id = None;
    resign_update(&mut state);
    validate_channel_update(&config, &funding, &state, &t).unwrap();
}

#[test]
fn channel_update_rejects_missing_funding_lane_when_configured() {
    let t = template();
    let mut funding = funding();
    funding.expected_lane_id = None;
    assert!(matches!(
        validate_channel_update(
            &channel_config(),
            &funding,
            &update(0, "state-0", t.hash()),
            &t
        ),
        Err(KurrentError::WrongLaneId { .. })
    ));
}

#[test]
fn channel_update_rejects_missing_header_lane_when_configured() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.header.expected_lane_id = None;
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::WrongLaneId { .. })
    ));
}

#[test]
fn channel_update_rejects_wrong_header_lane() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.header.expected_lane_id = Some(derive_kurrent_channel_lane_id("foreign-channel"));
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::WrongLaneId { .. })
    ));
}

#[test]
fn channel_update_rejects_native_or_malformed_lane_id() {
    let t = template();
    let state = update(0, "state-0", t.hash());

    let mut native_config = channel_config();
    native_config.expected_lane_id = Some("0000000000000000000000000000000000000000".to_string());
    assert!(matches!(
        validate_channel_update(&native_config, &funding(), &state, &t),
        Err(KurrentError::InvalidLaneId { field, .. }) if field == "config.expected_lane_id"
    ));

    let mut malformed_funding = funding();
    malformed_funding.expected_lane_id = Some("not-a-lane".to_string());
    assert!(matches!(
        validate_channel_update(&channel_config(), &malformed_funding, &state, &t),
        Err(KurrentError::InvalidLaneId { field, .. }) if field == "funding.expected_lane_id"
    ));
}

#[test]
fn settlement_eligibility_displaces_lower_candidate_and_matures_survivor() {
    let t = template();
    let lower = candidate(update(1, "state-1", t.hash()), "candidate-lower", 10, 100);
    let higher = candidate(update(2, "state-2", t.hash()), "candidate-higher", 11, 102);
    let decisions = evaluate_settlement_eligibility(
        &channel_config(),
        &funding(),
        &t,
        &eligibility_policy(5),
        &[lower, higher],
        107,
    )
    .unwrap();

    assert_eq!(decisions[0].status, SettlementEligibilityStatus::Displaced);
    assert_eq!(
        decisions[0].displaced_by.as_deref(),
        Some("candidate-higher")
    );
    assert_eq!(
        decisions[1].status,
        SettlementEligibilityStatus::EligibleToFinalise
    );
}

#[test]
fn settlement_eligibility_survivor_is_not_yet_eligible_before_window_closes() {
    let t = template();
    let lower = candidate(update(1, "state-1", t.hash()), "candidate-lower", 10, 100);
    let higher = candidate(update(2, "state-2", t.hash()), "candidate-higher", 11, 102);
    let decisions = evaluate_settlement_eligibility(
        &channel_config(),
        &funding(),
        &t,
        &eligibility_policy(5),
        &[lower, higher],
        106,
    )
    .unwrap();

    assert_eq!(decisions[0].status, SettlementEligibilityStatus::Displaced);
    assert_eq!(
        decisions[1].status,
        SettlementEligibilityStatus::NotYetEligible
    );
}

#[test]
fn settlement_candidate_remains_provisional_before_its_response_window_closes() {
    let t = template();
    let lower = candidate(update(1, "state-1", t.hash()), "candidate-lower", 10, 100);
    let decisions = evaluate_settlement_eligibility(
        &channel_config(),
        &funding(),
        &t,
        &eligibility_policy(5),
        &[lower],
        104,
    )
    .unwrap();

    assert_eq!(
        decisions[0].status,
        SettlementEligibilityStatus::Provisional
    );
}

#[test]
fn settlement_eligibility_rejects_wrong_candidate_lane() {
    let t = template();
    let mut lower = candidate(update(1, "state-1", t.hash()), "candidate-lower", 10, 100);
    lower.evidence.lane_id = derive_kurrent_channel_lane_id("foreign-channel");

    assert!(matches!(
        evaluate_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &[lower],
            104,
        ),
        Err(KurrentError::WrongLaneId { .. })
    ));
}

#[test]
fn settlement_eligibility_rejects_invalid_candidate_signature() {
    let t = template();
    let mut state = update(1, "state-1", t.hash());
    state
        .participant_signatures
        .insert("alice".to_string(), "00".repeat(64));
    let lower = candidate(state, "candidate-lower", 10, 100);

    assert!(matches!(
        evaluate_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &[lower],
            104,
        ),
        Err(KurrentError::InvalidParticipantSignature(participant)) if participant == "alice"
    ));
}

#[test]
fn settlement_eligibility_rejects_same_number_conflict() {
    let t = template();
    let first = candidate(update(1, "state-1", t.hash()), "candidate-a", 10, 100);
    let second = candidate(update(1, "state-1b", t.hash()), "candidate-b", 11, 101);

    assert!(matches!(
        evaluate_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &[first, second],
            107,
        ),
        Err(KurrentError::SameNumberConflict { state_number: 1 })
    ));
}

#[test]
fn settlement_eligibility_prefer_later_collapses_same_number_to_higher_accepted_order() {
    // Under SameNumberConflictRule::PreferLater, two candidates with the
    // same state_number are deduped to the one with the higher
    // KIP-21 lane-local accepted_order_index. The lower accepted_order
    // commitment is silently dropped; the survivor is then evaluated as
    // if it were the only candidate at that state number.
    let t = template();
    let mut config = channel_config();
    config.challenge_policy.same_number_conflict_rule = SameNumberConflictRule::PreferLater;
    let new_challenge_policy_hash = hash_json(DOMAIN_STATE, &config.challenge_policy);

    // Re-issue the updates against the modified challenge policy so that
    // both the signed payload hash and the state-header hash agree with
    // the new policy. The default `update()` helper hard-codes the
    // default RejectConflict rule via `channel_config()`, so we rebuild
    // the candidates manually here.
    let mut earlier_update = update(1, "state-1", t.hash());
    earlier_update.header.challenge_policy_hash = new_challenge_policy_hash.clone();
    resign_update(&mut earlier_update);
    let earlier = candidate(earlier_update, "candidate-earlier", 10, 100);

    let mut later_update = update(1, "state-1b", t.hash());
    later_update.header.challenge_policy_hash = new_challenge_policy_hash;
    resign_update(&mut later_update);
    let later = candidate(later_update, "candidate-later", 11, 101);

    let decisions = evaluate_settlement_eligibility(
        &config,
        &funding(),
        &t,
        &eligibility_policy(5),
        &[earlier, later],
        102,
    )
    .expect("PreferLater collapses same-number candidates without error");

    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].candidate_txid, "candidate-later");
    assert_eq!(decisions[0].state_number, 1);
    assert_eq!(decisions[0].accepted_order_index, 11);
}

#[test]
fn settlement_eligibility_prefer_later_still_rejects_identical_accepted_order() {
    // Two candidates with the same state_number AND the same
    // accepted_order_index cannot be resolved by PreferLater because the
    // lane-accepted-order is identical and the model has no further
    // ordering signal. This must remain an error: the registry would
    // otherwise silently pick an arbitrary commitment and the verifier
    // could not reproduce the choice deterministically.
    let t = template();
    let mut config = channel_config();
    config.challenge_policy.same_number_conflict_rule = SameNumberConflictRule::PreferLater;
    let new_challenge_policy_hash = hash_json(DOMAIN_STATE, &config.challenge_policy);

    let mut a_update = update(1, "state-1", t.hash());
    a_update.header.challenge_policy_hash = new_challenge_policy_hash.clone();
    resign_update(&mut a_update);
    let a = candidate(a_update, "candidate-a", 10, 100);

    let mut b_update = update(1, "state-1b", t.hash());
    b_update.header.challenge_policy_hash = new_challenge_policy_hash;
    resign_update(&mut b_update);
    let b = candidate(b_update, "candidate-b", 10, 101);

    assert!(matches!(
        evaluate_settlement_eligibility(
            &config,
            &funding(),
            &t,
            &eligibility_policy(5),
            &[a, b],
            102,
        ),
        Err(KurrentError::SameNumberConflict { state_number: 1 })
    ));
}

#[test]
fn same_number_conflict_rule_parse_defaults_unknown_values_to_reject_conflict() {
    // The wire form was a free-form string in earlier evidence; parsing
    // must continue to recognise "prefer-later" and fall back to the
    // conservative RejectConflict for any other value so that older JSON
    // evidence files remain valid after the field type was upgraded to
    // the enum.
    assert_eq!(
        SameNumberConflictRule::parse("prefer-later"),
        SameNumberConflictRule::PreferLater
    );
    assert_eq!(
        SameNumberConflictRule::parse("reject-conflict"),
        SameNumberConflictRule::RejectConflict
    );
    assert_eq!(
        SameNumberConflictRule::parse(""),
        SameNumberConflictRule::RejectConflict
    );
    assert_eq!(
        SameNumberConflictRule::parse("garbage"),
        SameNumberConflictRule::RejectConflict
    );
    assert_eq!(
        SameNumberConflictRule::default(),
        SameNumberConflictRule::RejectConflict
    );
}

#[test]
fn same_number_conflict_rule_serde_round_trip_preserves_variant_names() {
    // The serde form uses kebab-case so that the wire-level JSON matches
    // the human-readable variant names ("reject-conflict", "prefer-later").
    let reject = serde_json::to_string(&SameNumberConflictRule::RejectConflict).unwrap();
    let prefer = serde_json::to_string(&SameNumberConflictRule::PreferLater).unwrap();
    assert_eq!(reject, "\"reject-conflict\"");
    assert_eq!(prefer, "\"prefer-later\"");
    assert_eq!(
        serde_json::from_str::<SameNumberConflictRule>(&reject).unwrap(),
        SameNumberConflictRule::RejectConflict
    );
    assert_eq!(
        serde_json::from_str::<SameNumberConflictRule>(&prefer).unwrap(),
        SameNumberConflictRule::PreferLater
    );
}

#[test]
fn response_window_substrate_is_daa_score_not_blue_score() {
    // The response-window eligibility check uses `daa_score` (the
    // consensus-recognised virtual-time counter, target rate ~1/s) and
    // not `blue_score` (the cumulative DAG-work structural-ordering
    // measure). The two fields are deliberately set to inconsistent
    // values here so that the substrate choice is observable from the
    // decision:
    //
    // - daa_score = 100, response_window_daa = 5 → eligible_after = 105
    // - current_daa = 103 → Provisional (this is what we expect)
    // - If the model had used blue_score = 50 instead:
    //   eligible_after_blue = 55 → 103 >= 55 → EligibleToFinalise (wrong)
    //
    // Asserting Provisional pins the substrate choice: if a future
    // refactor accidentally consults blue_score for timing, this test
    // fails with a clear "expected Provisional, got EligibleToFinalise"
    // signal rather than a silent substrate swap.
    let t = template();
    let mut lower = candidate(update(1, "state-1", t.hash()), "candidate-lower", 10, 100);
    lower.evidence.daa_score = 100;
    lower.evidence.blue_score = 50;

    let decisions = evaluate_settlement_eligibility(
        &channel_config(),
        &funding(),
        &t,
        &eligibility_policy(5),
        &[lower],
        103,
    )
    .unwrap();

    assert_eq!(decisions.len(), 1);
    assert_eq!(
        decisions[0].status,
        SettlementEligibilityStatus::Provisional,
        "DAA score is the response-window substrate; blue score is structural-ordering only"
    );
}

#[test]
fn settlement_eligibility_allows_predecessor_independent_skipped_state_number() {
    let t = template();
    let first = candidate(update(1, "state-1", t.hash()), "candidate-a", 10, 100);
    let third = candidate(update(3, "state-3", t.hash()), "candidate-c", 11, 101);

    let decisions = evaluate_settlement_eligibility(
        &channel_config(),
        &funding(),
        &t,
        &eligibility_policy(5),
        &[first, third],
        107,
    )
    .unwrap();

    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].status, SettlementEligibilityStatus::Displaced);
    assert_eq!(decisions[0].displaced_by.as_deref(), Some("candidate-c"));
    assert_eq!(
        decisions[1].status,
        SettlementEligibilityStatus::EligibleToFinalise
    );
}

#[test]
fn settlement_eligibility_rejects_wrong_candidate_scope() {
    let t = template();
    let mut lower = candidate(update(1, "state-1", t.hash()), "candidate-lower", 10, 100);
    lower.evidence.channel_id = "foreign-channel".to_string();

    assert!(matches!(
        evaluate_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &[lower],
            104,
        ),
        Err(KurrentError::WrongChannelId { .. })
    ));
}

#[test]
fn fee_sponsored_candidates_preserve_latest_state_displacement() {
    let t = template();
    let lower = sponsored_candidate(
        sponsored_update(1, "state-1", t.hash()),
        "candidate-lower",
        10,
        100,
        80,
    );
    let higher = sponsored_candidate(
        sponsored_update(2, "state-2", t.hash()),
        "candidate-higher",
        11,
        102,
        20,
    );
    let decisions = evaluate_fee_sponsored_settlement_eligibility(
        &channel_config(),
        &funding(),
        &t,
        &eligibility_policy(5),
        &fee_policy(100),
        &[lower, higher],
        107,
    )
    .unwrap();

    assert_eq!(
        decisions[0].eligibility.status,
        SettlementEligibilityStatus::Displaced
    );
    assert_eq!(
        decisions[1].eligibility.status,
        SettlementEligibilityStatus::EligibleToFinalise
    );
    assert!(decisions[0].sponsor_fee > decisions[1].sponsor_fee);
}

#[test]
fn fee_sponsored_candidate_rejects_missing_or_wrong_fee_policy_hash() {
    let t = template();
    let mut missing = sponsored_candidate(
        sponsored_update(1, "state-1", t.hash()),
        "candidate-lower",
        10,
        100,
        10,
    );
    missing.eligibility.update.header.fee_policy_hash = None;
    resign_update(&mut missing.eligibility.update);
    missing.eligibility.evidence.state_header_hash = missing.eligibility.update.header.hash();

    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[missing],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("fee-policy hash")
    ));

    let mut wrong = sponsored_candidate(
        sponsored_update(1, "state-1", t.hash()),
        "candidate-lower",
        10,
        100,
        10,
    );
    wrong.eligibility.update.header.fee_policy_hash = Some(sha256_hex(b"wrong-fee-policy"));
    resign_update(&mut wrong.eligibility.update);
    wrong.eligibility.evidence.state_header_hash = wrong.eligibility.update.header.hash();

    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[wrong],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("fee-policy hash")
    ));
}

#[test]
fn fee_sponsored_candidate_rejects_channel_funding_as_sponsor_input() {
    let t = template();
    let mut lower = sponsored_candidate(
        sponsored_update(1, "state-1", t.hash()),
        "candidate-lower",
        10,
        100,
        10,
    );
    lower.sponsor.sponsor_input_outpoints = vec![funding().funding_outpoint];

    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[lower],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("external")
    ));
}

#[test]
fn fee_sponsored_candidate_rejects_bad_sponsor_accounting() {
    let t = template();
    let base = sponsored_candidate(
        sponsored_update(1, "state-1", t.hash()),
        "candidate-lower",
        10,
        100,
        10,
    );

    let mut zero_fee = base.clone();
    zero_fee.sponsor.sponsor_fee = 0;
    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[zero_fee],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("non-zero")
    ));

    let mut over_limit = base.clone();
    over_limit.sponsor.sponsor_fee = 101;
    over_limit.sponsor.sponsor_input_total = 1_101;
    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[over_limit],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("maximum")
    ));

    let mut bad_sum = base;
    bad_sum.sponsor.sponsor_input_total = 1_009;
    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[bad_sum],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("input total")
    ));
}

#[test]
fn fee_sponsored_candidate_rejects_tampered_template_or_distribution_hash() {
    let t = template();
    let base = sponsored_candidate(
        sponsored_update(1, "state-1", t.hash()),
        "candidate-lower",
        10,
        100,
        10,
    );

    let mut wrong_template = base.clone();
    wrong_template.sponsor.settlement_template_hash = sha256_hex(b"wrong-template");
    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[wrong_template],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("template")
    ));

    let mut wrong_distribution = base;
    wrong_distribution.sponsor.settlement_distribution_hash = sha256_hex(b"wrong-distribution");
    assert!(matches!(
        evaluate_fee_sponsored_settlement_eligibility(
            &channel_config(),
            &funding(),
            &t,
            &eligibility_policy(5),
            &fee_policy(100),
            &[wrong_distribution],
            104,
        ),
        Err(KurrentError::SettlementEligibilityEvidenceMismatch(reason))
            if reason.contains("distribution")
    ));
}

#[test]
fn settlement_eligibility_without_fee_policy_remains_valid() {
    let t = template();
    let lower = candidate(update(1, "state-1", t.hash()), "candidate-lower", 10, 100);
    let decisions = evaluate_settlement_eligibility(
        &channel_config(),
        &funding(),
        &t,
        &eligibility_policy(5),
        &[lower],
        104,
    )
    .unwrap();

    assert_eq!(
        decisions[0].status,
        SettlementEligibilityStatus::Provisional
    );
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

#[test]
fn channel_update_rejects_wrong_covenant_id() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.header.covenant_id = Some("foreign-covenant-id".to_string());
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::WrongCovenantId { .. })
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
    after.materialised_receipts.insert("mat-1".to_string());
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

#[test]
fn accept_update_after_settlement_fails() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    let s0 = update(0, "state-0", t.hash());
    registry.accept_update(s0.clone()).unwrap();
    registry.settle(&s0, &t).unwrap();
    assert!(matches!(
        registry.accept_update(update(1, "state-1", t.hash())),
        Err(KurrentError::ChannelAlreadySettled(id)) if id == "channel-a"
    ));
}

#[test]
fn validate_and_accept_update_rejects_unsigned_state() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    let mut s0 = update(0, "state-0", t.hash());
    s0.participant_signatures.clear();
    assert!(matches!(
        registry.validate_and_accept_update(&channel_config(), &funding(), s0, &t),
        Err(KurrentError::InsufficientSignatures {
            required: 2,
            actual: 0
        })
    ));
}

#[test]
fn validate_and_accept_update_rejects_forged_signature_and_does_not_mutate_registry() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    let mut s0 = update(0, "state-0", t.hash());
    let forged = sign_update_for("alice", &s0);
    s0.participant_signatures.insert("bob".to_string(), forged);
    assert!(matches!(
        registry.validate_and_accept_update(&channel_config(), &funding(), s0, &t),
        Err(KurrentError::InvalidParticipantSignature(participant)) if participant == "bob"
    ));
    assert!(registry.is_empty());
}

#[test]
fn challenge_policy_hash_mismatch_fails() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.header.challenge_policy_hash = "wrong-hash".to_string();
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::WrongChallengePolicyHash)
    ));
}

#[test]
fn settle_rejects_update_with_wrong_funding_outpoint_vs_stored() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    let s0 = update(0, "state-0", t.hash());
    registry.accept_update(s0.clone()).unwrap();
    let mut forged = s0.clone();
    forged.header.funding_outpoint = "foreign-funding:0".to_string();
    assert!(matches!(
        registry.settle(&forged, &t),
        Err(KurrentError::StaleState { .. })
    ));
}

#[test]
fn settlement_receipt_registration_failure_does_not_close_channel() {
    let t = template();
    let mut registry = SettlementRegistry::default();
    let s0 = update(0, "state-0", t.hash());
    registry.accept_update(s0.clone()).unwrap();
    let duplicate_receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        "channel-a",
        "funding:0",
        "settle-v1",
        0,
        t.hash(),
    );
    registry.register_receipt(&duplicate_receipt).unwrap();

    assert!(matches!(
        registry.settle(&s0, &t),
        Err(KurrentError::DuplicateReceipt(_))
    ));
    registry
        .accept_update(update(1, "state-1", t.hash()))
        .unwrap();
}

#[test]
fn channel_funding_sum_overflow_returns_conservation_error() {
    let t = template();
    let state = update(0, "state-0", t.hash());
    let mut funding = funding();
    funding.principal_by_participant = map(&[("alice", u64::MAX), ("bob", 1)]);
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding, &state, &t),
        Err(KurrentError::ConservationFailure { .. })
    ));
}

#[test]
fn channel_balance_sum_overflow_returns_conservation_error() {
    let t = template();
    let mut state = update(0, "state-0", t.hash());
    state.balances = map(&[("alice", u64::MAX), ("bob", 1)]);
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::ConservationFailure { .. })
    ));
}

#[test]
fn settlement_template_output_sum_overflow_returns_conservation_error() {
    let mut t = template();
    t.outputs = map(&[("alice", u64::MAX), ("bob", 1)]);
    let state = update(0, "state-0", t.hash());
    assert!(matches!(
        validate_channel_update(&channel_config(), &funding(), &state, &t),
        Err(KurrentError::ConservationFailure { .. })
    ));
}

#[test]
fn factory_output_sum_overflow_returns_conservation_error() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    let mut plan = materialisation_plan();
    plan.output_amounts = map(&[("alice", u64::MAX), ("bob", 1)]);
    assert!(matches!(
        validate_materialisation(&before, &after, &plan),
        Err(KurrentError::ConservationFailure { .. })
    ));
}

#[test]
fn factory_principal_sum_overflow_returns_invariant_error() {
    let mut before = factory();
    before.total_principal = u64::MAX;
    before
        .virtual_channels
        .get_mut("vc-1")
        .unwrap()
        .balance_by_participant = map(&[("alice", u64::MAX), ("bob", 1)]);
    let after = after_factory_materialisation(&before);
    assert!(matches!(
        validate_materialisation(&before, &after, &materialisation_plan()),
        Err(KurrentError::FactoryPrincipalInvariant { .. })
    ));
}

#[test]
fn factory_rejects_over_broad_touched_leaves() {
    let before = factory();
    let after = after_factory_materialisation(&before);
    let mut plan = materialisation_plan();
    plan.touched_leaves
        .virtual_channel_ids
        .insert("vc-2".to_string());
    assert!(matches!(
        validate_materialisation(&before, &after, &plan),
        Err(KurrentError::WrongVirtualChannelId(id)) if id == "vc-1"
    ));
}

#[test]
fn factory_rejects_injected_after_channel() {
    let before = factory();
    let mut after = after_factory_materialisation(&before);
    after.virtual_channels.insert(
        "injected-vc".to_string(),
        VirtualChannelState {
            virtual_channel_id: "injected-vc".to_string(),
            channel_id: "channel-injected".to_string(),
            balance_by_participant: map(&[("alice", 100)]),
            state_number: 0,
            state_commitment: "injected".to_string(),
        },
    );
    assert!(matches!(
        validate_materialisation(&before, &after, &materialisation_plan()),
        Err(KurrentError::InjectedVirtualChannel(id)) if id == "injected-vc"
    ));
}

#[test]
fn factory_rejects_inconsistent_total_principal() {
    let mut before = factory();
    before.total_principal = 999;
    let after = after_factory_materialisation(&before);
    assert!(matches!(
        validate_materialisation(&before, &after, &materialisation_plan()),
        Err(KurrentError::FactoryPrincipalInvariant {
            expected: 999,
            actual: 1000
        })
    ));
}

#[test]
fn factory_rejects_erased_materialised_receipts() {
    let before = factory();
    let mut after = after_factory_materialisation(&before);
    after.materialised_receipts.clear();
    assert!(matches!(
        validate_materialisation(&before, &after, &materialisation_plan()),
        Err(KurrentError::MaterialisedReceiptsNotPreserved)
    ));
}

#[test]
fn refund_claim_with_template_derives_maturity_from_template() {
    let mut registry = SettlementRegistry::default();
    assert!(matches!(
        registry.refund_claim_with_template("swap-1", &template(), 119),
        Err(KurrentError::RefundNotMature {
            current_daa: 119,
            required_daa: 120
        })
    ));
    registry
        .refund_claim_with_template("swap-1", &template(), 120)
        .unwrap();
}

#[test]
fn refund_claim_with_template_rejects_template_without_refund_window() {
    let mut registry = SettlementRegistry::default();
    let t = SettlementTemplate {
        template_id: "no-refund".to_string(),
        outputs: map(&[("alice", 600), ("bob", 400)]),
        refund_after_daa: None,
        script_covenant_hash: "script-hash".to_string(),
    };
    assert!(matches!(
        registry.refund_claim_with_template("swap-1", &t, 999),
        Err(KurrentError::RefundNotConfigured)
    ));
}
