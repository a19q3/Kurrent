use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    sign::sign,
    subnets::{SubnetworkId, SUBNETWORK_ID_NATIVE},
    tx::{
        CovenantBinding, GenesisCovenantGroup, MutableTransaction, ScriptPublicKey, Transaction,
        TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_grpc_client::GrpcClient;
use kaspa_hashes::{Hash, SeqCommitActiveNode};
use kaspa_rpc_core::{api::rpc::RpcApi, RpcDataVerbosityLevel, RpcTransactionId};
use kaspa_seq_commit::{
    hashing::{
        activity_digest_lane, activity_leaf, lane_key, lane_tip_next, mergeset_context_hash,
        smt_leaf_hash,
    },
    types::{LaneTipInput, MergesetContext, SmtLeafInput},
    verify::{verify_smt_metadata, SmtMetadata},
};
use kaspa_smt::proof::OwnedSmtProof;
use kaspa_testing_integration::common::{daemon::Daemon, utils::fetch_spendable_utxos};
use kaspa_txscript::{
    opcodes::codes::{
        OpAuthOutputCount, OpAuthOutputIdx, OpCheckSequenceVerify, OpElse, OpEndIf, OpEqualVerify,
        OpFalse, OpIf, OpSHA256, OpSwap, OpTrue, OpTxOutputAmount, OpTxOutputCount, OpTxOutputSpk,
        OpTxSubnetId,
    },
    pay_to_address_script, pay_to_script_hash_script, pay_to_script_hash_signature_script,
    script_builder::ScriptBuilder,
};
use kaspad_lib::args::Args;
use kurrent::{
    derive_kurrent_channel_lane_id, evaluate_fee_sponsored_settlement_eligibility,
    evaluate_settlement_eligibility, hash_json, participant_set_hash, settlement_distribution_hash,
    sha256_hex, state_update_signing_digest, validate_channel_update, validate_ln_swap,
    validate_materialisation, AccessManifest, ChallengePolicy, ChannelReceipt, ClaimScope,
    FactoryState, FeeSponsoredSettlementCandidate, FeeSponsoredSettlementDecision, FundingState,
    KurrentChannelConfig, LatestStateHeader, LnSwapEvidence, MaterialisationPlan,
    SameNumberConflictRule, SettlementCandidateEvidence, SettlementEligibilityCandidate,
    SettlementEligibilityDecision, SettlementEligibilityPolicy, SettlementEligibilityStatus,
    SettlementFeePolicy, SettlementRegistry, SettlementSponsorEvidence, SettlementTemplate,
    StateUpdate, TouchedLeaves, VirtualChannelState, DOMAIN_CHANNEL_RECEIPT,
    DOMAIN_FACTORY_MATERIALISATION, DOMAIN_SETTLEMENT_TEMPLATE, DOMAIN_STATE,
};
use secp256k1::{rand::thread_rng, Keypair, Message};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const FUNDING_FEE: u64 = 2_000_000;
const STATE_UPDATE_FEE: u64 = 25_000_000;
const SETTLEMENT_FEE: u64 = 25_000_000;
const MARKER_FEE: u64 = 1_000_000;
const COVENANT_COMPUTE_BUDGET: u16 = 2_000;

struct LiveKaspaContext<'a> {
    rpc: &'a GrpcClient,
    miner_sk: &'a Keypair,
    miner_address: &'a Address,
    coinbase_maturity: u64,
    output_dir: &'a Path,
}

#[derive(Clone)]
struct ExpectedLaneEvent {
    kind: &'static str,
    txid: String,
    version: u16,
}

struct SponsoredLaneMarker {
    tx: Transaction,
    accounting: SponsorMarkerAccounting,
}

#[derive(Clone, Serialize)]
struct SponsorMarkerAccounting {
    sponsor_input_outpoints: Vec<String>,
    sponsor_input_total: u64,
    sponsor_change_total: u64,
    sponsor_fee: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let mut args = env::args().skip(1);
    let first = args.next();
    let result = if first.as_deref() == Some("verify-semantic-evidence") {
        let output_dir = args
            .next()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("evidence"));
        run_semantic_evidence_verifier(&output_dir).map(|_| ())
    } else {
        let output_dir = first
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("evidence"));
        run(&output_dir).await
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

async fn run(output_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(output_dir)
        .map_err(|e| format!("failed to create {}: {e}", output_dir.display()))?;

    let override_params = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../rusty-kaspa/testing/integration/testdata/params/compute_budget_relay_test_params.json");
    let args = Args {
        simnet: true,
        unsafe_rpc: true,
        enable_unsynced_mining: true,
        disable_upnp: true,
        disable_dns_seeding: true,
        utxoindex: true,
        outbound_target: 0,
        block_template_cache_lifetime: Some(0),
        override_params_file: Some(override_params.to_string_lossy().to_string()),
        ..Default::default()
    };
    let mut kaspad = Daemon::new_random_with_args(args, 10);
    let rpc = kaspad.start().await;

    let (miner_sk, miner_address) = keypair_address(kaspad.network.into());
    let (alice_sk, alice_address) = keypair_address(kaspad.network.into());
    let (bob_sk, bob_address) = keypair_address(kaspad.network.into());

    let coinbase_maturity = 0;
    let maturity_barrier = 10;
    for _ in 0..maturity_barrier {
        mine_block(&rpc, &miner_address).await?;
    }
    wait_for_daa(&rpc, maturity_barrier).await?;

    let utxos = fetch_spendable_utxos(&rpc, miner_address.clone(), coinbase_maturity).await;
    let Some((funding_input_outpoint, funding_input_entry)) = utxos.first().cloned() else {
        return Err("no spendable miner UTXO after simnet maturity mining".to_string());
    };
    if funding_input_entry.amount <= FUNDING_FEE + SETTLEMENT_FEE + 1 {
        return Err(format!(
            "spendable miner UTXO {} is too small for Kurrent funding evidence",
            funding_input_entry.amount
        ));
    }

    let funding_value = funding_input_entry.amount - FUNDING_FEE;
    let state_2_value = funding_value - STATE_UPDATE_FEE;
    let settlement_value = state_2_value - SETTLEMENT_FEE;
    let alice_value = settlement_value * 60 / 100;
    let bob_value = settlement_value - alice_value;
    let alice_spk = pay_to_address_script(&alice_address);
    let bob_spk = pay_to_address_script(&bob_address);
    let channel_id = "channel-a";
    let expected_lane_id = derive_kurrent_channel_lane_id(channel_id);
    let expected_lane = subnetwork_id_from_hex(&expected_lane_id)?;
    let expected_lane_bytes = expected_lane.as_bytes().to_vec();
    let wrong_user_lane_id = derive_kurrent_channel_lane_id("channel-a-wrong-lane");
    let wrong_user_lane = subnetwork_id_from_hex(&wrong_user_lane_id)?;
    let monitor_start_block = rpc
        .get_sink()
        .await
        .map_err(|e| format!("failed to read lane monitor start block: {e}"))?
        .sink;
    let state_2_redeem_script = build_state_2_redeem_script(
        &expected_lane_bytes,
        alice_value,
        &alice_spk,
        bob_value,
        &bob_spk,
    )?;
    let state_2_spk = pay_to_script_hash_script(&state_2_redeem_script);
    let state_1_redeem_script =
        build_state_1_redeem_script(&expected_lane_bytes, state_2_value, &state_2_spk)?;
    let state_1_spk = pay_to_script_hash_script(&state_1_redeem_script);

    let funding_tx = signed_genesis_covenant_tx(
        &miner_sk,
        funding_input_outpoint,
        funding_input_entry,
        funding_value,
        state_1_spk,
        expected_lane,
        b"KURRENT_STATE_V1:funding",
    )?;
    let funding_covenant_id = funding_tx.outputs[0]
        .covenant
        .ok_or_else(|| "funding transaction did not populate a covenant id".to_string())?
        .covenant_id;
    let funding_covenant_id_string = funding_covenant_id.to_string();
    let funding_txid = submit_and_mine(&rpc, &miner_address, &funding_tx).await?;

    let state_update_signature_script = p2sh_signature_script(false, &state_1_redeem_script)?;
    let native_lane_state_update_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(funding_tx.id(), 0),
            state_update_signature_script.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![TransactionOutput::with_covenant(
            state_2_value,
            state_2_spk.clone(),
            Some(CovenantBinding::new(0, funding_covenant_id)),
        )],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        b"KURRENT_STATE_V1:update-state-1-to-2-native-lane-rejected".to_vec(),
    );
    let native_lane_rejection = rpc
        .submit_transaction((&native_lane_state_update_tx).into(), false)
        .await
        .err()
        .map(|e| e.to_string())
        .ok_or_else(|| "native-lane state update was unexpectedly accepted".to_string())?;
    let wrong_user_lane_state_update_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(funding_tx.id(), 0),
            state_update_signature_script.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![TransactionOutput::with_covenant(
            state_2_value,
            state_2_spk.clone(),
            Some(CovenantBinding::new(0, funding_covenant_id)),
        )],
        0,
        wrong_user_lane,
        0,
        b"KURRENT_STATE_V1:update-state-1-to-2-wrong-user-lane-rejected".to_vec(),
    );
    let wrong_user_lane_rejection = rpc
        .submit_transaction((&wrong_user_lane_state_update_tx).into(), false)
        .await
        .err()
        .map(|e| e.to_string())
        .ok_or_else(|| "wrong-user-lane state update was unexpectedly accepted".to_string())?;
    let state_update_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(funding_tx.id(), 0),
            state_update_signature_script.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![TransactionOutput::with_covenant(
            state_2_value,
            state_2_spk.clone(),
            Some(CovenantBinding::new(0, funding_covenant_id)),
        )],
        0,
        expected_lane,
        0,
        b"KURRENT_STATE_V1:update-state-1-to-2".to_vec(),
    );
    let state_update_txid = submit_and_mine(&rpc, &miner_address, &state_update_tx).await?;

    let stale_signature_script = p2sh_signature_script(false, &state_2_redeem_script)?;
    let stale_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(state_update_tx.id(), 0),
            stale_signature_script.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![TransactionOutput::with_covenant(
            state_2_value - STATE_UPDATE_FEE,
            state_2_spk.clone(),
            Some(CovenantBinding::new(0, funding_covenant_id)),
        )],
        0,
        expected_lane,
        0,
        b"KURRENT_STATE_V1:stale-state-rejected".to_vec(),
    );
    let stale_rejection = rpc
        .submit_transaction((&stale_tx).into(), false)
        .await
        .err()
        .map(|e| e.to_string())
        .ok_or_else(|| "stale/non-continuing state spend was unexpectedly accepted".to_string())?;

    let settlement_signature_script = p2sh_signature_script(true, &state_2_redeem_script)?;
    let native_lane_settlement_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(state_update_tx.id(), 0),
            settlement_signature_script.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![
            TransactionOutput::new(alice_value, alice_spk.clone()),
            TransactionOutput::new(bob_value, bob_spk.clone()),
        ],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        b"KURRENT_STATE_V1:settle-state-2-native-lane-rejected".to_vec(),
    );
    let native_lane_settlement_rejection = rpc
        .submit_transaction((&native_lane_settlement_tx).into(), false)
        .await
        .err()
        .map(|e| e.to_string())
        .ok_or_else(|| "native-lane settlement was unexpectedly accepted".to_string())?;
    let wrong_user_lane_settlement_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(state_update_tx.id(), 0),
            settlement_signature_script.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![
            TransactionOutput::new(alice_value, alice_spk.clone()),
            TransactionOutput::new(bob_value, bob_spk.clone()),
        ],
        0,
        wrong_user_lane,
        0,
        b"KURRENT_STATE_V1:settle-state-2-wrong-user-lane-rejected".to_vec(),
    );
    let wrong_user_lane_settlement_rejection = rpc
        .submit_transaction((&wrong_user_lane_settlement_tx).into(), false)
        .await
        .err()
        .map(|e| e.to_string())
        .ok_or_else(|| "wrong-user-lane settlement was unexpectedly accepted".to_string())?;
    let settlement_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(state_update_tx.id(), 0),
            settlement_signature_script.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![
            TransactionOutput::new(alice_value, alice_spk.clone()),
            TransactionOutput::new(bob_value, bob_spk.clone()),
        ],
        0,
        expected_lane,
        0,
        b"KURRENT_STATE_V1:settle-state-2".to_vec(),
    );
    let settlement_txid = submit_and_mine(&rpc, &miner_address, &settlement_tx).await?;
    mine_block(&rpc, &miner_address).await?;

    let alice_balance = rpc
        .get_balance_by_address(alice_address.clone())
        .await
        .map_err(|e| format!("failed to read Alice settlement balance: {e}"))?;
    let bob_balance = rpc
        .get_balance_by_address(bob_address.clone())
        .await
        .map_err(|e| format!("failed to read Bob settlement balance: {e}"))?;
    if alice_balance != alice_value || bob_balance != bob_value {
        return Err(format!(
            "settlement balances do not match outputs: alice {alice_balance}/{alice_value}, bob {bob_balance}/{bob_value}"
        ));
    }
    let lane_monitor_report = run_lane_monitor_evidence(
        &rpc,
        monitor_start_block,
        &expected_lane_id,
        &[
            ExpectedLaneEvent {
                kind: "funding",
                txid: funding_txid.to_string(),
                version: TX_VERSION_TOCCATA,
            },
            ExpectedLaneEvent {
                kind: "state_update",
                txid: state_update_txid.to_string(),
                version: TX_VERSION_TOCCATA,
            },
            ExpectedLaneEvent {
                kind: "settlement",
                txid: settlement_txid.to_string(),
                version: TX_VERSION_TOCCATA,
            },
        ],
        &[
            native_lane_state_update_tx.id().to_string(),
            wrong_user_lane_state_update_tx.id().to_string(),
            native_lane_settlement_tx.id().to_string(),
            wrong_user_lane_settlement_tx.id().to_string(),
        ],
    )
    .await?;

    let funding_raw = write_raw_tx(output_dir, "kurrent-live-funding-tx.hex", &funding_tx)?;
    let native_lane_raw = write_raw_tx(
        output_dir,
        "kurrent-live-native-lane-state-update-rejected-tx.hex",
        &native_lane_state_update_tx,
    )?;
    let wrong_user_lane_raw = write_raw_tx(
        output_dir,
        "kurrent-live-wrong-lane-state-update-rejected-tx.hex",
        &wrong_user_lane_state_update_tx,
    )?;
    let state_update_raw = write_raw_tx(
        output_dir,
        "kurrent-live-state-update-tx.hex",
        &state_update_tx,
    )?;
    let native_lane_settlement_raw = write_raw_tx(
        output_dir,
        "kurrent-live-native-lane-settlement-rejected-tx.hex",
        &native_lane_settlement_tx,
    )?;
    let wrong_user_lane_settlement_raw = write_raw_tx(
        output_dir,
        "kurrent-live-wrong-lane-settlement-rejected-tx.hex",
        &wrong_user_lane_settlement_tx,
    )?;
    let settlement_raw =
        write_raw_tx(output_dir, "kurrent-live-settlement-tx.hex", &settlement_tx)?;
    let stale_raw = write_raw_tx(output_dir, "kurrent-live-stale-rejected-tx.hex", &stale_tx)?;
    let state_1_redeem_file = write_bytes_hex(
        output_dir,
        "kurrent-live-state-1-redeem-script.hex",
        &state_1_redeem_script,
    )?;
    let state_2_redeem_file = write_bytes_hex(
        output_dir,
        "kurrent-live-state-2-redeem-script.hex",
        &state_2_redeem_script,
    )?;
    let state_update_witness_file = write_bytes_hex(
        output_dir,
        "kurrent-live-state-update-witness.hex",
        &state_update_signature_script,
    )?;
    let stale_witness_file = write_bytes_hex(
        output_dir,
        "kurrent-live-stale-rejected-witness.hex",
        &stale_signature_script,
    )?;
    let witness_file = write_bytes_hex(
        output_dir,
        "kurrent-live-settlement-witness.hex",
        &settlement_signature_script,
    )?;

    let template = json!({
        "domain_separator": DOMAIN_SETTLEMENT_TEMPLATE,
        "template_id": "live-state-2-settlement",
        "outputs": {
            "alice": alice_value,
            "bob": bob_value
        },
        "refund_after_daa": 120_u64,
        "script_covenant_hash": sha256_hex(&state_2_redeem_script),
    });
    let state_header = json!({
        "domain_separator": DOMAIN_STATE,
        "network_profile": "kaspa-simnet-toccata",
        "genesis_or_devnet_id": "in-process-simnet",
        "funding_outpoint": format!("{funding_txid}:0"),
        "channel_id": channel_id,
        "factory_id": null,
        "virtual_channel_id": null,
        "state_number": 2_u64,
        "previous_state_commitment": sha256_hex(b"kurrent-state-1"),
        "new_state_commitment": sha256_hex(b"kurrent-state-2"),
        "settlement_template_hash": hash_json(DOMAIN_SETTLEMENT_TEMPLATE, &template),
        "challenge_policy_hash": sha256_hex(b"latest-state-monotonic-counter-window-120"),
        "participant_set_hash": sha256_hex(b"alice+bob"),
        "covenant_id": funding_covenant_id_string.clone(),
        "expected_lane_id": expected_lane_id.clone(),
        "script_covenant_hash": sha256_hex(&state_2_redeem_script),
        "protocol_version": 1_u16,
    });
    let receipt_scope = json!({
        "domain_separator": DOMAIN_CHANNEL_RECEIPT,
        "protocol_version": 1_u16,
        "network_profile": "kaspa-simnet-toccata",
        "channel_id": channel_id,
        "funding_outpoint": format!("{funding_txid}:0"),
        "output_id": format!("{settlement_txid}:0,{settlement_txid}:1"),
        "state_number": 2_u64,
        "settlement_template_hash": hash_json(DOMAIN_SETTLEMENT_TEMPLATE, &template),
    });
    let funding_outpoint = format!("{funding_txid}:0");
    let settlement_output_id = format!("{settlement_txid}:0,{settlement_txid}:1");
    let model_artifacts = validate_live_state_model(LiveStateModelSpec {
        alice_sk: &alice_sk,
        bob_sk: &bob_sk,
        funding_outpoint: &funding_outpoint,
        total_principal: settlement_value,
        alice_value,
        bob_value,
        covenant_id: &funding_covenant_id_string,
        expected_lane_id: &expected_lane_id,
        state_2_redeem_script: &state_2_redeem_script,
        settlement_output_id: &settlement_output_id,
    })?;
    let model_validation = model_artifacts.report.clone();

    let live_context = LiveKaspaContext {
        rpc: &rpc,
        miner_sk: &miner_sk,
        miner_address: &miner_address,
        coinbase_maturity,
        output_dir,
    };
    let eligibility_policy = SettlementEligibilityPolicy {
        response_window_daa: 3,
    };
    let eligibility_monitor_start_block = rpc
        .get_sink()
        .await
        .map_err(|e| format!("failed to read settlement eligibility monitor start block: {e}"))?
        .sink;
    let lower_candidate_payload = settlement_candidate_marker_payload(
        "lower_candidate",
        &model_artifacts.state_1,
        &expected_lane_id,
    );
    let lower_candidate_payload_bytes = json_payload_bytes(&lower_candidate_payload)?;
    let lower_candidate_marker_tx =
        signed_lane_marker_tx(&live_context, expected_lane, &lower_candidate_payload_bytes).await?;
    submit_and_mine(&rpc, &miner_address, &lower_candidate_marker_tx).await?;

    let wrong_lane_candidate_payload = settlement_candidate_marker_payload(
        "wrong_lane_candidate",
        &model_artifacts.state_2,
        &wrong_user_lane_id,
    );
    let wrong_lane_candidate_payload_bytes = json_payload_bytes(&wrong_lane_candidate_payload)?;
    let wrong_lane_candidate_marker_tx = signed_lane_marker_tx(
        &live_context,
        wrong_user_lane,
        &wrong_lane_candidate_payload_bytes,
    )
    .await?;
    submit_and_mine(&rpc, &miner_address, &wrong_lane_candidate_marker_tx).await?;

    let higher_candidate_payload = settlement_candidate_marker_payload(
        "higher_candidate",
        &model_artifacts.state_2,
        &expected_lane_id,
    );
    let higher_candidate_payload_bytes = json_payload_bytes(&higher_candidate_payload)?;
    let higher_candidate_marker_tx = signed_lane_marker_tx(
        &live_context,
        expected_lane,
        &higher_candidate_payload_bytes,
    )
    .await?;
    submit_and_mine(&rpc, &miner_address, &higher_candidate_marker_tx).await?;
    for _ in 0..=eligibility_policy.response_window_daa {
        mine_block(&rpc, &miner_address).await?;
    }
    let settlement_eligibility_report = run_settlement_eligibility_evidence(
        &rpc,
        SettlementEligibilityEvidenceInput {
            output_dir,
            monitor_start_block: eligibility_monitor_start_block,
            expected_lane_id: &expected_lane_id,
            policy: &eligibility_policy,
            model: &model_artifacts,
            lower_marker_tx: &lower_candidate_marker_tx,
            lower_payload: &lower_candidate_payload,
            higher_marker_tx: &higher_candidate_marker_tx,
            higher_payload: &higher_candidate_payload,
            wrong_lane_marker_tx: &wrong_lane_candidate_marker_tx,
            wrong_lane_payload: &wrong_lane_candidate_payload,
        },
    )
    .await?;

    let fee_policy = SettlementFeePolicy {
        policy_id: "local-devnet-external-sponsor-v1".to_string(),
        max_sponsor_fee: 5_000_000,
        sponsor_mode: "external-sponsor-input".to_string(),
    };
    let fee_policy_hash = fee_policy.hash();
    let sponsored_signers = ModelSigners {
        alice: &alice_sk,
        bob: &bob_sk,
    };
    let sponsored_state_1 = state_update_with_fee_policy_hash(
        model_artifacts.state_1.clone(),
        &fee_policy_hash,
        &sponsored_signers,
    );
    let sponsored_state_2 = state_update_with_fee_policy_hash(
        model_artifacts.state_2.clone(),
        &fee_policy_hash,
        &sponsored_signers,
    );
    let fee_sponsored_monitor_start_block = rpc
        .get_sink()
        .await
        .map_err(|e| format!("failed to read fee-sponsored monitor start block: {e}"))?
        .sink;
    let sponsored_lower_payload = fee_sponsored_candidate_marker_payload(
        "lower_fee_sponsored_candidate",
        &sponsored_state_1,
        &expected_lane_id,
        &fee_policy,
        &model_artifacts.template,
    );
    let sponsored_lower_payload_bytes = json_payload_bytes(&sponsored_lower_payload)?;
    let sponsored_lower_marker = signed_sponsored_lane_marker_tx(
        &live_context,
        expected_lane,
        &sponsored_lower_payload_bytes,
        2_000_000,
    )
    .await?;
    submit_and_mine(&rpc, &miner_address, &sponsored_lower_marker.tx).await?;

    let sponsored_higher_payload = fee_sponsored_candidate_marker_payload(
        "higher_fee_sponsored_candidate",
        &sponsored_state_2,
        &expected_lane_id,
        &fee_policy,
        &model_artifacts.template,
    );
    let sponsored_higher_payload_bytes = json_payload_bytes(&sponsored_higher_payload)?;
    let sponsored_higher_marker = signed_sponsored_lane_marker_tx(
        &live_context,
        expected_lane,
        &sponsored_higher_payload_bytes,
        1_000_000,
    )
    .await?;
    submit_and_mine(&rpc, &miner_address, &sponsored_higher_marker.tx).await?;
    for _ in 0..=eligibility_policy.response_window_daa {
        mine_block(&rpc, &miner_address).await?;
    }
    let fee_sponsored_displacement_report = run_fee_sponsored_displacement_evidence(
        &rpc,
        FeeSponsoredDisplacementEvidenceInput {
            output_dir,
            monitor_start_block: fee_sponsored_monitor_start_block,
            expected_lane_id: &expected_lane_id,
            eligibility_policy: &eligibility_policy,
            fee_policy: &fee_policy,
            model: &model_artifacts,
            lower_update: &sponsored_state_1,
            lower_marker: &sponsored_lower_marker,
            lower_payload: &sponsored_lower_payload,
            higher_update: &sponsored_state_2,
            higher_marker: &sponsored_higher_marker,
            higher_payload: &sponsored_higher_payload,
        },
    )
    .await?;

    let report = json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "driver": "kurrent-kaspa-devnet-driver",
        "miner_address": miner_address.to_string(),
        "participants": {
            "alice_address": alice_address.to_string(),
            "bob_address": bob_address.to_string()
        },
        "lane_binding": {
            "expected_lane_id": expected_lane_id.clone(),
            "wrong_user_lane_id": wrong_user_lane_id.clone(),
            "binding_status": "script-enforced-by-OpTxSubnetId",
            "proof_status": "kip21-lane-proof-recorded-in-kurrent-live-lane-monitor-evidence"
        },
        "funding": {
            "input_outpoint": format!("{}:{}", funding_input_outpoint.transaction_id, funding_input_outpoint.index),
            "value": funding_value,
            "txid": funding_txid.to_string(),
            "outpoint": format!("{funding_txid}:0"),
            "covenant_id": funding_covenant_id_string,
            "observed_lane_id": tx_subnetwork_id_hex(&funding_tx),
            "raw_tx": funding_raw,
        },
        "state_update": {
            "from_state": 1_u64,
            "to_state": 2_u64,
            "value": state_2_value,
            "txid": state_update_txid.to_string(),
            "outpoint": format!("{state_update_txid}:0"),
            "observed_lane_id": tx_subnetwork_id_hex(&state_update_tx),
            "raw_tx": state_update_raw,
            "witness": state_update_witness_file,
        },
        "wrong_lane_rejections": {
            "native_state_update": {
                "status": "rejected",
                "attempted_txid": native_lane_state_update_tx.id().to_string(),
                "observed_lane_id": tx_subnetwork_id_hex(&native_lane_state_update_tx),
                "attempted_tx": native_lane_raw,
                "node_error": native_lane_rejection,
            },
            "wrong_user_state_update": {
                "status": "rejected",
                "attempted_txid": wrong_user_lane_state_update_tx.id().to_string(),
                "observed_lane_id": tx_subnetwork_id_hex(&wrong_user_lane_state_update_tx),
                "attempted_tx": wrong_user_lane_raw,
                "node_error": wrong_user_lane_rejection,
            },
            "native_settlement": {
                "status": "rejected",
                "attempted_txid": native_lane_settlement_tx.id().to_string(),
                "observed_lane_id": tx_subnetwork_id_hex(&native_lane_settlement_tx),
                "attempted_tx": native_lane_settlement_raw,
                "witness": witness_file.clone(),
                "node_error": native_lane_settlement_rejection,
            },
            "wrong_user_settlement": {
                "status": "rejected",
                "attempted_txid": wrong_user_lane_settlement_tx.id().to_string(),
                "observed_lane_id": tx_subnetwork_id_hex(&wrong_user_lane_settlement_tx),
                "attempted_tx": wrong_user_lane_settlement_raw,
                "witness": witness_file.clone(),
                "node_error": wrong_user_lane_settlement_rejection,
            },
        },
        "stale_state_rejection": {
            "status": "rejected",
            "attempted_txid": stale_tx.id().to_string(),
            "observed_lane_id": tx_subnetwork_id_hex(&stale_tx),
            "attempted_tx": stale_raw,
            "witness": stale_witness_file,
            "node_error": stale_rejection,
        },
        "settlement": {
            "state_number": 2_u64,
            "txid": settlement_txid.to_string(),
            "outputs": {
                "alice": alice_value,
                "bob": bob_value
            },
            "observed_lane_id": tx_subnetwork_id_hex(&settlement_tx),
            "raw_tx": settlement_raw,
            "witness": witness_file,
            "state_1_redeem_script": state_1_redeem_file,
            "state_2_redeem_script": state_2_redeem_file,
        },
        "state_header": {
            "hash": hash_json(DOMAIN_STATE, &state_header),
            "header": state_header,
        },
        "settlement_template": {
            "hash": hash_json(DOMAIN_SETTLEMENT_TEMPLATE, &template),
            "template": template,
        },
        "channel_receipt": {
            "hash": hash_json(DOMAIN_CHANNEL_RECEIPT, &receipt_scope),
            "scope": receipt_scope,
        },
        "model_validation": model_validation,
    });
    write_json(
        output_dir,
        "kurrent-live-state-channel-evidence.json",
        &report,
    )?;
    write_json(
        output_dir,
        "kurrent-live-lane-monitor-evidence.json",
        &lane_monitor_report,
    )?;
    write_json(
        output_dir,
        "kurrent-live-settlement-eligibility-evidence.json",
        &settlement_eligibility_report,
    )?;
    write_json(
        output_dir,
        "kurrent-live-fee-sponsored-displacement-evidence.json",
        &fee_sponsored_displacement_report,
    )?;

    let factory_report = run_live_factory_flow(&live_context, &alice_spk, &bob_spk).await?;
    write_json(
        output_dir,
        "kurrent-live-factory-evidence.json",
        &factory_report,
    )?;

    let ln_preimage = read_ln_preimage(output_dir)?;
    let ln_to_kaspa_report =
        run_live_hashlock_flow("ln-to-kaspa", &live_context, &ln_preimage, &alice_spk).await?;
    write_json(
        output_dir,
        "kurrent-live-ln-to-kaspa-evidence.json",
        &ln_to_kaspa_report,
    )?;
    let kaspa_to_ln_report =
        run_live_hashlock_flow("kaspa-to-ln", &live_context, &ln_preimage, &bob_spk).await?;
    write_json(
        output_dir,
        "kurrent-live-kaspa-to-ln-evidence.json",
        &kaspa_to_ln_report,
    )?;

    let refund_report = run_live_refund_flow(&live_context, &alice_spk).await?;
    write_json(
        output_dir,
        "kurrent-live-refund-evidence.json",
        &refund_report,
    )?;

    rpc.disconnect()
        .await
        .map_err(|e| format!("failed to disconnect Kaspa RPC client: {e}"))?;
    drop(rpc);
    kaspad.shutdown();
    Ok(())
}

fn keypair_address(prefix: kaspa_addresses::Prefix) -> (Keypair, Address) {
    let (secret_key, public_key) = secp256k1::generate_keypair(&mut thread_rng());
    let address = Address::new(
        prefix,
        Version::PubKey,
        &public_key.x_only_public_key().0.serialize(),
    );
    (
        Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key),
        address,
    )
}

struct LiveStateModelSpec<'a> {
    alice_sk: &'a Keypair,
    bob_sk: &'a Keypair,
    funding_outpoint: &'a str,
    total_principal: u64,
    alice_value: u64,
    bob_value: u64,
    covenant_id: &'a str,
    expected_lane_id: &'a str,
    state_2_redeem_script: &'a [u8],
    settlement_output_id: &'a str,
}

struct ModelSigners<'a> {
    alice: &'a Keypair,
    bob: &'a Keypair,
}

struct ModelStateUpdateSpec<'a> {
    state_number: u64,
    previous_state_commitment: &'a str,
    new_state_commitment: &'a str,
}

struct LiveStateModelArtifacts {
    report: Value,
    config: KurrentChannelConfig,
    funding: FundingState,
    template: SettlementTemplate,
    state_1: StateUpdate,
    state_2: StateUpdate,
}

fn validate_live_state_model(
    spec: LiveStateModelSpec<'_>,
) -> Result<LiveStateModelArtifacts, String> {
    let participants = vec!["alice".to_string(), "bob".to_string()];
    let participant_public_keys = BTreeMap::from([
        (
            "alice".to_string(),
            participant_public_key_hex(spec.alice_sk),
        ),
        ("bob".to_string(), participant_public_key_hex(spec.bob_sk)),
    ]);
    let config = KurrentChannelConfig {
        protocol_version: 1,
        network_profile: "kaspa-simnet-toccata".to_string(),
        genesis_or_devnet_id: Some("in-process-simnet".to_string()),
        channel_id: "channel-a".to_string(),
        participants: participants.clone(),
        challenge_policy: ChallengePolicy {
            mode: "latest-state".to_string(),
            challenge_window_daa: 120,
            same_number_conflict_rule: SameNumberConflictRule::RejectConflict,
        },
        access_manifest: AccessManifest {
            authorised_participants: participants.clone(),
            participant_public_keys,
            required_signatures: 2,
        },
        expected_lane_id: Some(spec.expected_lane_id.to_string()),
    };
    let funding = FundingState {
        funding_outpoint: spec.funding_outpoint.to_string(),
        total_principal: spec.total_principal,
        principal_by_participant: BTreeMap::from([
            ("alice".to_string(), spec.alice_value),
            ("bob".to_string(), spec.bob_value),
        ]),
        fee_reserve: 0,
        covenant_id: Some(spec.covenant_id.to_string()),
        expected_lane_id: Some(spec.expected_lane_id.to_string()),
        script_covenant_hash: sha256_hex(spec.state_2_redeem_script),
    };
    let template = SettlementTemplate {
        template_id: "live-state-2-settlement".to_string(),
        outputs: BTreeMap::from([
            ("alice".to_string(), spec.alice_value),
            ("bob".to_string(), spec.bob_value),
        ]),
        refund_after_daa: Some(120),
        script_covenant_hash: funding.script_covenant_hash.clone(),
    };

    let signers = ModelSigners {
        alice: spec.alice_sk,
        bob: spec.bob_sk,
    };
    let state_0 = signed_model_state_update(
        &config,
        &funding,
        &template,
        &signers,
        ModelStateUpdateSpec {
            state_number: 0,
            previous_state_commitment: "genesis",
            new_state_commitment: &sha256_hex(b"kurrent-live-state-0"),
        },
    );
    let state_1 = signed_model_state_update(
        &config,
        &funding,
        &template,
        &signers,
        ModelStateUpdateSpec {
            state_number: 1,
            previous_state_commitment: &state_0.header.new_state_commitment,
            new_state_commitment: &sha256_hex(b"kurrent-live-state-1"),
        },
    );
    let state_2 = signed_model_state_update(
        &config,
        &funding,
        &template,
        &signers,
        ModelStateUpdateSpec {
            state_number: 2,
            previous_state_commitment: &state_1.header.new_state_commitment,
            new_state_commitment: &sha256_hex(b"kurrent-live-state-2"),
        },
    );

    for state in [&state_0, &state_1, &state_2] {
        validate_channel_update(&config, &funding, state, &template)
            .map_err(|err| format!("live state model validation failed: {err:?}"))?;
    }

    let mut registry = SettlementRegistry::default();
    registry
        .accept_update(state_0.clone())
        .map_err(|err| format!("state 0 model registry acceptance failed: {err:?}"))?;
    registry
        .accept_update(state_1.clone())
        .map_err(|err| format!("state 1 model registry acceptance failed: {err:?}"))?;
    registry
        .accept_update(state_2.clone())
        .map_err(|err| format!("state 2 model registry acceptance failed: {err:?}"))?;
    let stale_error = registry
        .settle(&state_1, &template)
        .expect_err("state 1 must be stale after state 2 is accepted");
    registry
        .settle(&state_2, &template)
        .map_err(|err| format!("latest state model settlement failed: {err:?}"))?;

    let mut receipt = ChannelReceipt::new(
        1,
        "kaspa-simnet-toccata",
        "channel-a",
        spec.funding_outpoint,
        spec.settlement_output_id,
        2,
        template.hash(),
    );
    receipt.refresh_hash();
    receipt
        .validate_hash()
        .map_err(|err| format!("live channel receipt model hash failed: {err:?}"))?;

    let report = json!({
        "status": "passed",
        "validation_layer": "typed-kurrent-protocol-model",
        "validated_state_numbers": [0_u64, 1_u64, 2_u64],
        "latest_state_number": 2_u64,
        "stale_state_number": 1_u64,
        "stale_rejection": format!("{stale_error:?}"),
        "required_signatures": config.access_manifest.required_signatures,
        "participant_set_hash": participant_set_hash(&participants),
        "funding_state": funding,
        "settlement_template": template,
        "state_hashes": [
            { "state_number": 0_u64, "hash": state_0.header.hash() },
            { "state_number": 1_u64, "hash": state_1.header.hash() },
            { "state_number": 2_u64, "hash": state_2.header.hash() }
        ],
        "state_updates": {
            "state_1": state_1.clone(),
            "state_2": state_2.clone(),
        },
        "latest_state_header": state_2.header.clone(),
        "receipt": receipt,
    });

    Ok(LiveStateModelArtifacts {
        report,
        config,
        funding,
        template,
        state_1,
        state_2,
    })
}

fn signed_model_state_update(
    config: &KurrentChannelConfig,
    funding: &FundingState,
    template: &SettlementTemplate,
    signers: &ModelSigners<'_>,
    spec: ModelStateUpdateSpec<'_>,
) -> StateUpdate {
    let mut update = StateUpdate {
        header: LatestStateHeader {
            network_profile: config.network_profile.clone(),
            genesis_or_devnet_id: config.genesis_or_devnet_id.clone(),
            funding_outpoint: funding.funding_outpoint.clone(),
            channel_id: config.channel_id.clone(),
            factory_id: None,
            virtual_channel_id: None,
            state_number: spec.state_number,
            previous_state_commitment: spec.previous_state_commitment.to_string(),
            new_state_commitment: spec.new_state_commitment.to_string(),
            settlement_template_hash: template.hash(),
            fee_policy_hash: None,
            challenge_policy_hash: hash_json(DOMAIN_STATE, &config.challenge_policy),
            participant_set_hash: participant_set_hash(&config.participants),
            covenant_id: funding.covenant_id.clone(),
            expected_lane_id: funding.expected_lane_id.clone(),
            script_covenant_hash: funding.script_covenant_hash.clone(),
            protocol_version: config.protocol_version,
            domain_separator: DOMAIN_STATE.to_string(),
        },
        balances: funding.principal_by_participant.clone(),
        participant_signatures: BTreeMap::new(),
    };
    update.participant_signatures.insert(
        "alice".to_string(),
        sign_model_state_update(signers.alice, &update),
    );
    update.participant_signatures.insert(
        "bob".to_string(),
        sign_model_state_update(signers.bob, &update),
    );
    update
}

fn sign_model_state_update(keypair: &Keypair, update: &StateUpdate) -> String {
    let message = Message::from_digest(state_update_signing_digest(update));
    let signature = secp256k1::SECP256K1.sign_schnorr_no_aux_rand(&message, keypair);
    hex::encode(signature.as_ref())
}

fn participant_public_key_hex(keypair: &Keypair) -> String {
    let (public_key, _) = keypair.x_only_public_key();
    hex::encode(public_key.serialize())
}

fn lane_id_bytes(value: &str, label: &str) -> Result<[u8; 20], String> {
    let bytes = hex::decode(value).map_err(|e| format!("{label} is not valid hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{label} must be 20 bytes, got {}", bytes.len()))
}

fn subnetwork_id_from_hex(value: &str) -> Result<SubnetworkId, String> {
    Ok(SubnetworkId::from_bytes(lane_id_bytes(
        value,
        "subnetwork id",
    )?))
}

fn subnetwork_id_hex(id: &SubnetworkId) -> String {
    hex::encode(id.as_bytes())
}

fn tx_subnetwork_id_hex(tx: &Transaction) -> String {
    subnetwork_id_hex(&tx.subnetwork_id)
}

fn parse_hash(value: &str, label: &str) -> Result<Hash, String> {
    Hash::from_str(value).map_err(|e| format!("{label} is not a valid hash {value}: {e}"))
}

async fn run_lane_monitor_evidence(
    client: &GrpcClient,
    monitor_start_block: Hash,
    expected_lane_id: &str,
    expected_events: &[ExpectedLaneEvent],
    wrong_lane_txids: &[String],
) -> Result<Value, String> {
    let expected_lane_bytes = lane_id_bytes(expected_lane_id, "expected lane id")?;
    let expected_lane_key = lane_key(&expected_lane_bytes);
    let monitor_start_header = client
        .get_block(monitor_start_block, false)
        .await
        .map_err(|e| format!("failed to read lane monitor start block {monitor_start_block}: {e}"))?
        .header;
    let vcc = client
        .get_virtual_chain_from_block_v2(
            monitor_start_block,
            Some(RpcDataVerbosityLevel::Full),
            None,
        )
        .await
        .map_err(|e| format!("failed to read lane monitor virtual chain: {e}"))?;
    let proof_block_hash = vcc
        .added_chain_block_hashes
        .last()
        .copied()
        .ok_or_else(|| "lane monitor virtual chain returned no added chain blocks".to_string())?;
    let mut parent_seq_commit = monitor_start_header.accepted_id_merkle_root;
    let mut selected_parent_timestamp = monitor_start_header.timestamp;
    let mut all_accepted_txids = BTreeSet::new();
    let mut accepted_order_index = 0_u64;
    let mut lane_events = Vec::new();
    let mut lane_activity_blocks = Vec::new();
    let expected_by_txid: BTreeMap<String, (&'static str, u16)> = expected_events
        .iter()
        .map(|event| (event.txid.clone(), (event.kind, event.version)))
        .collect();
    let mut latest_lane_tip = None;
    let mut latest_lane_blue_score = None;
    let mut proof_header = None;

    for accepted_block in vcc.chain_block_accepted_transactions.iter() {
        let header = &accepted_block.chain_block_header;
        let block_hash = header
            .hash
            .ok_or_else(|| "lane monitor chain block is missing hash".to_string())?;
        let accepted_id_merkle_root = header.accepted_id_merkle_root.ok_or_else(|| {
            format!("lane monitor chain block {block_hash} is missing accepted_id_merkle_root")
        })?;
        let block_timestamp = header
            .timestamp
            .ok_or_else(|| format!("lane monitor chain block {block_hash} is missing timestamp"))?;
        let daa_score = header
            .daa_score
            .ok_or_else(|| format!("lane monitor chain block {block_hash} is missing daa_score"))?;
        let blue_score = header.blue_score.ok_or_else(|| {
            format!("lane monitor chain block {block_hash} is missing blue_score")
        })?;
        if block_hash == proof_block_hash {
            proof_header = Some((
                accepted_id_merkle_root,
                block_timestamp,
                daa_score,
                blue_score,
            ));
        }

        let block_order_start = accepted_order_index;
        let mut merge_index = 0_u32;
        let mut block_leaves = Vec::new();
        let mut block_events = Vec::new();
        for tx in accepted_block.accepted_transactions.iter() {
            let txid = tx
                .verbose_data
                .as_ref()
                .and_then(|data| data.transaction_id)
                .ok_or_else(|| format!("accepted transaction in {block_hash} is missing txid"))?;
            let version = tx.version.ok_or_else(|| {
                format!("accepted transaction {txid} in {block_hash} is missing version")
            })?;
            let subnetwork_id = tx.subnetwork_id.ok_or_else(|| {
                format!("accepted transaction {txid} in {block_hash} is missing subnetwork id")
            })?;
            all_accepted_txids.insert(txid.to_string());
            if subnetwork_id.as_bytes() == &expected_lane_bytes {
                let activity = activity_leaf(&txid, version, merge_index);
                let (kind, expected_version) = expected_by_txid
                    .get(&txid.to_string())
                    .copied()
                    .unwrap_or(("other_expected_lane_activity", version));
                if version != expected_version {
                    return Err(format!(
                        "accepted lane event {txid} has version {version}, expected {expected_version}"
                    ));
                }
                let event = json!({
                    "kind": kind,
                    "txid": txid.to_string(),
                    "version": version,
                    "lane_id": subnetwork_id_hex(&subnetwork_id),
                    "accepting_chain_block_hash": block_hash.to_string(),
                    "accepted_order_index": accepted_order_index,
                    "merge_index": merge_index,
                    "activity_leaf": activity.to_string(),
                });
                block_leaves.push(activity);
                block_events.push(event.clone());
                lane_events.push(event);
            }
            merge_index = merge_index
                .checked_add(1)
                .ok_or_else(|| "lane monitor merge index overflowed".to_string())?;
            accepted_order_index = accepted_order_index
                .checked_add(1)
                .ok_or_else(|| "lane monitor accepted-order index overflowed".to_string())?;
        }

        if !block_leaves.is_empty() {
            let context_hash = mergeset_context_hash(&MergesetContext {
                timestamp: selected_parent_timestamp,
                daa_score,
                blue_score,
            });
            let digest = activity_digest_lane(block_leaves.iter().copied());
            let parent_ref = latest_lane_tip.unwrap_or(parent_seq_commit);
            let next_tip = lane_tip_next(&LaneTipInput {
                parent_ref: &parent_ref,
                lane_key: &expected_lane_key,
                activity_digest: &digest,
                context_hash: &context_hash,
            });
            latest_lane_tip = Some(next_tip);
            latest_lane_blue_score = Some(blue_score);
            lane_activity_blocks.push(json!({
                "chain_block_hash": block_hash.to_string(),
                "accepted_id_merkle_root": accepted_id_merkle_root.to_string(),
                "parent_seq_commit": parent_seq_commit.to_string(),
                "timestamp": selected_parent_timestamp,
                "chain_block_timestamp": block_timestamp,
                "daa_score": daa_score,
                "blue_score": blue_score,
                "accepted_order_start": block_order_start,
                "activity_digest": digest.to_string(),
                "lane_tip_after_block": next_tip.to_string(),
                "events": block_events,
            }));
        }

        parent_seq_commit = accepted_id_merkle_root;
        selected_parent_timestamp = block_timestamp;
    }

    let (proof_accepted_id_merkle_root, proof_timestamp, proof_daa_score, proof_blue_score) =
        proof_header.ok_or_else(|| {
            format!("lane monitor proof block {proof_block_hash} was not present in chain data")
        })?;
    let event_positions: BTreeMap<String, u64> = lane_events
        .iter()
        .filter_map(|event| {
            Some((
                event.get("txid")?.as_str()?.to_string(),
                event.get("accepted_order_index")?.as_u64()?,
            ))
        })
        .collect();
    let mut previous_position = None;
    for expected in expected_events {
        let position = event_positions.get(&expected.txid).ok_or_else(|| {
            format!(
                "expected lane event {} ({}) was not found in accepted activity",
                expected.kind, expected.txid
            )
        })?;
        if let Some(previous) = previous_position {
            if *position <= previous {
                return Err(
                    "expected lane events are not in funding < update < settlement order"
                        .to_string(),
                );
            }
        }
        previous_position = Some(*position);
    }

    let wrong_lane_absence: Vec<Value> = wrong_lane_txids
        .iter()
        .map(|txid| {
            json!({
                "txid": txid,
                "absent_from_accepted_activity": !all_accepted_txids.contains(txid),
            })
        })
        .collect();
    if wrong_lane_absence.iter().any(|record| {
        record
            .get("absent_from_accepted_activity")
            .and_then(Value::as_bool)
            != Some(true)
    }) {
        return Err("wrong-lane rejected transaction appeared in accepted activity".to_string());
    }

    let proof = client
        .get_seq_commit_lane_proof(proof_block_hash, expected_lane_key)
        .await
        .map_err(|e| format!("failed to obtain KIP-21 lane proof: {e}"))?;
    let proof_lane = proof.lane.as_ref().ok_or_else(|| {
        "KIP-21 lane proof returned non-inclusion for active Kurrent lane".to_string()
    })?;
    let expected_tip = latest_lane_tip
        .ok_or_else(|| "lane monitor did not observe any expected-lane activity".to_string())?;
    if proof_lane.tip != expected_tip {
        return Err(format!(
            "lane proof tip mismatch: expected reconstructed {expected_tip}, actual {}",
            proof_lane.tip
        ));
    }
    if Some(proof_lane.blue_score) != latest_lane_blue_score {
        return Err(format!(
            "lane proof blue score mismatch: expected {:?}, actual {}",
            latest_lane_blue_score, proof_lane.blue_score
        ));
    }
    verify_lane_proof_material(LaneProofMaterial {
        lane_key_hash: expected_lane_key,
        lane_tip: proof_lane.tip,
        lane_blue_score: proof_lane.blue_score,
        smt_proof_bytes: &proof.smt_proof,
        payload_and_ctx_digest: proof.payload_and_ctx_digest,
        parent_seq_commit: proof.parent_seq_commit,
        inactivity_shortcut: proof.inactivity_shortcut,
        accepted_id_merkle_root: proof_accepted_id_merkle_root,
    })?;

    Ok(json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "driver": "kurrent-kaspa-devnet-driver",
        "monitor_scope": "state-channel-lane-local-evidence",
        "expected_lane_id": expected_lane_id,
        "lane_key": expected_lane_key.to_string(),
        "monitor_start_block": monitor_start_block.to_string(),
        "monitor_start_accepted_id_merkle_root": monitor_start_header.accepted_id_merkle_root.to_string(),
        "proof_block_hash": proof_block_hash.to_string(),
        "proof_header": {
            "accepted_id_merkle_root": proof_accepted_id_merkle_root.to_string(),
            "timestamp": proof_timestamp,
            "daa_score": proof_daa_score,
            "blue_score": proof_blue_score,
        },
        "proof": {
            "smt_proof": hex::encode(&proof.smt_proof),
            "lane": {
                "tip": proof_lane.tip.to_string(),
                "blue_score": proof_lane.blue_score,
            },
            "payload_and_ctx_digest": proof.payload_and_ctx_digest.to_string(),
            "parent_seq_commit": proof.parent_seq_commit.to_string(),
            "inactivity_shortcut": proof.inactivity_shortcut.to_string(),
        },
        "lane_activity_blocks": lane_activity_blocks,
        "lane_events": lane_events,
        "wrong_lane_absence": wrong_lane_absence,
        "claim_boundary": "KIP-21 proves lane-local accepted-order evidence; Kurrent's replacement rule is still supplied by the covenant and semantic verifier.",
    }))
}

struct LaneProofMaterial<'a> {
    lane_key_hash: Hash,
    lane_tip: Hash,
    lane_blue_score: u64,
    smt_proof_bytes: &'a [u8],
    payload_and_ctx_digest: Hash,
    parent_seq_commit: Hash,
    inactivity_shortcut: Hash,
    accepted_id_merkle_root: Hash,
}

fn verify_lane_proof_material(material: LaneProofMaterial<'_>) -> Result<(), String> {
    let proof = OwnedSmtProof::from_bytes(material.smt_proof_bytes)
        .map_err(|e| format!("failed to parse KIP-21 SMT proof: {e}"))?;
    let leaf = Some(smt_leaf_hash(&SmtLeafInput {
        lane_tip: &material.lane_tip,
        blue_score: material.lane_blue_score,
    }));
    let lanes_root = proof
        .as_proof()
        .compute_root::<SeqCommitActiveNode>(&material.lane_key_hash, leaf)
        .map_err(|e| format!("failed to compute KIP-21 lanes root: {e}"))?;
    verify_smt_metadata(
        &SmtMetadata {
            lanes_root: &lanes_root,
            payload_and_ctx_digest: &material.payload_and_ctx_digest,
            parent_seq_commit: &material.parent_seq_commit,
        },
        material.inactivity_shortcut,
        material.accepted_id_merkle_root,
        material.parent_seq_commit,
    )
    .map_err(|e| format!("KIP-21 lane proof does not chain to accepted_id_merkle_root: {e}"))
}

struct SettlementEligibilityEvidenceInput<'a> {
    output_dir: &'a Path,
    monitor_start_block: Hash,
    expected_lane_id: &'a str,
    policy: &'a SettlementEligibilityPolicy,
    model: &'a LiveStateModelArtifacts,
    lower_marker_tx: &'a Transaction,
    lower_payload: &'a Value,
    higher_marker_tx: &'a Transaction,
    higher_payload: &'a Value,
    wrong_lane_marker_tx: &'a Transaction,
    wrong_lane_payload: &'a Value,
}

async fn run_settlement_eligibility_evidence(
    client: &GrpcClient,
    input: SettlementEligibilityEvidenceInput<'_>,
) -> Result<Value, String> {
    let SettlementEligibilityEvidenceInput {
        output_dir,
        monitor_start_block,
        expected_lane_id,
        policy,
        model,
        lower_marker_tx,
        lower_payload,
        higher_marker_tx,
        higher_payload,
        wrong_lane_marker_tx,
        wrong_lane_payload,
    } = input;
    let expected_lane_bytes = lane_id_bytes(expected_lane_id, "settlement eligibility lane id")?;
    let expected_lane_key = lane_key(&expected_lane_bytes);
    let monitor_start_header = client
        .get_block(monitor_start_block, false)
        .await
        .map_err(|e| {
            format!(
                "failed to read settlement eligibility monitor start block {monitor_start_block}: {e}"
            )
        })?
        .header;
    let initial_lane_proof = client
        .get_seq_commit_lane_proof(monitor_start_block, expected_lane_key)
        .await
        .map_err(|e| format!("failed to obtain settlement eligibility initial lane proof: {e}"))?;
    let initial_lane = initial_lane_proof.lane.as_ref().map(|lane| {
        json!({
            "tip": lane.tip.to_string(),
            "blue_score": lane.blue_score,
        })
    });
    let vcc = client
        .get_virtual_chain_from_block_v2(
            monitor_start_block,
            Some(RpcDataVerbosityLevel::Full),
            None,
        )
        .await
        .map_err(|e| format!("failed to read settlement eligibility virtual chain: {e}"))?;
    let proof_block_hash = vcc
        .added_chain_block_hashes
        .last()
        .copied()
        .ok_or_else(|| {
            "settlement eligibility virtual chain returned no added chain blocks".to_string()
        })?;

    let expected_by_txid = BTreeMap::from([
        (
            lower_marker_tx.id().to_string(),
            ("lower_candidate", TX_VERSION_TOCCATA),
        ),
        (
            higher_marker_tx.id().to_string(),
            ("higher_candidate", TX_VERSION_TOCCATA),
        ),
    ]);
    let wrong_lane_txid = wrong_lane_marker_tx.id().to_string();
    let mut parent_seq_commit = monitor_start_header.accepted_id_merkle_root;
    let mut selected_parent_timestamp = monitor_start_header.timestamp;
    let mut accepted_order_index = 0_u64;
    let mut lane_events = Vec::new();
    let mut lane_activity_blocks = Vec::new();
    let mut latest_lane_tip = initial_lane_proof.lane.as_ref().map(|lane| lane.tip);
    let mut latest_lane_blue_score = initial_lane_proof.lane.as_ref().map(|lane| lane.blue_score);
    let mut proof_header = None;
    let mut wrong_lane_observation = None;

    for accepted_block in vcc.chain_block_accepted_transactions.iter() {
        let header = &accepted_block.chain_block_header;
        let block_hash = header
            .hash
            .ok_or_else(|| "settlement eligibility chain block is missing hash".to_string())?;
        let accepted_id_merkle_root = header.accepted_id_merkle_root.ok_or_else(|| {
            format!(
                "settlement eligibility chain block {block_hash} is missing accepted_id_merkle_root"
            )
        })?;
        let block_timestamp = header.timestamp.ok_or_else(|| {
            format!("settlement eligibility chain block {block_hash} is missing timestamp")
        })?;
        let daa_score = header.daa_score.ok_or_else(|| {
            format!("settlement eligibility chain block {block_hash} is missing daa_score")
        })?;
        let blue_score = header.blue_score.ok_or_else(|| {
            format!("settlement eligibility chain block {block_hash} is missing blue_score")
        })?;
        if block_hash == proof_block_hash {
            proof_header = Some((
                accepted_id_merkle_root,
                block_timestamp,
                daa_score,
                blue_score,
            ));
        }

        let block_order_start = accepted_order_index;
        let mut merge_index = 0_u32;
        let mut block_leaves = Vec::new();
        let mut block_events = Vec::new();
        for tx in accepted_block.accepted_transactions.iter() {
            let txid = tx
                .verbose_data
                .as_ref()
                .and_then(|data| data.transaction_id)
                .ok_or_else(|| format!("accepted transaction in {block_hash} is missing txid"))?;
            let version = tx.version.ok_or_else(|| {
                format!("accepted transaction {txid} in {block_hash} is missing version")
            })?;
            let subnetwork_id = tx.subnetwork_id.ok_or_else(|| {
                format!("accepted transaction {txid} in {block_hash} is missing subnetwork id")
            })?;
            let txid_string = txid.to_string();
            if txid_string == wrong_lane_txid {
                wrong_lane_observation = Some(json!({
                    "txid": txid_string,
                    "version": version,
                    "lane_id": subnetwork_id_hex(&subnetwork_id),
                    "accepting_chain_block_hash": block_hash.to_string(),
                    "accepted_order_index": accepted_order_index,
                    "merge_index": merge_index,
                    "daa_score": daa_score,
                    "blue_score": blue_score,
                    "ignored_reason": "wrong lane",
                }));
            }
            if subnetwork_id.as_bytes() == &expected_lane_bytes {
                let activity = activity_leaf(&txid, version, merge_index);
                let (kind, expected_version) = expected_by_txid
                    .get(&txid_string)
                    .copied()
                    .unwrap_or(("other_expected_lane_activity", version));
                if expected_by_txid.contains_key(&txid_string) && version != expected_version {
                    return Err(format!(
                        "settlement eligibility marker {txid} has version {version}, expected {expected_version}"
                    ));
                }
                let event = json!({
                    "kind": kind,
                    "txid": txid_string,
                    "version": version,
                    "lane_id": subnetwork_id_hex(&subnetwork_id),
                    "accepting_chain_block_hash": block_hash.to_string(),
                    "accepted_order_index": accepted_order_index,
                    "merge_index": merge_index,
                    "daa_score": daa_score,
                    "blue_score": blue_score,
                    "activity_leaf": activity.to_string(),
                });
                block_leaves.push(activity);
                block_events.push(event.clone());
                lane_events.push(event);
            }
            merge_index = merge_index
                .checked_add(1)
                .ok_or_else(|| "settlement eligibility merge index overflowed".to_string())?;
            accepted_order_index = accepted_order_index.checked_add(1).ok_or_else(|| {
                "settlement eligibility accepted-order index overflowed".to_string()
            })?;
        }

        if !block_leaves.is_empty() {
            let context_hash = mergeset_context_hash(&MergesetContext {
                timestamp: selected_parent_timestamp,
                daa_score,
                blue_score,
            });
            let digest = activity_digest_lane(block_leaves.iter().copied());
            let parent_ref = latest_lane_tip.unwrap_or(parent_seq_commit);
            let next_tip = lane_tip_next(&LaneTipInput {
                parent_ref: &parent_ref,
                lane_key: &expected_lane_key,
                activity_digest: &digest,
                context_hash: &context_hash,
            });
            latest_lane_tip = Some(next_tip);
            latest_lane_blue_score = Some(blue_score);
            lane_activity_blocks.push(json!({
                "chain_block_hash": block_hash.to_string(),
                "accepted_id_merkle_root": accepted_id_merkle_root.to_string(),
                "parent_seq_commit": parent_seq_commit.to_string(),
                "timestamp": selected_parent_timestamp,
                "chain_block_timestamp": block_timestamp,
                "daa_score": daa_score,
                "blue_score": blue_score,
                "accepted_order_start": block_order_start,
                "activity_digest": digest.to_string(),
                "lane_tip_after_block": next_tip.to_string(),
                "events": block_events,
            }));
        }

        parent_seq_commit = accepted_id_merkle_root;
        selected_parent_timestamp = block_timestamp;
    }

    let (proof_accepted_id_merkle_root, proof_timestamp, proof_daa_score, proof_blue_score) =
        proof_header.ok_or_else(|| {
            format!(
                "settlement eligibility proof block {proof_block_hash} was not present in chain data"
            )
        })?;
    let proof = client
        .get_seq_commit_lane_proof(proof_block_hash, expected_lane_key)
        .await
        .map_err(|e| format!("failed to obtain settlement eligibility KIP-21 lane proof: {e}"))?;
    let proof_lane = proof.lane.as_ref().ok_or_else(|| {
        "settlement eligibility KIP-21 proof returned non-inclusion for active lane".to_string()
    })?;
    let expected_tip = latest_lane_tip.ok_or_else(|| {
        "settlement eligibility did not observe expected-lane markers".to_string()
    })?;
    if proof_lane.tip != expected_tip {
        return Err(format!(
            "settlement eligibility proof tip mismatch: expected reconstructed {expected_tip}, actual {}",
            proof_lane.tip
        ));
    }
    if Some(proof_lane.blue_score) != latest_lane_blue_score {
        return Err(format!(
            "settlement eligibility proof blue score mismatch: expected {:?}, actual {}",
            latest_lane_blue_score, proof_lane.blue_score
        ));
    }
    verify_lane_proof_material(LaneProofMaterial {
        lane_key_hash: expected_lane_key,
        lane_tip: proof_lane.tip,
        lane_blue_score: proof_lane.blue_score,
        smt_proof_bytes: &proof.smt_proof,
        payload_and_ctx_digest: proof.payload_and_ctx_digest,
        parent_seq_commit: proof.parent_seq_commit,
        inactivity_shortcut: proof.inactivity_shortcut,
        accepted_id_merkle_root: proof_accepted_id_merkle_root,
    })?;

    let lower_marker_txid = lower_marker_tx.id().to_string();
    let higher_marker_txid = higher_marker_tx.id().to_string();
    let lower_event = lane_events
        .iter()
        .find(|event| event.get("txid").and_then(Value::as_str) == Some(lower_marker_txid.as_str()))
        .ok_or_else(|| {
            "lower settlement candidate marker was not observed on expected lane".to_string()
        })?;
    let higher_event = lane_events
        .iter()
        .find(|event| {
            event.get("txid").and_then(Value::as_str) == Some(higher_marker_txid.as_str())
        })
        .ok_or_else(|| {
            "higher settlement candidate marker was not observed on expected lane".to_string()
        })?;
    let wrong_lane_observation = wrong_lane_observation.ok_or_else(|| {
        "wrong-lane settlement candidate marker was not observed as accepted".to_string()
    })?;
    require_not_eq(
        required_str(&wrong_lane_observation, "/lane_id")?,
        expected_lane_id,
        "wrong-lane settlement candidate marker lane",
    )?;

    let lower_candidate = SettlementEligibilityCandidate {
        update: model.state_1.clone(),
        evidence: settlement_candidate_evidence_from_event(
            &model.state_1,
            expected_lane_id,
            lower_event,
        )?,
    };
    let higher_candidate = SettlementEligibilityCandidate {
        update: model.state_2.clone(),
        evidence: settlement_candidate_evidence_from_event(
            &model.state_2,
            expected_lane_id,
            higher_event,
        )?,
    };
    let decisions = evaluate_settlement_eligibility(
        &model.config,
        &model.funding,
        &model.template,
        policy,
        &[lower_candidate.clone(), higher_candidate.clone()],
        proof_daa_score,
    )
    .map_err(|err| format!("settlement eligibility model evaluation failed: {err:?}"))?;

    let lower_payload_bytes = json_payload_bytes(lower_payload)?;
    let higher_payload_bytes = json_payload_bytes(higher_payload)?;
    let wrong_lane_payload_bytes = json_payload_bytes(wrong_lane_payload)?;
    let lower_raw = write_raw_tx(
        output_dir,
        "kurrent-live-settlement-candidate-lower-marker-tx.hex",
        lower_marker_tx,
    )?;
    let higher_raw = write_raw_tx(
        output_dir,
        "kurrent-live-settlement-candidate-higher-marker-tx.hex",
        higher_marker_tx,
    )?;
    let wrong_lane_raw = write_raw_tx(
        output_dir,
        "kurrent-live-settlement-candidate-wrong-lane-marker-tx.hex",
        wrong_lane_marker_tx,
    )?;

    Ok(json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "driver": "kurrent-kaspa-devnet-driver",
        "monitor_scope": "state-channel-settlement-eligibility-evidence",
        "expected_lane_id": expected_lane_id,
        "lane_key": expected_lane_key.to_string(),
        "initial_lane": initial_lane,
        "monitor_start_block": monitor_start_block.to_string(),
        "monitor_start_accepted_id_merkle_root": monitor_start_header.accepted_id_merkle_root.to_string(),
        "proof_block_hash": proof_block_hash.to_string(),
        "proof_header": {
            "accepted_id_merkle_root": proof_accepted_id_merkle_root.to_string(),
            "timestamp": proof_timestamp,
            "daa_score": proof_daa_score,
            "blue_score": proof_blue_score,
        },
        "proof": {
            "smt_proof": hex::encode(&proof.smt_proof),
            "lane": {
                "tip": proof_lane.tip.to_string(),
                "blue_score": proof_lane.blue_score,
            },
            "payload_and_ctx_digest": proof.payload_and_ctx_digest.to_string(),
            "parent_seq_commit": proof.parent_seq_commit.to_string(),
            "inactivity_shortcut": proof.inactivity_shortcut.to_string(),
        },
        "policy": policy,
        "candidate_markers": {
            "lower": {
                "role": "lower_candidate",
                "txid": lower_marker_tx.id().to_string(),
                "observed_lane_id": tx_subnetwork_id_hex(lower_marker_tx),
                "state_number": model.state_1.header.state_number,
                "state_header_hash": model.state_1.header.hash(),
                "payload": lower_payload,
                "payload_hash": sha256_hex(&lower_payload_bytes),
                "raw_tx": lower_raw,
                "accepted_event": lower_event,
            },
            "higher": {
                "role": "higher_candidate",
                "txid": higher_marker_tx.id().to_string(),
                "observed_lane_id": tx_subnetwork_id_hex(higher_marker_tx),
                "state_number": model.state_2.header.state_number,
                "state_header_hash": model.state_2.header.hash(),
                "payload": higher_payload,
                "payload_hash": sha256_hex(&higher_payload_bytes),
                "raw_tx": higher_raw,
                "accepted_event": higher_event,
            },
            "wrong_lane": {
                "status": "ignored_wrong_lane",
                "txid": wrong_lane_marker_tx.id().to_string(),
                "observed_lane_id": tx_subnetwork_id_hex(wrong_lane_marker_tx),
                "payload": wrong_lane_payload,
                "payload_hash": sha256_hex(&wrong_lane_payload_bytes),
                "raw_tx": wrong_lane_raw,
                "accepted_observation": wrong_lane_observation,
                "absent_from_expected_lane_activity": !lane_events.iter().any(|event| {
                    event.get("txid").and_then(Value::as_str) == Some(&wrong_lane_txid)
                }),
            }
        },
        "lane_activity_blocks": lane_activity_blocks,
        "lane_events": lane_events,
        "model_validation": {
            "status": "passed",
            "validation_layer": "typed-kurrent-settlement-eligibility-model",
            "config": model.config.clone(),
            "funding": model.funding.clone(),
            "settlement_template": model.template.clone(),
            "candidates": [lower_candidate, higher_candidate],
            "current_daa": proof_daa_score,
            "decisions": decisions,
        },
        "claim_boundary": "This local-devnet harness demonstrates settlement eligibility over lane-proven ordering; it does not specify production finality, watchtower economics, fee policy, or a consensus tie-breaker.",
    }))
}

struct FeeSponsoredDisplacementEvidenceInput<'a> {
    output_dir: &'a Path,
    monitor_start_block: Hash,
    expected_lane_id: &'a str,
    eligibility_policy: &'a SettlementEligibilityPolicy,
    fee_policy: &'a SettlementFeePolicy,
    model: &'a LiveStateModelArtifacts,
    lower_update: &'a StateUpdate,
    lower_marker: &'a SponsoredLaneMarker,
    lower_payload: &'a Value,
    higher_update: &'a StateUpdate,
    higher_marker: &'a SponsoredLaneMarker,
    higher_payload: &'a Value,
}

async fn run_fee_sponsored_displacement_evidence(
    client: &GrpcClient,
    input: FeeSponsoredDisplacementEvidenceInput<'_>,
) -> Result<Value, String> {
    let FeeSponsoredDisplacementEvidenceInput {
        output_dir,
        monitor_start_block,
        expected_lane_id,
        eligibility_policy,
        fee_policy,
        model,
        lower_update,
        lower_marker,
        lower_payload,
        higher_update,
        higher_marker,
        higher_payload,
    } = input;
    let expected_lane_bytes =
        lane_id_bytes(expected_lane_id, "fee-sponsored displacement lane id")?;
    let expected_lane_key = lane_key(&expected_lane_bytes);
    let monitor_start_header = client
        .get_block(monitor_start_block, false)
        .await
        .map_err(|e| {
            format!("failed to read fee-sponsored monitor start block {monitor_start_block}: {e}")
        })?
        .header;
    let initial_lane_proof = client
        .get_seq_commit_lane_proof(monitor_start_block, expected_lane_key)
        .await
        .map_err(|e| format!("failed to obtain fee-sponsored initial lane proof: {e}"))?;
    let initial_lane = initial_lane_proof.lane.as_ref().map(|lane| {
        json!({
            "tip": lane.tip.to_string(),
            "blue_score": lane.blue_score,
        })
    });
    let vcc = client
        .get_virtual_chain_from_block_v2(
            monitor_start_block,
            Some(RpcDataVerbosityLevel::Full),
            None,
        )
        .await
        .map_err(|e| format!("failed to read fee-sponsored virtual chain: {e}"))?;
    let proof_block_hash = vcc
        .added_chain_block_hashes
        .last()
        .copied()
        .ok_or_else(|| "fee-sponsored virtual chain returned no added chain blocks".to_string())?;

    let expected_by_txid = BTreeMap::from([
        (
            lower_marker.tx.id().to_string(),
            ("lower_fee_sponsored_candidate", TX_VERSION_TOCCATA),
        ),
        (
            higher_marker.tx.id().to_string(),
            ("higher_fee_sponsored_candidate", TX_VERSION_TOCCATA),
        ),
    ]);
    let mut parent_seq_commit = monitor_start_header.accepted_id_merkle_root;
    let mut selected_parent_timestamp = monitor_start_header.timestamp;
    let mut accepted_order_index = 0_u64;
    let mut lane_events = Vec::new();
    let mut lane_activity_blocks = Vec::new();
    let mut latest_lane_tip = initial_lane_proof.lane.as_ref().map(|lane| lane.tip);
    let mut latest_lane_blue_score = initial_lane_proof.lane.as_ref().map(|lane| lane.blue_score);
    let mut proof_header = None;

    for accepted_block in vcc.chain_block_accepted_transactions.iter() {
        let header = &accepted_block.chain_block_header;
        let block_hash = header
            .hash
            .ok_or_else(|| "fee-sponsored chain block is missing hash".to_string())?;
        let accepted_id_merkle_root = header.accepted_id_merkle_root.ok_or_else(|| {
            format!("fee-sponsored chain block {block_hash} is missing accepted_id_merkle_root")
        })?;
        let block_timestamp = header.timestamp.ok_or_else(|| {
            format!("fee-sponsored chain block {block_hash} is missing timestamp")
        })?;
        let daa_score = header.daa_score.ok_or_else(|| {
            format!("fee-sponsored chain block {block_hash} is missing daa_score")
        })?;
        let blue_score = header.blue_score.ok_or_else(|| {
            format!("fee-sponsored chain block {block_hash} is missing blue_score")
        })?;
        if block_hash == proof_block_hash {
            proof_header = Some((
                accepted_id_merkle_root,
                block_timestamp,
                daa_score,
                blue_score,
            ));
        }

        let block_order_start = accepted_order_index;
        let mut merge_index = 0_u32;
        let mut block_leaves = Vec::new();
        let mut block_events = Vec::new();
        for tx in accepted_block.accepted_transactions.iter() {
            let txid = tx
                .verbose_data
                .as_ref()
                .and_then(|data| data.transaction_id)
                .ok_or_else(|| format!("accepted transaction in {block_hash} is missing txid"))?;
            let version = tx.version.ok_or_else(|| {
                format!("accepted transaction {txid} in {block_hash} is missing version")
            })?;
            let subnetwork_id = tx.subnetwork_id.ok_or_else(|| {
                format!("accepted transaction {txid} in {block_hash} is missing subnetwork id")
            })?;
            let txid_string = txid.to_string();
            if subnetwork_id.as_bytes() == &expected_lane_bytes {
                let activity = activity_leaf(&txid, version, merge_index);
                let (kind, expected_version) = expected_by_txid
                    .get(&txid_string)
                    .copied()
                    .unwrap_or(("other_expected_lane_activity", version));
                if expected_by_txid.contains_key(&txid_string) && version != expected_version {
                    return Err(format!(
                        "fee-sponsored marker {txid} has version {version}, expected {expected_version}"
                    ));
                }
                let event = json!({
                    "kind": kind,
                    "txid": txid_string,
                    "version": version,
                    "lane_id": subnetwork_id_hex(&subnetwork_id),
                    "accepting_chain_block_hash": block_hash.to_string(),
                    "accepted_order_index": accepted_order_index,
                    "merge_index": merge_index,
                    "daa_score": daa_score,
                    "blue_score": blue_score,
                    "activity_leaf": activity.to_string(),
                });
                block_leaves.push(activity);
                block_events.push(event.clone());
                lane_events.push(event);
            }
            merge_index = merge_index
                .checked_add(1)
                .ok_or_else(|| "fee-sponsored merge index overflowed".to_string())?;
            accepted_order_index = accepted_order_index
                .checked_add(1)
                .ok_or_else(|| "fee-sponsored accepted-order index overflowed".to_string())?;
        }

        if !block_leaves.is_empty() {
            let context_hash = mergeset_context_hash(&MergesetContext {
                timestamp: selected_parent_timestamp,
                daa_score,
                blue_score,
            });
            let digest = activity_digest_lane(block_leaves.iter().copied());
            let parent_ref = latest_lane_tip.unwrap_or(parent_seq_commit);
            let next_tip = lane_tip_next(&LaneTipInput {
                parent_ref: &parent_ref,
                lane_key: &expected_lane_key,
                activity_digest: &digest,
                context_hash: &context_hash,
            });
            latest_lane_tip = Some(next_tip);
            latest_lane_blue_score = Some(blue_score);
            lane_activity_blocks.push(json!({
                "chain_block_hash": block_hash.to_string(),
                "accepted_id_merkle_root": accepted_id_merkle_root.to_string(),
                "parent_seq_commit": parent_seq_commit.to_string(),
                "timestamp": selected_parent_timestamp,
                "chain_block_timestamp": block_timestamp,
                "daa_score": daa_score,
                "blue_score": blue_score,
                "accepted_order_start": block_order_start,
                "activity_digest": digest.to_string(),
                "lane_tip_after_block": next_tip.to_string(),
                "events": block_events,
            }));
        }

        parent_seq_commit = accepted_id_merkle_root;
        selected_parent_timestamp = block_timestamp;
    }

    let (proof_accepted_id_merkle_root, proof_timestamp, proof_daa_score, proof_blue_score) =
        proof_header.ok_or_else(|| {
            format!("fee-sponsored proof block {proof_block_hash} was not present in chain data")
        })?;
    let proof = client
        .get_seq_commit_lane_proof(proof_block_hash, expected_lane_key)
        .await
        .map_err(|e| format!("failed to obtain fee-sponsored KIP-21 lane proof: {e}"))?;
    let proof_lane = proof.lane.as_ref().ok_or_else(|| {
        "fee-sponsored KIP-21 proof returned non-inclusion for active lane".to_string()
    })?;
    let expected_tip = latest_lane_tip.ok_or_else(|| {
        "fee-sponsored evidence did not observe expected-lane markers".to_string()
    })?;
    if proof_lane.tip != expected_tip {
        return Err(format!(
            "fee-sponsored proof tip mismatch: expected reconstructed {expected_tip}, actual {}",
            proof_lane.tip
        ));
    }
    if Some(proof_lane.blue_score) != latest_lane_blue_score {
        return Err(format!(
            "fee-sponsored proof blue score mismatch: expected {:?}, actual {}",
            latest_lane_blue_score, proof_lane.blue_score
        ));
    }
    verify_lane_proof_material(LaneProofMaterial {
        lane_key_hash: expected_lane_key,
        lane_tip: proof_lane.tip,
        lane_blue_score: proof_lane.blue_score,
        smt_proof_bytes: &proof.smt_proof,
        payload_and_ctx_digest: proof.payload_and_ctx_digest,
        parent_seq_commit: proof.parent_seq_commit,
        inactivity_shortcut: proof.inactivity_shortcut,
        accepted_id_merkle_root: proof_accepted_id_merkle_root,
    })?;

    let lower_marker_txid = lower_marker.tx.id().to_string();
    let higher_marker_txid = higher_marker.tx.id().to_string();
    let lower_event = lane_events
        .iter()
        .find(|event| event.get("txid").and_then(Value::as_str) == Some(lower_marker_txid.as_str()))
        .ok_or_else(|| {
            "lower fee-sponsored marker was not observed on expected lane".to_string()
        })?;
    let higher_event = lane_events
        .iter()
        .find(|event| {
            event.get("txid").and_then(Value::as_str) == Some(higher_marker_txid.as_str())
        })
        .ok_or_else(|| {
            "higher fee-sponsored marker was not observed on expected lane".to_string()
        })?;

    let distribution_hash = settlement_distribution_hash(&model.template);
    let template_hash = model.template.hash();
    let lower_candidate = FeeSponsoredSettlementCandidate {
        eligibility: SettlementEligibilityCandidate {
            update: lower_update.clone(),
            evidence: settlement_candidate_evidence_from_event(
                lower_update,
                expected_lane_id,
                lower_event,
            )?,
        },
        sponsor: SettlementSponsorEvidence {
            candidate_txid: lower_marker_txid.clone(),
            sponsor_input_outpoints: lower_marker.accounting.sponsor_input_outpoints.clone(),
            sponsor_input_total: lower_marker.accounting.sponsor_input_total,
            sponsor_change_total: lower_marker.accounting.sponsor_change_total,
            sponsor_fee: lower_marker.accounting.sponsor_fee,
            settlement_template_hash: template_hash.clone(),
            settlement_distribution_hash: distribution_hash.clone(),
        },
    };
    let higher_candidate = FeeSponsoredSettlementCandidate {
        eligibility: SettlementEligibilityCandidate {
            update: higher_update.clone(),
            evidence: settlement_candidate_evidence_from_event(
                higher_update,
                expected_lane_id,
                higher_event,
            )?,
        },
        sponsor: SettlementSponsorEvidence {
            candidate_txid: higher_marker_txid.clone(),
            sponsor_input_outpoints: higher_marker.accounting.sponsor_input_outpoints.clone(),
            sponsor_input_total: higher_marker.accounting.sponsor_input_total,
            sponsor_change_total: higher_marker.accounting.sponsor_change_total,
            sponsor_fee: higher_marker.accounting.sponsor_fee,
            settlement_template_hash: template_hash,
            settlement_distribution_hash: distribution_hash.clone(),
        },
    };
    let fee_sponsored_decisions = evaluate_fee_sponsored_settlement_eligibility(
        &model.config,
        &model.funding,
        &model.template,
        eligibility_policy,
        fee_policy,
        &[lower_candidate.clone(), higher_candidate.clone()],
        proof_daa_score,
    )
    .map_err(|err| format!("fee-sponsored model evaluation failed: {err:?}"))?;

    let lower_payload_bytes = json_payload_bytes(lower_payload)?;
    let higher_payload_bytes = json_payload_bytes(higher_payload)?;
    let lower_raw = write_raw_tx(
        output_dir,
        "kurrent-live-fee-sponsored-lower-marker-tx.hex",
        &lower_marker.tx,
    )?;
    let higher_raw = write_raw_tx(
        output_dir,
        "kurrent-live-fee-sponsored-higher-marker-tx.hex",
        &higher_marker.tx,
    )?;

    Ok(json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "driver": "kurrent-kaspa-devnet-driver",
        "monitor_scope": "fee-sponsored-displacement-evidence",
        "expected_lane_id": expected_lane_id,
        "lane_key": expected_lane_key.to_string(),
        "initial_lane": initial_lane,
        "monitor_start_block": monitor_start_block.to_string(),
        "monitor_start_accepted_id_merkle_root": monitor_start_header.accepted_id_merkle_root.to_string(),
        "proof_block_hash": proof_block_hash.to_string(),
        "proof_header": {
            "accepted_id_merkle_root": proof_accepted_id_merkle_root.to_string(),
            "timestamp": proof_timestamp,
            "daa_score": proof_daa_score,
            "blue_score": proof_blue_score,
        },
        "proof": {
            "smt_proof": hex::encode(&proof.smt_proof),
            "lane": {
                "tip": proof_lane.tip.to_string(),
                "blue_score": proof_lane.blue_score,
            },
            "payload_and_ctx_digest": proof.payload_and_ctx_digest.to_string(),
            "parent_seq_commit": proof.parent_seq_commit.to_string(),
            "inactivity_shortcut": proof.inactivity_shortcut.to_string(),
        },
        "eligibility_policy": eligibility_policy,
        "fee_policy": fee_policy,
        "fee_policy_hash": fee_policy.hash(),
        "settlement_distribution_hash": distribution_hash,
        "sponsored_markers": {
            "lower": {
                "role": "lower_fee_sponsored_candidate",
                "txid": lower_marker_txid,
                "observed_lane_id": tx_subnetwork_id_hex(&lower_marker.tx),
                "state_number": lower_update.header.state_number,
                "state_header_hash": lower_update.header.hash(),
                "payload": lower_payload,
                "payload_hash": sha256_hex(&lower_payload_bytes),
                "raw_tx": lower_raw,
                "accepted_event": lower_event,
                "sponsor": lower_marker.accounting.clone(),
            },
            "higher": {
                "role": "higher_fee_sponsored_candidate",
                "txid": higher_marker_txid,
                "observed_lane_id": tx_subnetwork_id_hex(&higher_marker.tx),
                "state_number": higher_update.header.state_number,
                "state_header_hash": higher_update.header.hash(),
                "payload": higher_payload,
                "payload_hash": sha256_hex(&higher_payload_bytes),
                "raw_tx": higher_raw,
                "accepted_event": higher_event,
                "sponsor": higher_marker.accounting.clone(),
            }
        },
        "lane_activity_blocks": lane_activity_blocks,
        "lane_events": lane_events,
        "model_validation": {
            "status": "passed",
            "validation_layer": "typed-kurrent-fee-sponsored-displacement-model",
            "config": model.config.clone(),
            "funding": model.funding.clone(),
            "settlement_template": model.template.clone(),
            "candidates": [lower_candidate, higher_candidate],
            "current_daa": proof_daa_score,
            "decisions": fee_sponsored_decisions,
        },
        "claim_boundary": "This local-devnet harness demonstrates sponsor-funded eligibility evidence without settlement-distribution mutation; it does not specify fee markets, mempool policy, sponsor economics, production finality, or a consensus tie-breaker.",
    }))
}

fn settlement_candidate_evidence_from_event(
    state: &StateUpdate,
    expected_lane_id: &str,
    event: &Value,
) -> Result<SettlementCandidateEvidence, String> {
    Ok(SettlementCandidateEvidence {
        network_profile: state.header.network_profile.clone(),
        funding_outpoint: state.header.funding_outpoint.clone(),
        channel_id: state.header.channel_id.clone(),
        factory_id: state.header.factory_id.clone(),
        virtual_channel_id: state.header.virtual_channel_id.clone(),
        state_number: state.header.state_number,
        state_header_hash: state.header.hash(),
        lane_id: expected_lane_id.to_string(),
        candidate_txid: required_str(event, "/txid")?,
        accepted_order_index: required_u64(event, "/accepted_order_index")?,
        accepting_chain_block_hash: required_str(event, "/accepting_chain_block_hash")?,
        daa_score: required_u64(event, "/daa_score")?,
        blue_score: required_u64(event, "/blue_score")?,
    })
}

fn build_state_1_redeem_script(
    expected_lane_id: &[u8],
    state_2_value: u64,
    state_2_spk: &ScriptPublicKey,
) -> Result<Vec<u8>, String> {
    let state_2_spk_bytes = spk_bytes(state_2_spk);
    ScriptBuilder::new()
        .add_op(OpTxSubnetId)
        .and_then(|b| b.add_data(expected_lane_id))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_data(&[1]))
        .and_then(|b| b.add_op(OpSwap))
        .and_then(|b| b.add_op(OpIf))
        .and_then(|b| b.add_op(OpFalse))
        .and_then(|b| b.add_op(OpElse))
        .and_then(|b| b.add_data(&[1]))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_op(OpAuthOutputCount))
        .and_then(|b| b.add_i64(1))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_op(OpAuthOutputIdx))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_op(OpTxOutputAmount))
        .and_then(|b| b.add_i64(state_2_value as i64))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_op(OpTxOutputSpk))
        .and_then(|b| b.add_data(&state_2_spk_bytes))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_op(OpTrue))
        .and_then(|b| b.add_op(OpEndIf))
        .map(|b| b.drain())
        .map_err(|e| format!("failed to build Kurrent state-1 covenant script: {e}"))
}

fn build_state_2_redeem_script(
    expected_lane_id: &[u8],
    alice_value: u64,
    alice_spk: &ScriptPublicKey,
    bob_value: u64,
    bob_spk: &ScriptPublicKey,
) -> Result<Vec<u8>, String> {
    let alice_spk_bytes = spk_bytes(alice_spk);
    let bob_spk_bytes = spk_bytes(bob_spk);
    ScriptBuilder::new()
        .add_op(OpTxSubnetId)
        .and_then(|b| b.add_data(expected_lane_id))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_data(&[2]))
        .and_then(|b| b.add_op(OpSwap))
        .and_then(|b| b.add_op(OpIf))
        .and_then(|b| b.add_data(&[2]))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_op(OpTxOutputCount))
        .and_then(|b| b.add_i64(2))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_op(OpTxOutputAmount))
        .and_then(|b| b.add_i64(alice_value as i64))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(0))
        .and_then(|b| b.add_op(OpTxOutputSpk))
        .and_then(|b| b.add_data(&alice_spk_bytes))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(1))
        .and_then(|b| b.add_op(OpTxOutputAmount))
        .and_then(|b| b.add_i64(bob_value as i64))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_i64(1))
        .and_then(|b| b.add_op(OpTxOutputSpk))
        .and_then(|b| b.add_data(&bob_spk_bytes))
        .and_then(|b| b.add_op(OpEqualVerify))
        .and_then(|b| b.add_op(OpTrue))
        .and_then(|b| b.add_op(OpElse))
        .and_then(|b| b.add_op(OpFalse))
        .and_then(|b| b.add_op(OpEndIf))
        .map(|b| b.drain())
        .map_err(|e| format!("failed to build Kurrent state-2 covenant script: {e}"))
}

fn spk_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    spk.version()
        .to_be_bytes()
        .into_iter()
        .chain(spk.script().iter().copied())
        .collect()
}

fn p2sh_signature_script(settlement: bool, redeem_script: &[u8]) -> Result<Vec<u8>, String> {
    let branch_selector = if settlement {
        vec![OpTrue]
    } else {
        vec![OpFalse]
    };
    pay_to_script_hash_signature_script(redeem_script.to_vec(), branch_selector)
        .map_err(|e| format!("failed to build Kurrent P2SH witness: {e}"))
}

fn signed_genesis_covenant_tx(
    signer: &Keypair,
    previous_outpoint: TransactionOutpoint,
    entry: UtxoEntry,
    funding_value: u64,
    state_1_spk: ScriptPublicKey,
    subnetwork_id: SubnetworkId,
    payload: &[u8],
) -> Result<Transaction, String> {
    let mut unsigned = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            previous_outpoint,
            vec![],
            0,
            10,
        )],
        vec![TransactionOutput::new(funding_value, state_1_spk)],
        0,
        subnetwork_id,
        0,
        payload.to_vec(),
    );
    unsigned
        .populate_genesis_covenants(&[GenesisCovenantGroup::new(0, vec![0])])
        .map_err(|e| format!("failed to populate Kurrent genesis covenant id: {e}"))?;
    unsigned.finalize();
    Ok(sign(
        MutableTransaction::with_entries(unsigned, vec![entry]),
        *signer,
    )
    .tx)
}

async fn run_live_factory_flow(
    ctx: &LiveKaspaContext<'_>,
    alice_spk: &ScriptPublicKey,
    bob_spk: &ScriptPublicKey,
) -> Result<Value, String> {
    let (funding_tx, funding_value, factory_redeem_script) = fund_plain_p2sh(
        ctx,
        STATE_UPDATE_FEE,
        |value| build_factory_redeem_script(value, alice_spk, bob_spk),
        b"KURRENT_FACTORY_V1:funding",
    )
    .await?;
    let funding_txid = submit_and_mine(ctx.rpc, ctx.miner_address, &funding_tx).await?;
    let materialisation_value = funding_value - STATE_UPDATE_FEE;
    let alice_value = materialisation_value * 55 / 100;
    let bob_value = materialisation_value - alice_value;
    let materialisation_script =
        build_factory_redeem_script(materialisation_value, alice_spk, bob_spk)?;
    let materialisation_witness =
        pay_to_script_hash_signature_script(materialisation_script.clone(), vec![])
            .map_err(|e| format!("failed to build Kurrent factory witness: {e}"))?;
    let materialisation_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(funding_tx.id(), 0),
            materialisation_witness.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![
            TransactionOutput::new(alice_value, alice_spk.clone()),
            TransactionOutput::new(bob_value, bob_spk.clone()),
        ],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        b"KURRENT_FACTORY_V1:materialise".to_vec(),
    );
    let materialisation_txid =
        submit_and_mine(ctx.rpc, ctx.miner_address, &materialisation_tx).await?;
    let model_validation = validate_live_factory_model(
        &format!("{funding_txid}:0"),
        &format!("{materialisation_txid}:0,{materialisation_txid}:1"),
        materialisation_value,
        alice_value,
        bob_value,
        &factory_redeem_script,
    )?;

    Ok(json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "flow": "kaspa_factory_flow",
        "funding": {
            "txid": funding_txid.to_string(),
            "value": funding_value,
            "outpoint": format!("{funding_txid}:0"),
            "raw_tx": write_raw_tx(ctx.output_dir, "kurrent-live-factory-funding-tx.hex", &funding_tx)?,
        },
        "materialisation": {
            "txid": materialisation_txid.to_string(),
            "outputs": {
                "alice": alice_value,
                "bob": bob_value
            },
            "raw_tx": write_raw_tx(ctx.output_dir, "kurrent-live-factory-materialisation-tx.hex", &materialisation_tx)?,
            "witness": write_bytes_hex(ctx.output_dir, "kurrent-live-factory-materialisation-witness.hex", &materialisation_witness)?,
            "redeem_script": write_bytes_hex(ctx.output_dir, "kurrent-live-factory-redeem-script.hex", &factory_redeem_script)?,
        },
        "model_validation": model_validation,
    }))
}

async fn run_live_hashlock_flow(
    label: &str,
    ctx: &LiveKaspaContext<'_>,
    preimage: &[u8],
    recipient_spk: &ScriptPublicKey,
) -> Result<Value, String> {
    let (funding_tx, funding_value, redeem_script) = fund_plain_p2sh(
        ctx,
        SETTLEMENT_FEE,
        |value| build_hashlock_redeem_script(preimage, value, recipient_spk),
        format!("KURRENT_HASHLOCK_V1:{label}:funding").as_bytes(),
    )
    .await?;
    let funding_txid = submit_and_mine(ctx.rpc, ctx.miner_address, &funding_tx).await?;
    let prefix = ScriptBuilder::new()
        .add_data(preimage)
        .map_err(|e| format!("failed to build Kurrent hashlock preimage witness: {e}"))?
        .drain();
    let witness = pay_to_script_hash_signature_script(redeem_script.clone(), prefix)
        .map_err(|e| format!("failed to build Kurrent hashlock witness: {e}"))?;
    let tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(funding_tx.id(), 0),
            witness.clone(),
            0,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![TransactionOutput::new(
            funding_value - SETTLEMENT_FEE,
            recipient_spk.clone(),
        )],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        format!("KURRENT_HASHLOCK_V1:{label}:settle").into_bytes(),
    );
    let txid = submit_and_mine(ctx.rpc, ctx.miner_address, &tx).await?;
    let safe_label = label.replace('-', "_");
    let settlement_value = funding_value - SETTLEMENT_FEE;
    let model_validation = validate_live_hashlock_model(
        label,
        preimage,
        &format!("{funding_txid}:0"),
        &format!("{txid}:0"),
        settlement_value,
        &redeem_script,
    )?;

    Ok(json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "flow": label,
        "preimage_sha256": sha256_hex(preimage),
        "funding": {
            "txid": funding_txid.to_string(),
            "value": funding_value,
            "outpoint": format!("{funding_txid}:0"),
            "raw_tx": write_raw_tx(ctx.output_dir, &format!("kurrent-live-{safe_label}-funding-tx.hex"), &funding_tx)?,
        },
        "settlement": {
            "txid": txid.to_string(),
            "output_value": settlement_value,
            "raw_tx": write_raw_tx(ctx.output_dir, &format!("kurrent-live-{safe_label}-settlement-tx.hex"), &tx)?,
            "witness": write_bytes_hex(ctx.output_dir, &format!("kurrent-live-{safe_label}-settlement-witness.hex"), &witness)?,
            "redeem_script": write_bytes_hex(ctx.output_dir, &format!("kurrent-live-{safe_label}-redeem-script.hex"), &redeem_script)?,
        },
        "model_validation": model_validation,
    }))
}

async fn run_live_refund_flow(
    ctx: &LiveKaspaContext<'_>,
    refund_spk: &ScriptPublicKey,
) -> Result<Value, String> {
    const REFUND_SEQUENCE: u64 = 120;
    let (funding_tx, funding_value, redeem_script) = fund_plain_p2sh(
        ctx,
        SETTLEMENT_FEE,
        |value| build_refund_redeem_script(REFUND_SEQUENCE, value, refund_spk),
        b"KURRENT_REFUND_V1:funding",
    )
    .await?;
    let funding_txid = submit_and_mine(ctx.rpc, ctx.miner_address, &funding_tx).await?;
    let early_witness = pay_to_script_hash_signature_script(redeem_script.clone(), vec![])
        .map_err(|e| format!("failed to build Kurrent early-refund witness: {e}"))?;
    let early_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(funding_tx.id(), 0),
            early_witness.clone(),
            REFUND_SEQUENCE - 1,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![TransactionOutput::new(
            funding_value - SETTLEMENT_FEE,
            refund_spk.clone(),
        )],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        b"KURRENT_REFUND_V1:early-rejected".to_vec(),
    );
    let early_rejection = ctx
        .rpc
        .submit_transaction((&early_tx).into(), false)
        .await
        .err()
        .map(|e| e.to_string())
        .ok_or_else(|| "early refund was unexpectedly accepted".to_string())?;

    for _ in 0..(REFUND_SEQUENCE + 5) {
        mine_block(ctx.rpc, ctx.miner_address).await?;
    }
    let refund_witness = pay_to_script_hash_signature_script(redeem_script.clone(), vec![])
        .map_err(|e| format!("failed to build Kurrent refund witness: {e}"))?;
    let refund_tx = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(funding_tx.id(), 0),
            refund_witness.clone(),
            REFUND_SEQUENCE,
            COVENANT_COMPUTE_BUDGET,
        )],
        vec![TransactionOutput::new(
            funding_value - SETTLEMENT_FEE,
            refund_spk.clone(),
        )],
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        b"KURRENT_REFUND_V1:refund".to_vec(),
    );
    let refund_txid = submit_and_mine(ctx.rpc, ctx.miner_address, &refund_tx).await?;
    let refund_value = funding_value - SETTLEMENT_FEE;
    let model_validation = validate_live_refund_model(
        &format!("{funding_txid}:0"),
        &format!("{refund_txid}:0"),
        REFUND_SEQUENCE,
        &redeem_script,
    )?;

    Ok(json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "flow": "refund_timeout_flow",
        "funding": {
            "txid": funding_txid.to_string(),
            "value": funding_value,
            "outpoint": format!("{funding_txid}:0"),
            "raw_tx": write_raw_tx(ctx.output_dir, "kurrent-live-refund-funding-tx.hex", &funding_tx)?,
        },
        "early_refund_rejection": {
            "status": "rejected",
            "attempted_txid": early_tx.id().to_string(),
            "attempted_tx": write_raw_tx(ctx.output_dir, "kurrent-live-early-refund-rejected-tx.hex", &early_tx)?,
            "witness": write_bytes_hex(ctx.output_dir, "kurrent-live-early-refund-rejected-witness.hex", &early_witness)?,
            "node_error": early_rejection,
        },
        "refund": {
            "txid": refund_txid.to_string(),
            "output_value": refund_value,
            "raw_tx": write_raw_tx(ctx.output_dir, "kurrent-live-refund-tx.hex", &refund_tx)?,
            "witness": write_bytes_hex(ctx.output_dir, "kurrent-live-refund-witness.hex", &refund_witness)?,
            "redeem_script": write_bytes_hex(ctx.output_dir, "kurrent-live-refund-redeem-script.hex", &redeem_script)?,
        },
        "model_validation": model_validation,
    }))
}

fn validate_live_factory_model(
    funding_outpoint: &str,
    materialisation_output_id: &str,
    materialisation_value: u64,
    alice_value: u64,
    bob_value: u64,
    redeem_script: &[u8],
) -> Result<Value, String> {
    let untouched_principal = 1_000_000_u64;
    let materialisation_id = materialisation_output_id.to_string();
    let before = FactoryState {
        factory_id: "factory-live-1".to_string(),
        network_profile: "kaspa-simnet-toccata".to_string(),
        total_principal: materialisation_value + untouched_principal,
        fee_reserve: 0,
        virtual_channels: BTreeMap::from([
            (
                "factory-live-vc-1".to_string(),
                VirtualChannelState {
                    virtual_channel_id: "factory-live-vc-1".to_string(),
                    channel_id: "factory-live-channel-1".to_string(),
                    balance_by_participant: BTreeMap::from([
                        ("alice".to_string(), alice_value),
                        ("bob".to_string(), bob_value),
                    ]),
                    state_number: 2,
                    state_commitment: sha256_hex(b"factory-live-vc-1-state-2"),
                },
            ),
            (
                "factory-live-vc-2".to_string(),
                VirtualChannelState {
                    virtual_channel_id: "factory-live-vc-2".to_string(),
                    channel_id: "factory-live-channel-2".to_string(),
                    balance_by_participant: BTreeMap::from([(
                        "carol".to_string(),
                        untouched_principal,
                    )]),
                    state_number: 0,
                    state_commitment: sha256_hex(b"factory-live-vc-2-state-0"),
                },
            ),
        ]),
        materialised_receipts: BTreeSet::new(),
    };
    let mut after = before.clone();
    after.total_principal = untouched_principal;
    after.virtual_channels.remove("factory-live-vc-1");
    after
        .materialised_receipts
        .insert(materialisation_id.clone());
    let plan = MaterialisationPlan {
        materialisation_id,
        factory_id: before.factory_id.clone(),
        virtual_channel_id: "factory-live-vc-1".to_string(),
        touched_leaves: TouchedLeaves {
            virtual_channel_ids: BTreeSet::from(["factory-live-vc-1".to_string()]),
        },
        principal_input_ids: BTreeSet::from([funding_outpoint.to_string()]),
        fee_input_ids: BTreeSet::new(),
        principal_amount: materialisation_value,
        fee_amount: 0,
        output_amounts: BTreeMap::from([
            ("alice".to_string(), alice_value),
            ("bob".to_string(), bob_value),
        ]),
    };
    let receipt = validate_materialisation(&before, &after, &plan)
        .map_err(|err| format!("live factory model validation failed: {err:?}"))?;
    Ok(json!({
        "status": "passed",
        "validation_layer": "typed-kurrent-protocol-model",
        "factory_state_roots": [
            hash_json(DOMAIN_FACTORY_MATERIALISATION, &before),
            hash_json(DOMAIN_FACTORY_MATERIALISATION, &after)
        ],
        "plan_hash": hash_json(DOMAIN_FACTORY_MATERIALISATION, &plan),
        "redeem_script_sha256": sha256_hex(redeem_script),
        "before": before,
        "after": after,
        "plan": plan,
        "receipt": receipt,
    }))
}

fn validate_live_hashlock_model(
    direction: &str,
    preimage: &[u8],
    funding_outpoint: &str,
    settlement_outpoint: &str,
    amount: u64,
    redeem_script: &[u8],
) -> Result<Value, String> {
    let payment_hash = sha256_hex(preimage);
    let script_hash = sha256_hex(redeem_script);
    let swap_id = format!("swap-{direction}-live");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "kaspa-simnet-toccata".to_string(),
        swap_id: swap_id.clone(),
        direction: direction.to_string(),
        ln_payment_hash: payment_hash.clone(),
        preimage: hex::encode(preimage),
        preimage_hash: payment_hash,
        kaspa_funding_outpoint: funding_outpoint.to_string(),
        kaspa_settlement_outpoint: settlement_outpoint.to_string(),
        amount,
        recipient: match direction {
            "ln-to-kaspa" => "alice".to_string(),
            "kaspa-to-ln" => "bob".to_string(),
            _ => direction.to_string(),
        },
        script_hash: script_hash.clone(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "kaspa-simnet-toccata",
        format!("channel-{direction}"),
        funding_outpoint,
        settlement_outpoint,
        2,
        script_hash,
    );
    receipt.swap_id = Some(swap_id);
    receipt.direction = Some(direction.to_string());
    receipt.refresh_hash();
    validate_ln_swap(&evidence, &receipt)
        .map_err(|err| format!("live {direction} swap model validation failed: {err:?}"))?;
    Ok(json!({
        "status": "passed",
        "validation_layer": "typed-kurrent-protocol-model",
        "swap_evidence": evidence,
        "receipt": receipt,
    }))
}

fn validate_live_refund_model(
    funding_outpoint: &str,
    refund_outpoint: &str,
    refund_sequence: u64,
    redeem_script: &[u8],
) -> Result<Value, String> {
    let scope = ClaimScope {
        network_profile: "kaspa-simnet-toccata".to_string(),
        funding_outpoint: funding_outpoint.to_string(),
        output_id: refund_outpoint.to_string(),
        claim_subject: "refund-timeout-live".to_string(),
    };
    let mut early_registry = SettlementRegistry::default();
    let early_rejection = early_registry
        .refund_scoped_claim(&scope, refund_sequence - 1, refund_sequence)
        .expect_err("early refund must be rejected by model");
    let mut mature_registry = SettlementRegistry::default();
    mature_registry
        .refund_scoped_claim(&scope, refund_sequence, refund_sequence)
        .map_err(|err| format!("mature refund model claim failed: {err:?}"))?;
    let duplicate_rejection = mature_registry
        .refund_scoped_claim(&scope, refund_sequence, refund_sequence)
        .expect_err("duplicate refund must be rejected by model");
    Ok(json!({
        "status": "passed",
        "validation_layer": "typed-kurrent-protocol-model",
        "refund_sequence": refund_sequence,
        "claim_scope": scope,
        "claim_key": scope.exclusive_key(),
        "redeem_script_sha256": sha256_hex(redeem_script),
        "early_rejection": format!("{early_rejection:?}"),
        "duplicate_rejection": format!("{duplicate_rejection:?}"),
    }))
}

async fn fund_plain_p2sh(
    ctx: &LiveKaspaContext<'_>,
    spend_fee: u64,
    build_redeem_script: impl FnOnce(u64) -> Result<Vec<u8>, String>,
    payload: &[u8],
) -> Result<(Transaction, u64, Vec<u8>), String> {
    let utxos =
        fetch_spendable_utxos(ctx.rpc, ctx.miner_address.clone(), ctx.coinbase_maturity).await;
    let Some((outpoint, entry)) = utxos.first().cloned() else {
        return Err("no spendable miner UTXO for live Kurrent flow".to_string());
    };
    if entry.amount <= FUNDING_FEE + spend_fee {
        return Err(format!(
            "spendable miner UTXO {} is too small for live Kurrent flow with spend fee {spend_fee}",
            entry.amount
        ));
    }
    let value = entry.amount - FUNDING_FEE;
    let redeem_script = build_redeem_script(value - spend_fee)?;
    let spk = pay_to_script_hash_script(&redeem_script);
    let tx = signed_plain_v1_tx(
        ctx.miner_sk,
        outpoint,
        entry,
        vec![TransactionOutput::new(value, spk)],
        payload,
    );
    Ok((tx, value, redeem_script))
}

fn signed_plain_v1_tx(
    signer: &Keypair,
    previous_outpoint: TransactionOutpoint,
    entry: UtxoEntry,
    outputs: Vec<TransactionOutput>,
    payload: &[u8],
) -> Transaction {
    signed_plain_lane_tx(
        signer,
        previous_outpoint,
        entry,
        outputs,
        SUBNETWORK_ID_NATIVE,
        payload,
    )
}

fn signed_plain_lane_tx(
    signer: &Keypair,
    previous_outpoint: TransactionOutpoint,
    entry: UtxoEntry,
    outputs: Vec<TransactionOutput>,
    subnetwork_id: SubnetworkId,
    payload: &[u8],
) -> Transaction {
    let unsigned = Transaction::new(
        TX_VERSION_TOCCATA,
        vec![TransactionInput::new_with_compute_budget(
            previous_outpoint,
            vec![],
            0,
            10,
        )],
        outputs,
        0,
        subnetwork_id,
        0,
        payload.to_vec(),
    );
    sign(
        MutableTransaction::with_entries(unsigned, vec![entry]),
        *signer,
    )
    .tx
}

async fn signed_lane_marker_tx(
    ctx: &LiveKaspaContext<'_>,
    subnetwork_id: SubnetworkId,
    payload: &[u8],
) -> Result<Transaction, String> {
    let utxos =
        fetch_spendable_utxos(ctx.rpc, ctx.miner_address.clone(), ctx.coinbase_maturity).await;
    let Some((outpoint, entry)) = utxos.first().cloned() else {
        return Err("no spendable miner UTXO for settlement eligibility marker".to_string());
    };
    if entry.amount <= MARKER_FEE {
        return Err(format!(
            "spendable miner UTXO {} is too small for settlement eligibility marker",
            entry.amount
        ));
    }
    let output = TransactionOutput::new(
        entry.amount - MARKER_FEE,
        pay_to_address_script(ctx.miner_address),
    );
    Ok(signed_plain_lane_tx(
        ctx.miner_sk,
        outpoint,
        entry,
        vec![output],
        subnetwork_id,
        payload,
    ))
}

async fn signed_sponsored_lane_marker_tx(
    ctx: &LiveKaspaContext<'_>,
    subnetwork_id: SubnetworkId,
    payload: &[u8],
    sponsor_fee: u64,
) -> Result<SponsoredLaneMarker, String> {
    let utxos =
        fetch_spendable_utxos(ctx.rpc, ctx.miner_address.clone(), ctx.coinbase_maturity).await;
    let Some((outpoint, entry)) = utxos.first().cloned() else {
        return Err("no spendable miner UTXO for fee-sponsored marker".to_string());
    };
    if sponsor_fee == 0 {
        return Err("fee-sponsored marker requires a non-zero sponsor fee".to_string());
    }
    if entry.amount <= sponsor_fee {
        return Err(format!(
            "spendable miner UTXO {} is too small for fee-sponsored marker fee {sponsor_fee}",
            entry.amount
        ));
    }
    let sponsor_change_total = entry.amount - sponsor_fee;
    let sponsor_input_outpoint = format!("{}:{}", outpoint.transaction_id, outpoint.index);
    let output = TransactionOutput::new(
        sponsor_change_total,
        pay_to_address_script(ctx.miner_address),
    );
    let tx = signed_plain_lane_tx(
        ctx.miner_sk,
        outpoint,
        entry.clone(),
        vec![output],
        subnetwork_id,
        payload,
    );
    Ok(SponsoredLaneMarker {
        tx,
        accounting: SponsorMarkerAccounting {
            sponsor_input_outpoints: vec![sponsor_input_outpoint],
            sponsor_input_total: entry.amount,
            sponsor_change_total,
            sponsor_fee,
        },
    })
}

fn settlement_candidate_marker_payload(role: &str, state: &StateUpdate, lane_id: &str) -> Value {
    json!({
        "domain": "KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1",
        "role": role,
        "network_profile": state.header.network_profile.clone(),
        "funding_outpoint": state.header.funding_outpoint.clone(),
        "channel_id": state.header.channel_id.clone(),
        "state_number": state.header.state_number,
        "state_header_hash": state.header.hash(),
        "lane_id": lane_id,
    })
}

fn fee_sponsored_candidate_marker_payload(
    role: &str,
    state: &StateUpdate,
    lane_id: &str,
    fee_policy: &SettlementFeePolicy,
    template: &SettlementTemplate,
) -> Value {
    json!({
        "domain": "KURRENT_FEE_SPONSORED_CANDIDATE_MARKER_V1",
        "role": role,
        "network_profile": state.header.network_profile.clone(),
        "funding_outpoint": state.header.funding_outpoint.clone(),
        "channel_id": state.header.channel_id.clone(),
        "state_number": state.header.state_number,
        "state_header_hash": state.header.hash(),
        "lane_id": lane_id,
        "settlement_template_hash": state.header.settlement_template_hash.clone(),
        "settlement_distribution_hash": settlement_distribution_hash(template),
        "fee_policy_hash": fee_policy.hash(),
    })
}

fn state_update_with_fee_policy_hash(
    mut state: StateUpdate,
    fee_policy_hash: &str,
    signers: &ModelSigners<'_>,
) -> StateUpdate {
    state.header.fee_policy_hash = Some(fee_policy_hash.to_string());
    state.participant_signatures.clear();
    state.participant_signatures.insert(
        "alice".to_string(),
        sign_model_state_update(signers.alice, &state),
    );
    state.participant_signatures.insert(
        "bob".to_string(),
        sign_model_state_update(signers.bob, &state),
    );
    state
}

fn json_payload_bytes(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| format!("failed to encode marker payload JSON: {e}"))
}

fn build_factory_redeem_script(
    materialisation_value: u64,
    alice_spk: &ScriptPublicKey,
    bob_spk: &ScriptPublicKey,
) -> Result<Vec<u8>, String> {
    let alice_value = materialisation_value * 55 / 100;
    let bob_value = materialisation_value - alice_value;
    build_exact_outputs_script(&[(alice_value, alice_spk), (bob_value, bob_spk)])
        .map_err(|e| format!("failed to build Kurrent factory script: {e}"))
}

fn build_hashlock_redeem_script(
    preimage: &[u8],
    value: u64,
    recipient_spk: &ScriptPublicKey,
) -> Result<Vec<u8>, String> {
    let hash = hex::decode(sha256_hex(preimage))
        .map_err(|e| format!("failed to hash Kurrent preimage: {e}"))?;
    let mut builder = ScriptBuilder::new();
    builder
        .add_op(OpSHA256)
        .and_then(|b| b.add_data(&hash))
        .and_then(|b| b.add_op(OpEqualVerify))
        .map_err(|e| format!("failed to build Kurrent hashlock prefix: {e}"))?;
    append_exact_outputs_script(builder, &[(value, recipient_spk)])
        .map_err(|e| format!("failed to build Kurrent hashlock script: {e}"))
}

fn build_refund_redeem_script(
    sequence: u64,
    value: u64,
    recipient_spk: &ScriptPublicKey,
) -> Result<Vec<u8>, String> {
    let mut builder = ScriptBuilder::new();
    builder
        .add_data(&sequence.to_le_bytes())
        .and_then(|b| b.add_op(OpCheckSequenceVerify))
        .map_err(|e| format!("failed to build Kurrent refund prefix: {e}"))?;
    append_exact_outputs_script(builder, &[(value, recipient_spk)])
        .map_err(|e| format!("failed to build Kurrent refund script: {e}"))
}

fn build_exact_outputs_script(outputs: &[(u64, &ScriptPublicKey)]) -> Result<Vec<u8>, String> {
    append_exact_outputs_script(ScriptBuilder::new(), outputs).map_err(|e| e.to_string())
}

fn append_exact_outputs_script(
    mut builder: ScriptBuilder,
    outputs: &[(u64, &ScriptPublicKey)],
) -> Result<Vec<u8>, kaspa_txscript::script_builder::ScriptBuilderError> {
    builder
        .add_op(OpTxOutputCount)?
        .add_i64(outputs.len() as i64)?
        .add_op(OpEqualVerify)?;
    for (index, (value, spk)) in outputs.iter().enumerate() {
        let spk_bytes = spk_bytes(spk);
        builder
            .add_i64(index as i64)?
            .add_op(OpTxOutputAmount)?
            .add_i64(*value as i64)?
            .add_op(OpEqualVerify)?
            .add_i64(index as i64)?
            .add_op(OpTxOutputSpk)?
            .add_data(&spk_bytes)?
            .add_op(OpEqualVerify)?;
    }
    builder.add_op(OpTrue)?;
    Ok(builder.drain())
}

fn read_ln_preimage(output_dir: &Path) -> Result<Vec<u8>, String> {
    let path = output_dir.join("ln-devnet-evidence.json");
    let bytes = fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
    let preimage = value
        .pointer("/invoice/preimage")
        .and_then(Value::as_str)
        .ok_or_else(|| "LN evidence does not contain /invoice/preimage".to_string())?;
    hex::decode(preimage).map_err(|e| format!("failed to decode LN preimage: {e}"))
}

async fn submit_and_mine(
    client: &GrpcClient,
    miner_address: &Address,
    tx: &Transaction,
) -> Result<RpcTransactionId, String> {
    let txid = tx.id();
    client
        .submit_transaction(tx.into(), false)
        .await
        .map_err(|e| format!("failed to submit transaction {txid}: {e}"))?;
    wait_for_mempool(client, txid).await?;
    mine_block(client, miner_address).await?;
    Ok(txid)
}

async fn wait_for_mempool(client: &GrpcClient, txid: RpcTransactionId) -> Result<(), String> {
    for _ in 0..100 {
        if client.get_mempool_entry(txid, false, false).await.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!(
        "transaction {txid} was not admitted to the mempool"
    ))
}

async fn wait_for_daa(client: &GrpcClient, target: u64) -> Result<(), String> {
    for _ in 0..100 {
        let info = client
            .get_server_info()
            .await
            .map_err(|e| format!("failed to read Kaspa server info: {e}"))?;
        if info.virtual_daa_score >= target {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("virtual DAA score did not reach {target}"))
}

async fn mine_block(client: &GrpcClient, miner_address: &Address) -> Result<(), String> {
    let template = client
        .get_block_template(miner_address.clone(), vec![])
        .await
        .map_err(|e| format!("failed to get Kaspa block template: {e}"))?;
    client
        .submit_block(template.block, false)
        .await
        .map_err(|e| format!("failed to submit Kaspa block template: {e}"))?;
    tokio::time::sleep(Duration::from_millis(20)).await;
    Ok(())
}

fn run_semantic_evidence_verifier(output_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(output_dir.join("production")).map_err(|e| {
        format!(
            "failed to create production evidence directory under {}: {e}",
            output_dir.display()
        )
    })?;

    let mut checks = Vec::new();
    let mut decoded_transactions = 0_u64;
    let mut verified_hex_records = 0_u64;

    verify_state_channel_semantics(
        output_dir,
        &mut checks,
        &mut decoded_transactions,
        &mut verified_hex_records,
    )?;
    verify_lane_monitor_semantics(output_dir, &mut checks)?;
    verify_settlement_eligibility_semantics(
        output_dir,
        &mut checks,
        &mut decoded_transactions,
        &mut verified_hex_records,
    )?;
    verify_fee_sponsored_displacement_semantics(
        output_dir,
        &mut checks,
        &mut decoded_transactions,
        &mut verified_hex_records,
    )?;
    verify_factory_semantics(
        output_dir,
        &mut checks,
        &mut decoded_transactions,
        &mut verified_hex_records,
    )?;
    verify_hashlock_semantics(
        output_dir,
        &mut checks,
        &mut decoded_transactions,
        &mut verified_hex_records,
    )?;
    verify_refund_semantics(
        output_dir,
        &mut checks,
        &mut decoded_transactions,
        &mut verified_hex_records,
    )?;

    let report = json!({
        "status": "passed",
        "checked_at_unix": unix_now(),
        "decoded_transactions": decoded_transactions,
        "verified_hex_records": verified_hex_records,
        "checks": checks,
    });
    write_json(
        &output_dir.join("production"),
        "semantic-transaction-verifier.json",
        &report,
    )
}

fn verify_state_channel_semantics(
    output_dir: &Path,
    checks: &mut Vec<Value>,
    decoded_transactions: &mut u64,
    verified_hex_records: &mut u64,
) -> Result<(), String> {
    let report = read_json(&output_dir.join("kurrent-live-state-channel-evidence.json"))?;
    require_status(&report, "state channel live evidence")?;
    require_status(
        &required_value(&report, "/model_validation")?,
        "state channel model validation",
    )?;
    require_eq(
        required_str(&report, "/model_validation/validation_layer")?,
        "typed-kurrent-protocol-model",
        "state channel model validation layer",
    )?;
    require_json_hash(
        &report,
        DOMAIN_SETTLEMENT_TEMPLATE,
        "/settlement_template/template",
        "/settlement_template/hash",
        "state settlement template hash",
    )?;
    require_json_hash(
        &report,
        DOMAIN_STATE,
        "/state_header/header",
        "/state_header/hash",
        "state header hash",
    )?;
    require_json_hash(
        &report,
        DOMAIN_CHANNEL_RECEIPT,
        "/channel_receipt/scope",
        "/channel_receipt/hash",
        "state channel receipt hash",
    )?;
    let expected_lane_id = required_str(&report, "/lane_binding/expected_lane_id")?;

    let funding_tx = transaction_from_record(&report, "/funding/raw_tx", verified_hex_records)?;
    *decoded_transactions += 1;
    require_txid(
        &funding_tx,
        &required_str(&report, "/funding/txid")?,
        "state funding",
    )?;
    require_outpoint(
        &required_str(&report, "/funding/outpoint")?,
        &funding_tx,
        0,
        "state funding outpoint",
    )?;
    require_output_value(
        &funding_tx,
        0,
        required_u64(&report, "/funding/value")?,
        "state funding value",
    )?;
    require_tx_lane(&funding_tx, &expected_lane_id, "state funding lane")?;
    require_eq(
        required_str(&report, "/funding/observed_lane_id")?,
        expected_lane_id.as_str(),
        "state funding recorded lane",
    )?;

    let state_update_tx =
        transaction_from_record(&report, "/state_update/raw_tx", verified_hex_records)?;
    *decoded_transactions += 1;
    require_txid(
        &state_update_tx,
        &required_str(&report, "/state_update/txid")?,
        "state update",
    )?;
    require_input_outpoint(
        &state_update_tx,
        0,
        &required_str(&report, "/funding/outpoint")?,
        "state update spends funding",
    )?;
    require_outpoint(
        &required_str(&report, "/state_update/outpoint")?,
        &state_update_tx,
        0,
        "state update outpoint",
    )?;
    require_output_value(
        &state_update_tx,
        0,
        required_u64(&report, "/state_update/value")?,
        "state update value",
    )?;
    require_tx_lane(&state_update_tx, &expected_lane_id, "state update lane")?;
    require_eq(
        required_str(&report, "/state_update/observed_lane_id")?,
        expected_lane_id.as_str(),
        "state update recorded lane",
    )?;

    let native_lane_tx = transaction_from_record(
        &report,
        "/wrong_lane_rejections/native_state_update/attempted_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &native_lane_tx,
        &required_str(
            &report,
            "/wrong_lane_rejections/native_state_update/attempted_txid",
        )?,
        "native-lane rejected state update",
    )?;
    require_input_outpoint(
        &native_lane_tx,
        0,
        &required_str(&report, "/funding/outpoint")?,
        "native-lane rejected state update spends funding",
    )?;
    require_not_eq(
        tx_subnetwork_id_hex(&native_lane_tx),
        expected_lane_id.as_str(),
        "native-lane rejected state update lane",
    )?;
    require_eq(
        required_str(
            &report,
            "/wrong_lane_rejections/native_state_update/observed_lane_id",
        )?,
        tx_subnetwork_id_hex(&native_lane_tx).as_str(),
        "native-lane rejected state update recorded lane",
    )?;
    require_eq(
        required_str(&report, "/wrong_lane_rejections/native_state_update/status")?,
        "rejected",
        "native-lane rejected state update status",
    )?;

    let wrong_user_lane_tx = transaction_from_record(
        &report,
        "/wrong_lane_rejections/wrong_user_state_update/attempted_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &wrong_user_lane_tx,
        &required_str(
            &report,
            "/wrong_lane_rejections/wrong_user_state_update/attempted_txid",
        )?,
        "wrong-user-lane rejected state update",
    )?;
    require_input_outpoint(
        &wrong_user_lane_tx,
        0,
        &required_str(&report, "/funding/outpoint")?,
        "wrong-user-lane rejected state update spends funding",
    )?;
    require_not_eq(
        tx_subnetwork_id_hex(&wrong_user_lane_tx),
        expected_lane_id.as_str(),
        "wrong-user-lane rejected state update lane",
    )?;
    require_eq(
        required_str(
            &report,
            "/wrong_lane_rejections/wrong_user_state_update/observed_lane_id",
        )?,
        tx_subnetwork_id_hex(&wrong_user_lane_tx).as_str(),
        "wrong-user-lane rejected state update recorded lane",
    )?;
    require_eq(
        required_str(
            &report,
            "/wrong_lane_rejections/wrong_user_state_update/status",
        )?,
        "rejected",
        "wrong-user-lane rejected state update status",
    )?;

    let native_lane_settlement_tx = transaction_from_record(
        &report,
        "/wrong_lane_rejections/native_settlement/attempted_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &native_lane_settlement_tx,
        &required_str(
            &report,
            "/wrong_lane_rejections/native_settlement/attempted_txid",
        )?,
        "native-lane rejected settlement",
    )?;
    require_input_outpoint(
        &native_lane_settlement_tx,
        0,
        &required_str(&report, "/state_update/outpoint")?,
        "native-lane rejected settlement spends latest state output",
    )?;
    require_output_value(
        &native_lane_settlement_tx,
        0,
        required_u64(&report, "/settlement/outputs/alice")?,
        "native-lane rejected settlement Alice output",
    )?;
    require_output_value(
        &native_lane_settlement_tx,
        1,
        required_u64(&report, "/settlement/outputs/bob")?,
        "native-lane rejected settlement Bob output",
    )?;
    require_not_eq(
        tx_subnetwork_id_hex(&native_lane_settlement_tx),
        expected_lane_id.as_str(),
        "native-lane rejected settlement lane",
    )?;
    require_eq(
        required_str(
            &report,
            "/wrong_lane_rejections/native_settlement/observed_lane_id",
        )?,
        tx_subnetwork_id_hex(&native_lane_settlement_tx).as_str(),
        "native-lane rejected settlement recorded lane",
    )?;
    require_eq(
        required_str(&report, "/wrong_lane_rejections/native_settlement/status")?,
        "rejected",
        "native-lane rejected settlement status",
    )?;

    let wrong_user_lane_settlement_tx = transaction_from_record(
        &report,
        "/wrong_lane_rejections/wrong_user_settlement/attempted_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &wrong_user_lane_settlement_tx,
        &required_str(
            &report,
            "/wrong_lane_rejections/wrong_user_settlement/attempted_txid",
        )?,
        "wrong-user-lane rejected settlement",
    )?;
    require_input_outpoint(
        &wrong_user_lane_settlement_tx,
        0,
        &required_str(&report, "/state_update/outpoint")?,
        "wrong-user-lane rejected settlement spends latest state output",
    )?;
    require_output_value(
        &wrong_user_lane_settlement_tx,
        0,
        required_u64(&report, "/settlement/outputs/alice")?,
        "wrong-user-lane rejected settlement Alice output",
    )?;
    require_output_value(
        &wrong_user_lane_settlement_tx,
        1,
        required_u64(&report, "/settlement/outputs/bob")?,
        "wrong-user-lane rejected settlement Bob output",
    )?;
    require_not_eq(
        tx_subnetwork_id_hex(&wrong_user_lane_settlement_tx),
        expected_lane_id.as_str(),
        "wrong-user-lane rejected settlement lane",
    )?;
    require_eq(
        required_str(
            &report,
            "/wrong_lane_rejections/wrong_user_settlement/observed_lane_id",
        )?,
        tx_subnetwork_id_hex(&wrong_user_lane_settlement_tx).as_str(),
        "wrong-user-lane rejected settlement recorded lane",
    )?;
    require_eq(
        required_str(
            &report,
            "/wrong_lane_rejections/wrong_user_settlement/status",
        )?,
        "rejected",
        "wrong-user-lane rejected settlement status",
    )?;

    let stale_tx = transaction_from_record(
        &report,
        "/stale_state_rejection/attempted_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &stale_tx,
        &required_str(&report, "/stale_state_rejection/attempted_txid")?,
        "stale state attempt",
    )?;
    require_input_outpoint(
        &stale_tx,
        0,
        &required_str(&report, "/state_update/outpoint")?,
        "stale state attempt spends latest state output",
    )?;
    require_eq(
        required_str(&report, "/stale_state_rejection/status")?,
        "rejected",
        "stale state rejection status",
    )?;
    require_tx_lane(&stale_tx, &expected_lane_id, "stale attempt lane")?;
    require_eq(
        required_str(&report, "/stale_state_rejection/observed_lane_id")?,
        expected_lane_id.as_str(),
        "stale attempt recorded lane",
    )?;

    let settlement_tx =
        transaction_from_record(&report, "/settlement/raw_tx", verified_hex_records)?;
    *decoded_transactions += 1;
    require_txid(
        &settlement_tx,
        &required_str(&report, "/settlement/txid")?,
        "state settlement",
    )?;
    require_input_outpoint(
        &settlement_tx,
        0,
        &required_str(&report, "/state_update/outpoint")?,
        "settlement spends latest state output",
    )?;
    require_output_value(
        &settlement_tx,
        0,
        required_u64(&report, "/settlement/outputs/alice")?,
        "settlement Alice output",
    )?;
    require_output_value(
        &settlement_tx,
        1,
        required_u64(&report, "/settlement/outputs/bob")?,
        "settlement Bob output",
    )?;
    require_tx_lane(&settlement_tx, &expected_lane_id, "state settlement lane")?;
    require_eq(
        required_str(&report, "/settlement/observed_lane_id")?,
        expected_lane_id.as_str(),
        "state settlement recorded lane",
    )?;
    require_eq(
        required_str(&report, "/model_validation/funding_state/funding_outpoint")?,
        &required_str(&report, "/funding/outpoint")?,
        "state model funding outpoint",
    )?;
    require_eq(
        required_str(
            &report,
            "/model_validation/latest_state_header/funding_outpoint",
        )?,
        &required_str(&report, "/funding/outpoint")?,
        "state model latest header funding outpoint",
    )?;
    require_eq(
        required_str(&report, "/model_validation/funding_state/expected_lane_id")?,
        expected_lane_id.as_str(),
        "state model funding lane",
    )?;
    require_eq(
        required_str(
            &report,
            "/model_validation/latest_state_header/expected_lane_id",
        )?,
        expected_lane_id.as_str(),
        "state model latest header lane",
    )?;
    require_eq(
        required_str(&report, "/model_validation/receipt/output_id")?,
        &format!("{}:0,{}:1", settlement_tx.id(), settlement_tx.id()),
        "state model receipt output id",
    )?;
    require_eq(
        required_str(&report, "/state_header/header/script_covenant_hash")?,
        &required_str(&report, "/settlement/state_2_redeem_script/sha256")?,
        "state header script covenant hash",
    )?;
    require_eq(
        required_str(
            &report,
            "/model_validation/settlement_template/script_covenant_hash",
        )?,
        &required_str(&report, "/settlement/state_2_redeem_script/sha256")?,
        "state model script covenant hash",
    )?;

    for pointer in [
        "/state_update/witness",
        "/stale_state_rejection/witness",
        "/settlement/witness",
        "/settlement/state_1_redeem_script",
        "/settlement/state_2_redeem_script",
    ] {
        verify_hex_record_hash(&required_value(&report, pointer)?, verified_hex_records)?;
    }
    checks.push(json!({
        "id": "state_channel_transactions",
        "status": "passed",
        "details": "funding, update, wrong-lane rejections, stale rejection, and settlement transactions decode and match recorded txids, outpoints, values, lane ids, rejection status, JSON hashes, and typed state-model bindings"
    }));
    Ok(())
}

fn verify_lane_monitor_semantics(output_dir: &Path, checks: &mut Vec<Value>) -> Result<(), String> {
    let state = read_json(&output_dir.join("kurrent-live-state-channel-evidence.json"))?;
    let report = read_json(&output_dir.join("kurrent-live-lane-monitor-evidence.json"))?;
    require_status(&report, "lane monitor evidence")?;

    let expected_lane_id = required_str(&report, "/expected_lane_id")?;
    require_eq(
        expected_lane_id.as_str(),
        &required_str(&state, "/lane_binding/expected_lane_id")?,
        "lane monitor expected lane matches state evidence",
    )?;
    let lane_bytes = lane_id_bytes(&expected_lane_id, "lane monitor expected lane id")?;
    let expected_lane_key = lane_key(&lane_bytes);
    require_eq(
        required_str(&report, "/lane_key")?,
        expected_lane_key.to_string().as_str(),
        "lane monitor lane key",
    )?;

    let expected_txids = [
        ("funding", required_str(&state, "/funding/txid")?),
        ("state_update", required_str(&state, "/state_update/txid")?),
        ("settlement", required_str(&state, "/settlement/txid")?),
    ];
    let mut observed_positions = BTreeMap::new();
    for event in required_array(&report, "/lane_events")? {
        require_eq(
            required_str(event, "/lane_id")?,
            expected_lane_id.as_str(),
            "lane monitor event lane id",
        )?;
        observed_positions.insert(
            required_str(event, "/txid")?,
            required_u64(event, "/accepted_order_index")?,
        );
    }
    let mut previous_position = None;
    for (kind, txid) in expected_txids {
        let position = observed_positions
            .get(&txid)
            .ok_or_else(|| format!("lane monitor missing expected {kind} txid {txid}"))?;
        if let Some(previous) = previous_position {
            if *position <= previous {
                return Err(
                    "lane monitor expected events are not in funding < update < settlement order"
                        .to_string(),
                );
            }
        }
        previous_position = Some(*position);
    }

    for record in required_array(&report, "/wrong_lane_absence")? {
        if !required_bool(record, "/absent_from_accepted_activity")? {
            return Err(
                "wrong-lane rejected transaction appeared in accepted activity".to_string(),
            );
        }
        let txid = required_str(record, "/txid")?;
        if observed_positions.contains_key(&txid) {
            return Err(format!(
                "wrong-lane transaction {txid} appeared as a lane event"
            ));
        }
    }

    let mut reconstructed_tip = None;
    let mut reconstructed_blue_score = None;
    for block in required_array(&report, "/lane_activity_blocks")? {
        let parent_seq_commit = required_hash(block, "/parent_seq_commit")?;
        let timestamp = required_u64(block, "/timestamp")?;
        let daa_score = required_u64(block, "/daa_score")?;
        let blue_score = required_u64(block, "/blue_score")?;
        let accepted_order_start = required_u64(block, "/accepted_order_start")?;
        let context_hash = mergeset_context_hash(&MergesetContext {
            timestamp,
            daa_score,
            blue_score,
        });
        let mut leaves = Vec::new();
        for event in required_array(block, "/events")? {
            require_eq(
                required_str(event, "/lane_id")?,
                expected_lane_id.as_str(),
                "lane monitor block event lane id",
            )?;
            let txid = required_hash(event, "/txid")?;
            let version = required_u64(event, "/version")?;
            let merge_index = required_u64(event, "/merge_index")?;
            let accepted_order_index = required_u64(event, "/accepted_order_index")?;
            if accepted_order_index != accepted_order_start + merge_index {
                return Err(format!(
                    "lane monitor accepted-order index mismatch: expected {}, actual {accepted_order_index}",
                    accepted_order_start + merge_index
                ));
            }
            let version = u16::try_from(version)
                .map_err(|_| format!("lane monitor tx version {version} does not fit u16"))?;
            let merge_index = u32::try_from(merge_index)
                .map_err(|_| format!("lane monitor merge index {merge_index} does not fit u32"))?;
            let computed_leaf = activity_leaf(&txid, version, merge_index);
            require_eq(
                computed_leaf.to_string(),
                required_str(event, "/activity_leaf")?.as_str(),
                "lane monitor activity leaf",
            )?;
            leaves.push(computed_leaf);
        }
        if leaves.is_empty() {
            return Err("lane monitor activity block contains no events".to_string());
        }
        let activity_digest = activity_digest_lane(leaves.iter().copied());
        require_eq(
            activity_digest.to_string(),
            required_str(block, "/activity_digest")?.as_str(),
            "lane monitor activity digest",
        )?;
        let parent_ref = reconstructed_tip.unwrap_or(parent_seq_commit);
        let next_tip = lane_tip_next(&LaneTipInput {
            parent_ref: &parent_ref,
            lane_key: &expected_lane_key,
            activity_digest: &activity_digest,
            context_hash: &context_hash,
        });
        require_eq(
            next_tip.to_string(),
            required_str(block, "/lane_tip_after_block")?.as_str(),
            "lane monitor reconstructed lane tip",
        )?;
        reconstructed_tip = Some(next_tip);
        reconstructed_blue_score = Some(blue_score);
    }

    let proof_lane_tip = required_hash(&report, "/proof/lane/tip")?;
    let proof_lane_blue_score = required_u64(&report, "/proof/lane/blue_score")?;
    if Some(proof_lane_tip) != reconstructed_tip {
        return Err(format!(
            "lane monitor proof tip does not match reconstructed activity tip: proof {proof_lane_tip}, reconstructed {reconstructed_tip:?}"
        ));
    }
    if Some(proof_lane_blue_score) != reconstructed_blue_score {
        return Err(format!(
            "lane monitor proof blue score does not match reconstructed activity score: proof {proof_lane_blue_score}, reconstructed {reconstructed_blue_score:?}"
        ));
    }

    let smt_proof = hex::decode(required_str(&report, "/proof/smt_proof")?)
        .map_err(|e| format!("lane monitor proof smt_proof is not valid hex: {e}"))?;
    verify_lane_proof_material(LaneProofMaterial {
        lane_key_hash: expected_lane_key,
        lane_tip: proof_lane_tip,
        lane_blue_score: proof_lane_blue_score,
        smt_proof_bytes: &smt_proof,
        payload_and_ctx_digest: required_hash(&report, "/proof/payload_and_ctx_digest")?,
        parent_seq_commit: required_hash(&report, "/proof/parent_seq_commit")?,
        inactivity_shortcut: required_hash(&report, "/proof/inactivity_shortcut")?,
        accepted_id_merkle_root: required_hash(&report, "/proof_header/accepted_id_merkle_root")?,
    })?;

    checks.push(json!({
        "id": "kip21_lane_monitor_evidence",
        "status": "passed",
        "details": "KIP-21 lane proof verifies against the recorded selected-parent accepted_id_merkle_root, and lane activity reconstructs funding < update < settlement order for the bound Kurrent lane"
    }));
    Ok(())
}

fn verify_settlement_eligibility_semantics(
    output_dir: &Path,
    checks: &mut Vec<Value>,
    decoded_transactions: &mut u64,
    verified_hex_records: &mut u64,
) -> Result<(), String> {
    let state = read_json(&output_dir.join("kurrent-live-state-channel-evidence.json"))?;
    let report = read_json(&output_dir.join("kurrent-live-settlement-eligibility-evidence.json"))?;
    require_status(&report, "settlement eligibility evidence")?;

    let expected_lane_id = required_str(&report, "/expected_lane_id")?;
    require_eq(
        expected_lane_id.as_str(),
        &required_str(&state, "/lane_binding/expected_lane_id")?,
        "settlement eligibility expected lane matches state evidence",
    )?;
    let lane_bytes = lane_id_bytes(&expected_lane_id, "settlement eligibility lane id")?;
    let expected_lane_key = lane_key(&lane_bytes);
    require_eq(
        required_str(&report, "/lane_key")?,
        expected_lane_key.to_string().as_str(),
        "settlement eligibility lane key",
    )?;

    let lower_tx = transaction_from_record(
        &report,
        "/candidate_markers/lower/raw_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &lower_tx,
        &required_str(&report, "/candidate_markers/lower/txid")?,
        "lower settlement candidate marker",
    )?;
    require_tx_lane(
        &lower_tx,
        &expected_lane_id,
        "lower settlement candidate marker lane",
    )?;
    require_marker_payload(
        &lower_tx,
        &report,
        "/candidate_markers/lower",
        "lower settlement candidate marker",
    )?;

    let higher_tx = transaction_from_record(
        &report,
        "/candidate_markers/higher/raw_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &higher_tx,
        &required_str(&report, "/candidate_markers/higher/txid")?,
        "higher settlement candidate marker",
    )?;
    require_tx_lane(
        &higher_tx,
        &expected_lane_id,
        "higher settlement candidate marker lane",
    )?;
    require_marker_payload(
        &higher_tx,
        &report,
        "/candidate_markers/higher",
        "higher settlement candidate marker",
    )?;

    let wrong_lane_tx = transaction_from_record(
        &report,
        "/candidate_markers/wrong_lane/raw_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &wrong_lane_tx,
        &required_str(&report, "/candidate_markers/wrong_lane/txid")?,
        "wrong-lane settlement candidate marker",
    )?;
    require_not_eq(
        tx_subnetwork_id_hex(&wrong_lane_tx),
        expected_lane_id.as_str(),
        "wrong-lane settlement candidate marker lane",
    )?;
    require_eq(
        required_str(&report, "/candidate_markers/wrong_lane/status")?,
        "ignored_wrong_lane",
        "wrong-lane settlement candidate marker status",
    )?;
    require_marker_payload(
        &wrong_lane_tx,
        &report,
        "/candidate_markers/wrong_lane",
        "wrong-lane settlement candidate marker",
    )?;
    if !required_bool(
        &report,
        "/candidate_markers/wrong_lane/absent_from_expected_lane_activity",
    )? {
        return Err(
            "wrong-lane settlement candidate marker appeared in expected-lane activity".to_string(),
        );
    }
    require_eq(
        required_str(
            &report,
            "/candidate_markers/wrong_lane/accepted_observation/lane_id",
        )?,
        tx_subnetwork_id_hex(&wrong_lane_tx).as_str(),
        "wrong-lane settlement candidate accepted observation lane",
    )?;

    let mut event_by_txid = BTreeMap::new();
    for event in required_array(&report, "/lane_events")? {
        require_eq(
            required_str(event, "/lane_id")?,
            expected_lane_id.as_str(),
            "settlement eligibility lane event lane id",
        )?;
        event_by_txid.insert(required_str(event, "/txid")?, event.clone());
    }
    let lower_txid = lower_tx.id().to_string();
    let higher_txid = higher_tx.id().to_string();
    let lower_event = event_by_txid
        .get(&lower_txid)
        .ok_or_else(|| "missing lower marker from expected-lane events".to_string())?;
    let higher_event = event_by_txid
        .get(&higher_txid)
        .ok_or_else(|| "missing higher marker from expected-lane events".to_string())?;
    require_value_eq(
        &required_value(&report, "/candidate_markers/lower/accepted_event")?,
        lower_event,
        "lower marker accepted event",
    )?;
    require_value_eq(
        &required_value(&report, "/candidate_markers/higher/accepted_event")?,
        higher_event,
        "higher marker accepted event",
    )?;
    let lower_order = required_u64(lower_event, "/accepted_order_index")?;
    let higher_order = required_u64(higher_event, "/accepted_order_index")?;
    if lower_order >= higher_order {
        return Err("settlement eligibility lower marker must precede higher marker".to_string());
    }

    let policy: SettlementEligibilityPolicy = required_typed(&report, "/policy")?;
    let lower_daa = required_u64(lower_event, "/daa_score")?;
    let higher_daa = required_u64(higher_event, "/daa_score")?;
    let lower_deadline = lower_daa
        .checked_add(policy.response_window_daa)
        .ok_or_else(|| "settlement eligibility lower response-window overflow".to_string())?;
    if higher_daa > lower_deadline {
        return Err(format!(
            "higher marker DAA {higher_daa} is outside lower response window ending at {lower_deadline}"
        ));
    }
    let survivor_deadline = higher_daa
        .checked_add(policy.response_window_daa)
        .ok_or_else(|| "settlement eligibility survivor response-window overflow".to_string())?;
    let proof_daa = required_u64(&report, "/proof_header/daa_score")?;
    if proof_daa < survivor_deadline {
        return Err(format!(
            "proof DAA {proof_daa} is before survivor eligibility threshold {survivor_deadline}"
        ));
    }

    let config: KurrentChannelConfig = required_typed(&report, "/model_validation/config")?;
    let funding: FundingState = required_typed(&report, "/model_validation/funding")?;
    let template: SettlementTemplate =
        required_typed(&report, "/model_validation/settlement_template")?;
    let candidates: Vec<SettlementEligibilityCandidate> =
        required_typed(&report, "/model_validation/candidates")?;
    let recorded_decisions: Vec<SettlementEligibilityDecision> =
        required_typed(&report, "/model_validation/decisions")?;
    let current_daa = required_u64(&report, "/model_validation/current_daa")?;
    require_eq(
        current_daa.to_string(),
        proof_daa.to_string().as_str(),
        "settlement eligibility current DAA",
    )?;
    let recomputed_decisions = evaluate_settlement_eligibility(
        &config,
        &funding,
        &template,
        &policy,
        &candidates,
        current_daa,
    )
    .map_err(|err| format!("settlement eligibility typed re-evaluation failed: {err:?}"))?;
    if recomputed_decisions != recorded_decisions {
        return Err(
            "settlement eligibility decisions do not match typed re-evaluation".to_string(),
        );
    }
    require_decision_status(
        &recorded_decisions,
        1,
        SettlementEligibilityStatus::Displaced,
    )?;
    require_decision_status(
        &recorded_decisions,
        2,
        SettlementEligibilityStatus::EligibleToFinalise,
    )?;

    let mut reconstructed_tip = match report.pointer("/initial_lane") {
        Some(Value::Null) | None => None,
        Some(_) => Some(required_hash(&report, "/initial_lane/tip")?),
    };
    let mut reconstructed_blue_score = match report.pointer("/initial_lane") {
        Some(Value::Null) | None => None,
        Some(_) => Some(required_u64(&report, "/initial_lane/blue_score")?),
    };
    for block in required_array(&report, "/lane_activity_blocks")? {
        let parent_seq_commit = required_hash(block, "/parent_seq_commit")?;
        let timestamp = required_u64(block, "/timestamp")?;
        let daa_score = required_u64(block, "/daa_score")?;
        let blue_score = required_u64(block, "/blue_score")?;
        let accepted_order_start = required_u64(block, "/accepted_order_start")?;
        let context_hash = mergeset_context_hash(&MergesetContext {
            timestamp,
            daa_score,
            blue_score,
        });
        let mut leaves = Vec::new();
        for event in required_array(block, "/events")? {
            require_eq(
                required_str(event, "/lane_id")?,
                expected_lane_id.as_str(),
                "settlement eligibility block event lane id",
            )?;
            let txid = required_hash(event, "/txid")?;
            let version = required_u64(event, "/version")?;
            let merge_index = required_u64(event, "/merge_index")?;
            let accepted_order_index = required_u64(event, "/accepted_order_index")?;
            let expected_order =
                accepted_order_start
                    .checked_add(merge_index)
                    .ok_or_else(|| {
                        "settlement eligibility accepted-order index overflow".to_string()
                    })?;
            if accepted_order_index != expected_order {
                return Err(format!(
                    "settlement eligibility accepted-order index mismatch: expected {expected_order}, actual {accepted_order_index}"
                ));
            }
            let version = u16::try_from(version).map_err(|_| {
                format!("settlement eligibility tx version {version} does not fit u16")
            })?;
            let merge_index = u32::try_from(merge_index).map_err(|_| {
                format!("settlement eligibility merge index {merge_index} does not fit u32")
            })?;
            let computed_leaf = activity_leaf(&txid, version, merge_index);
            require_eq(
                computed_leaf.to_string(),
                required_str(event, "/activity_leaf")?.as_str(),
                "settlement eligibility activity leaf",
            )?;
            leaves.push(computed_leaf);
        }
        if leaves.is_empty() {
            return Err("settlement eligibility activity block contains no events".to_string());
        }
        let activity_digest = activity_digest_lane(leaves.iter().copied());
        require_eq(
            activity_digest.to_string(),
            required_str(block, "/activity_digest")?.as_str(),
            "settlement eligibility activity digest",
        )?;
        let parent_ref = reconstructed_tip.unwrap_or(parent_seq_commit);
        let next_tip = lane_tip_next(&LaneTipInput {
            parent_ref: &parent_ref,
            lane_key: &expected_lane_key,
            activity_digest: &activity_digest,
            context_hash: &context_hash,
        });
        require_eq(
            next_tip.to_string(),
            required_str(block, "/lane_tip_after_block")?.as_str(),
            "settlement eligibility reconstructed lane tip",
        )?;
        reconstructed_tip = Some(next_tip);
        reconstructed_blue_score = Some(blue_score);
    }

    let proof_lane_tip = required_hash(&report, "/proof/lane/tip")?;
    let proof_lane_blue_score = required_u64(&report, "/proof/lane/blue_score")?;
    if Some(proof_lane_tip) != reconstructed_tip {
        return Err(format!(
            "settlement eligibility proof tip does not match reconstructed activity tip: proof {proof_lane_tip}, reconstructed {reconstructed_tip:?}"
        ));
    }
    if Some(proof_lane_blue_score) != reconstructed_blue_score {
        return Err(format!(
            "settlement eligibility proof blue score does not match reconstructed activity score: proof {proof_lane_blue_score}, reconstructed {reconstructed_blue_score:?}"
        ));
    }
    let smt_proof = hex::decode(required_str(&report, "/proof/smt_proof")?)
        .map_err(|e| format!("settlement eligibility smt_proof is not valid hex: {e}"))?;
    verify_lane_proof_material(LaneProofMaterial {
        lane_key_hash: expected_lane_key,
        lane_tip: proof_lane_tip,
        lane_blue_score: proof_lane_blue_score,
        smt_proof_bytes: &smt_proof,
        payload_and_ctx_digest: required_hash(&report, "/proof/payload_and_ctx_digest")?,
        parent_seq_commit: required_hash(&report, "/proof/parent_seq_commit")?,
        inactivity_shortcut: required_hash(&report, "/proof/inactivity_shortcut")?,
        accepted_id_merkle_root: required_hash(&report, "/proof_header/accepted_id_merkle_root")?,
    })?;

    checks.push(json!({
        "id": "settlement_eligibility_evidence",
        "status": "passed",
        "details": "lane-proven candidate markers decode, lower candidate is displaced within the response window, and the higher candidate is eligible-to-finalise under the local-devnet DAA policy"
    }));
    Ok(())
}

fn verify_fee_sponsored_displacement_semantics(
    output_dir: &Path,
    checks: &mut Vec<Value>,
    decoded_transactions: &mut u64,
    verified_hex_records: &mut u64,
) -> Result<(), String> {
    let state = read_json(&output_dir.join("kurrent-live-state-channel-evidence.json"))?;
    let report =
        read_json(&output_dir.join("kurrent-live-fee-sponsored-displacement-evidence.json"))?;
    require_status(&report, "fee-sponsored displacement evidence")?;

    let expected_lane_id = required_str(&report, "/expected_lane_id")?;
    require_eq(
        expected_lane_id.as_str(),
        &required_str(&state, "/lane_binding/expected_lane_id")?,
        "fee-sponsored expected lane matches state evidence",
    )?;
    let lane_bytes = lane_id_bytes(&expected_lane_id, "fee-sponsored lane id")?;
    let expected_lane_key = lane_key(&lane_bytes);
    require_eq(
        required_str(&report, "/lane_key")?,
        expected_lane_key.to_string().as_str(),
        "fee-sponsored lane key",
    )?;

    let fee_policy: SettlementFeePolicy = required_typed(&report, "/fee_policy")?;
    let fee_policy_hash = fee_policy.hash();
    require_eq(
        required_str(&report, "/fee_policy_hash")?,
        fee_policy_hash.as_str(),
        "fee-sponsored fee-policy hash",
    )?;

    let lower_tx = transaction_from_record(
        &report,
        "/sponsored_markers/lower/raw_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &lower_tx,
        &required_str(&report, "/sponsored_markers/lower/txid")?,
        "lower fee-sponsored marker",
    )?;
    require_tx_lane(
        &lower_tx,
        &expected_lane_id,
        "lower fee-sponsored marker lane",
    )?;
    require_marker_payload(
        &lower_tx,
        &report,
        "/sponsored_markers/lower",
        "lower fee-sponsored marker",
    )?;

    let higher_tx = transaction_from_record(
        &report,
        "/sponsored_markers/higher/raw_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &higher_tx,
        &required_str(&report, "/sponsored_markers/higher/txid")?,
        "higher fee-sponsored marker",
    )?;
    require_tx_lane(
        &higher_tx,
        &expected_lane_id,
        "higher fee-sponsored marker lane",
    )?;
    require_marker_payload(
        &higher_tx,
        &report,
        "/sponsored_markers/higher",
        "higher fee-sponsored marker",
    )?;

    let channel_funding_outpoint = required_str(&state, "/funding/outpoint")?;
    require_sponsor_accounting(
        &lower_tx,
        &report,
        "/sponsored_markers/lower",
        &channel_funding_outpoint,
        "lower fee-sponsored marker",
    )?;
    require_sponsor_accounting(
        &higher_tx,
        &report,
        "/sponsored_markers/higher",
        &channel_funding_outpoint,
        "higher fee-sponsored marker",
    )?;
    let lower_fee = required_u64(&report, "/sponsored_markers/lower/sponsor/sponsor_fee")?;
    let higher_fee = required_u64(&report, "/sponsored_markers/higher/sponsor/sponsor_fee")?;
    if lower_fee <= higher_fee {
        return Err(
            "fee independence check requires lower stale marker fee > higher survivor marker fee"
                .to_string(),
        );
    }

    let mut event_by_txid = BTreeMap::new();
    for event in required_array(&report, "/lane_events")? {
        require_eq(
            required_str(event, "/lane_id")?,
            expected_lane_id.as_str(),
            "fee-sponsored lane event lane id",
        )?;
        event_by_txid.insert(required_str(event, "/txid")?, event.clone());
    }
    let lower_txid = lower_tx.id().to_string();
    let higher_txid = higher_tx.id().to_string();
    let lower_event = event_by_txid
        .get(&lower_txid)
        .ok_or_else(|| "missing lower fee-sponsored marker from lane events".to_string())?;
    let higher_event = event_by_txid
        .get(&higher_txid)
        .ok_or_else(|| "missing higher fee-sponsored marker from lane events".to_string())?;
    require_value_eq(
        &required_value(&report, "/sponsored_markers/lower/accepted_event")?,
        lower_event,
        "lower fee-sponsored accepted event",
    )?;
    require_value_eq(
        &required_value(&report, "/sponsored_markers/higher/accepted_event")?,
        higher_event,
        "higher fee-sponsored accepted event",
    )?;
    let lower_order = required_u64(lower_event, "/accepted_order_index")?;
    let higher_order = required_u64(higher_event, "/accepted_order_index")?;
    if lower_order >= higher_order {
        return Err("fee-sponsored lower marker must precede higher marker".to_string());
    }

    let eligibility_policy: SettlementEligibilityPolicy =
        required_typed(&report, "/eligibility_policy")?;
    let lower_daa = required_u64(lower_event, "/daa_score")?;
    let higher_daa = required_u64(higher_event, "/daa_score")?;
    let lower_deadline = lower_daa
        .checked_add(eligibility_policy.response_window_daa)
        .ok_or_else(|| "fee-sponsored lower response-window overflow".to_string())?;
    if higher_daa > lower_deadline {
        return Err(format!(
            "fee-sponsored higher marker DAA {higher_daa} is outside lower response window ending at {lower_deadline}"
        ));
    }
    let survivor_deadline = higher_daa
        .checked_add(eligibility_policy.response_window_daa)
        .ok_or_else(|| "fee-sponsored survivor response-window overflow".to_string())?;
    let proof_daa = required_u64(&report, "/proof_header/daa_score")?;
    if proof_daa < survivor_deadline {
        return Err(format!(
            "fee-sponsored proof DAA {proof_daa} is before survivor eligibility threshold {survivor_deadline}"
        ));
    }

    let config: KurrentChannelConfig = required_typed(&report, "/model_validation/config")?;
    let funding: FundingState = required_typed(&report, "/model_validation/funding")?;
    let template: SettlementTemplate =
        required_typed(&report, "/model_validation/settlement_template")?;
    let distribution_hash = settlement_distribution_hash(&template);
    require_eq(
        required_str(&report, "/settlement_distribution_hash")?,
        distribution_hash.as_str(),
        "fee-sponsored settlement-distribution hash",
    )?;
    for marker in ["lower", "higher"] {
        let payload_pointer = format!("/sponsored_markers/{marker}/payload");
        let payload = required_value(&report, &payload_pointer)?;
        require_eq(
            required_str(&payload, "/fee_policy_hash")?,
            fee_policy_hash.as_str(),
            &format!("{marker} marker payload fee-policy hash"),
        )?;
        require_eq(
            required_str(&payload, "/settlement_distribution_hash")?,
            distribution_hash.as_str(),
            &format!("{marker} marker payload distribution hash"),
        )?;
        require_eq(
            required_str(&payload, "/settlement_template_hash")?,
            template.hash().as_str(),
            &format!("{marker} marker payload template hash"),
        )?;
    }

    let candidates: Vec<FeeSponsoredSettlementCandidate> =
        required_typed(&report, "/model_validation/candidates")?;
    let recorded_decisions: Vec<FeeSponsoredSettlementDecision> =
        required_typed(&report, "/model_validation/decisions")?;
    let current_daa = required_u64(&report, "/model_validation/current_daa")?;
    require_eq(
        current_daa.to_string(),
        proof_daa.to_string().as_str(),
        "fee-sponsored current DAA",
    )?;
    let recomputed_decisions = evaluate_fee_sponsored_settlement_eligibility(
        &config,
        &funding,
        &template,
        &eligibility_policy,
        &fee_policy,
        &candidates,
        current_daa,
    )
    .map_err(|err| format!("fee-sponsored typed re-evaluation failed: {err:?}"))?;
    if recomputed_decisions != recorded_decisions {
        return Err("fee-sponsored decisions do not match typed re-evaluation".to_string());
    }
    require_fee_sponsored_decision_status(
        &recorded_decisions,
        1,
        SettlementEligibilityStatus::Displaced,
    )?;
    require_fee_sponsored_decision_status(
        &recorded_decisions,
        2,
        SettlementEligibilityStatus::EligibleToFinalise,
    )?;

    let mut reconstructed_tip = match report.pointer("/initial_lane") {
        Some(Value::Null) | None => None,
        Some(_) => Some(required_hash(&report, "/initial_lane/tip")?),
    };
    let mut reconstructed_blue_score = match report.pointer("/initial_lane") {
        Some(Value::Null) | None => None,
        Some(_) => Some(required_u64(&report, "/initial_lane/blue_score")?),
    };
    for block in required_array(&report, "/lane_activity_blocks")? {
        let parent_seq_commit = required_hash(block, "/parent_seq_commit")?;
        let timestamp = required_u64(block, "/timestamp")?;
        let daa_score = required_u64(block, "/daa_score")?;
        let blue_score = required_u64(block, "/blue_score")?;
        let accepted_order_start = required_u64(block, "/accepted_order_start")?;
        let context_hash = mergeset_context_hash(&MergesetContext {
            timestamp,
            daa_score,
            blue_score,
        });
        let mut leaves = Vec::new();
        for event in required_array(block, "/events")? {
            require_eq(
                required_str(event, "/lane_id")?,
                expected_lane_id.as_str(),
                "fee-sponsored block event lane id",
            )?;
            let txid = required_hash(event, "/txid")?;
            let version = required_u64(event, "/version")?;
            let merge_index = required_u64(event, "/merge_index")?;
            let accepted_order_index = required_u64(event, "/accepted_order_index")?;
            let expected_order = accepted_order_start
                .checked_add(merge_index)
                .ok_or_else(|| "fee-sponsored accepted-order index overflow".to_string())?;
            if accepted_order_index != expected_order {
                return Err(format!(
                    "fee-sponsored accepted-order index mismatch: expected {expected_order}, actual {accepted_order_index}"
                ));
            }
            let version = u16::try_from(version)
                .map_err(|_| format!("fee-sponsored tx version {version} does not fit u16"))?;
            let merge_index = u32::try_from(merge_index)
                .map_err(|_| format!("fee-sponsored merge index {merge_index} does not fit u32"))?;
            let computed_leaf = activity_leaf(&txid, version, merge_index);
            require_eq(
                computed_leaf.to_string(),
                required_str(event, "/activity_leaf")?.as_str(),
                "fee-sponsored activity leaf",
            )?;
            leaves.push(computed_leaf);
        }
        if leaves.is_empty() {
            return Err("fee-sponsored activity block contains no events".to_string());
        }
        let activity_digest = activity_digest_lane(leaves.iter().copied());
        require_eq(
            activity_digest.to_string(),
            required_str(block, "/activity_digest")?.as_str(),
            "fee-sponsored activity digest",
        )?;
        let parent_ref = reconstructed_tip.unwrap_or(parent_seq_commit);
        let next_tip = lane_tip_next(&LaneTipInput {
            parent_ref: &parent_ref,
            lane_key: &expected_lane_key,
            activity_digest: &activity_digest,
            context_hash: &context_hash,
        });
        require_eq(
            next_tip.to_string(),
            required_str(block, "/lane_tip_after_block")?.as_str(),
            "fee-sponsored reconstructed lane tip",
        )?;
        reconstructed_tip = Some(next_tip);
        reconstructed_blue_score = Some(blue_score);
    }

    let proof_lane_tip = required_hash(&report, "/proof/lane/tip")?;
    let proof_lane_blue_score = required_u64(&report, "/proof/lane/blue_score")?;
    if Some(proof_lane_tip) != reconstructed_tip {
        return Err(format!(
            "fee-sponsored proof tip does not match reconstructed activity tip: proof {proof_lane_tip}, reconstructed {reconstructed_tip:?}"
        ));
    }
    if Some(proof_lane_blue_score) != reconstructed_blue_score {
        return Err(format!(
            "fee-sponsored proof blue score does not match reconstructed activity score: proof {proof_lane_blue_score}, reconstructed {reconstructed_blue_score:?}"
        ));
    }
    let smt_proof = hex::decode(required_str(&report, "/proof/smt_proof")?)
        .map_err(|e| format!("fee-sponsored smt_proof is not valid hex: {e}"))?;
    verify_lane_proof_material(LaneProofMaterial {
        lane_key_hash: expected_lane_key,
        lane_tip: proof_lane_tip,
        lane_blue_score: proof_lane_blue_score,
        smt_proof_bytes: &smt_proof,
        payload_and_ctx_digest: required_hash(&report, "/proof/payload_and_ctx_digest")?,
        parent_seq_commit: required_hash(&report, "/proof/parent_seq_commit")?,
        inactivity_shortcut: required_hash(&report, "/proof/inactivity_shortcut")?,
        accepted_id_merkle_root: required_hash(&report, "/proof_header/accepted_id_merkle_root")?,
    })?;

    checks.push(json!({
        "id": "fee_sponsored_displacement_evidence",
        "status": "passed",
        "details": "sponsored marker fee accounting is bound to the signed fee policy, the stale lower marker pays a higher sponsor fee, and lane-proven latest-state semantics still select the higher survivor"
    }));
    Ok(())
}

fn verify_factory_semantics(
    output_dir: &Path,
    checks: &mut Vec<Value>,
    decoded_transactions: &mut u64,
    verified_hex_records: &mut u64,
) -> Result<(), String> {
    let report = read_json(&output_dir.join("kurrent-live-factory-evidence.json"))?;
    require_status(&report, "factory live evidence")?;
    require_status(
        &required_value(&report, "/model_validation")?,
        "factory model validation",
    )?;
    let funding_tx = transaction_from_record(&report, "/funding/raw_tx", verified_hex_records)?;
    *decoded_transactions += 1;
    require_txid(
        &funding_tx,
        &required_str(&report, "/funding/txid")?,
        "factory funding",
    )?;
    require_outpoint(
        &required_str(&report, "/funding/outpoint")?,
        &funding_tx,
        0,
        "factory funding outpoint",
    )?;

    let materialisation_tx =
        transaction_from_record(&report, "/materialisation/raw_tx", verified_hex_records)?;
    *decoded_transactions += 1;
    require_txid(
        &materialisation_tx,
        &required_str(&report, "/materialisation/txid")?,
        "factory materialisation",
    )?;
    require_input_outpoint(
        &materialisation_tx,
        0,
        &required_str(&report, "/funding/outpoint")?,
        "materialisation spends factory funding",
    )?;
    require_output_count(
        &materialisation_tx,
        2,
        "factory materialisation output count",
    )?;
    require_output_value(
        &materialisation_tx,
        0,
        required_u64(&report, "/materialisation/outputs/alice")?,
        "factory materialisation Alice output",
    )?;
    require_output_value(
        &materialisation_tx,
        1,
        required_u64(&report, "/materialisation/outputs/bob")?,
        "factory materialisation Bob output",
    )?;
    for pointer in ["/materialisation/witness", "/materialisation/redeem_script"] {
        verify_hex_record_hash(&required_value(&report, pointer)?, verified_hex_records)?;
    }
    require_eq(
        required_str(&report, "/model_validation/plan/principal_input_ids/0")?,
        &required_str(&report, "/funding/outpoint")?,
        "factory model funding input binding",
    )?;
    require_eq(
        required_str(&report, "/model_validation/redeem_script_sha256")?,
        &required_str(&report, "/materialisation/redeem_script/sha256")?,
        "factory model redeem script hash",
    )?;
    require_eq(
        required_str(&report, "/model_validation/plan/materialisation_id")?,
        &format!(
            "{}:0,{}:1",
            materialisation_tx.id(),
            materialisation_tx.id()
        ),
        "factory model materialisation output binding",
    )?;
    checks.push(json!({
        "id": "factory_transactions",
        "status": "passed",
        "details": "factory funding and materialisation transactions decode and preserve recorded txid, spend, output semantics, script hash, and typed factory materialisation bindings"
    }));
    Ok(())
}

fn verify_hashlock_semantics(
    output_dir: &Path,
    checks: &mut Vec<Value>,
    decoded_transactions: &mut u64,
    verified_hex_records: &mut u64,
) -> Result<(), String> {
    let ln = read_json(&output_dir.join("ln-devnet-evidence.json"))?;
    require_status(&ln, "LN devnet evidence")?;
    let preimage = hex::decode(required_str(&ln, "/invoice/preimage")?)
        .map_err(|e| format!("LN invoice preimage is not valid hex: {e}"))?;
    let payment_hash = required_str(&ln, "/invoice/payment_hash")?;
    require_eq(
        sha256_hex(&preimage),
        payment_hash.as_str(),
        "LN preimage hashes to payment hash",
    )?;

    for (label, file_name) in [
        ("ln-to-kaspa", "kurrent-live-ln-to-kaspa-evidence.json"),
        ("kaspa-to-ln", "kurrent-live-kaspa-to-ln-evidence.json"),
    ] {
        let report = read_json(&output_dir.join(file_name))?;
        require_status(&report, label)?;
        require_eq(
            required_str(&report, "/preimage_sha256")?,
            payment_hash.as_str(),
            &format!("{label} preimage binding"),
        )?;
        let funding_tx = transaction_from_record(&report, "/funding/raw_tx", verified_hex_records)?;
        *decoded_transactions += 1;
        require_txid(
            &funding_tx,
            &required_str(&report, "/funding/txid")?,
            &format!("{label} funding"),
        )?;
        require_outpoint(
            &required_str(&report, "/funding/outpoint")?,
            &funding_tx,
            0,
            &format!("{label} funding outpoint"),
        )?;

        let settlement_tx =
            transaction_from_record(&report, "/settlement/raw_tx", verified_hex_records)?;
        *decoded_transactions += 1;
        require_txid(
            &settlement_tx,
            &required_str(&report, "/settlement/txid")?,
            &format!("{label} settlement"),
        )?;
        require_input_outpoint(
            &settlement_tx,
            0,
            &required_str(&report, "/funding/outpoint")?,
            &format!("{label} settlement spends hashlock funding"),
        )?;
        require_output_count(
            &settlement_tx,
            1,
            &format!("{label} settlement output count"),
        )?;
        require_output_value(
            &settlement_tx,
            0,
            required_u64(&report, "/settlement/output_value")?,
            &format!("{label} settlement output value"),
        )?;
        for pointer in ["/settlement/witness", "/settlement/redeem_script"] {
            verify_hex_record_hash(&required_value(&report, pointer)?, verified_hex_records)?;
        }
        require_status(
            &required_value(&report, "/model_validation")?,
            &format!("{label} model validation"),
        )?;
        require_eq(
            required_str(&report, "/model_validation/swap_evidence/ln_payment_hash")?,
            payment_hash.as_str(),
            &format!("{label} model payment hash"),
        )?;
        require_eq(
            required_str(
                &report,
                "/model_validation/swap_evidence/kaspa_funding_outpoint",
            )?,
            &required_str(&report, "/funding/outpoint")?,
            &format!("{label} model funding outpoint"),
        )?;
        require_eq(
            required_str(
                &report,
                "/model_validation/swap_evidence/kaspa_settlement_outpoint",
            )?,
            &format!("{}:0", settlement_tx.id()),
            &format!("{label} model settlement outpoint"),
        )?;
        require_eq(
            required_str(&report, "/model_validation/swap_evidence/script_hash")?,
            &required_str(&report, "/settlement/redeem_script/sha256")?,
            &format!("{label} model script hash"),
        )?;
    }
    checks.push(json!({
        "id": "hashlock_transactions",
        "status": "passed",
        "details": "both hashlock directions decode, consume the LN preimage hash, spend their recorded funding outputs, and match typed swap receipt bindings"
    }));
    Ok(())
}

fn verify_refund_semantics(
    output_dir: &Path,
    checks: &mut Vec<Value>,
    decoded_transactions: &mut u64,
    verified_hex_records: &mut u64,
) -> Result<(), String> {
    const REFUND_SEQUENCE: u64 = 120;
    let report = read_json(&output_dir.join("kurrent-live-refund-evidence.json"))?;
    require_status(&report, "refund live evidence")?;
    require_status(
        &required_value(&report, "/model_validation")?,
        "refund model validation",
    )?;
    let funding_tx = transaction_from_record(&report, "/funding/raw_tx", verified_hex_records)?;
    *decoded_transactions += 1;
    require_txid(
        &funding_tx,
        &required_str(&report, "/funding/txid")?,
        "refund funding",
    )?;
    require_outpoint(
        &required_str(&report, "/funding/outpoint")?,
        &funding_tx,
        0,
        "refund funding outpoint",
    )?;

    let early_tx = transaction_from_record(
        &report,
        "/early_refund_rejection/attempted_tx",
        verified_hex_records,
    )?;
    *decoded_transactions += 1;
    require_txid(
        &early_tx,
        &required_str(&report, "/early_refund_rejection/attempted_txid")?,
        "early refund attempt",
    )?;
    require_input_outpoint(
        &early_tx,
        0,
        &required_str(&report, "/funding/outpoint")?,
        "early refund spends refund funding",
    )?;
    require_input_sequence(&early_tx, 0, REFUND_SEQUENCE - 1, "early refund sequence")?;
    require_eq(
        required_str(&report, "/early_refund_rejection/status")?,
        "rejected",
        "early refund rejection status",
    )?;

    let refund_tx = transaction_from_record(&report, "/refund/raw_tx", verified_hex_records)?;
    *decoded_transactions += 1;
    require_txid(
        &refund_tx,
        &required_str(&report, "/refund/txid")?,
        "mature refund",
    )?;
    require_input_outpoint(
        &refund_tx,
        0,
        &required_str(&report, "/funding/outpoint")?,
        "mature refund spends refund funding",
    )?;
    require_input_sequence(&refund_tx, 0, REFUND_SEQUENCE, "mature refund sequence")?;
    require_output_count(&refund_tx, 1, "mature refund output count")?;
    require_output_value(
        &refund_tx,
        0,
        required_u64(&report, "/refund/output_value")?,
        "mature refund output value",
    )?;
    for pointer in [
        "/early_refund_rejection/witness",
        "/refund/witness",
        "/refund/redeem_script",
    ] {
        verify_hex_record_hash(&required_value(&report, pointer)?, verified_hex_records)?;
    }
    require_eq(
        required_str(&report, "/model_validation/claim_scope/funding_outpoint")?,
        &required_str(&report, "/funding/outpoint")?,
        "refund model funding outpoint",
    )?;
    require_eq(
        required_str(&report, "/model_validation/claim_scope/output_id")?,
        &format!("{}:0", refund_tx.id()),
        "refund model output id",
    )?;
    require_eq(
        required_str(&report, "/model_validation/redeem_script_sha256")?,
        &required_str(&report, "/refund/redeem_script/sha256")?,
        "refund model redeem script hash",
    )?;
    checks.push(json!({
        "id": "refund_transactions",
        "status": "passed",
        "details": "early and mature refund transactions decode, spend the recorded funding output, use the expected sequence-lock values, and match typed refund claim bindings"
    }));
    Ok(())
}

fn transaction_from_record(
    report: &Value,
    pointer: &str,
    verified_hex_records: &mut u64,
) -> Result<Transaction, String> {
    let record = required_value(report, pointer)?;
    let bytes = verify_hex_record_hash(&record, verified_hex_records)?;
    borsh::from_slice(&bytes).map_err(|e| format!("failed to decode transaction at {pointer}: {e}"))
}

fn verify_hex_record_hash(
    record: &Value,
    verified_hex_records: &mut u64,
) -> Result<Vec<u8>, String> {
    let path = required_str(record, "/path")?;
    let expected_hash = required_str(record, "/sha256")?;
    let bytes = read_hex_file(&resolve_record_path(&path))?;
    let actual_hash = sha256_hex(&bytes);
    if actual_hash != expected_hash {
        return Err(format!(
            "hex evidence hash mismatch for {path}: expected {expected_hash}, actual {actual_hash}"
        ));
    }
    *verified_hex_records += 1;
    Ok(bytes)
}

fn read_hex_file(path: &Path) -> Result<Vec<u8>, String> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read hex evidence {}: {e}", path.display()))?;
    hex::decode(text.trim())
        .map_err(|e| format!("hex evidence {} is not valid hex: {e}", path.display()))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

fn resolve_record_path(path: &str) -> PathBuf {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    }
}

fn required_value(value: &Value, pointer: &str) -> Result<Value, String> {
    value
        .pointer(pointer)
        .cloned()
        .ok_or_else(|| format!("missing required JSON pointer {pointer} in {value}"))
}

fn required_typed<T: DeserializeOwned>(value: &Value, pointer: &str) -> Result<T, String> {
    serde_json::from_value(required_value(value, pointer)?)
        .map_err(|e| format!("failed to decode typed JSON pointer {pointer}: {e}"))
}

fn required_str(value: &Value, pointer: &str) -> Result<String, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing required string pointer {pointer} in {value}"))
}

fn required_u64(value: &Value, pointer: &str) -> Result<u64, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing required integer pointer {pointer} in {value}"))
}

fn required_bool(value: &Value, pointer: &str) -> Result<bool, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("missing required boolean pointer {pointer} in {value}"))
}

fn required_array<'a>(value: &'a Value, pointer: &str) -> Result<&'a Vec<Value>, String> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("missing required array pointer {pointer} in {value}"))
}

fn required_hash(value: &Value, pointer: &str) -> Result<Hash, String> {
    let text = required_str(value, pointer)?;
    parse_hash(&text, pointer)
}

fn require_status(value: &Value, label: &str) -> Result<(), String> {
    require_eq(
        required_str(value, "/status")?,
        "passed",
        &format!("{label} status"),
    )
}

fn require_json_hash(
    value: &Value,
    domain: &str,
    value_pointer: &str,
    hash_pointer: &str,
    label: &str,
) -> Result<(), String> {
    let payload = required_value(value, value_pointer)?;
    let expected = required_str(value, hash_pointer)?;
    require_eq(hash_json(domain, &payload), expected.as_str(), label)
}

fn require_eq(actual: impl AsRef<str>, expected: &str, label: &str) -> Result<(), String> {
    let actual = actual.as_ref();
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected}, actual {actual}"))
    }
}

fn require_value_eq(actual: &Value, expected: &Value, label: &str) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label}: expected JSON {expected}, actual JSON {actual}"
        ))
    }
}

fn require_not_eq(actual: impl AsRef<str>, forbidden: &str, label: &str) -> Result<(), String> {
    let actual = actual.as_ref();
    if actual == forbidden {
        Err(format!("{label}: value must not be {forbidden}"))
    } else {
        Ok(())
    }
}

fn require_txid(tx: &Transaction, expected: &str, label: &str) -> Result<(), String> {
    require_eq(tx.id().to_string(), expected, label)
}

fn require_tx_lane(tx: &Transaction, expected: &str, label: &str) -> Result<(), String> {
    require_eq(tx_subnetwork_id_hex(tx), expected, label)
}

fn require_marker_payload(
    tx: &Transaction,
    report: &Value,
    marker_pointer: &str,
    label: &str,
) -> Result<(), String> {
    let payload_hash_pointer = format!("{marker_pointer}/payload_hash");
    require_eq(
        sha256_hex(&tx.payload),
        required_str(report, &payload_hash_pointer)?.as_str(),
        &format!("{label} payload hash"),
    )?;
    let payload_pointer = format!("{marker_pointer}/payload");
    let expected_payload = required_value(report, &payload_pointer)?;
    let actual_payload: Value = serde_json::from_slice(&tx.payload)
        .map_err(|e| format!("{label} payload is not valid JSON: {e}"))?;
    require_value_eq(
        &actual_payload,
        &expected_payload,
        &format!("{label} payload"),
    )
}

fn require_decision_status(
    decisions: &[SettlementEligibilityDecision],
    state_number: u64,
    expected: SettlementEligibilityStatus,
) -> Result<(), String> {
    let decision = decisions
        .iter()
        .find(|decision| decision.state_number == state_number)
        .ok_or_else(|| {
            format!("missing settlement eligibility decision for state {state_number}")
        })?;
    if decision.status == expected {
        Ok(())
    } else {
        Err(format!(
            "settlement eligibility state {state_number}: expected {:?}, actual {:?}",
            expected, decision.status
        ))
    }
}

fn require_fee_sponsored_decision_status(
    decisions: &[FeeSponsoredSettlementDecision],
    state_number: u64,
    expected: SettlementEligibilityStatus,
) -> Result<(), String> {
    let decision = decisions
        .iter()
        .find(|decision| decision.eligibility.state_number == state_number)
        .ok_or_else(|| format!("missing fee-sponsored decision for state {state_number}"))?;
    if decision.eligibility.status == expected {
        Ok(())
    } else {
        Err(format!(
            "fee-sponsored state {state_number}: expected {:?}, actual {:?}",
            expected, decision.eligibility.status
        ))
    }
}

fn require_sponsor_accounting(
    tx: &Transaction,
    report: &Value,
    marker_pointer: &str,
    channel_funding_outpoint: &str,
    label: &str,
) -> Result<(), String> {
    let outpoints_pointer = format!("{marker_pointer}/sponsor/sponsor_input_outpoints");
    let sponsor_input_outpoints: Vec<String> = required_typed(report, &outpoints_pointer)?;
    if sponsor_input_outpoints.len() != tx.inputs.len() {
        return Err(format!(
            "{label}: expected {} sponsor inputs, actual {}",
            sponsor_input_outpoints.len(),
            tx.inputs.len()
        ));
    }
    for (index, outpoint) in sponsor_input_outpoints.iter().enumerate() {
        if outpoint == channel_funding_outpoint {
            return Err(format!(
                "{label}: sponsor input touches channel funding outpoint"
            ));
        }
        require_input_outpoint(
            tx,
            index,
            outpoint,
            &format!("{label} sponsor input {index}"),
        )?;
    }

    require_output_count(tx, 1, label)?;
    let change_pointer = format!("{marker_pointer}/sponsor/sponsor_change_total");
    let sponsor_change_total = required_u64(report, &change_pointer)?;
    require_output_value(tx, 0, sponsor_change_total, label)?;

    let input_pointer = format!("{marker_pointer}/sponsor/sponsor_input_total");
    let fee_pointer = format!("{marker_pointer}/sponsor/sponsor_fee");
    let sponsor_input_total = required_u64(report, &input_pointer)?;
    let sponsor_fee = required_u64(report, &fee_pointer)?;
    let accounted_total = sponsor_change_total
        .checked_add(sponsor_fee)
        .ok_or_else(|| format!("{label}: sponsor accounting overflows u64"))?;
    if accounted_total != sponsor_input_total {
        return Err(format!(
            "{label}: sponsor input total {sponsor_input_total} does not equal change {sponsor_change_total} plus fee {sponsor_fee}"
        ));
    }
    Ok(())
}

fn require_outpoint(
    expected: &str,
    tx: &Transaction,
    output_index: usize,
    label: &str,
) -> Result<(), String> {
    require_output_index(tx, output_index, label)?;
    require_eq(format!("{}:{output_index}", tx.id()), expected, label)
}

fn require_input_outpoint(
    tx: &Transaction,
    input_index: usize,
    expected: &str,
    label: &str,
) -> Result<(), String> {
    let input = tx
        .inputs
        .get(input_index)
        .ok_or_else(|| format!("{label}: missing input {input_index}"))?;
    require_eq(
        format!(
            "{}:{}",
            input.previous_outpoint.transaction_id, input.previous_outpoint.index
        ),
        expected,
        label,
    )
}

fn require_input_sequence(
    tx: &Transaction,
    input_index: usize,
    expected: u64,
    label: &str,
) -> Result<(), String> {
    let input = tx
        .inputs
        .get(input_index)
        .ok_or_else(|| format!("{label}: missing input {input_index}"))?;
    if input.sequence == expected {
        Ok(())
    } else {
        Err(format!(
            "{label}: expected sequence {expected}, actual {}",
            input.sequence
        ))
    }
}

fn require_output_value(
    tx: &Transaction,
    output_index: usize,
    expected: u64,
    label: &str,
) -> Result<(), String> {
    let output = tx
        .outputs
        .get(output_index)
        .ok_or_else(|| format!("{label}: missing output {output_index}"))?;
    if output.value == expected {
        Ok(())
    } else {
        Err(format!(
            "{label}: expected value {expected}, actual {}",
            output.value
        ))
    }
}

fn require_output_count(tx: &Transaction, expected: usize, label: &str) -> Result<(), String> {
    let actual = tx.outputs.len();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{label}: expected {expected} outputs, actual {actual}"
        ))
    }
}

fn require_output_index(tx: &Transaction, output_index: usize, label: &str) -> Result<(), String> {
    if output_index < tx.outputs.len() {
        Ok(())
    } else {
        Err(format!("{label}: missing output {output_index}"))
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn write_raw_tx(output_dir: &Path, name: &str, tx: &Transaction) -> Result<FileRecord, String> {
    let bytes = borsh::to_vec(tx)
        .map_err(|e| format!("failed to serialise transaction {}: {e}", tx.id()))?;
    write_bytes_hex(output_dir, name, &bytes)
}

fn write_bytes_hex(output_dir: &Path, name: &str, bytes: &[u8]) -> Result<FileRecord, String> {
    let path = output_dir.join(name);
    fs::write(&path, format!("{}\n", hex::encode(bytes)))
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(FileRecord::new(&path, bytes))
}

fn write_json<T: Serialize>(output_dir: &Path, name: &str, value: &T) -> Result<(), String> {
    let path = output_dir.join(name);
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    fs::write(&path, [bytes, b"\n".to_vec()].concat())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

#[derive(Clone, Serialize)]
struct FileRecord {
    path: String,
    sha256: String,
}

impl FileRecord {
    fn new(path: &Path, original_bytes: &[u8]) -> Self {
        Self {
            path: path.display().to_string(),
            sha256: sha256_hex(original_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_marker_payload_hash_detects_tampering() {
        let payload = json!({
            "domain": "KURRENT_SETTLEMENT_CANDIDATE_MARKER_V1",
            "role": "lower_candidate",
            "state_number": 1_u64,
        });
        let payload_bytes = json_payload_bytes(&payload).unwrap();
        let tx = Transaction::new(
            TX_VERSION_TOCCATA,
            vec![],
            vec![],
            0,
            SubnetworkId::from_bytes([1; 20]),
            0,
            payload_bytes.clone(),
        );
        let report = json!({
            "candidate_markers": {
                "lower": {
                    "payload": payload,
                    "payload_hash": sha256_hex(&payload_bytes),
                }
            }
        });
        require_marker_payload(&tx, &report, "/candidate_markers/lower", "marker").unwrap();

        let bad_hash_report = json!({
            "candidate_markers": {
                "lower": {
                    "payload": report.pointer("/candidate_markers/lower/payload").unwrap(),
                    "payload_hash": sha256_hex(b"tampered"),
                }
            }
        });
        assert!(require_marker_payload(
            &tx,
            &bad_hash_report,
            "/candidate_markers/lower",
            "marker"
        )
        .is_err());

        let bad_payload_report = json!({
            "candidate_markers": {
                "lower": {
                    "payload": {"role": "higher_candidate"},
                    "payload_hash": sha256_hex(&payload_bytes),
                }
            }
        });
        assert!(require_marker_payload(
            &tx,
            &bad_payload_report,
            "/candidate_markers/lower",
            "marker"
        )
        .is_err());
    }

    #[test]
    fn lane_key_derivation_uses_twenty_byte_lane_id() {
        let lane_id = derive_kurrent_channel_lane_id("channel-a");
        let lane_bytes = lane_id_bytes(&lane_id, "test lane").unwrap();
        assert_eq!(lane_bytes.len(), 20);
        assert_eq!(lane_key(&lane_bytes), lane_key(&lane_bytes));
    }

    #[test]
    fn malformed_smt_proof_is_rejected() {
        let err = verify_lane_proof_material(LaneProofMaterial {
            lane_key_hash: Hash::from_bytes([1; 32]),
            lane_tip: Hash::from_bytes([2; 32]),
            lane_blue_score: 10,
            smt_proof_bytes: &[0xff, 0x00],
            payload_and_ctx_digest: Hash::from_bytes([3; 32]),
            parent_seq_commit: Hash::from_bytes([4; 32]),
            inactivity_shortcut: Hash::from_bytes([5; 32]),
            accepted_id_merkle_root: Hash::from_bytes([6; 32]),
        })
        .expect_err("malformed proof bytes must not verify");
        assert!(err.contains("failed to parse KIP-21 SMT proof"));
    }

    #[test]
    fn fee_sponsored_marker_payload_binds_policy_and_distribution() {
        let policy = SettlementFeePolicy {
            policy_id: "test-policy".to_string(),
            max_sponsor_fee: 100,
            sponsor_mode: "external-sponsor-input".to_string(),
        };
        let template = SettlementTemplate {
            template_id: "test-template".to_string(),
            outputs: BTreeMap::from([("alice".to_string(), 60), ("bob".to_string(), 40)]),
            refund_after_daa: Some(10),
            script_covenant_hash: sha256_hex(b"script"),
        };
        let state = StateUpdate {
            header: LatestStateHeader {
                network_profile: "test".to_string(),
                genesis_or_devnet_id: None,
                funding_outpoint: "funding:0".to_string(),
                channel_id: "channel-a".to_string(),
                factory_id: None,
                virtual_channel_id: None,
                state_number: 1,
                previous_state_commitment: "state-0".to_string(),
                new_state_commitment: "state-1".to_string(),
                settlement_template_hash: template.hash(),
                fee_policy_hash: Some(policy.hash()),
                challenge_policy_hash: sha256_hex(b"challenge"),
                participant_set_hash: sha256_hex(b"participants"),
                covenant_id: None,
                expected_lane_id: Some(derive_kurrent_channel_lane_id("channel-a")),
                script_covenant_hash: template.script_covenant_hash.clone(),
                protocol_version: 1,
                domain_separator: DOMAIN_STATE.to_string(),
            },
            balances: BTreeMap::from([("alice".to_string(), 60), ("bob".to_string(), 40)]),
            participant_signatures: BTreeMap::new(),
        };

        let payload = fee_sponsored_candidate_marker_payload(
            "lower_fee_sponsored_candidate",
            &state,
            state.header.expected_lane_id.as_deref().unwrap(),
            &policy,
            &template,
        );

        assert_eq!(
            required_str(&payload, "/fee_policy_hash").unwrap(),
            policy.hash()
        );
        assert_eq!(
            required_str(&payload, "/settlement_distribution_hash").unwrap(),
            settlement_distribution_hash(&template)
        );
    }

    #[test]
    fn sponsor_accounting_rejects_tampered_change_amount() {
        let input_txid = Hash::from_bytes([9; 32]);
        let input_outpoint = format!("{input_txid}:0");
        let tx = Transaction::new(
            TX_VERSION_TOCCATA,
            vec![TransactionInput::new(
                TransactionOutpoint::new(input_txid, 0),
                vec![],
                0,
                0,
            )],
            vec![TransactionOutput::new(
                900,
                ScriptPublicKey::from_vec(0, vec![]),
            )],
            0,
            SubnetworkId::from_bytes([1; 20]),
            0,
            vec![],
        );
        let report = json!({
            "sponsored_markers": {
                "lower": {
                    "sponsor": {
                        "sponsor_input_outpoints": [input_outpoint],
                        "sponsor_input_total": 1_000_u64,
                        "sponsor_change_total": 899_u64,
                        "sponsor_fee": 100_u64
                    }
                }
            }
        });

        assert!(require_sponsor_accounting(
            &tx,
            &report,
            "/sponsored_markers/lower",
            "funding:0",
            "sponsor marker",
        )
        .is_err());
    }
}
