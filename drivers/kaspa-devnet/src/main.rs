use kaspa_addresses::{Address, Version};
use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    sign::sign,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        CovenantBinding, GenesisCovenantGroup, MutableTransaction, ScriptPublicKey, Transaction,
        TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, RpcTransactionId};
use kaspa_testing_integration::common::{daemon::Daemon, utils::fetch_spendable_utxos};
use kaspa_txscript::{
    opcodes::codes::{
        OpAuthOutputCount, OpAuthOutputIdx, OpCheckSequenceVerify, OpElse, OpEndIf, OpEqualVerify,
        OpFalse, OpIf, OpSHA256, OpSwap, OpTrue, OpTxOutputAmount, OpTxOutputCount, OpTxOutputSpk,
    },
    pay_to_address_script, pay_to_script_hash_script, pay_to_script_hash_signature_script,
    script_builder::ScriptBuilder,
};
use kaspad_lib::args::Args;
use kurrent::{
    hash_json, sha256_hex, DOMAIN_CHANNEL_RECEIPT, DOMAIN_SETTLEMENT_TEMPLATE, DOMAIN_STATE,
};
use secp256k1::{rand::thread_rng, Keypair};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const FUNDING_FEE: u64 = 2_000_000;
const STATE_UPDATE_FEE: u64 = 25_000_000;
const SETTLEMENT_FEE: u64 = 25_000_000;
const COVENANT_COMPUTE_BUDGET: u16 = 2_000;

struct LiveKaspaContext<'a> {
    rpc: &'a GrpcClient,
    miner_sk: &'a Keypair,
    miner_address: &'a Address,
    coinbase_maturity: u64,
    output_dir: &'a Path,
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
        .join("../../../rusty-kaspa-toccata/testing/integration/testdata/params/compute_budget_relay_test_params.json");
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
    let (_alice_sk, alice_address) = keypair_address(kaspad.network.into());
    let (_bob_sk, bob_address) = keypair_address(kaspad.network.into());

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
    let state_2_redeem_script =
        build_state_2_redeem_script(alice_value, &alice_spk, bob_value, &bob_spk)?;
    let state_2_spk = pay_to_script_hash_script(&state_2_redeem_script);
    let state_1_redeem_script = build_state_1_redeem_script(state_2_value, &state_2_spk)?;
    let state_1_spk = pay_to_script_hash_script(&state_1_redeem_script);

    let funding_tx = signed_genesis_covenant_tx(
        &miner_sk,
        funding_input_outpoint,
        funding_input_entry,
        funding_value,
        state_1_spk,
        b"KURRENT_STATE_V1:funding",
    )?;
    let funding_covenant_id = funding_tx.outputs[0]
        .covenant
        .ok_or_else(|| "funding transaction did not populate a covenant id".to_string())?
        .covenant_id;
    let funding_txid = submit_and_mine(&rpc, &miner_address, &funding_tx).await?;

    let state_update_signature_script = p2sh_signature_script(false, &state_1_redeem_script)?;
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
        SUBNETWORK_ID_NATIVE,
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
        SUBNETWORK_ID_NATIVE,
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
        SUBNETWORK_ID_NATIVE,
        0,
        b"KURRENT_STATE_V1:settle-state-2".to_vec(),
    );
    let settlement_txid = submit_and_mine(&rpc, &miner_address, &settlement_tx).await?;

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

    let funding_raw = write_raw_tx(output_dir, "kurrent-live-funding-tx.hex", &funding_tx)?;
    let state_update_raw = write_raw_tx(
        output_dir,
        "kurrent-live-state-update-tx.hex",
        &state_update_tx,
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
        "channel_id": "channel-a",
        "factory_id": null,
        "virtual_channel_id": null,
        "state_number": 2_u64,
        "previous_state_commitment": sha256_hex(b"kurrent-state-1"),
        "new_state_commitment": sha256_hex(b"kurrent-state-2"),
        "settlement_template_hash": hash_json(DOMAIN_SETTLEMENT_TEMPLATE, &template),
        "challenge_policy_hash": sha256_hex(b"latest-state-monotonic-counter-window-120"),
        "participant_set_hash": sha256_hex(b"alice+bob"),
        "script_covenant_hash": sha256_hex(&state_2_redeem_script),
        "protocol_version": 1_u16,
    });
    let receipt_scope = json!({
        "domain_separator": DOMAIN_CHANNEL_RECEIPT,
        "protocol_version": 1_u16,
        "network_profile": "kaspa-simnet-toccata",
        "channel_id": "channel-a",
        "funding_outpoint": format!("{funding_txid}:0"),
        "output_id": format!("{settlement_txid}:0,{settlement_txid}:1"),
        "state_number": 2_u64,
        "settlement_template_hash": hash_json(DOMAIN_SETTLEMENT_TEMPLATE, &template),
    });

    let report = json!({
        "status": "passed",
        "network_profile": "kaspa-simnet-toccata",
        "driver": "kurrent-kaspa-devnet-driver",
        "miner_address": miner_address.to_string(),
        "participants": {
            "alice_address": alice_address.to_string(),
            "bob_address": bob_address.to_string()
        },
        "funding": {
            "input_outpoint": format!("{}:{}", funding_input_outpoint.transaction_id, funding_input_outpoint.index),
            "value": funding_value,
            "txid": funding_txid.to_string(),
            "outpoint": format!("{funding_txid}:0"),
            "covenant_id": funding_covenant_id.to_string(),
            "raw_tx": funding_raw,
        },
        "state_update": {
            "from_state": 1_u64,
            "to_state": 2_u64,
            "value": state_2_value,
            "txid": state_update_txid.to_string(),
            "outpoint": format!("{state_update_txid}:0"),
            "raw_tx": state_update_raw,
            "witness": state_update_witness_file,
        },
        "stale_state_rejection": {
            "status": "rejected",
            "attempted_txid": stale_tx.id().to_string(),
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
    });
    write_json(
        output_dir,
        "kurrent-live-state-channel-evidence.json",
        &report,
    )?;

    let live_context = LiveKaspaContext {
        rpc: &rpc,
        miner_sk: &miner_sk,
        miner_address: &miner_address,
        coinbase_maturity,
        output_dir,
    };

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

fn build_state_1_redeem_script(
    state_2_value: u64,
    state_2_spk: &ScriptPublicKey,
) -> Result<Vec<u8>, String> {
    let state_2_spk_bytes = spk_bytes(state_2_spk);
    ScriptBuilder::new()
        .add_data(&[1])
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
    alice_value: u64,
    alice_spk: &ScriptPublicKey,
    bob_value: u64,
    bob_spk: &ScriptPublicKey,
) -> Result<Vec<u8>, String> {
    let alice_spk_bytes = spk_bytes(alice_spk);
    let bob_spk_bytes = spk_bytes(bob_spk);
    ScriptBuilder::new()
        .add_data(&[2])
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
        SUBNETWORK_ID_NATIVE,
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

    Ok(json!({
        "status": "passed",
        "flow": "kaspa_factory_flow",
        "funding": {
            "txid": funding_txid.to_string(),
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
        }
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

    Ok(json!({
        "status": "passed",
        "flow": label,
        "preimage_sha256": sha256_hex(preimage),
        "funding": {
            "txid": funding_txid.to_string(),
            "outpoint": format!("{funding_txid}:0"),
            "raw_tx": write_raw_tx(ctx.output_dir, &format!("kurrent-live-{safe_label}-funding-tx.hex"), &funding_tx)?,
        },
        "settlement": {
            "txid": txid.to_string(),
            "raw_tx": write_raw_tx(ctx.output_dir, &format!("kurrent-live-{safe_label}-settlement-tx.hex"), &tx)?,
            "witness": write_bytes_hex(ctx.output_dir, &format!("kurrent-live-{safe_label}-settlement-witness.hex"), &witness)?,
            "redeem_script": write_bytes_hex(ctx.output_dir, &format!("kurrent-live-{safe_label}-redeem-script.hex"), &redeem_script)?,
        }
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

    Ok(json!({
        "status": "passed",
        "flow": "refund_timeout_flow",
        "funding": {
            "txid": funding_txid.to_string(),
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
            "raw_tx": write_raw_tx(ctx.output_dir, "kurrent-live-refund-tx.hex", &refund_tx)?,
            "witness": write_bytes_hex(ctx.output_dir, "kurrent-live-refund-witness.hex", &refund_witness)?,
            "redeem_script": write_bytes_hex(ctx.output_dir, "kurrent-live-refund-redeem-script.hex", &redeem_script)?,
        }
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
        SUBNETWORK_ID_NATIVE,
        0,
        payload.to_vec(),
    );
    sign(
        MutableTransaction::with_entries(unsigned, vec![entry]),
        *signer,
    )
    .tx
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
        "details": "funding, update, stale rejection, and settlement transactions decode and match recorded txids, outpoints, values, and rejection status"
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
    checks.push(json!({
        "id": "factory_transactions",
        "status": "passed",
        "details": "factory funding and materialisation transactions decode and preserve recorded txid, spend, and output semantics"
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
        for pointer in ["/settlement/witness", "/settlement/redeem_script"] {
            verify_hex_record_hash(&required_value(&report, pointer)?, verified_hex_records)?;
        }
    }
    checks.push(json!({
        "id": "hashlock_transactions",
        "status": "passed",
        "details": "both hashlock directions decode, consume the LN preimage hash, and spend their recorded funding outputs"
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
    for pointer in [
        "/early_refund_rejection/witness",
        "/refund/witness",
        "/refund/redeem_script",
    ] {
        verify_hex_record_hash(&required_value(&report, pointer)?, verified_hex_records)?;
    }
    checks.push(json!({
        "id": "refund_transactions",
        "status": "passed",
        "details": "early and mature refund transactions decode, spend the recorded funding output, and use the expected sequence-lock values"
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

fn require_status(value: &Value, label: &str) -> Result<(), String> {
    require_eq(
        required_str(value, "/status")?,
        "passed",
        &format!("{label} status"),
    )
}

fn require_eq(actual: impl AsRef<str>, expected: &str, label: &str) -> Result<(), String> {
    let actual = actual.as_ref();
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label}: expected {expected}, actual {actual}"))
    }
}

fn require_txid(tx: &Transaction, expected: &str, label: &str) -> Result<(), String> {
    require_eq(tx.id().to_string(), expected, label)
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

#[derive(Serialize)]
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
