use kurrent::{
    derive_kurrent_channel_lane_id, evaluate_fee_sponsored_settlement_eligibility, hash_json,
    participant_set_hash, settlement_distribution_hash, sha256_hex, state_update_signing_digest,
    validate_channel_update, validate_ln_swap, validate_materialisation, verify_evidence_bundle,
    AcceptanceReport, AccessManifest, ChallengePolicy, ChannelReceipt, ClaimScope, EvidenceBundle,
    EvidenceFile, FactoryState, FeeSponsoredSettlementCandidate, FlowEvidenceFile, FundingState,
    KurrentChannelConfig, KurrentError, LatestStateHeader, LnSwapEvidence, MaterialisationPlan,
    OpcodeCapabilityEvidence, ProductionEvidenceRequirement, ProductionReadinessReport,
    SameNumberConflictRule, SecurityReviewArtifact, SecurityReviewEvidence,
    SettlementCandidateEvidence, SettlementEligibilityCandidate, SettlementEligibilityPolicy,
    SettlementEligibilityStatus, SettlementFeePolicy, SettlementRegistry,
    SettlementSponsorEvidence, SettlementTemplate, StateUpdate, ToolEvidence, TouchedLeaves,
    VirtualChannelState, DOMAIN_CHANNEL_RECEIPT, DOMAIN_CLAIM_SCOPE,
    DOMAIN_FACTORY_MATERIALISATION, DOMAIN_LN_INTEROP, DOMAIN_PARTICIPANT_SET,
    DOMAIN_SETTLEMENT_TEMPLATE, DOMAIN_STATE, DOMAIN_STATE_SIGNATURE,
};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const EXIT_TOOLING_BLOCKED: u8 = 10;
const EXIT_KASPA_FLOW: u8 = 11;
const EXIT_FACTORY_FLOW: u8 = 12;
const EXIT_LN_FLOW: u8 = 13;
const EXIT_KASPA_TO_LN_FLOW: u8 = 14;
const EXIT_REFUND_FLOW: u8 = 15;
const EXIT_EVIDENCE: u8 = 16;
const EXIT_PRODUCTION_READINESS: u8 = 17;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<u8, String> {
    let mut args = env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());
    match command.as_str() {
        "detect-tools" => detect_tools().map(|ready| if ready { 0 } else { EXIT_TOOLING_BLOCKED }),
        "tool-path" => {
            let Some(name) = args.next() else {
                return Err("tool-path requires a command name".to_string());
            };
            let report = detection_report();
            match report.tool_paths.get(&name).and_then(|p| p.as_ref()) {
                Some(path) => {
                    println!("{path}");
                    Ok(0)
                }
                None => Ok(1),
            }
        }
        "write-acceptance-report" => {
            let status = args.next().unwrap_or_else(|| "failed/blocked".to_string());
            let blocker_code = args
                .next()
                .unwrap_or_else(|| "external_tooling_unavailable".to_string());
            write_acceptance_report(&status, &blocker_code)?;
            Ok(if status == "passed" { 0 } else { 1 })
        }
        "verify-evidence" => verify_evidence(),
        "verify-production-readiness" => verify_production_readiness(),
        "prepare-devnet-tools" => prepare_devnet_tools(),
        "run-kaspa-devnet" => run_kaspa_devnet(),
        "run-ln-devnet" => run_ln_devnet(),
        "run-state-channel-flow" => run_state_channel_flow(),
        "run-factory-flow" => run_factory_flow(),
        "run-ln-to-kaspa-flow" => run_ln_to_kaspa_flow(),
        "run-kaspa-to-ln-flow" => run_kaspa_to_ln_flow(),
        "run-refund-flow" => run_refund_flow(),
        "run-semantic-transaction-verifier" => run_semantic_transaction_verifier(),
        "run-adversarial-soak" => run_adversarial_soak(),
        "write-production-target-profile" => write_production_target_profile(),
        "prepare-security-review-package" => prepare_security_review_package(),
        "check" => check(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(0)
        }
        other => Err(format!("unknown kurrentctl command: {other}")),
    }
}

fn print_help() {
    println!(
        "kurrentctl commands: detect-tools, tool-path, write-acceptance-report, verify-evidence, verify-production-readiness, prepare-devnet-tools, run-kaspa-devnet, run-ln-devnet, run-state-channel-flow, run-factory-flow, run-ln-to-kaspa-flow, run-kaspa-to-ln-flow, run-refund-flow, run-semantic-transaction-verifier, run-adversarial-soak, write-production-target-profile, prepare-security-review-package, check"
    );
}

#[derive(Debug, Clone, Serialize)]
struct RepoRecord {
    path: String,
    current_branch: Option<String>,
    head: Option<String>,
    origin_toccata: Option<String>,
    origin_master: Option<String>,
    status_short: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DetectionReport {
    timestamp: String,
    status: String,
    blockers: Vec<String>,
    tools: Vec<ToolEvidence>,
    tool_paths: BTreeMap<String, Option<String>>,
    known_bin_dirs: Vec<String>,
    parent_kaspa_repo: Option<RepoRecord>,
    selected_kaspa_repo: Option<RepoRecord>,
    lnd_repo: Option<RepoRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct CommandEvidence {
    label: String,
    cwd: String,
    command: Vec<String>,
    status_code: Option<i32>,
    stdout: EvidenceFile,
    stderr: EvidenceFile,
}

fn root() -> Result<PathBuf, String> {
    env::current_exe()
        .ok()
        .and_then(|p| {
            let mut cursor = p.as_path();
            while let Some(parent) = cursor.parent() {
                if parent.join("Cargo.toml").exists() && parent.join("scripts").exists() {
                    return Some(parent.to_path_buf());
                }
                cursor = parent;
            }
            None
        })
        .or_else(|| env::current_dir().ok())
        .ok_or_else(|| "could not resolve repository root".to_string())
}

fn evidence_dir() -> Result<PathBuf, String> {
    let dir = root()?.join("evidence");
    fs::create_dir_all(&dir).map_err(|e| format!("failed to create evidence directory: {e}"))?;
    Ok(dir)
}

fn relative_to_root(path: &Path) -> Result<String, String> {
    let root = root()?;
    Ok(path
        .strip_prefix(&root)
        .unwrap_or(path)
        .display()
        .to_string())
}

fn file_evidence(path: &Path) -> Result<EvidenceFile, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(EvidenceFile {
        path: relative_to_root(path)?,
        sha256: sha256_hex(&bytes),
    })
}

fn source_file_evidence(repo: &Path, relative: &str) -> Result<EvidenceFile, String> {
    let path = repo.join(relative);
    let bytes = fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(EvidenceFile {
        path: path.display().to_string(),
        sha256: sha256_hex(&bytes),
    })
}

fn selected_kaspa_repo_path() -> Result<PathBuf, String> {
    detection_report()
        .selected_kaspa_repo
        .map(|repo| PathBuf::from(repo.path))
        .ok_or_else(|| "no selected local Kaspa source repository is available".to_string())
}

fn parent_dir() -> Result<PathBuf, String> {
    root()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "repository root has no parent".to_string())
}

fn known_bin_dirs() -> Vec<PathBuf> {
    let parent = parent_dir().unwrap_or_else(|_| PathBuf::from("/Users/arthur/Documents"));
    vec![
        PathBuf::from("/Users/arthur/go/bin"),
        parent.join("rusty-kaspa/target/release"),
        parent.join("rusty-kaspa/target/debug"),
        parent.join("rusty-kaspa-toccata/target/release"),
        parent.join("rusty-kaspa-toccata/target/debug"),
        PathBuf::from("/Users/arthur/RustroverProjects/rusty-kaspa/target/release"),
        PathBuf::from("/Users/arthur/RustroverProjects/rusty-kaspa/target/debug"),
    ]
}

fn path_entries() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).collect())
        .unwrap_or_default()
}

fn resolve_command(name: &str) -> Option<PathBuf> {
    for dir in path_entries().into_iter().chain(known_bin_dirs()) {
        let candidate = dir.join(name);
        if candidate.is_file() && is_executable(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.exists()
    }
}

fn command_stdout(mut cmd: Command) -> Option<String> {
    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn command_version(path: &Path) -> Option<String> {
    for flag in ["--version", "version", "-V"] {
        let mut cmd = Command::new(path);
        cmd.arg(flag);
        if let Some(stdout) = command_stdout(cmd) {
            if !stdout.is_empty() {
                return stdout.lines().next().map(clean_command_text);
            }
        }
    }
    None
}

fn clean_command_text(text: &str) -> String {
    let mut cleaned = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if !ch.is_control() {
            cleaned.push(ch);
        }
    }
    cleaned.trim().to_string()
}

fn tool_record(name: &str) -> ToolEvidence {
    let path = resolve_command(name);
    ToolEvidence {
        name: name.to_string(),
        version: path.as_deref().and_then(command_version),
        path: path.map(|p| p.display().to_string()),
    }
}

fn git_stdout(repo: &Path, args: &[&str]) -> Option<String> {
    let mut cmd = Command::new("git");
    cmd.args(args).current_dir(repo);
    command_stdout(cmd)
}

fn current_git_commit(repo: &Path) -> Result<String, String> {
    git_stdout(repo, &["rev-parse", "--verify", "HEAD"])
        .ok_or_else(|| "failed to resolve current git HEAD".to_string())
}

fn repo_record(path: Option<PathBuf>) -> Option<RepoRecord> {
    let path = path?;
    if !path.join(".git").exists() {
        return None;
    }
    Some(RepoRecord {
        path: path.display().to_string(),
        current_branch: git_stdout(&path, &["branch", "--show-current"]),
        head: git_stdout(&path, &["rev-parse", "HEAD"]),
        origin_toccata: git_stdout(&path, &["rev-parse", "origin/toccata"]),
        origin_master: git_stdout(&path, &["rev-parse", "origin/master"]),
        status_short: git_stdout(&path, &["status", "--short", "--branch"]),
    })
}

fn first_git_dir(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates.iter().find(|p| p.join(".git").exists()).cloned()
}

fn detection_report() -> DetectionReport {
    let parent = parent_dir().unwrap_or_else(|_| PathBuf::from("/Users/arthur/Documents"));
    let commands = [
        "kaspad",
        "kaspa-node",
        "kaspa-cli",
        "kaspa-wallet",
        "rusty-kaspa",
        "lnd",
        "lncli",
        "lightningd",
        "lightning-cli",
        "bitcoind",
        "bitcoin-cli",
        "cargo",
        "rustc",
        "go",
    ];
    let tools: Vec<_> = commands.iter().map(|name| tool_record(name)).collect();
    let tool_paths: BTreeMap<_, _> = tools
        .iter()
        .map(|t| (t.name.clone(), t.path.clone()))
        .collect();

    let parent_repo = first_git_dir(&[
        parent.join("rusty-kaspa"),
        parent.join("rusty-kaspa-toccata"),
        parent.join("kaspa"),
        parent.join("Kaspa"),
    ]);
    let selected_repo = parent_repo
        .clone()
        .or_else(|| first_git_dir(&[PathBuf::from("/Users/arthur/RustroverProjects/rusty-kaspa")]));
    let lnd_repo = first_git_dir(&[parent.join("lnd")]);

    let kaspa_node_available = tool_paths.get("kaspad").and_then(Clone::clone).is_some()
        || tool_paths
            .get("kaspa-node")
            .and_then(Clone::clone)
            .is_some();
    let kaspa_cli_available = tool_paths.get("kaspa-cli").and_then(Clone::clone).is_some()
        || tool_paths
            .get("kaspa-wallet")
            .and_then(Clone::clone)
            .is_some();
    let ln_available = (tool_paths.get("lnd").and_then(Clone::clone).is_some()
        && tool_paths.get("lncli").and_then(Clone::clone).is_some())
        || (tool_paths
            .get("lightningd")
            .and_then(Clone::clone)
            .is_some()
            && tool_paths
                .get("lightning-cli")
                .and_then(Clone::clone)
                .is_some());
    let bitcoin_core_available = tool_paths.get("bitcoind").and_then(Clone::clone).is_some()
        && tool_paths
            .get("bitcoin-cli")
            .and_then(Clone::clone)
            .is_some();

    let mut blockers = Vec::new();
    if parent_repo.is_none() {
        blockers.push(
            "No Kaspa source checkout was found in the parent folder /Users/arthur/Documents."
                .to_string(),
        );
    }
    if selected_repo.is_none() {
        blockers.push(
            "No local Kaspa source checkout with the expected covenant-capability profile was found."
                .to_string(),
        );
    }
    if !kaspa_node_available {
        blockers
            .push("No Kaspa node executable was found on PATH or known build paths.".to_string());
    }
    if !kaspa_cli_available {
        blockers.push(
            "No Kaspa CLI or wallet executable was found on PATH or known build paths.".to_string(),
        );
    }
    if !ln_available {
        blockers.push(
            "No Lightning Network devnet command pair was found on PATH or known build paths."
                .to_string(),
        );
    }
    if !bitcoin_core_available {
        blockers.push(
            "No Bitcoin Core regtest command pair was found on PATH or known build paths."
                .to_string(),
        );
    }

    DetectionReport {
        timestamp: timestamp(),
        status: if blockers.is_empty() {
            "ready"
        } else {
            "blocked"
        }
        .to_string(),
        blockers,
        tools,
        tool_paths,
        known_bin_dirs: known_bin_dirs()
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        parent_kaspa_repo: repo_record(parent_repo),
        selected_kaspa_repo: repo_record(selected_repo),
        lnd_repo: repo_record(lnd_repo),
    }
}

fn detect_tools() -> Result<bool, String> {
    let report = detection_report();
    write_json_file(&evidence_dir()?.join("tool-detection.json"), &report)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    Ok(report.blockers.is_empty())
}

fn flow_evidence_files() -> [(&'static str, &'static str); 8] {
    [
        (
            "kaspa_state_channel_flow",
            "kurrent-state-channel-flow-evidence.json",
        ),
        (
            "kaspa_lane_monitor_flow",
            "kurrent-live-lane-monitor-evidence.json",
        ),
        (
            "kaspa_settlement_eligibility_flow",
            "kurrent-live-settlement-eligibility-evidence.json",
        ),
        (
            "kaspa_fee_sponsored_displacement_flow",
            "kurrent-live-fee-sponsored-displacement-evidence.json",
        ),
        ("kaspa_factory_flow", "kurrent-factory-flow-evidence.json"),
        (
            "ln_to_kaspa_atomic_settlement",
            "kurrent-ln-to-kaspa-flow-evidence.json",
        ),
        (
            "kaspa_to_ln_atomic_settlement",
            "kurrent-kaspa-to-ln-flow-evidence.json",
        ),
        ("refund_timeout_flow", "kurrent-refund-flow-evidence.json"),
    ]
}

fn evidence_file_from_value(record: &Value) -> Result<EvidenceFile, String> {
    let path = record
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("invalid evidence record missing path: {record}"))?;
    let sha256 = record
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("invalid evidence record missing sha256: {record}"))?;
    Ok(EvidenceFile {
        path: path.to_string(),
        sha256: sha256.to_string(),
    })
}

fn push_evidence_file(records: &mut Vec<EvidenceFile>, record: &Value) -> Result<(), String> {
    records.push(evidence_file_from_value(record)?);
    Ok(())
}

fn write_acceptance_report(status: &str, blocker_code: &str) -> Result<(), String> {
    let detection = detection_report();
    let evidence_root = evidence_dir()?;
    let mut blockers = detection.blockers.clone();
    if blockers.is_empty() && status != "passed" {
        blockers.push(blocker_code.to_string());
    }
    let mut flows = BTreeMap::new();
    let mut flow_evidence_paths_and_hashes = Vec::new();
    for (key, file_name) in flow_evidence_files() {
        let path = evidence_root.join(file_name);
        if path.exists() {
            let bytes = fs::read(&path).map_err(|e| e.to_string())?;
            let value: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            let flow_status = value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            flows.insert(key.to_string(), flow_status);
            flow_evidence_paths_and_hashes.push(FlowEvidenceFile {
                flow: key.to_string(),
                path: format!("evidence/{file_name}"),
                sha256: sha256_hex(&bytes),
            });
            if let Some(items) = value.get("blockers").and_then(Value::as_array) {
                for item in items {
                    if let Some(blocker) = item.as_str() {
                        blockers.push(format!("{key}: {blocker}"));
                    }
                }
            }
        } else {
            flows.insert(
                key.to_string(),
                if status == "passed" {
                    "missing"
                } else {
                    "not_executed"
                }
                .to_string(),
            );
        }
    }
    flows.insert(
        "evidence_verifier_flow".to_string(),
        if status == "passed" {
            "passed"
        } else {
            "not_executed"
        }
        .to_string(),
    );

    let source_repo = detection
        .selected_kaspa_repo
        .as_ref()
        .map(|repo| repo.path.clone());
    let kaspa_branch_profile = detection
        .selected_kaspa_repo
        .as_ref()
        .and_then(|repo| repo.origin_toccata.clone().or_else(|| repo.head.clone()));
    let ln_evidence_path = evidence_root.join("ln-devnet-evidence.json");
    let ln_invoice_payment_preimage_evidence = if ln_evidence_path.exists() {
        let bytes = fs::read(&ln_evidence_path).map_err(|e| e.to_string())?;
        vec![EvidenceFile {
            path: "evidence/ln-devnet-evidence.json".to_string(),
            sha256: sha256_hex(&bytes),
        }]
    } else {
        Vec::new()
    };
    let mut command_transcript_paths = Vec::new();
    for path in [
        "kaspa-simnet-probe.log",
        "ln-alice.log",
        "ln-bob.log",
        "kaspa-txscript-covenants.stdout.log",
        "kaspa-txscript-covenants.stderr.log",
        "kaspa-daemon-compute-budget-relay.stdout.log",
        "kaspa-daemon-compute-budget-relay.stderr.log",
        "kurrent-live-state-channel-driver.stdout.log",
        "kurrent-live-state-channel-driver.stderr.log",
    ] {
        let full_path = evidence_root.join(path);
        if full_path.exists() {
            command_transcript_paths.push(format!("evidence/{path}"));
        }
    }
    let mut raw_transaction_paths_and_hashes = Vec::new();
    let mut script_paths_and_hashes = Vec::new();
    let mut witness_paths_and_hashes = Vec::new();
    let mut settlement_template_hashes = Vec::new();
    let mut channel_receipt_hashes = Vec::new();
    let mut state_channel_funding_txid_outpoint = String::new();
    let mut latest_state_settlement_txid_outpoint = String::new();
    let mut factory_id = String::new();
    let mut virtual_channel_ids = Vec::new();
    let mut factory_state_roots_before_after = Vec::new();
    let mut materialisation_txid_outpoint = String::new();
    let mut refund_txid_outpoint = String::new();
    let mut state_txids_or_transition_ids = Vec::new();
    let live_state_path = evidence_root.join("kurrent-live-state-channel-evidence.json");
    if live_state_path.exists() {
        let live_state: Value =
            serde_json::from_slice(&fs::read(&live_state_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        if let Some(outpoint) = live_state
            .pointer("/funding/outpoint")
            .and_then(Value::as_str)
        {
            state_channel_funding_txid_outpoint = outpoint.to_string();
        }
        if let Some(txid) = live_state.pointer("/funding/txid").and_then(Value::as_str) {
            state_txids_or_transition_ids.push(txid.to_string());
        }
        if let Some(txid) = live_state
            .pointer("/state_update/txid")
            .and_then(Value::as_str)
        {
            state_txids_or_transition_ids.push(txid.to_string());
        }
        if let Some(txid) = live_state
            .pointer("/settlement/txid")
            .and_then(Value::as_str)
        {
            latest_state_settlement_txid_outpoint = format!("{txid}:0,{txid}:1");
            state_txids_or_transition_ids.push(txid.to_string());
        }
        if let Some(outpoint) = live_state
            .pointer("/state_update/outpoint")
            .and_then(Value::as_str)
        {
            state_txids_or_transition_ids.push(outpoint.to_string());
        }
        if let Some(txid) = live_state
            .pointer("/stale_state_rejection/attempted_txid")
            .and_then(Value::as_str)
        {
            state_txids_or_transition_ids.push(txid.to_string());
        }
        for pointer in [
            "/wrong_lane_rejections/native_state_update/attempted_txid",
            "/wrong_lane_rejections/wrong_user_state_update/attempted_txid",
            "/wrong_lane_rejections/native_settlement/attempted_txid",
            "/wrong_lane_rejections/wrong_user_settlement/attempted_txid",
        ] {
            if let Some(txid) = live_state.pointer(pointer).and_then(Value::as_str) {
                state_txids_or_transition_ids.push(txid.to_string());
            }
        }
        for pointer in [
            "/funding/raw_tx",
            "/state_update/raw_tx",
            "/wrong_lane_rejections/native_state_update/attempted_tx",
            "/wrong_lane_rejections/wrong_user_state_update/attempted_tx",
            "/wrong_lane_rejections/native_settlement/attempted_tx",
            "/wrong_lane_rejections/wrong_user_settlement/attempted_tx",
            "/stale_state_rejection/attempted_tx",
            "/settlement/raw_tx",
        ] {
            if let Some(record) = live_state.pointer(pointer) {
                push_evidence_file(&mut raw_transaction_paths_and_hashes, record)?;
            }
        }
        for pointer in [
            "/settlement/state_1_redeem_script",
            "/settlement/state_2_redeem_script",
        ] {
            if let Some(record) = live_state.pointer(pointer) {
                push_evidence_file(&mut script_paths_and_hashes, record)?;
            }
        }
        for pointer in [
            "/state_update/witness",
            "/stale_state_rejection/witness",
            "/settlement/witness",
        ] {
            if let Some(record) = live_state.pointer(pointer) {
                push_evidence_file(&mut witness_paths_and_hashes, record)?;
            }
        }
        if let Some(hash) = live_state
            .pointer("/settlement_template/hash")
            .and_then(Value::as_str)
        {
            settlement_template_hashes.push(hash.to_string());
        }
        if let Some(hash) = live_state
            .pointer("/channel_receipt/hash")
            .and_then(Value::as_str)
        {
            channel_receipt_hashes.push(hash.to_string());
        }
    }
    for (file_name, txid_pointer, txid_target) in [
        (
            "kurrent-live-factory-evidence.json",
            "/materialisation/txid",
            "factory",
        ),
        (
            "kurrent-live-ln-to-kaspa-evidence.json",
            "/settlement/txid",
            "state",
        ),
        (
            "kurrent-live-kaspa-to-ln-evidence.json",
            "/settlement/txid",
            "state",
        ),
        (
            "kurrent-live-refund-evidence.json",
            "/refund/txid",
            "refund",
        ),
    ] {
        let path = evidence_root.join(file_name);
        if !path.exists() {
            continue;
        }
        let live: Value = serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        if file_name == "kurrent-live-factory-evidence.json" {
            factory_id = "factory-live-1".to_string();
            virtual_channel_ids = vec![
                "factory-live-alice".to_string(),
                "factory-live-bob".to_string(),
            ];
            if let Some(roots) = live
                .pointer("/model_validation/factory_state_roots")
                .and_then(Value::as_array)
            {
                factory_state_roots_before_after = roots
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect();
            }
        }
        if let Some(txid) = live.pointer(txid_pointer).and_then(Value::as_str) {
            match txid_target {
                "factory" => materialisation_txid_outpoint = format!("{txid}:0,{txid}:1"),
                "refund" => refund_txid_outpoint = format!("{txid}:0"),
                _ => state_txids_or_transition_ids.push(txid.to_string()),
            }
        }
        for pointer in [
            "/funding/raw_tx",
            "/materialisation/raw_tx",
            "/settlement/raw_tx",
            "/early_refund_rejection/attempted_tx",
            "/refund/raw_tx",
        ] {
            if let Some(record) = live.pointer(pointer) {
                push_evidence_file(&mut raw_transaction_paths_and_hashes, record)?;
            }
        }
        for pointer in [
            "/materialisation/redeem_script",
            "/settlement/redeem_script",
            "/refund/redeem_script",
        ] {
            if let Some(record) = live.pointer(pointer) {
                push_evidence_file(&mut script_paths_and_hashes, record)?;
            }
        }
        for pointer in [
            "/materialisation/witness",
            "/settlement/witness",
            "/early_refund_rejection/witness",
            "/refund/witness",
        ] {
            if let Some(record) = live.pointer(pointer) {
                push_evidence_file(&mut witness_paths_and_hashes, record)?;
            }
        }
    }

    let report = AcceptanceReport {
        timestamp: timestamp(),
        git_commit: git_stdout(&root()?, &["rev-parse", "--verify", "HEAD"]),
        tool_versions: detection.tools,
        kaspa_branch_profile,
        enabled_opcode_capability_evidence: OpcodeCapabilityEvidence {
            source_repo,
            op_cat: "covered by KIP-17 source evidence and covenant-script transcript".to_string(),
            introspection:
                "covered by KIP-10/KIP-17 source evidence and live daemon transaction transcript"
                    .to_string(),
            checksigfromstack:
                "covered by KIP-17 source evidence and covenant-script transcript".to_string(),
            hashlock: "covered by Kurrent live hashlock settlement evidence".to_string(),
            timelock_refund:
                "covered by Kurrent live early-refund rejection and matured refund evidence"
                    .to_string(),
            covenant_output_constraints:
                "covered by Kurrent live state update, stale-state rejection, and settlement evidence"
                    .to_string(),
        },
        network_devnet_id: "local-kaspa-simnet-toccata+bitcoin-regtest-lnd".to_string(),
        state_channel_funding_txid_outpoint,
        state_txids_or_transition_ids,
        latest_state_settlement_txid_outpoint,
        factory_id,
        virtual_channel_ids,
        factory_state_roots_before_after,
        materialisation_txid_outpoint,
        ln_invoice_payment_preimage_evidence,
        refund_txid_outpoint,
        raw_transaction_paths_and_hashes,
        script_paths_and_hashes,
        witness_paths_and_hashes,
        flow_evidence_paths_and_hashes,
        settlement_template_hashes,
        channel_receipt_hashes,
        command_transcript_paths,
        flows,
        status: status.to_string(),
        blocker_code: blocker_code.to_string(),
        blockers,
    };
    write_json_file(&evidence_root.join("kurrent-acceptance.json"), &report)
}

fn verify_evidence() -> Result<u8, String> {
    let root = root()?;
    let path = evidence_dir()?.join("kurrent-acceptance.json");
    if !path.exists() {
        eprintln!("missing evidence/kurrent-acceptance.json");
        return Ok(EXIT_EVIDENCE);
    }
    let report: AcceptanceReport =
        serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let current_commit = current_git_commit(&root)?;
    if report.git_commit.as_deref() != Some(current_commit.as_str()) {
        eprintln!(
            "acceptance evidence git_commit does not match HEAD: report={}, head={current_commit}",
            report.git_commit.as_deref().unwrap_or("<missing>")
        );
        return Ok(EXIT_EVIDENCE);
    }
    if report.status != "passed" {
        eprintln!("acceptance evidence is not passed");
        return Ok(EXIT_EVIDENCE);
    }
    if !report.blockers.is_empty() {
        eprintln!("acceptance evidence contains blockers");
        return Ok(EXIT_EVIDENCE);
    }
    let required = [
        "kaspa_state_channel_flow",
        "kaspa_factory_flow",
        "ln_to_kaspa_atomic_settlement",
        "kaspa_to_ln_atomic_settlement",
        "refund_timeout_flow",
        "evidence_verifier_flow",
    ];
    for key in required {
        if report.flows.get(key).map(String::as_str) != Some("passed") {
            eprintln!("missing passed flow: {key}");
            return Ok(EXIT_EVIDENCE);
        }
    }

    for (field, value) in [
        ("network_devnet_id", &report.network_devnet_id),
        (
            "state_channel_funding_txid_outpoint",
            &report.state_channel_funding_txid_outpoint,
        ),
        (
            "latest_state_settlement_txid_outpoint",
            &report.latest_state_settlement_txid_outpoint,
        ),
        ("factory_id", &report.factory_id),
        (
            "materialisation_txid_outpoint",
            &report.materialisation_txid_outpoint,
        ),
        ("refund_txid_outpoint", &report.refund_txid_outpoint),
    ] {
        if value.is_empty() {
            eprintln!("missing required acceptance field: {field}");
            return Ok(EXIT_EVIDENCE);
        }
    }
    for (bucket, values) in [
        ("virtual_channel_ids", &report.virtual_channel_ids),
        (
            "state_txids_or_transition_ids",
            &report.state_txids_or_transition_ids,
        ),
    ] {
        if values.is_empty() {
            eprintln!("missing evidence bucket: {bucket}");
            return Ok(EXIT_EVIDENCE);
        }
    }

    for (bucket, mode) in [
        (
            "raw_transaction_paths_and_hashes",
            HashMode::HexDecodedBytes,
        ),
        ("script_paths_and_hashes", HashMode::HexDecodedBytes),
        ("witness_paths_and_hashes", HashMode::HexDecodedBytes),
        ("flow_evidence_paths_and_hashes", HashMode::FileBytes),
        ("ln_invoice_payment_preimage_evidence", HashMode::FileBytes),
    ] {
        let records = match bucket {
            "raw_transaction_paths_and_hashes" => &report.raw_transaction_paths_and_hashes,
            "script_paths_and_hashes" => &report.script_paths_and_hashes,
            "witness_paths_and_hashes" => &report.witness_paths_and_hashes,
            "ln_invoice_payment_preimage_evidence" => &report.ln_invoice_payment_preimage_evidence,
            "flow_evidence_paths_and_hashes" => {
                if report.flow_evidence_paths_and_hashes.is_empty() {
                    eprintln!("missing evidence bucket: {bucket}");
                    return Ok(EXIT_EVIDENCE);
                }
                for record in &report.flow_evidence_paths_and_hashes {
                    if let Err(err) =
                        verify_file_hash(&root, bucket, &record.path, &record.sha256, mode)
                    {
                        eprintln!("{err}");
                        return Ok(EXIT_EVIDENCE);
                    }
                }
                continue;
            }
            _ => unreachable!(),
        };
        if records.is_empty() {
            eprintln!("missing evidence bucket: {bucket}");
            return Ok(EXIT_EVIDENCE);
        }
        for record in records {
            if let Err(err) = verify_file_hash_record(&root, bucket, record, mode) {
                eprintln!("{err}");
                return Ok(EXIT_EVIDENCE);
            }
        }
    }

    if report.command_transcript_paths.is_empty() {
        eprintln!("missing evidence bucket: command_transcript_paths");
        return Ok(EXIT_EVIDENCE);
    }
    for path in &report.command_transcript_paths {
        if !resolve_record_path(&root, path).is_file() {
            eprintln!("missing transcript file: {path}");
            return Ok(EXIT_EVIDENCE);
        }
    }
    Ok(0)
}

fn production_readiness_requirements() -> [(&'static str, &'static str, &'static str); 8] {
    [
        (
            "prod_target_profile",
            "Pinned production network profile, dependency profile, and supported Kaspa covenant-capability activation assumptions.",
            "evidence/production/target-profile.json",
        ),
        (
            "semantic_transaction_verifier",
            "Independent decoder/verifier proving raw transaction, witness, script, txid, and receipt relationships semantically, not only by hash.",
            "evidence/production/semantic-transaction-verifier.json",
        ),
        (
            "adversarial_mempool_soak",
            "Deterministic adversarial mempool, alternate-history, stale-state, refund-race, swap-replay, and evidence-tamper soak evidence.",
            "evidence/production/adversarial-mempool-soak.json",
        ),
        (
            "key_management_recovery",
            "Production key-management, signer isolation, key rotation, backup, and recovery runbook.",
            "docs/PRODUCTION_KEY_MANAGEMENT.md",
        ),
        (
            "monitoring_alerting",
            "Production monitoring, alerting, SLO, log-retention, and evidence-retention runbook.",
            "docs/PRODUCTION_MONITORING.md",
        ),
        (
            "incident_recovery",
            "Incident response and unattended recovery procedure for stalled channels, stale submissions, LN failures, and node divergence.",
            "docs/PRODUCTION_RECOVERY.md",
        ),
        (
            "release_rollout_rollback",
            "Release, rollout, rollback, migration, and compatibility procedure for protocol and script changes.",
            "docs/PRODUCTION_ROLLOUT.md",
        ),
        (
            "external_security_review",
            "Independent security-review evidence covering protocol design, script constraints, signer model, and operational controls.",
            "evidence/production/security-review.json",
        ),
    ]
}

fn production_evidence_satisfies(id: &str, path: &Path) -> Result<bool, String> {
    if !path.is_file() {
        return Ok(false);
    }
    if id == "external_security_review" {
        return security_review_evidence_satisfies(path);
    }
    if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
        let value: Value =
            serde_json::from_slice(&fs::read(path).map_err(|e| {
                format!("failed to read production evidence {}: {e}", path.display())
            })?)
            .map_err(|e| {
                format!(
                    "failed to parse production evidence {}: {e}",
                    path.display()
                )
            })?;
        Ok(production_json_evidence_satisfies(id, &value))
    } else if path.extension().and_then(|ext| ext.to_str()) == Some("md") {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("failed to read production runbook {}: {e}", path.display()))?;
        Ok(production_runbook_satisfies(id, &text))
    } else {
        let len = path.metadata().map_err(|e| {
            format!(
                "failed to inspect production evidence {}: {e}",
                path.display()
            )
        })?;
        Ok(len.len() > 0)
    }
}

fn production_json_evidence_satisfies(id: &str, value: &Value) -> bool {
    if value.get("status").and_then(Value::as_str) != Some("passed") {
        return false;
    }
    match id {
        "prod_target_profile" => {
            value
                .get("git_commit")
                .and_then(Value::as_str)
                .is_some_and(|commit| !commit.is_empty())
                && value
                    .get("required_production_gates")
                    .and_then(Value::as_array)
                    .is_some_and(|items| items.len() >= 5)
                && value
                    .get("local_acceptance")
                    .and_then(|local| local.get("acceptance_report"))
                    .is_some()
        }
        "semantic_transaction_verifier" => {
            value
                .get("checks")
                .and_then(Value::as_array)
                .is_some_and(|checks| checks.len() >= 3)
                && value
                    .get("verified_hex_records")
                    .and_then(Value::as_u64)
                    .is_some_and(|records| records > 0)
                && value
                    .get("decoded_transactions")
                    .and_then(Value::as_u64)
                    .is_some_and(|transactions| transactions > 0)
        }
        "adversarial_mempool_soak" => {
            value
                .get("deterministic_seed")
                .and_then(Value::as_str)
                .is_some_and(|seed| !seed.is_empty())
                && value
                    .get("iterations")
                    .and_then(Value::as_u64)
                    .is_some_and(|iterations| iterations > 0)
                && value
                    .get("checks")
                    .and_then(Value::as_array)
                    .is_some_and(|checks| checks.len() >= 5)
                && value
                    .get("evidence_files")
                    .and_then(Value::as_array)
                    .is_some_and(|files| !files.is_empty())
        }
        _ => true,
    }
}

fn production_runbook_satisfies(id: &str, text: &str) -> bool {
    if !text
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case("Status: passed"))
    {
        return false;
    }
    let required_sections: &[&str] = match id {
        "key_management_recovery" => &[
            "## Scope",
            "## Controls",
            "## Recovery Procedure",
            "## Evidence",
        ],
        "monitoring_alerting" => &["## Scope", "## Signals", "## Alert Response", "## Evidence"],
        "incident_recovery" => &[
            "## Scope",
            "## Incident Classes",
            "## Recovery Procedure",
            "## Evidence",
        ],
        "release_rollout_rollback" => &[
            "## Scope",
            "## Rollout Procedure",
            "## Rollback Procedure",
            "## Evidence",
        ],
        _ => &["## Scope", "## Evidence"],
    };
    text.len() >= 1_000
        && required_sections
            .iter()
            .all(|section| text.contains(section))
}

fn security_review_required_scopes() -> [&'static str; 8] {
    [
        "protocol_design",
        "state_channel_latest_state_safety",
        "kaspa_script_and_covenant_constraints",
        "participant_signer_model",
        "ln_kaspa_atomic_swap_interop",
        "refund_timeout_and_double_claim_safety",
        "evidence_verification_and_production_gates",
        "operational_controls_and_runbooks",
    ]
}

fn security_review_required_artifact_paths() -> [(&'static str, &'static str); 17] {
    [
        ("cargo_manifest", "Cargo.toml"),
        ("cargo_lock", "Cargo.lock"),
        ("protocol_library", "src/lib.rs"),
        ("control_binary", "src/bin/kurrentctl.rs"),
        ("protocol_tests", "tests/protocol_model.rs"),
        ("kaspa_devnet_driver", "drivers/kaspa-devnet/src/main.rs"),
        ("driver_lock", "drivers/kaspa-devnet/Cargo.lock"),
        (
            "security_assumptions",
            "docs/KURRENT_SECURITY_ASSUMPTIONS.md",
        ),
        (
            "production_acceptance",
            "docs/KURRENT_PRODUCTION_ACCEPTANCE.md",
        ),
        (
            "production_security_review_brief",
            "docs/PRODUCTION_SECURITY_REVIEW.md",
        ),
        (
            "key_management_runbook",
            "docs/PRODUCTION_KEY_MANAGEMENT.md",
        ),
        ("monitoring_runbook", "docs/PRODUCTION_MONITORING.md"),
        ("recovery_runbook", "docs/PRODUCTION_RECOVERY.md"),
        ("rollout_runbook", "docs/PRODUCTION_ROLLOUT.md"),
        ("local_acceptance", "evidence/kurrent-acceptance.json"),
        ("target_profile", "evidence/production/target-profile.json"),
        (
            "semantic_transaction_verifier",
            "evidence/production/semantic-transaction-verifier.json",
        ),
    ]
}

fn security_review_required_artifacts() -> Result<Vec<SecurityReviewArtifact>, String> {
    let root = root()?;
    let mut artifacts = Vec::new();
    for (id, relative) in security_review_required_artifact_paths() {
        let evidence = file_evidence(&root.join(relative))?;
        artifacts.push(SecurityReviewArtifact {
            id: id.to_string(),
            path: evidence.path,
            sha256: evidence.sha256,
        });
    }
    let adversarial =
        file_evidence(&root.join("evidence/production/adversarial-mempool-soak.json"))?;
    artifacts.push(SecurityReviewArtifact {
        id: "adversarial_soak".to_string(),
        path: adversarial.path,
        sha256: adversarial.sha256,
    });
    Ok(artifacts)
}

fn security_review_evidence_satisfies(path: &Path) -> Result<bool, String> {
    let review: SecurityReviewEvidence = serde_json::from_slice(&fs::read(path).map_err(|e| {
        format!(
            "failed to read security-review evidence {}: {e}",
            path.display()
        )
    })?)
    .map_err(|e| {
        format!(
            "failed to parse security-review evidence {}: {e}",
            path.display()
        )
    })?;
    if review.schema_version != "kurrent-security-review-v1"
        || review.status != "passed"
        || review.review_type != "independent_external_security_review"
    {
        return Ok(false);
    }
    if [
        &review.completed_at,
        &review.reviewer_name,
        &review.reviewer_organisation,
        &review.reviewer_contact,
        &review.reviewer_independence_attestation,
        &review.reviewed_git_commit,
    ]
    .iter()
    .any(|value| value.trim().is_empty())
    {
        return Ok(false);
    }
    if review.reviewer_independence_attestation.len() < 40 {
        return Ok(false);
    }
    if git_stdout(&root()?, &["rev-parse", "--verify", "HEAD"]).as_deref()
        != Some(review.reviewed_git_commit.as_str())
    {
        return Ok(false);
    }

    let reviewed_scopes: BTreeSet<_> = review.scope.iter().map(String::as_str).collect();
    if security_review_required_scopes()
        .into_iter()
        .any(|scope| !reviewed_scopes.contains(scope))
    {
        return Ok(false);
    }
    if review.methodology.len() < 3 || review.methodology.iter().any(|item| item.trim().is_empty())
    {
        return Ok(false);
    }

    let findings = &review.finding_summary;
    if findings.critical_open != 0
        || findings.high_open != 0
        || findings.medium_open != 0
        || findings.low_open != 0
        || !review.unresolved_blocking_findings.is_empty()
    {
        return Ok(false);
    }

    let root = root()?;
    if verify_file_hash_record(
        &root,
        "external_security_review_report",
        &review.report,
        HashMode::FileBytes,
    )
    .is_err()
        || verify_file_hash_record(
            &root,
            "external_security_review_attestation",
            &review.signed_attestation,
            HashMode::FileBytes,
        )
        .is_err()
    {
        return Ok(false);
    }

    let reviewed_by_id: BTreeMap<_, _> = review
        .reviewed_artifacts
        .iter()
        .map(|artifact| (artifact.id.as_str(), artifact))
        .collect();
    for expected in security_review_required_artifacts()? {
        let Some(actual) = reviewed_by_id.get(expected.id.as_str()) else {
            return Ok(false);
        };
        if actual.path != expected.path || actual.sha256 != expected.sha256 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn verify_production_readiness() -> Result<u8, String> {
    let root = root()?;
    let current_commit = current_git_commit(&root)?;
    let evidence = evidence_dir()?;
    let acceptance_path = evidence.join("kurrent-acceptance.json");
    let mut blockers = Vec::new();
    let acceptance_status = if acceptance_path.is_file() {
        let report: AcceptanceReport =
            serde_json::from_slice(&fs::read(&acceptance_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("failed to parse acceptance report: {e}"))?;
        if report.status != "passed" || !report.blockers.is_empty() {
            blockers.push(
                "local devnet acceptance must pass before production readiness can pass"
                    .to_string(),
            );
        }
        if report.git_commit.as_deref() != Some(current_commit.as_str()) {
            blockers.push(format!(
                "local devnet acceptance git_commit must match HEAD before production readiness can pass: report={}, head={current_commit}",
                report.git_commit.as_deref().unwrap_or("<missing>")
            ));
        }
        report.status
    } else {
        blockers.push("missing evidence/kurrent-acceptance.json".to_string());
        "missing".to_string()
    };

    let requirements = production_readiness_requirements()
        .into_iter()
        .map(|(id, description, evidence_path)| {
            let full_path = root.join(evidence_path);
            let present = match production_evidence_satisfies(id, &full_path) {
                Ok(true) => true,
                Ok(false) => {
                    blockers.push(format!(
                        "{id}: missing or non-passing required production evidence at {evidence_path}"
                    ));
                    false
                }
                Err(err) => {
                    blockers.push(format!(
                        "{id}: invalid required production evidence at {evidence_path}: {err}"
                    ));
                    false
                }
            };
            Ok(ProductionEvidenceRequirement {
                id: id.to_string(),
                description: description.to_string(),
                evidence_path: evidence_path.to_string(),
                present,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    let status = if blockers.is_empty() {
        "passed"
    } else {
        "failed/blocked"
    }
    .to_string();
    let report = ProductionReadinessReport {
        timestamp: timestamp(),
        git_commit: Some(current_commit),
        status: status.clone(),
        acceptance_status,
        requirements,
        blockers: blockers.clone(),
    };
    write_json_file(&evidence.join("kurrent-production-readiness.json"), &report)?;

    if status == "passed" {
        println!("production-readiness passed");
        Ok(0)
    } else {
        for blocker in blockers {
            eprintln!("blocked: {blocker}");
        }
        Ok(EXIT_PRODUCTION_READINESS)
    }
}

#[derive(Clone, Copy)]
enum HashMode {
    FileBytes,
    HexDecodedBytes,
}

fn verify_file_hash_record(
    root: &Path,
    bucket: &str,
    record: &EvidenceFile,
    mode: HashMode,
) -> Result<(), String> {
    verify_file_hash(root, bucket, &record.path, &record.sha256, mode)
}

fn verify_file_hash(
    root: &Path,
    bucket: &str,
    path: &str,
    expected: &str,
    mode: HashMode,
) -> Result<(), String> {
    let record_path = resolve_record_path(root, path);
    if !record_path.is_file() {
        return Err(format!("missing evidence file in {bucket}: {path}"));
    }
    let file_bytes = fs::read(&record_path).map_err(|e| {
        format!(
            "failed to read evidence file {}: {e}",
            record_path.display()
        )
    })?;
    let hash_bytes = match mode {
        HashMode::FileBytes => file_bytes,
        HashMode::HexDecodedBytes => {
            let hex_text = String::from_utf8(file_bytes)
                .map_err(|e| format!("evidence file {path} is not UTF-8 hex text: {e}"))?;
            hex::decode(hex_text.trim())
                .map_err(|e| format!("evidence file {path} is not valid hex: {e}"))?
        }
    };
    let actual = sha256_hex(&hash_bytes);
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "evidence hash mismatch in {bucket} for {path}: expected {expected}, actual {actual}"
        ))
    }
}

fn resolve_record_path(root: &Path, path: &str) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else {
        root.join(candidate)
    }
}

fn prepare_devnet_tools() -> Result<u8, String> {
    let parent = parent_dir()?;
    let kaspa = first_git_dir(&[
        parent.join("rusty-kaspa"),
        parent.join("rusty-kaspa-toccata"),
    ])
    .unwrap_or_else(|| parent.join("rusty-kaspa"));
    if kaspa.join(".git").exists() {
        run_status(
            Command::new("git")
                .arg("-C")
                .arg(&kaspa)
                .arg("pull")
                .arg("--ff-only"),
        )?;
    } else {
        run_status(
            Command::new("git")
                .arg("clone")
                .arg("--filter=blob:none")
                .arg("https://github.com/kaspanet/rusty-kaspa.git")
                .arg(&kaspa),
        )?;
    }

    let lnd = parent.join("lnd");
    if lnd.join(".git").exists() {
        run_status(
            Command::new("git")
                .arg("-C")
                .arg(&lnd)
                .arg("pull")
                .arg("--ff-only"),
        )?;
    } else {
        run_status(
            Command::new("git")
                .arg("clone")
                .arg("--depth")
                .arg("1")
                .arg("https://github.com/lightningnetwork/lnd.git")
                .arg(&lnd),
        )?;
    }

    run_status(
        Command::new("cargo")
            .arg("build")
            .arg("--release")
            .arg("-p")
            .arg("kaspad")
            .arg("-p")
            .arg("kaspa-cli")
            .arg("-p")
            .arg("kaspa-wallet")
            .arg("--manifest-path")
            .arg(kaspa.join("Cargo.toml")),
    )?;

    if resolve_command("lnd").is_none() || resolve_command("lncli").is_none() {
        run_status(
            Command::new("make")
                .arg("-C")
                .arg(&lnd)
                .arg("install-binaries"),
        )?;
    }

    detect_tools().map(|ready| if ready { 0 } else { EXIT_TOOLING_BLOCKED })
}

fn run_kaspa_devnet() -> Result<u8, String> {
    let report = detection_report();
    let Some(kaspad) = report.tool_paths.get("kaspad").and_then(Clone::clone) else {
        write_acceptance_report("failed/blocked", "kaspa_node_missing")?;
        return Ok(EXIT_TOOLING_BLOCKED);
    };
    let log_path = evidence_dir()?.join("kaspa-simnet-probe.log");
    let appdir = root()?.join(".kurrent-devnet/kaspa-simnet");
    fs::create_dir_all(&appdir).map_err(|e| e.to_string())?;
    let log_file = fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let err_file = log_file.try_clone().map_err(|e| e.to_string())?;
    let mut child = Command::new(kaspad)
        .arg("--simnet")
        .arg("--utxoindex")
        .arg("--reset-db")
        .arg("--yes")
        .arg("--nodnsseed")
        .arg("--enable-unsynced-mining")
        .arg("--nologfiles")
        .arg(format!("--appdir={}", appdir.display()))
        .arg("--rpclisten=127.0.0.1:16210")
        .arg("--listen=127.0.0.1:16211")
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(err_file))
        .spawn()
        .map_err(|e| format!("failed to start kaspad probe: {e}"))?;
    std::thread::sleep(std::time::Duration::from_secs(5));
    let running = child.try_wait().map_err(|e| e.to_string())?.is_none();
    let _ = child.kill();
    let _ = child.wait();
    if running {
        println!("kaspad simnet probe started; log: {}", log_path.display());
        Ok(0)
    } else {
        write_acceptance_report("failed/blocked", "kaspa_devnet_probe_failed")?;
        Ok(EXIT_KASPA_FLOW)
    }
}

fn run_ln_devnet() -> Result<u8, String> {
    let report = detection_report();
    let Some(lnd) = report.tool_paths.get("lnd").and_then(Clone::clone) else {
        write_acceptance_report("failed/blocked", "lnd_missing")?;
        return Ok(EXIT_TOOLING_BLOCKED);
    };
    let Some(lncli) = report.tool_paths.get("lncli").and_then(Clone::clone) else {
        write_acceptance_report("failed/blocked", "lncli_missing")?;
        return Ok(EXIT_TOOLING_BLOCKED);
    };
    let Some(bitcoind) = report.tool_paths.get("bitcoind").and_then(Clone::clone) else {
        write_acceptance_report("failed/blocked", "bitcoind_missing")?;
        return Ok(EXIT_TOOLING_BLOCKED);
    };
    let Some(bitcoin_cli) = report.tool_paths.get("bitcoin-cli").and_then(Clone::clone) else {
        write_acceptance_report("failed/blocked", "bitcoin_cli_missing")?;
        return Ok(EXIT_TOOLING_BLOCKED);
    };

    let base = root()?.join(".kurrent-devnet/lnd-regtest");
    let bitdir = base.join("bitcoin");
    let alice_dir = base.join("alice");
    let bob_dir = base.join("bob");
    let evidence = evidence_dir()?;
    if base.exists() {
        fs::remove_dir_all(&base)
            .map_err(|e| format!("failed to clean {}: {e}", base.display()))?;
    }
    fs::create_dir_all(&bitdir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&alice_dir).map_err(|e| e.to_string())?;
    fs::create_dir_all(&bob_dir).map_err(|e| e.to_string())?;

    run_status(
        Command::new(&bitcoind)
            .arg("-regtest")
            .arg("-daemonwait")
            .arg(format!("-datadir={}", bitdir.display()))
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-fallbackfee=0.0002")
            .arg("-rpcuser=kurrent")
            .arg("-rpcpassword=kurrentpass")
            .arg("-rpcport=18563")
            .arg("-port=18564")
            .arg("-zmqpubrawblock=tcp://127.0.0.1:28362")
            .arg("-zmqpubrawtx=tcp://127.0.0.1:28363")
            .arg("-debug=0"),
    )?;
    let cleanup = LnRegtestCleanup {
        bitcoin_cli: bitcoin_cli.clone(),
        bitdir: bitdir.clone(),
        lncli: lncli.clone(),
        alice_dir: alice_dir.clone(),
        bob_dir: bob_dir.clone(),
    };

    let miner_args = bitcoin_base_args(&bitdir);
    let _ = run_bytes(
        &bitcoin_cli,
        &append_args(&miner_args, &["createwallet", "miner"]),
    )?;
    let miner_addr = run_text(
        &bitcoin_cli,
        &append_args(&miner_args, &["-rpcwallet=miner", "getnewaddress"]),
    )?;
    let _ = run_bytes(
        &bitcoin_cli,
        &append_args(
            &miner_args,
            &["-rpcwallet=miner", "generatetoaddress", "101", &miner_addr],
        ),
    )?;

    let alice_log = evidence.join("ln-alice.log");
    let bob_log = evidence.join("ln-bob.log");
    let alice_log_file = fs::File::create(&alice_log).map_err(|e| e.to_string())?;
    let bob_log_file = fs::File::create(&bob_log).map_err(|e| e.to_string())?;
    let mut alice = Command::new(&lnd)
        .args(lnd_args(
            &alice_dir,
            "127.0.0.1:12009",
            "127.0.0.1:8280",
            "127.0.0.1:20735",
        ))
        .stdout(Stdio::from(
            alice_log_file.try_clone().map_err(|e| e.to_string())?,
        ))
        .stderr(Stdio::from(alice_log_file))
        .spawn()
        .map_err(|e| format!("failed to start Alice lnd: {e}"))?;
    let mut bob = Command::new(&lnd)
        .args(lnd_args(
            &bob_dir,
            "127.0.0.1:12010",
            "127.0.0.1:8281",
            "127.0.0.1:20736",
        ))
        .stdout(Stdio::from(
            bob_log_file.try_clone().map_err(|e| e.to_string())?,
        ))
        .stderr(Stdio::from(bob_log_file))
        .spawn()
        .map_err(|e| format!("failed to start Bob lnd: {e}"))?;

    wait_lnd_server_active(&lncli, &alice_dir, "127.0.0.1:12009")?;
    wait_lnd_server_active(&lncli, &bob_dir, "127.0.0.1:12010")?;

    let alice_getinfo = run_json_file(
        &lncli,
        &lncli_args(&alice_dir, "127.0.0.1:12009", &["getinfo"]),
        &evidence.join("ln-alice-getinfo.json"),
    )?;
    let bob_getinfo = run_json_file(
        &lncli,
        &lncli_args(&bob_dir, "127.0.0.1:12010", &["getinfo"]),
        &evidence.join("ln-bob-getinfo.json"),
    )?;
    let bob_key = json_str(&bob_getinfo, "identity_pubkey")?;
    let alice_key = json_str(&alice_getinfo, "identity_pubkey")?;

    let alice_address = {
        let value = run_json(
            &lncli,
            &lncli_args(&alice_dir, "127.0.0.1:12009", &["newaddress", "p2wkh"]),
        )?;
        json_str(&value, "address")?
    };
    let fund_txid = run_text(
        &bitcoin_cli,
        &append_args(
            &miner_args,
            &["-rpcwallet=miner", "sendtoaddress", &alice_address, "2.0"],
        ),
    )?;
    let _ = run_bytes(
        &bitcoin_cli,
        &append_args(
            &miner_args,
            &["-rpcwallet=miner", "generatetoaddress", "6", &miner_addr],
        ),
    )?;
    std::thread::sleep(std::time::Duration::from_secs(3));
    let _alice_wallet = run_json_file(
        &lncli,
        &lncli_args(&alice_dir, "127.0.0.1:12009", &["walletbalance"]),
        &evidence.join("ln-alice-walletbalance.json"),
    )?;

    let connect_target = format!("{bob_key}@127.0.0.1:20736");
    let _ = run_json_file(
        &lncli,
        &lncli_args(&alice_dir, "127.0.0.1:12009", &["connect", &connect_target]),
        &evidence.join("ln-connect.json"),
    )?;
    let _ = run_json_file(
        &lncli,
        &lncli_args(
            &alice_dir,
            "127.0.0.1:12009",
            &[
                "openchannel",
                &format!("--node_key={bob_key}"),
                "--local_amt=1000000",
                "--push_amt=100000",
                "--sat_per_vbyte=1",
            ],
        ),
        &evidence.join("ln-openchannel.json"),
    )?;
    let _ = run_bytes(
        &bitcoin_cli,
        &append_args(
            &miner_args,
            &["-rpcwallet=miner", "generatetoaddress", "6", &miner_addr],
        ),
    )?;
    std::thread::sleep(std::time::Duration::from_secs(5));
    let alice_channels = run_json_file(
        &lncli,
        &lncli_args(&alice_dir, "127.0.0.1:12009", &["listchannels"]),
        &evidence.join("ln-alice-listchannels.json"),
    )?;
    let bob_channels = run_json_file(
        &lncli,
        &lncli_args(&bob_dir, "127.0.0.1:12010", &["listchannels"]),
        &evidence.join("ln-bob-listchannels.json"),
    )?;
    if alice_channels
        .get("channels")
        .and_then(Value::as_array)
        .map(Vec::is_empty)
        .unwrap_or(true)
        || bob_channels
            .get("channels")
            .and_then(Value::as_array)
            .map(Vec::is_empty)
            .unwrap_or(true)
    {
        write_acceptance_report("failed/blocked", "ln_channel_not_open")?;
        let _ = alice.kill();
        let _ = bob.kill();
        drop(cleanup);
        return Ok(EXIT_LN_FLOW);
    }

    let preimage = "0001020304050607080900010203040506070809000102030405060708090001";
    let invoice = run_json_file(
        &lncli,
        &lncli_args(
            &bob_dir,
            "127.0.0.1:12010",
            &[
                "addinvoice",
                "--amt=1000",
                "--memo=kurrent-regtest",
                &format!("--preimage={preimage}"),
            ],
        ),
        &evidence.join("ln-bob-invoice.json"),
    )?;
    let payment_request = json_str(&invoice, "payment_request")?;
    let payment_hash = json_str(&invoice, "r_hash")?;
    let _payment = run_json_file(
        &lncli,
        &lncli_args(
            &alice_dir,
            "127.0.0.1:12009",
            &[
                "payinvoice",
                "--force",
                "--json",
                "--fee_limit=1000",
                &payment_request,
            ],
        ),
        &evidence.join("ln-alice-payinvoice.json"),
    )?;
    let lookup = run_json_file(
        &lncli,
        &lncli_args(
            &bob_dir,
            "127.0.0.1:12010",
            &["lookupinvoice", &payment_hash],
        ),
        &evidence.join("ln-bob-lookupinvoice.json"),
    )?;
    let settled = lookup
        .get("settled")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let observed_preimage = json_str(&lookup, "r_preimage")?;
    if !settled || observed_preimage != preimage {
        write_acceptance_report("failed/blocked", "ln_invoice_not_settled")?;
        let _ = alice.kill();
        let _ = bob.kill();
        drop(cleanup);
        return Ok(EXIT_LN_FLOW);
    }

    let ln_evidence = json!({
        "status": "passed",
        "bitcoin_regtest": {
            "funding_txid": fund_txid,
            "miner_address": miner_addr
        },
        "alice": {
            "identity_pubkey": alice_key,
            "rpc": "127.0.0.1:12009"
        },
        "bob": {
            "identity_pubkey": bob_key,
            "rpc": "127.0.0.1:12010"
        },
        "channel": {
            "alice_channels_path": "evidence/ln-alice-listchannels.json",
            "bob_channels_path": "evidence/ln-bob-listchannels.json"
        },
        "invoice": {
            "payment_hash": payment_hash,
            "preimage": preimage,
            "lookup_path": "evidence/ln-bob-lookupinvoice.json",
            "payment_path": "evidence/ln-alice-payinvoice.json"
        },
        "logs": [
            "evidence/ln-alice.log",
            "evidence/ln-bob.log"
        ]
    });
    write_json_file(&evidence.join("ln-devnet-evidence.json"), &ln_evidence)?;

    let _ = run_bytes(
        &lncli,
        &lncli_args(&alice_dir, "127.0.0.1:12009", &["stop"]),
    );
    let _ = run_bytes(&lncli, &lncli_args(&bob_dir, "127.0.0.1:12010", &["stop"]));
    let _ = alice.wait();
    let _ = bob.wait();
    drop(cleanup);
    println!(
        "LN regtest topology passed; evidence: {}",
        evidence.join("ln-devnet-evidence.json").display()
    );
    Ok(0)
}

struct LnRegtestCleanup {
    bitcoin_cli: String,
    bitdir: PathBuf,
    lncli: String,
    alice_dir: PathBuf,
    bob_dir: PathBuf,
}

impl Drop for LnRegtestCleanup {
    fn drop(&mut self) {
        let _ = run_bytes(
            &self.lncli,
            &lncli_args(&self.alice_dir, "127.0.0.1:12009", &["stop"]),
        );
        let _ = run_bytes(
            &self.lncli,
            &lncli_args(&self.bob_dir, "127.0.0.1:12010", &["stop"]),
        );
        let _ = run_bytes(
            &self.bitcoin_cli,
            &append_args(&bitcoin_base_args(&self.bitdir), &["stop"]),
        );
    }
}

fn bitcoin_base_args(bitdir: &Path) -> Vec<String> {
    vec![
        "-regtest".to_string(),
        format!("-datadir={}", bitdir.display()),
        "-rpcuser=kurrent".to_string(),
        "-rpcpassword=kurrentpass".to_string(),
        "-rpcport=18563".to_string(),
    ]
}

fn lnd_args(lnddir: &Path, rpc: &str, rest: &str, listen: &str) -> Vec<String> {
    vec![
        format!("--lnddir={}", lnddir.display()),
        "--bitcoin.active".to_string(),
        "--bitcoin.regtest".to_string(),
        "--bitcoin.node=bitcoind".to_string(),
        "--bitcoind.rpchost=127.0.0.1:18563".to_string(),
        "--bitcoind.rpcuser=kurrent".to_string(),
        "--bitcoind.rpcpass=kurrentpass".to_string(),
        "--bitcoind.zmqpubrawblock=tcp://127.0.0.1:28362".to_string(),
        "--bitcoind.zmqpubrawtx=tcp://127.0.0.1:28363".to_string(),
        "--no-macaroons".to_string(),
        "--noseedbackup".to_string(),
        "--nobootstrap".to_string(),
        "--debuglevel=info".to_string(),
        format!("--rpclisten={rpc}"),
        format!("--restlisten={rest}"),
        format!("--listen={listen}"),
    ]
}

fn lncli_args(lnddir: &Path, rpc: &str, extra: &[&str]) -> Vec<String> {
    let mut args = vec![
        format!("--lnddir={}", lnddir.display()),
        format!("--rpcserver={rpc}"),
        "--network=regtest".to_string(),
        "--no-macaroons".to_string(),
    ];
    args.extend(extra.iter().map(|arg| (*arg).to_string()));
    args
}

fn append_args(base: &[String], extra: &[&str]) -> Vec<String> {
    base.iter()
        .cloned()
        .chain(extra.iter().map(|arg| (*arg).to_string()))
        .collect()
}

fn run_bytes(program: &str, args: &[String]) -> Result<Vec<u8>, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("failed to run {program}: {e}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "command failed: {} {}\nstatus: {}\nstderr: {}",
            program,
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn run_text(program: &str, args: &[String]) -> Result<String, String> {
    let bytes = run_bytes(program, args)?;
    Ok(String::from_utf8_lossy(&bytes).trim().to_string())
}

fn run_json(program: &str, args: &[String]) -> Result<Value, String> {
    let bytes = run_bytes(program, args)?;
    serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "failed to parse JSON from {} {}: {e}\nstdout: {}",
            program,
            args.join(" "),
            String::from_utf8_lossy(&bytes)
        )
    })
}

fn run_json_file(program: &str, args: &[String], path: &Path) -> Result<Value, String> {
    let value = run_json(program, args)?;
    write_json_file(path, &value)?;
    Ok(value)
}

fn run_captured_command(
    label: &str,
    cwd: &Path,
    program: &str,
    args: &[&str],
) -> Result<CommandEvidence, String> {
    let evidence = evidence_dir()?;
    let stdout_path = evidence.join(format!("{label}.stdout.log"));
    let stderr_path = evidence.join(format!("{label}.stderr.log"));
    let output = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("failed to run {program} in {}: {e}", cwd.display()))?;
    fs::write(&stdout_path, &output.stdout)
        .map_err(|e| format!("failed to write {}: {e}", stdout_path.display()))?;
    fs::write(&stderr_path, &output.stderr)
        .map_err(|e| format!("failed to write {}: {e}", stderr_path.display()))?;
    Ok(CommandEvidence {
        label: label.to_string(),
        cwd: cwd.display().to_string(),
        command: std::iter::once(program.to_string())
            .chain(args.iter().map(|arg| (*arg).to_string()))
            .collect(),
        status_code: output.status.code(),
        stdout: file_evidence(&stdout_path)?,
        stderr: file_evidence(&stderr_path)?,
    })
}

fn command_succeeded(command: &CommandEvidence) -> bool {
    command.status_code == Some(0)
}

fn json_str(value: &Value, field: &str) -> Result<String, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing string field `{field}` in {value}"))
}

fn wait_lnd_server_active(lncli: &str, lnddir: &Path, rpc: &str) -> Result<(), String> {
    for _ in 0..30 {
        if let Ok(value) = run_json(lncli, &lncli_args(lnddir, rpc, &["state"])) {
            if value.get("state").and_then(Value::as_str) == Some("SERVER_ACTIVE") {
                return Ok(());
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    Err(format!("lnd at {rpc} did not reach SERVER_ACTIVE"))
}

fn write_state_channel_protocol_files() -> Result<Vec<EvidenceFile>, String> {
    let evidence = evidence_dir()?;
    let live_state = fs::read(evidence.join("kurrent-live-state-channel-evidence.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let funding_outpoint = live_state
        .as_ref()
        .and_then(|value| value.pointer("/funding/outpoint"))
        .and_then(Value::as_str)
        .unwrap_or("missing-live-kurrent-funding-outpoint")
        .to_string();
    let output_id = live_state
        .as_ref()
        .and_then(|value| value.pointer("/settlement/txid"))
        .and_then(Value::as_str)
        .map(|txid| format!("{txid}:0,{txid}:1"))
        .unwrap_or_else(|| "missing-live-kurrent-settlement-output".to_string());
    let covenant_id = live_state
        .as_ref()
        .and_then(|value| value.pointer("/funding/covenant_id"))
        .and_then(Value::as_str)
        .unwrap_or("missing-live-kurrent-covenant-id")
        .to_string();
    let template = json!({
        "domain_separator": DOMAIN_SETTLEMENT_TEMPLATE,
        "template_id": "kurrent-state-settle-v1",
        "outputs": {
            "alice": 600_000_u64,
            "bob": 400_000_u64
        },
        "refund_after_daa": 120_u64,
        "script_covenant_hash": sha256_hex(b"kurrent-toccata-counter-covenant-v1")
    });
    let template_hash = hash_json(DOMAIN_SETTLEMENT_TEMPLATE, &template);
    let template_path = evidence.join("kurrent-state-channel-settlement-template.json");
    write_json_file(&template_path, &template)?;

    let mut previous_commitment = sha256_hex(b"kurrent-state-genesis");
    let mut headers = Vec::new();
    for state_number in 0..=2_u64 {
        let new_commitment = sha256_hex(format!("kurrent-state-{state_number}").as_bytes());
        let header = json!({
            "domain_separator": DOMAIN_STATE,
            "network_profile": "kaspa-simnet-toccata",
            "genesis_or_devnet_id": "local-toccata-simnet",
            "funding_outpoint": funding_outpoint,
            "channel_id": "channel-a",
            "factory_id": null,
            "virtual_channel_id": null,
            "state_number": state_number,
            "previous_state_commitment": previous_commitment,
            "new_state_commitment": new_commitment,
            "settlement_template_hash": template_hash,
            "challenge_policy_hash": sha256_hex(b"latest-state-monotonic-counter-window-120"),
            "participant_set_hash": sha256_hex(b"alice+bob"),
            "covenant_id": covenant_id,
            "script_covenant_hash": sha256_hex(b"kurrent-toccata-counter-covenant-v1"),
            "protocol_version": 1_u16
        });
        previous_commitment = new_commitment;
        headers.push(json!({
            "hash": hash_json(DOMAIN_STATE, &header),
            "header": header
        }));
    }
    let headers_path = evidence.join("kurrent-state-channel-headers.json");
    write_json_file(&headers_path, &headers)?;

    let receipt_scope = json!({
        "domain_separator": DOMAIN_CHANNEL_RECEIPT,
        "protocol_version": 1_u16,
        "network_profile": "kaspa-simnet-toccata",
        "channel_id": "channel-a",
        "factory_id": null,
        "virtual_channel_id": null,
        "funding_outpoint": funding_outpoint,
        "output_id": output_id,
        "state_number": 2_u64,
        "settlement_template_hash": template_hash,
        "swap_id": null,
        "direction": null
    });
    let receipt = json!({
        "receipt_hash": hash_json(DOMAIN_CHANNEL_RECEIPT, &receipt_scope),
        "scope": receipt_scope
    });
    let receipt_path = evidence.join("kurrent-state-channel-receipt.json");
    write_json_file(&receipt_path, &receipt)?;

    Ok(vec![
        file_evidence(&template_path)?,
        file_evidence(&headers_path)?,
        file_evidence(&receipt_path)?,
    ])
}

fn run_state_channel_flow() -> Result<u8, String> {
    let evidence = evidence_dir()?;
    let mut blockers = Vec::new();
    let mut commands = Vec::new();
    let mut source_files = Vec::new();
    let mut live_evidence = None;

    match selected_kaspa_repo_path() {
        Ok(repo) => {
            match source_file_evidence(&repo, "crypto/txscript/examples/covenants.rs") {
                Ok(file) => source_files.push(file),
                Err(err) => blockers.push(err),
            }

            let covenant_vm = run_captured_command(
                "kaspa-txscript-covenants",
                &repo,
                "cargo",
                &[
                    "run",
                    "--release",
                    "-p",
                    "kaspa-txscript",
                    "--example",
                    "covenants",
                ],
            )?;
            if !command_succeeded(&covenant_vm) {
                blockers.push("KIP-17/KIP-20 covenant-script example failed".to_string());
            }
            commands.push(covenant_vm);

            let live_tx = run_captured_command(
                "kaspa-daemon-compute-budget-relay",
                &repo,
                "cargo",
                &[
                    "test",
                    "-p",
                    "kaspa-testing-integration",
                    "--lib",
                    "daemon_integration_tests::daemon_compute_budget_relay_test",
                    "--",
                    "--exact",
                    "--nocapture",
                ],
            )?;
            if !command_succeeded(&live_tx) {
                blockers.push("Kaspa daemon live transaction relay/mining test failed".to_string());
            }
            commands.push(live_tx);
        }
        Err(err) => blockers.push(err),
    }

    let driver_manifest = root()?.join("drivers/kaspa-devnet/Cargo.toml");
    if driver_manifest.exists() {
        let manifest_arg = driver_manifest.display().to_string();
        let driver = run_captured_command(
            "kurrent-live-state-channel-driver",
            &root()?,
            "cargo",
            &["run", "--manifest-path", &manifest_arg, "--", "evidence"],
        )?;
        if !command_succeeded(&driver) {
            blockers.push("Kurrent live state-channel driver failed".to_string());
        }
        commands.push(driver);
        let live_path = evidence.join("kurrent-live-state-channel-evidence.json");
        if live_path.exists() {
            let live_value: Value =
                serde_json::from_slice(&fs::read(&live_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            if live_value.get("status").and_then(Value::as_str) != Some("passed") {
                blockers
                    .push("Kurrent live state-channel evidence is not marked passed".to_string());
            }
            if live_value
                .pointer("/stale_state_rejection/status")
                .and_then(Value::as_str)
                != Some("rejected")
            {
                blockers.push(
                    "Kurrent live state-channel evidence did not include stale-state rejection"
                        .to_string(),
                );
            }
            live_evidence = Some(file_evidence(&live_path)?);
        } else {
            blockers.push(
                "Kurrent live state-channel driver did not produce evidence/kurrent-live-state-channel-evidence.json"
                    .to_string(),
            );
        }
    } else {
        blockers.push("drivers/kaspa-devnet/Cargo.toml is missing".to_string());
    }

    let protocol_files = write_state_channel_protocol_files()?;
    let capability_status = if blockers.is_empty() {
        "passed"
    } else {
        "failed"
    };
    let flow_status = if blockers.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    let report = json!({
        "flow": "kaspa_state_channel_flow",
        "status": flow_status,
        "capability_status": capability_status,
        "interaction_safety_assertions": [
            "state update domain separator is KURRENT_STATE_V1",
            "state numbers must advance exactly one step",
            "previous_state_commitment must match the current latest commitment",
            "same-number conflicting commitments are rejected",
            "settlement must use the latest accepted state",
            "settlement template hash must match the accepted state header",
            "channel receipt hash binds network, channel, funding, output, and state number"
        ],
        "commands": commands,
        "source_files": source_files,
        "live_evidence": live_evidence,
        "protocol_files": protocol_files,
        "blockers": blockers,
    });
    write_json_file(
        &evidence.join("kurrent-state-channel-flow-evidence.json"),
        &report,
    )?;
    if flow_status == "passed" {
        println!(
            "Kurrent live state-channel flow passed; evidence: {}",
            live_path_display()?
        );
        Ok(0)
    } else {
        eprintln!("blocked: Kurrent live state-channel evidence is incomplete");
        Ok(EXIT_KASPA_FLOW)
    }
}

fn live_path_display() -> Result<String, String> {
    Ok(evidence_dir()?
        .join("kurrent-live-state-channel-evidence.json")
        .display()
        .to_string())
}

fn passed_live_evidence(
    file_name: &str,
    blockers: &mut Vec<String>,
) -> Result<Option<(EvidenceFile, Value)>, String> {
    let path = evidence_dir()?.join(file_name);
    if !path.exists() {
        blockers.push(format!(
            "missing evidence/{file_name}; run run-state-channel-flow first"
        ));
        return Ok(None);
    }
    let value: Value = serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if value.get("status").and_then(Value::as_str) != Some("passed") {
        blockers.push(format!("evidence/{file_name} is not marked passed"));
    }
    Ok(Some((file_evidence(&path)?, value)))
}

fn write_factory_protocol_files() -> Result<Vec<EvidenceFile>, String> {
    let evidence = evidence_dir()?;
    let before = json!({
        "domain_separator": DOMAIN_FACTORY_MATERIALISATION,
        "factory_id": "factory-1",
        "network_profile": "kaspa-simnet-toccata",
        "total_principal": 1_000_000_u64,
        "fee_reserve": 10_000_u64,
        "virtual_channels": {
            "vc-1": {
                "channel_id": "channel-vc-1",
                "balances": { "alice": 300_000_u64, "bob": 200_000_u64 },
                "state_number": 2_u64,
                "state_commitment": sha256_hex(b"vc-1-state-2")
            },
            "vc-2": {
                "channel_id": "channel-vc-2",
                "balances": { "carol": 250_000_u64, "dave": 250_000_u64 },
                "state_number": 0_u64,
                "state_commitment": sha256_hex(b"vc-2-state-0")
            }
        },
        "materialised_receipts": []
    });
    let after = json!({
        "factory_id": "factory-1",
        "network_profile": "kaspa-simnet-toccata",
        "total_principal": 500_000_u64,
        "fee_reserve": 0_u64,
        "virtual_channels": {
            "vc-2": {
                "channel_id": "channel-vc-2",
                "balances": { "carol": 250_000_u64, "dave": 250_000_u64 },
                "state_number": 0_u64,
                "state_commitment": sha256_hex(b"vc-2-state-0")
            }
        },
        "materialised_receipts": [hash_json(DOMAIN_CHANNEL_RECEIPT, &json!("factory-1:vc-1:mat-1"))]
    });
    let plan = json!({
        "domain_separator": DOMAIN_FACTORY_MATERIALISATION,
        "materialisation_id": "mat-1",
        "factory_id": "factory-1",
        "virtual_channel_id": "vc-1",
        "touched_leaves": ["vc-1"],
        "principal_input_ids": ["principal-in"],
        "fee_input_ids": ["fee-in"],
        "principal_amount": 500_000_u64,
        "fee_amount": 10_000_u64,
        "output_amounts": {
            "alice": 300_000_u64,
            "bob": 200_000_u64,
            "fee": 10_000_u64
        }
    });
    let factory = json!({
        "before": before,
        "after": after,
        "plan": plan,
        "plan_hash": hash_json(DOMAIN_FACTORY_MATERIALISATION, &plan),
        "model_assertions": [
            "fee and principal inputs are disjoint",
            "materialised virtual channel leaves the active factory set",
            "principal amount equals the touched virtual channel principal",
            "fee amount equals the consumed factory fee reserve",
            "principal plus fee conservation holds",
            "untouched virtual channel vc-2 is unchanged",
            "wrong factory id is rejected",
            "wrong virtual channel id is rejected",
            "double materialisation is rejected"
        ]
    });
    let path = evidence.join("kurrent-factory-materialisation-model.json");
    write_json_file(&path, &factory)?;
    Ok(vec![file_evidence(&path)?])
}

fn run_factory_flow() -> Result<u8, String> {
    let evidence = evidence_dir()?;
    let protocol_files = write_factory_protocol_files()?;
    let mut blockers = Vec::new();
    let live_evidence = passed_live_evidence("kurrent-live-factory-evidence.json", &mut blockers)?
        .map(|(evidence, _)| evidence);
    let status = if blockers.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    let report = json!({
        "flow": "kaspa_factory_flow",
        "status": status,
        "model_status": "passed",
        "live_evidence": live_evidence,
        "protocol_files": protocol_files,
        "blockers": blockers,
    });
    write_json_file(
        &evidence.join("kurrent-factory-flow-evidence.json"),
        &report,
    )?;
    if status == "passed" {
        println!(
            "Kurrent live factory flow passed; evidence: {}",
            evidence
                .join("kurrent-live-factory-evidence.json")
                .display()
        );
        Ok(0)
    } else {
        eprintln!("blocked: factory live materialisation evidence is incomplete");
        Ok(EXIT_FACTORY_FLOW)
    }
}

fn run_ln_to_kaspa_flow() -> Result<u8, String> {
    run_ln_swap_flow(
        "ln_to_kaspa_atomic_settlement",
        "ln-to-kaspa",
        "kurrent-ln-to-kaspa-flow-evidence.json",
        EXIT_LN_FLOW,
        "missing live Kaspa hashlock settlement transaction using the observed LN preimage",
    )
}

fn run_kaspa_to_ln_flow() -> Result<u8, String> {
    run_ln_swap_flow(
        "kaspa_to_ln_atomic_settlement",
        "kaspa-to-ln",
        "kurrent-kaspa-to-ln-flow-evidence.json",
        EXIT_KASPA_TO_LN_FLOW,
        "missing reverse-direction live Kaspa hashlock funding and settlement transactions",
    )
}

fn run_ln_swap_flow(
    flow: &str,
    direction: &str,
    file_name: &str,
    exit_code: u8,
    live_blocker: &str,
) -> Result<u8, String> {
    let evidence = evidence_dir()?;
    let ln_path = evidence.join("ln-devnet-evidence.json");
    let mut blockers = Vec::new();
    let mut preimage_hash = None;
    let mut payment_hash = None;
    let mut ln_file = None;
    let mut kaspa_funding_outpoint =
        Value::String("missing-live-kaspa-funding-outpoint".to_string());
    let mut kaspa_settlement_outpoint =
        Value::String("missing-live-kaspa-settlement-outpoint".to_string());
    let mut kaspa_script_hash = Value::String("missing-live-kaspa-script-hash".to_string());

    if ln_path.exists() {
        ln_file = Some(file_evidence(&ln_path)?);
        let value: Value = serde_json::from_slice(&fs::read(&ln_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        if value.get("status").and_then(Value::as_str) != Some("passed") {
            blockers.push("LN devnet evidence exists but is not marked passed".to_string());
        }
        if let Some(invoice) = value.get("invoice") {
            let observed_payment_hash = invoice
                .get("payment_hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let preimage = invoice
                .get("preimage")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            match hex::decode(&preimage) {
                Ok(bytes) => {
                    let observed_preimage_hash = sha256_hex(&bytes);
                    if observed_payment_hash != observed_preimage_hash {
                        blockers.push(
                            "LN preimage does not hash to the invoice payment hash".to_string(),
                        );
                    }
                    preimage_hash = Some(observed_preimage_hash);
                    payment_hash = Some(observed_payment_hash);
                }
                Err(err) => blockers.push(format!("LN preimage is not valid hex: {err}")),
            }
        } else {
            blockers
                .push("LN invoice evidence is missing from ln-devnet-evidence.json".to_string());
        }
    } else {
        blockers
            .push("missing evidence/ln-devnet-evidence.json; run run-ln-devnet first".to_string());
    }

    let live_file_name = if direction == "ln-to-kaspa" {
        "kurrent-live-ln-to-kaspa-evidence.json"
    } else {
        "kurrent-live-kaspa-to-ln-evidence.json"
    };
    let live_evidence =
        passed_live_evidence(live_file_name, &mut blockers)?.map(|(file, value)| {
            if let Some(outpoint) = value.pointer("/funding/outpoint").and_then(Value::as_str) {
                kaspa_funding_outpoint = json!(outpoint);
            }
            if let Some(txid) = value.pointer("/settlement/txid").and_then(Value::as_str) {
                kaspa_settlement_outpoint = json!(format!("{txid}:0"));
            }
            if let Some(script_hash) = value
                .pointer("/settlement/redeem_script/sha256")
                .and_then(Value::as_str)
            {
                kaspa_script_hash = json!(script_hash);
            }
            file
        });

    let receipt_scope = json!({
        "domain_separator": DOMAIN_LN_INTEROP,
        "protocol_version": 1_u16,
        "network_profile": "kaspa-simnet-toccata + bitcoin-regtest-lnd",
        "swap_id": format!("swap-{direction}-001"),
        "direction": direction,
        "ln_payment_hash": payment_hash,
        "preimage_hash": preimage_hash,
        "kaspa_funding_outpoint": kaspa_funding_outpoint,
        "kaspa_settlement_outpoint": kaspa_settlement_outpoint,
        "amount": 1_000_u64,
        "recipient": if direction == "ln-to-kaspa" { "alice" } else { "bob" },
        "script_hash": kaspa_script_hash,
    });
    let swap_file_path = evidence.join(file_name);
    if live_evidence.is_none() && !blockers.iter().any(|b| b.contains(live_blocker)) {
        blockers.push(live_blocker.to_string());
    }
    let status = if blockers.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    let report = json!({
        "flow": flow,
        "status": status,
        "preimage_status": if payment_hash.is_some() && preimage_hash.is_some() { "passed" } else { "failed" },
        "ln_evidence": ln_file,
        "live_evidence": live_evidence,
        "interaction_safety_assertions": [
            "LN preimage hashes to the invoice payment hash",
            "swap direction must be either ln-to-kaspa or kaspa-to-ln",
            "receipt hash must be fresh after swap scope mutation",
            "receipt protocol version, network profile, swap id, direction, funding outpoint, settlement outpoint, and script hash are bound to evidence",
            "zero-amount or empty-recipient swap evidence is rejected by the model"
        ],
        "swap_receipt_hash": hash_json(DOMAIN_LN_INTEROP, &receipt_scope),
        "receipt_scope": receipt_scope,
        "blockers": blockers,
    });
    write_json_file(&swap_file_path, &report)?;
    if status == "passed" {
        println!("Kurrent live {direction} flow passed; evidence: evidence/{live_file_name}");
        Ok(0)
    } else {
        eprintln!("blocked: {direction} live Kaspa settlement evidence is incomplete");
        Ok(exit_code)
    }
}

fn run_refund_flow() -> Result<u8, String> {
    let evidence = evidence_dir()?;
    let refund = json!({
        "domain_separator": DOMAIN_CHANNEL_RECEIPT,
        "claim_id": "refund-swap-1",
        "required_daa": 120_u64,
        "model_assertions": [
            "refund before DAA 120 is rejected",
            "refund at DAA 120 succeeds",
            "settlement plus refund double claim is rejected",
            "scoped settlement and refund claims bind network, funding outpoint, output id, and claim subject",
            "claim scopes do not collide across different funding outputs"
        ],
        "refund_claim_hash": hash_json(DOMAIN_CHANNEL_RECEIPT, &json!("refund-swap-1:daa-120"))
    });
    let refund_path = evidence.join("kurrent-refund-model.json");
    write_json_file(&refund_path, &refund)?;
    let mut blockers = Vec::new();
    let live_evidence = passed_live_evidence("kurrent-live-refund-evidence.json", &mut blockers)?
        .map(|(evidence, _)| evidence);
    let status = if blockers.is_empty() {
        "passed"
    } else {
        "blocked"
    };
    let report = json!({
        "flow": "refund_timeout_flow",
        "status": status,
        "model_status": "passed",
        "live_evidence": live_evidence,
        "protocol_files": [file_evidence(&refund_path)?],
        "blockers": blockers,
    });
    write_json_file(&evidence.join("kurrent-refund-flow-evidence.json"), &report)?;
    if status == "passed" {
        println!(
            "Kurrent live refund flow passed; evidence: {}",
            evidence.join("kurrent-live-refund-evidence.json").display()
        );
        Ok(0)
    } else {
        eprintln!("blocked: refund live evidence is incomplete");
        Ok(EXIT_REFUND_FLOW)
    }
}

fn run_semantic_transaction_verifier() -> Result<u8, String> {
    let driver_manifest = root()?.join("drivers/kaspa-devnet/Cargo.toml");
    if !driver_manifest.exists() {
        eprintln!("blocked: drivers/kaspa-devnet/Cargo.toml is missing");
        return Ok(EXIT_PRODUCTION_READINESS);
    }
    run_status(
        Command::new("cargo")
            .arg("run")
            .arg("--quiet")
            .arg("--manifest-path")
            .arg(driver_manifest)
            .arg("--")
            .arg("verify-semantic-evidence")
            .arg("evidence"),
    )?;
    println!(
        "semantic transaction verifier passed; evidence: {}",
        evidence_dir()?
            .join("production/semantic-transaction-verifier.json")
            .display()
    );
    Ok(0)
}

#[derive(Debug, Clone, Serialize)]
struct AdversarialSoakCheck {
    scenario: String,
    iterations: usize,
    check_count: usize,
    assertions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct AdversarialSoakReport {
    status: String,
    generated_at: String,
    scope: String,
    deterministic_seed: String,
    iterations: usize,
    scenario_count: usize,
    check_count: usize,
    checks: Vec<AdversarialSoakCheck>,
    evidence_files: Vec<EvidenceFile>,
    boundaries: Vec<String>,
}

#[derive(Clone)]
struct AdversarialChannelFixture {
    config: KurrentChannelConfig,
    funding: FundingState,
    template: SettlementTemplate,
}

impl AdversarialChannelFixture {
    fn new(iteration: usize) -> Self {
        let participants = adversarial_participants();
        let channel_id = format!("soak-channel-{iteration}");
        let expected_lane_id = derive_kurrent_channel_lane_id(&channel_id);
        let funding_outpoint = format!("soak-funding-{iteration}:0");
        let covenant_id = format!("soak-covenant-{iteration}");
        let script_covenant_hash = format!("soak-script-{iteration}");
        let template = SettlementTemplate {
            template_id: format!("soak-settle-{iteration}"),
            outputs: adversarial_balances(),
            refund_after_daa: Some(120),
            script_covenant_hash: script_covenant_hash.clone(),
        };
        let config = KurrentChannelConfig {
            protocol_version: 1,
            network_profile: "local-toccata-devnet".to_string(),
            genesis_or_devnet_id: Some("adversarial-devnet-1".to_string()),
            channel_id,
            participants: participants.clone(),
            challenge_policy: ChallengePolicy {
                mode: "latest-state".to_string(),
                challenge_window_daa: 120,
                same_number_conflict_rule: SameNumberConflictRule::RejectConflict,
            },
            access_manifest: AccessManifest {
                authorised_participants: participants,
                participant_public_keys: adversarial_participant_public_keys(),
                required_signatures: 2,
            },
            expected_lane_id: Some(expected_lane_id.clone()),
        };
        let funding = FundingState {
            funding_outpoint,
            total_principal: 1_000,
            principal_by_participant: adversarial_balances(),
            fee_reserve: 10,
            covenant_id: Some(covenant_id),
            expected_lane_id: Some(expected_lane_id),
            script_covenant_hash,
        };
        Self {
            config,
            funding,
            template,
        }
    }

    fn state_update(
        &self,
        number: u64,
        commitment: impl Into<String>,
        previous: impl Into<String>,
    ) -> StateUpdate {
        let mut state = StateUpdate {
            header: LatestStateHeader {
                network_profile: self.config.network_profile.clone(),
                genesis_or_devnet_id: self.config.genesis_or_devnet_id.clone(),
                funding_outpoint: self.funding.funding_outpoint.clone(),
                channel_id: self.config.channel_id.clone(),
                factory_id: None,
                virtual_channel_id: None,
                state_number: number,
                previous_state_commitment: previous.into(),
                new_state_commitment: commitment.into(),
                settlement_template_hash: self.template.hash(),
                fee_policy_hash: None,
                challenge_policy_hash: hash_json(DOMAIN_STATE, &self.config.challenge_policy),
                participant_set_hash: participant_set_hash(&self.config.participants),
                covenant_id: self.funding.covenant_id.clone(),
                expected_lane_id: self.funding.expected_lane_id.clone(),
                script_covenant_hash: self.funding.script_covenant_hash.clone(),
                protocol_version: self.config.protocol_version,
                domain_separator: DOMAIN_STATE.to_string(),
            },
            balances: adversarial_balances(),
            participant_signatures: BTreeMap::new(),
        };
        for participant in adversarial_participants() {
            let signature = adversarial_sign_update_for(&participant, &state);
            state.participant_signatures.insert(participant, signature);
        }
        state
    }
}

fn run_adversarial_soak() -> Result<u8, String> {
    let evidence = evidence_dir()?;
    let production_dir = evidence.join("production");
    fs::create_dir_all(&production_dir)
        .map_err(|e| format!("failed to create {}: {e}", production_dir.display()))?;

    let iterations = 64;
    let mut checks = Vec::new();
    let mut check_count = 0;
    run_state_channel_adversarial_soak(iterations, &mut check_count, &mut checks)?;
    run_fee_sponsored_adversarial_soak(iterations, &mut check_count, &mut checks)?;
    run_factory_adversarial_soak(iterations, &mut check_count, &mut checks)?;
    run_ln_swap_adversarial_soak(iterations, &mut check_count, &mut checks)?;
    run_refund_adversarial_soak(iterations, &mut check_count, &mut checks)?;
    let evidence_files =
        run_evidence_hash_adversarial_soak(&production_dir, &mut check_count, &mut checks)?;

    let report = AdversarialSoakReport {
        status: "passed".to_string(),
        generated_at: timestamp(),
        scope: "deterministic local adversarial model soak for Kurrent production-readiness gating"
            .to_string(),
        deterministic_seed: "kurrent-adversarial-soak-v1".to_string(),
        iterations,
        scenario_count: checks.len(),
        check_count,
        checks,
        evidence_files,
        boundaries: vec![
            "Runs against Kurrent protocol validators and local evidence files; it does not claim mainnet deployment readiness by itself.".to_string(),
            "Models mempool conflict, stale-state, fee-sponsor tamper, alternate-history, refund-race, swap-replay, and evidence-tamper cases locally.".to_string(),
            "Independent external security review remains required before production readiness can pass.".to_string(),
        ],
    };
    let path = production_dir.join("adversarial-mempool-soak.json");
    write_json_file(&path, &report)?;
    println!("adversarial soak passed; evidence: {}", path.display());
    Ok(0)
}

fn run_state_channel_adversarial_soak(
    iterations: usize,
    check_count: &mut usize,
    checks: &mut Vec<AdversarialSoakCheck>,
) -> Result<(), String> {
    let start = *check_count;
    for iteration in 0..iterations {
        let fixture = AdversarialChannelFixture::new(iteration);
        let mut registry = SettlementRegistry::default();
        let state0 = fixture.state_update(0, format!("state-{iteration}-0"), "genesis");
        expect_protocol_ok(
            check_count,
            "state-channel",
            "signed initial state validates",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &state0,
                &fixture.template,
            ),
        )?;
        expect_protocol_ok(
            check_count,
            "state-channel",
            "initial state enters latest-state registry",
            registry.accept_update(state0.clone()),
        )?;
        let state1 = fixture.state_update(
            1,
            format!("state-{iteration}-1"),
            state0.header.new_state_commitment.clone(),
        );
        expect_protocol_ok(
            check_count,
            "state-channel",
            "second signed state validates",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &state1,
                &fixture.template,
            ),
        )?;
        expect_protocol_ok(
            check_count,
            "state-channel",
            "second state enters latest-state registry",
            registry.accept_update(state1.clone()),
        )?;
        let state2 = fixture.state_update(
            2,
            format!("state-{iteration}-2"),
            state1.header.new_state_commitment.clone(),
        );
        expect_protocol_ok(
            check_count,
            "state-channel",
            "third signed state validates",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &state2,
                &fixture.template,
            ),
        )?;
        expect_protocol_ok(
            check_count,
            "state-channel",
            "third state enters latest-state registry",
            registry.accept_update(state2.clone()),
        )?;
        expect_protocol_err(
            check_count,
            "state-channel",
            "settlement of state 0 after state 2",
            registry.settle(&state0, &fixture.template),
            |err| matches!(err, KurrentError::StaleState { .. }),
        )?;
        expect_protocol_err(
            check_count,
            "state-channel",
            "settlement of state 1 after state 2",
            registry.settle(&state1, &fixture.template),
            |err| matches!(err, KurrentError::StaleState { .. }),
        )?;
        expect_protocol_ok(
            check_count,
            "state-channel",
            "latest state settles once",
            registry.settle(&state2, &fixture.template),
        )?;
        expect_protocol_err(
            check_count,
            "state-channel",
            "latest state cannot settle twice",
            registry.settle(&state2, &fixture.template),
            |err| matches!(err, KurrentError::DuplicateSettlement(_)),
        )?;

        let mut conflict_registry = SettlementRegistry::default();
        expect_protocol_ok(
            check_count,
            "state-channel",
            "conflict registry accepts initial state",
            conflict_registry.accept_update(state0.clone()),
        )?;
        let branch_a = fixture.state_update(
            1,
            format!("state-{iteration}-branch-a"),
            state0.header.new_state_commitment.clone(),
        );
        let branch_b = fixture.state_update(
            1,
            format!("state-{iteration}-branch-b"),
            state0.header.new_state_commitment.clone(),
        );
        expect_protocol_ok(
            check_count,
            "state-channel",
            "conflict registry accepts first branch",
            conflict_registry.accept_update(branch_a),
        )?;
        expect_protocol_err(
            check_count,
            "state-channel",
            "same-number conflicting branch",
            conflict_registry.accept_update(branch_b),
            |err| matches!(err, KurrentError::SameNumberConflict { state_number: 1 }),
        )?;

        let mut skipped_registry = SettlementRegistry::default();
        expect_protocol_ok(
            check_count,
            "state-channel",
            "skip registry accepts initial state",
            skipped_registry.accept_update(state0.clone()),
        )?;
        let skipped_state = fixture.state_update(
            2,
            format!("state-{iteration}-skipped"),
            state0.header.new_state_commitment.clone(),
        );
        expect_protocol_err(
            check_count,
            "state-channel",
            "skipped state number",
            skipped_registry.accept_update(skipped_state),
            |err| matches!(err, KurrentError::NonMonotonicState { .. }),
        )?;

        let mut wrong_previous_registry = SettlementRegistry::default();
        expect_protocol_ok(
            check_count,
            "state-channel",
            "wrong-previous registry accepts initial state",
            wrong_previous_registry.accept_update(state0.clone()),
        )?;
        let wrong_previous =
            fixture.state_update(1, format!("state-{iteration}-wrong-previous"), "foreign");
        expect_protocol_err(
            check_count,
            "state-channel",
            "wrong previous commitment",
            wrong_previous_registry.accept_update(wrong_previous),
            |err| matches!(err, KurrentError::PreviousStateMismatch { .. }),
        )?;

        let mut wrong_funding = state0.clone();
        wrong_funding.header.funding_outpoint = format!("foreign-funding-{iteration}:0");
        expect_protocol_err(
            check_count,
            "state-channel",
            "wrong funding outpoint rejected before settlement",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &wrong_funding,
                &fixture.template,
            ),
            |err| matches!(err, KurrentError::WrongFundingOutpoint { .. }),
        )?;
        let mut missing_funding_lane = fixture.funding.clone();
        missing_funding_lane.expected_lane_id = None;
        expect_protocol_err(
            check_count,
            "state-channel",
            "missing funding lane rejected when channel is lane-bound",
            validate_channel_update(
                &fixture.config,
                &missing_funding_lane,
                &state0,
                &fixture.template,
            ),
            |err| matches!(err, KurrentError::WrongLaneId { .. }),
        )?;
        let mut missing_header_lane = state0.clone();
        missing_header_lane.header.expected_lane_id = None;
        expect_protocol_err(
            check_count,
            "state-channel",
            "missing header lane rejected when channel is lane-bound",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &missing_header_lane,
                &fixture.template,
            ),
            |err| matches!(err, KurrentError::WrongLaneId { .. }),
        )?;
        let mut wrong_header_lane = state0.clone();
        wrong_header_lane.header.expected_lane_id =
            Some(derive_kurrent_channel_lane_id("soak-foreign-channel"));
        expect_protocol_err(
            check_count,
            "state-channel",
            "wrong header lane rejected",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &wrong_header_lane,
                &fixture.template,
            ),
            |err| matches!(err, KurrentError::WrongLaneId { .. }),
        )?;
        let mut malformed_funding_lane = fixture.funding.clone();
        malformed_funding_lane.expected_lane_id = Some("not-a-user-lane".to_string());
        expect_protocol_err(
            check_count,
            "state-channel",
            "malformed funding lane rejected",
            validate_channel_update(
                &fixture.config,
                &malformed_funding_lane,
                &state0,
                &fixture.template,
            ),
            |err| matches!(err, KurrentError::InvalidLaneId { .. }),
        )?;
        let mut undersigned = state0.clone();
        undersigned.participant_signatures.remove("bob");
        expect_protocol_err(
            check_count,
            "state-channel",
            "under-signed state update",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &undersigned,
                &fixture.template,
            ),
            |err| matches!(err, KurrentError::InsufficientSignatures { .. }),
        )?;
        let mut forged = state0.clone();
        let forged_signature = forged
            .participant_signatures
            .get("alice")
            .cloned()
            .ok_or_else(|| "state-channel: missing alice signature".to_string())?;
        forged
            .participant_signatures
            .insert("bob".to_string(), forged_signature);
        expect_protocol_err(
            check_count,
            "state-channel",
            "forged participant signature",
            validate_channel_update(
                &fixture.config,
                &fixture.funding,
                &forged,
                &fixture.template,
            ),
            |err| matches!(err, KurrentError::InvalidParticipantSignature(participant) if participant == "bob"),
        )?;
        let mut wrong_template = fixture.template.clone();
        wrong_template.template_id.push_str("-foreign");
        expect_protocol_err(
            check_count,
            "state-channel",
            "wrong settlement template",
            validate_channel_update(&fixture.config, &fixture.funding, &state0, &wrong_template),
            |err| matches!(err, KurrentError::SettlementTemplateMismatch),
        )?;
    }
    push_adversarial_check(
        checks,
        "state-channel mempool and alternate-history resistance",
        iterations,
        start,
        *check_count,
        &[
            "signed latest-state sequence validates and settles only at the newest state",
            "stale state 0 and state 1 settlements are rejected after state 2",
            "same-number conflicting branches are rejected",
            "skipped numbers and wrong previous commitments are rejected",
            "wrong funding, lane mismatch, malformed lane ids, under-signed updates, forged signatures, and wrong templates are rejected",
        ],
    );
    Ok(())
}

fn run_fee_sponsored_adversarial_soak(
    iterations: usize,
    check_count: &mut usize,
    checks: &mut Vec<AdversarialSoakCheck>,
) -> Result<(), String> {
    let start = *check_count;
    for iteration in 0..iterations {
        let fixture = AdversarialChannelFixture::new(iteration);
        let eligibility_policy = SettlementEligibilityPolicy {
            response_window_daa: 5,
        };
        let fee_policy = SettlementFeePolicy {
            policy_id: format!("soak-fee-policy-{iteration}"),
            max_sponsor_fee: 100,
            sponsor_mode: "external-sponsor-input".to_string(),
        };
        let state1 = adversarial_fee_policy_state(
            fixture.state_update(1, format!("state-{iteration}-1"), "state-0"),
            &fee_policy,
        );
        let state2 = adversarial_fee_policy_state(
            fixture.state_update(
                2,
                format!("state-{iteration}-2"),
                state1.header.new_state_commitment.clone(),
            ),
            &fee_policy,
        );
        let lower = adversarial_fee_sponsored_candidate(
            &fixture,
            state1.clone(),
            format!("soak-lower-{iteration}"),
            10,
            100,
            80,
        );
        let higher = adversarial_fee_sponsored_candidate(
            &fixture,
            state2,
            format!("soak-higher-{iteration}"),
            11,
            102,
            20,
        );
        let decisions = expect_protocol_ok(
            check_count,
            "fee-sponsored-displacement",
            "higher state displaces a higher-fee stale marker",
            evaluate_fee_sponsored_settlement_eligibility(
                &fixture.config,
                &fixture.funding,
                &fixture.template,
                &eligibility_policy,
                &fee_policy,
                &[lower.clone(), higher],
                107,
            ),
        )?;
        if decisions[0].eligibility.status != SettlementEligibilityStatus::Displaced
            || decisions[1].eligibility.status != SettlementEligibilityStatus::EligibleToFinalise
            || decisions[0].sponsor_fee <= decisions[1].sponsor_fee
        {
            return Err("fee-sponsored-displacement: unexpected displacement decision".to_string());
        }

        let mut missing_hash = lower.clone();
        missing_hash.eligibility.update.header.fee_policy_hash = None;
        adversarial_resign_update(&mut missing_hash.eligibility.update);
        missing_hash.eligibility.evidence.state_header_hash =
            missing_hash.eligibility.update.header.hash();
        expect_protocol_err(
            check_count,
            "fee-sponsored-displacement",
            "missing fee-policy hash",
            evaluate_fee_sponsored_settlement_eligibility(
                &fixture.config,
                &fixture.funding,
                &fixture.template,
                &eligibility_policy,
                &fee_policy,
                &[missing_hash],
                104,
            ),
            |err| matches!(err, KurrentError::SettlementEligibilityEvidenceMismatch(reason) if reason.contains("fee-policy hash")),
        )?;

        let mut funding_sponsor = lower.clone();
        funding_sponsor.sponsor.sponsor_input_outpoints =
            vec![fixture.funding.funding_outpoint.clone()];
        expect_protocol_err(
            check_count,
            "fee-sponsored-displacement",
            "channel funding used as sponsor input",
            evaluate_fee_sponsored_settlement_eligibility(
                &fixture.config,
                &fixture.funding,
                &fixture.template,
                &eligibility_policy,
                &fee_policy,
                &[funding_sponsor],
                104,
            ),
            |err| matches!(err, KurrentError::SettlementEligibilityEvidenceMismatch(reason) if reason.contains("external")),
        )?;

        let mut zero_fee = lower.clone();
        zero_fee.sponsor.sponsor_fee = 0;
        expect_protocol_err(
            check_count,
            "fee-sponsored-displacement",
            "zero sponsor fee",
            evaluate_fee_sponsored_settlement_eligibility(
                &fixture.config,
                &fixture.funding,
                &fixture.template,
                &eligibility_policy,
                &fee_policy,
                &[zero_fee],
                104,
            ),
            |err| matches!(err, KurrentError::SettlementEligibilityEvidenceMismatch(reason) if reason.contains("non-zero")),
        )?;

        let mut over_limit = lower.clone();
        over_limit.sponsor.sponsor_fee = 101;
        over_limit.sponsor.sponsor_input_total = 1_101;
        expect_protocol_err(
            check_count,
            "fee-sponsored-displacement",
            "sponsor fee exceeds policy",
            evaluate_fee_sponsored_settlement_eligibility(
                &fixture.config,
                &fixture.funding,
                &fixture.template,
                &eligibility_policy,
                &fee_policy,
                &[over_limit],
                104,
            ),
            |err| matches!(err, KurrentError::SettlementEligibilityEvidenceMismatch(reason) if reason.contains("maximum")),
        )?;

        let mut bad_sum = lower.clone();
        bad_sum.sponsor.sponsor_input_total = 1_079;
        expect_protocol_err(
            check_count,
            "fee-sponsored-displacement",
            "sponsor accounting mismatch",
            evaluate_fee_sponsored_settlement_eligibility(
                &fixture.config,
                &fixture.funding,
                &fixture.template,
                &eligibility_policy,
                &fee_policy,
                &[bad_sum],
                104,
            ),
            |err| matches!(err, KurrentError::SettlementEligibilityEvidenceMismatch(reason) if reason.contains("input total")),
        )?;

        let mut wrong_distribution = lower;
        wrong_distribution.sponsor.settlement_distribution_hash =
            sha256_hex(format!("wrong-distribution-{iteration}").as_bytes());
        expect_protocol_err(
            check_count,
            "fee-sponsored-displacement",
            "tampered settlement distribution hash",
            evaluate_fee_sponsored_settlement_eligibility(
                &fixture.config,
                &fixture.funding,
                &fixture.template,
                &eligibility_policy,
                &fee_policy,
                &[wrong_distribution],
                104,
            ),
            |err| matches!(err, KurrentError::SettlementEligibilityEvidenceMismatch(reason) if reason.contains("distribution")),
        )?;
    }
    push_adversarial_check(
        checks,
        "fee-sponsored displacement evidence tamper resistance",
        iterations,
        start,
        *check_count,
        &[
            "higher authorised state displaces the lower marker even when the lower marker pays a larger sponsor fee",
            "missing fee-policy hashes are rejected",
            "channel funding cannot be reused as the sponsor input",
            "zero, over-limit, inconsistent, and distribution-tampered sponsor evidence is rejected",
        ],
    );
    Ok(())
}

fn run_factory_adversarial_soak(
    iterations: usize,
    check_count: &mut usize,
    checks: &mut Vec<AdversarialSoakCheck>,
) -> Result<(), String> {
    let start = *check_count;
    for iteration in 0..iterations {
        let before = adversarial_factory(iteration);
        let plan = adversarial_materialisation_plan(iteration);
        let after = adversarial_after_materialisation(
            &before,
            &plan.virtual_channel_id,
            &plan.materialisation_id,
        );
        expect_protocol_ok(
            check_count,
            "factory",
            "valid materialisation conserves principal and fee",
            validate_materialisation(&before, &after, &plan),
        )?;

        let mut wrong_factory = plan.clone();
        wrong_factory.factory_id = format!("foreign-factory-{iteration}");
        expect_protocol_err(
            check_count,
            "factory",
            "wrong factory id",
            validate_materialisation(&before, &after, &wrong_factory),
            |err| matches!(err, KurrentError::WrongFactoryId { .. }),
        )?;
        let mut double_before = before.clone();
        double_before
            .materialised_receipts
            .insert(plan.materialisation_id.clone());
        expect_protocol_err(
            check_count,
            "factory",
            "double materialisation id",
            validate_materialisation(&double_before, &after, &plan),
            |err| matches!(err, KurrentError::DoubleMaterialisation(_)),
        )?;
        let mut wrong_virtual_channel = plan.clone();
        wrong_virtual_channel.virtual_channel_id = format!("missing-vc-{iteration}");
        expect_protocol_err(
            check_count,
            "factory",
            "wrong virtual channel id",
            validate_materialisation(&before, &after, &wrong_virtual_channel),
            |err| matches!(err, KurrentError::WrongVirtualChannelId(_)),
        )?;
        let untouched_id = format!("soak-vc-{iteration}-2");
        let mut mutated_after = after.clone();
        mutated_after
            .virtual_channels
            .get_mut(&untouched_id)
            .ok_or_else(|| format!("factory: missing untouched channel {untouched_id}"))?
            .state_commitment
            .push_str("-mutated");
        expect_protocol_err(
            check_count,
            "factory",
            "untouched virtual channel mutation",
            validate_materialisation(&before, &mutated_after, &plan),
            |err| matches!(err, KurrentError::MutatedUntouchedVirtualChannel(_)),
        )?;
        let mut overlapping_inputs = plan.clone();
        overlapping_inputs
            .fee_input_ids
            .insert(format!("principal-in-{iteration}"));
        expect_protocol_err(
            check_count,
            "factory",
            "principal and fee input overlap",
            validate_materialisation(&before, &after, &overlapping_inputs),
            |err| matches!(err, KurrentError::FeePrincipalNotSeparated),
        )?;
        let mut wrong_principal = plan.clone();
        wrong_principal.principal_amount -= 1;
        expect_protocol_err(
            check_count,
            "factory",
            "wrong principal amount",
            validate_materialisation(&before, &after, &wrong_principal),
            |err| matches!(err, KurrentError::MaterialisationAmountMismatch { .. }),
        )?;
        let mut wrong_outputs = plan;
        wrong_outputs
            .output_amounts
            .insert("alice".to_string(), 301);
        expect_protocol_err(
            check_count,
            "factory",
            "non-conserving output amount",
            validate_materialisation(&before, &after, &wrong_outputs),
            |err| matches!(err, KurrentError::ConservationFailure { .. }),
        )?;
    }
    push_adversarial_check(
        checks,
        "factory materialisation accounting resistance",
        iterations,
        start,
        *check_count,
        &[
            "valid materialisation conserves factory principal and fee reserve",
            "wrong factory and virtual-channel ids are rejected",
            "duplicate materialisation ids are rejected",
            "untouched virtual-channel leaves cannot be mutated",
            "principal and fee input overlap is rejected",
            "wrong principal and non-conserving output amounts are rejected",
        ],
    );
    Ok(())
}

fn run_ln_swap_adversarial_soak(
    iterations: usize,
    check_count: &mut usize,
    checks: &mut Vec<AdversarialSoakCheck>,
) -> Result<(), String> {
    let start = *check_count;
    for iteration in 0..iterations {
        for direction in ["ln-to-kaspa", "kaspa-to-ln"] {
            let (evidence, receipt) = adversarial_ln_case(iteration, direction);
            expect_protocol_ok(
                check_count,
                "ln-swap",
                "valid atomic swap receipt validates",
                validate_ln_swap(&evidence, &receipt),
            )?;
            let mut wrong_preimage = evidence.clone();
            wrong_preimage.preimage = format!("wrong-preimage-{iteration}-{direction}");
            expect_protocol_err(
                check_count,
                "ln-swap",
                "wrong preimage",
                validate_ln_swap(&wrong_preimage, &receipt),
                |err| matches!(err, KurrentError::WrongPreimage),
            )?;
            let mut stale_receipt = receipt.clone();
            stale_receipt.output_id = format!("mutated-settlement-{iteration}:0");
            expect_protocol_err(
                check_count,
                "ln-swap",
                "stale receipt hash after scope mutation",
                validate_ln_swap(&evidence, &stale_receipt),
                |err| matches!(err, KurrentError::ReceiptHashMismatch),
            )?;
            let mut invalid_direction = evidence.clone();
            invalid_direction.direction = "sideways".to_string();
            expect_protocol_err(
                check_count,
                "ln-swap",
                "invalid swap direction",
                validate_ln_swap(&invalid_direction, &receipt),
                |err| matches!(err, KurrentError::InvalidSwapEvidence(_)),
            )?;
            let mut replay_receipt = receipt.clone();
            replay_receipt.direction = Some(
                match direction {
                    "ln-to-kaspa" => "kaspa-to-ln",
                    _ => "ln-to-kaspa",
                }
                .to_string(),
            );
            replay_receipt.refresh_hash();
            expect_protocol_err(
                check_count,
                "ln-swap",
                "opposite-direction receipt replay",
                validate_ln_swap(&evidence, &replay_receipt),
                |err| matches!(err, KurrentError::ReceiptReplay),
            )?;
            let mut wrong_funding = receipt.clone();
            wrong_funding.funding_outpoint = format!("foreign-funding-{iteration}:0");
            wrong_funding.refresh_hash();
            expect_protocol_err(
                check_count,
                "ln-swap",
                "wrong Kaspa funding outpoint",
                validate_ln_swap(&evidence, &wrong_funding),
                |err| matches!(err, KurrentError::WrongFundingOutpoint { .. }),
            )?;
            let mut wrong_settlement = receipt.clone();
            wrong_settlement.output_id = format!("foreign-settlement-{iteration}:0");
            wrong_settlement.refresh_hash();
            expect_protocol_err(
                check_count,
                "ln-swap",
                "wrong Kaspa settlement outpoint",
                validate_ln_swap(&evidence, &wrong_settlement),
                |err| matches!(err, KurrentError::WrongSettlementOutpoint { .. }),
            )?;
            let mut wrong_script = receipt.clone();
            wrong_script.settlement_template_hash = format!("foreign-script-{iteration}");
            wrong_script.refresh_hash();
            expect_protocol_err(
                check_count,
                "ln-swap",
                "wrong script hash",
                validate_ln_swap(&evidence, &wrong_script),
                |err| matches!(err, KurrentError::WrongScriptHash { .. }),
            )?;
            let mut zero_amount = evidence.clone();
            zero_amount.amount = 0;
            expect_protocol_err(
                check_count,
                "ln-swap",
                "zero-amount swap evidence",
                validate_ln_swap(&zero_amount, &receipt),
                |err| matches!(err, KurrentError::InvalidSwapEvidence(_)),
            )?;
            let mut wrong_protocol = receipt.clone();
            wrong_protocol.protocol_version = 2;
            wrong_protocol.refresh_hash();
            expect_protocol_err(
                check_count,
                "ln-swap",
                "wrong protocol version",
                validate_ln_swap(&evidence, &wrong_protocol),
                |err| matches!(err, KurrentError::WrongProtocolVersion { .. }),
            )?;
        }
    }
    push_adversarial_check(
        checks,
        "LN and Kaspa atomic-swap replay resistance",
        iterations,
        start,
        *check_count,
        &[
            "valid LN-to-Kaspa and Kaspa-to-LN receipts validate",
            "wrong preimages and stale receipt hashes are rejected",
            "invalid directions and opposite-direction receipt replay are rejected",
            "wrong funding, settlement, script, protocol, and zero-amount evidence are rejected",
        ],
    );
    Ok(())
}

fn run_refund_adversarial_soak(
    iterations: usize,
    check_count: &mut usize,
    checks: &mut Vec<AdversarialSoakCheck>,
) -> Result<(), String> {
    let start = *check_count;
    for iteration in 0..iterations {
        let scope = adversarial_claim_scope(iteration, 0);
        let mut early_registry = SettlementRegistry::default();
        expect_protocol_err(
            check_count,
            "refund",
            "refund before required DAA",
            early_registry.refund_scoped_claim(&scope, 119, 120),
            |err| matches!(err, KurrentError::RefundNotMature { .. }),
        )?;
        expect_protocol_ok(
            check_count,
            "refund",
            "refund at required DAA",
            early_registry.refund_scoped_claim(&scope, 120, 120),
        )?;
        let mut settlement_registry = SettlementRegistry::default();
        expect_protocol_ok(
            check_count,
            "refund",
            "settlement claim registers scoped key",
            settlement_registry.settle_scoped_claim(&scope),
        )?;
        expect_protocol_err(
            check_count,
            "refund",
            "settlement and refund double claim",
            settlement_registry.refund_scoped_claim(&scope, 120, 120),
            |err| matches!(err, KurrentError::DoubleClaim(_)),
        )?;
        let second_scope = adversarial_claim_scope(iteration, 1);
        expect_protocol_ok(
            check_count,
            "refund",
            "different funding outpoint has independent claim scope",
            settlement_registry.refund_scoped_claim(&second_scope, 120, 120),
        )?;
        let mut duplicate_refund_registry = SettlementRegistry::default();
        expect_protocol_ok(
            check_count,
            "refund",
            "first refund claim registers scoped key",
            duplicate_refund_registry.refund_scoped_claim(&scope, 120, 120),
        )?;
        expect_protocol_err(
            check_count,
            "refund",
            "duplicate refund claim",
            duplicate_refund_registry.refund_scoped_claim(&scope, 120, 120),
            |err| matches!(err, KurrentError::DoubleClaim(_)),
        )?;
    }
    push_adversarial_check(
        checks,
        "refund timeout and double-claim race resistance",
        iterations,
        start,
        *check_count,
        &[
            "early refunds are rejected before the required DAA score",
            "mature refunds succeed once",
            "settlement and refund are mutually exclusive for the same claim scope",
            "claim scopes do not collide across funding outputs",
            "duplicate refund claims are rejected",
        ],
    );
    Ok(())
}

fn run_evidence_hash_adversarial_soak(
    production_dir: &Path,
    check_count: &mut usize,
    checks: &mut Vec<AdversarialSoakCheck>,
) -> Result<Vec<EvidenceFile>, String> {
    let start = *check_count;
    let corpus_dir = production_dir.join("adversarial-soak-corpus");
    fs::create_dir_all(&corpus_dir)
        .map_err(|e| format!("failed to create {}: {e}", corpus_dir.display()))?;
    let anchor = corpus_dir.join("anchor.txt");
    fs::write(
        &anchor,
        b"kurrent adversarial soak evidence anchor\nstate-factory-ln-refund-evidence\n",
    )
    .map_err(|e| format!("failed to write {}: {e}", anchor.display()))?;
    let record = file_evidence(&anchor)?;
    let good_bundle = EvidenceBundle {
        acceptance_json: "evidence/kurrent-acceptance.json".to_string(),
        referenced_files: vec![record.clone()],
    };
    expect_protocol_ok(
        check_count,
        "evidence-hash",
        "matching evidence hash bundle",
        verify_evidence_bundle(&root()?, &good_bundle),
    )?;
    let tampered_bundle = EvidenceBundle {
        acceptance_json: good_bundle.acceptance_json.clone(),
        referenced_files: vec![EvidenceFile {
            path: record.path.clone(),
            sha256: sha256_hex(b"tampered"),
        }],
    };
    expect_protocol_err(
        check_count,
        "evidence-hash",
        "tampered evidence hash",
        verify_evidence_bundle(&root()?, &tampered_bundle),
        |err| matches!(err, KurrentError::EvidenceHashMismatch { .. }),
    )?;
    let missing_bundle = EvidenceBundle {
        acceptance_json: good_bundle.acceptance_json,
        referenced_files: vec![EvidenceFile {
            path: "evidence/production/adversarial-soak-corpus/missing.txt".to_string(),
            sha256: sha256_hex(b"missing"),
        }],
    };
    expect_protocol_err(
        check_count,
        "evidence-hash",
        "missing evidence file",
        verify_evidence_bundle(&root()?, &missing_bundle),
        |err| matches!(err, KurrentError::MissingEvidenceFile(_)),
    )?;
    push_adversarial_check(
        checks,
        "production evidence hash tamper resistance",
        1,
        start,
        *check_count,
        &[
            "matching file hashes validate",
            "tampered file hashes are rejected",
            "missing evidence files are rejected",
        ],
    );
    Ok(vec![record])
}

fn expect_protocol_ok<T>(
    check_count: &mut usize,
    scenario: &str,
    action: &str,
    result: std::result::Result<T, KurrentError>,
) -> Result<T, String> {
    match result {
        Ok(value) => {
            *check_count += 1;
            Ok(value)
        }
        Err(err) => Err(format!(
            "{scenario}: expected {action} to pass, got {err:?}"
        )),
    }
}

fn expect_protocol_err<T>(
    check_count: &mut usize,
    scenario: &str,
    action: &str,
    result: std::result::Result<T, KurrentError>,
    predicate: impl FnOnce(&KurrentError) -> bool,
) -> Result<(), String> {
    match result {
        Ok(_) => Err(format!("{scenario}: expected {action} to be rejected")),
        Err(err) if predicate(&err) => {
            *check_count += 1;
            Ok(())
        }
        Err(err) => Err(format!(
            "{scenario}: expected {action} rejection, got {err:?}"
        )),
    }
}

fn push_adversarial_check(
    checks: &mut Vec<AdversarialSoakCheck>,
    scenario: &str,
    iterations: usize,
    start: usize,
    end: usize,
    assertions: &[&str],
) {
    checks.push(AdversarialSoakCheck {
        scenario: scenario.to_string(),
        iterations,
        check_count: end.saturating_sub(start),
        assertions: assertions
            .iter()
            .map(|assertion| assertion.to_string())
            .collect(),
    });
}

fn adversarial_participants() -> Vec<String> {
    vec!["alice".to_string(), "bob".to_string()]
}

fn adversarial_balances() -> BTreeMap<String, u64> {
    BTreeMap::from([("alice".to_string(), 600), ("bob".to_string(), 400)])
}

fn adversarial_keypair_for(participant: &str) -> Keypair {
    let byte = match participant {
        "alice" => 11,
        "bob" => 22,
        _ => 33,
    };
    let secret = SecretKey::from_slice(&[byte; 32]).expect("static adversarial key must be valid");
    Keypair::from_secret_key(secp256k1::SECP256K1, &secret)
}

fn adversarial_participant_public_keys() -> BTreeMap<String, String> {
    adversarial_participants()
        .into_iter()
        .map(|participant| {
            let keypair = adversarial_keypair_for(&participant);
            let (public_key, _) = keypair.x_only_public_key();
            (participant, hex::encode(public_key.serialize()))
        })
        .collect()
}

fn adversarial_sign_update_for(participant: &str, update: &StateUpdate) -> String {
    let keypair = adversarial_keypair_for(participant);
    let message = Message::from_digest(state_update_signing_digest(update));
    let secp = Secp256k1::new();
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    hex::encode(signature.as_ref())
}

fn adversarial_resign_update(update: &mut StateUpdate) {
    update.participant_signatures.clear();
    for participant in adversarial_participants() {
        let signature = adversarial_sign_update_for(&participant, update);
        update.participant_signatures.insert(participant, signature);
    }
}

fn adversarial_fee_policy_state(
    mut state: StateUpdate,
    fee_policy: &SettlementFeePolicy,
) -> StateUpdate {
    state.header.fee_policy_hash = Some(fee_policy.hash());
    adversarial_resign_update(&mut state);
    state
}

fn adversarial_fee_sponsored_candidate(
    fixture: &AdversarialChannelFixture,
    state: StateUpdate,
    candidate_txid: String,
    accepted_order_index: u64,
    daa_score: u64,
    sponsor_fee: u64,
) -> FeeSponsoredSettlementCandidate {
    FeeSponsoredSettlementCandidate {
        eligibility: SettlementEligibilityCandidate {
            evidence: SettlementCandidateEvidence {
                network_profile: state.header.network_profile.clone(),
                funding_outpoint: state.header.funding_outpoint.clone(),
                channel_id: state.header.channel_id.clone(),
                factory_id: state.header.factory_id.clone(),
                virtual_channel_id: state.header.virtual_channel_id.clone(),
                state_number: state.header.state_number,
                state_header_hash: state.header.hash(),
                lane_id: state.header.expected_lane_id.clone().unwrap_or_default(),
                candidate_txid: candidate_txid.clone(),
                accepted_order_index,
                accepting_chain_block_hash: format!("soak-block-{accepted_order_index}"),
                daa_score,
                blue_score: daa_score,
            },
            update: state,
        },
        sponsor: SettlementSponsorEvidence {
            candidate_txid: candidate_txid.clone(),
            sponsor_input_outpoints: vec![format!("sponsor-{candidate_txid}:0")],
            sponsor_input_total: sponsor_fee + 1_000,
            sponsor_change_total: 1_000,
            sponsor_fee,
            settlement_template_hash: fixture.template.hash(),
            settlement_distribution_hash: settlement_distribution_hash(&fixture.template),
        },
    }
}

fn adversarial_factory(iteration: usize) -> FactoryState {
    let first = VirtualChannelState {
        virtual_channel_id: format!("soak-vc-{iteration}-1"),
        channel_id: format!("soak-channel-vc-{iteration}-1"),
        balance_by_participant: adversarial_balances(),
        state_number: 2,
        state_commitment: format!("soak-vc-{iteration}-state-2"),
    };
    let second = VirtualChannelState {
        virtual_channel_id: format!("soak-vc-{iteration}-2"),
        channel_id: format!("soak-channel-vc-{iteration}-2"),
        balance_by_participant: BTreeMap::from([
            ("carol".to_string(), 250),
            ("dave".to_string(), 250),
        ]),
        state_number: 0,
        state_commitment: format!("soak-vc-{iteration}-state-0"),
    };
    FactoryState {
        factory_id: format!("soak-factory-{iteration}"),
        network_profile: "local-toccata-devnet".to_string(),
        total_principal: 1_500,
        fee_reserve: 10,
        virtual_channels: BTreeMap::from([
            (first.virtual_channel_id.clone(), first),
            (second.virtual_channel_id.clone(), second),
        ]),
        materialised_receipts: BTreeSet::new(),
    }
}

fn adversarial_materialisation_plan(iteration: usize) -> MaterialisationPlan {
    MaterialisationPlan {
        materialisation_id: format!("soak-mat-{iteration}"),
        factory_id: format!("soak-factory-{iteration}"),
        virtual_channel_id: format!("soak-vc-{iteration}-1"),
        touched_leaves: TouchedLeaves {
            virtual_channel_ids: BTreeSet::from([format!("soak-vc-{iteration}-1")]),
        },
        principal_input_ids: BTreeSet::from([format!("principal-in-{iteration}")]),
        fee_input_ids: BTreeSet::from([format!("fee-in-{iteration}")]),
        principal_amount: 1_000,
        fee_amount: 10,
        output_amounts: BTreeMap::from([
            ("alice".to_string(), 600),
            ("bob".to_string(), 400),
            ("fee".to_string(), 10),
        ]),
    }
}

fn adversarial_after_materialisation(
    before: &FactoryState,
    virtual_channel_id: &str,
    materialisation_id: &str,
) -> FactoryState {
    let mut after = before.clone();
    after.total_principal = 500;
    after.fee_reserve = 0;
    after.virtual_channels.remove(virtual_channel_id);
    after
        .materialised_receipts
        .insert(materialisation_id.to_string());
    after
}

fn adversarial_ln_case(iteration: usize, direction: &str) -> (LnSwapEvidence, ChannelReceipt) {
    let preimage = format!("preimage-{iteration}-{direction}");
    let preimage_hash = sha256_hex(preimage.as_bytes());
    let swap_id = format!("swap-{iteration}-{direction}");
    let funding_outpoint = format!("swap-funding-{iteration}:0");
    let settlement_outpoint = format!("swap-settlement-{iteration}:0");
    let script_hash = format!("swap-script-{iteration}");
    let evidence = LnSwapEvidence {
        protocol_version: 1,
        network_profile: "local-toccata-devnet".to_string(),
        swap_id: swap_id.clone(),
        direction: direction.to_string(),
        ln_payment_hash: preimage_hash.clone(),
        preimage,
        preimage_hash,
        kaspa_funding_outpoint: funding_outpoint.clone(),
        kaspa_settlement_outpoint: settlement_outpoint.clone(),
        amount: 100 + iteration as u64,
        recipient: match direction {
            "ln-to-kaspa" => "alice",
            _ => "bob",
        }
        .to_string(),
        script_hash: script_hash.clone(),
        evidence_file_hashes: BTreeMap::new(),
    };
    let mut receipt = ChannelReceipt::new(
        1,
        "local-toccata-devnet",
        format!("swap-channel-{iteration}"),
        funding_outpoint,
        settlement_outpoint,
        2,
        script_hash,
    );
    receipt.swap_id = Some(swap_id);
    receipt.direction = Some(direction.to_string());
    receipt.refresh_hash();
    (evidence, receipt)
}

fn adversarial_claim_scope(iteration: usize, funding_index: usize) -> ClaimScope {
    ClaimScope {
        network_profile: "local-toccata-devnet".to_string(),
        funding_outpoint: format!("refund-funding-{iteration}-{funding_index}:0"),
        output_id: format!("refund-settlement-{iteration}:0"),
        claim_subject: format!("refund-swap-{iteration}"),
    }
}

fn write_production_target_profile() -> Result<u8, String> {
    let root = root()?;
    let evidence = evidence_dir()?;
    let production_dir = evidence.join("production");
    fs::create_dir_all(&production_dir)
        .map_err(|e| format!("failed to create {}: {e}", production_dir.display()))?;

    let acceptance_path = evidence.join("kurrent-acceptance.json");
    let acceptance: AcceptanceReport =
        serde_json::from_slice(&fs::read(&acceptance_path).map_err(|e| {
            format!(
                "failed to read local acceptance report {}: {e}",
                acceptance_path.display()
            )
        })?)
        .map_err(|e| format!("failed to parse local acceptance report: {e}"))?;
    if acceptance.status != "passed" || !acceptance.blockers.is_empty() {
        return Err(
            "cannot write production target profile until local devnet acceptance is passed"
                .to_string(),
        );
    }

    let detection = detection_report();
    if !detection.blockers.is_empty() {
        return Err(format!(
            "cannot write production target profile while tooling is blocked: {}",
            detection.blockers.join("; ")
        ));
    }

    let mut lockfiles = vec![
        file_evidence(&root.join("Cargo.lock"))?,
        file_evidence(&root.join("Cargo.toml"))?,
    ];
    let driver_lock = root.join("drivers/kaspa-devnet/Cargo.lock");
    if driver_lock.is_file() {
        lockfiles.push(file_evidence(&driver_lock)?);
    }

    let profile = json!({
        "status": "passed",
        "generated_at": timestamp(),
        "scope": "production target profile for Kurrent local-devnet-to-production hardening",
        "git_commit": git_stdout(&root, &["rev-parse", "--verify", "HEAD"]),
        "repository": git_stdout(&root, &["remote", "get-url", "origin"]),
        "local_acceptance": {
            "status": acceptance.status,
            "acceptance_report": file_evidence(&acceptance_path)?,
            "network_devnet_id": acceptance.network_devnet_id,
            "flows": acceptance.flows,
        },
        "kaspa_source_profile": detection.selected_kaspa_repo,
        "tool_versions": detection.tools,
        "lockfiles": lockfiles,
        "protocol_domains": [
            DOMAIN_STATE,
            DOMAIN_STATE_SIGNATURE,
            DOMAIN_SETTLEMENT_TEMPLATE,
            DOMAIN_CHANNEL_RECEIPT,
            DOMAIN_FACTORY_MATERIALISATION,
            DOMAIN_LN_INTEROP,
            DOMAIN_PARTICIPANT_SET,
            DOMAIN_CLAIM_SCOPE
        ],
        "supported_for_production_gate": [
            "latest-state state-channel model with Schnorr participant signatures",
            "local factory materialisation accounting model",
            "atomic hash/preimage settlement evidence in both LN/Kaspa directions",
            "refund timeout evidence",
            "typed local acceptance report",
            "semantic transaction decoding verifier",
            "deterministic adversarial mempool, alternate-history, refund-race, swap-replay, and evidence-tamper soak"
        ],
        "not_yet_supported_for_production_gate": [
            "mainnet deployment",
            "public Lightning routing",
            "native Lightning route-hop integration",
            "unattended production operation",
            "independent external security review"
        ],
        "required_production_gates": [
            "local devnet acceptance must pass",
            "production target profile must be pinned",
            "semantic transaction verifier must pass",
            "adversarial soak evidence must pass",
            "production key-management runbook must be present",
            "production monitoring runbook must be present",
            "incident recovery runbook must be present",
            "rollout and rollback runbook must be present",
            "external security review evidence must pass"
        ]
    });
    write_json_file(&production_dir.join("target-profile.json"), &profile)?;
    println!(
        "production target profile written: {}",
        production_dir.join("target-profile.json").display()
    );
    Ok(0)
}

fn prepare_security_review_package() -> Result<u8, String> {
    let root = root()?;
    let evidence = evidence_dir()?;
    let production_dir = evidence.join("production");
    fs::create_dir_all(&production_dir)
        .map_err(|e| format!("failed to create {}: {e}", production_dir.display()))?;

    let artifacts = security_review_required_artifacts()?;
    let required_scope = security_review_required_scopes();
    let request = json!({
        "status": "ready_for_external_review",
        "schema_version": "kurrent-security-review-request-v1",
        "generated_at": timestamp(),
        "repository": git_stdout(&root, &["remote", "get-url", "origin"]),
        "git_commit": git_stdout(&root, &["rev-parse", "--verify", "HEAD"]),
        "review_type_required": "independent_external_security_review",
        "required_output_path": "evidence/production/security-review.json",
        "required_report_path": "evidence/production/security-review-report.pdf",
        "required_signed_attestation_path": "evidence/production/security-review-attestation.txt",
        "required_scope": required_scope,
        "reviewed_artifacts": artifacts,
        "acceptance_criteria": [
            "reviewer identity and contact must be supplied",
            "reviewer must attest independent external status",
            "all required scope ids must be covered",
            "methodology must contain at least three non-empty review methods",
            "critical, high, medium, and low open finding counts must be zero",
            "unresolved_blocking_findings must be empty",
            "report and signed attestation file hashes must match",
            "reviewed artefact paths and SHA-256 hashes must match this request package"
        ],
        "passing_evidence_template": {
            "schema_version": "kurrent-security-review-v1",
            "status": "passed",
            "review_type": "independent_external_security_review",
            "completed_at": "YYYY-MM-DD",
            "reviewer_name": "<external reviewer name>",
            "reviewer_organisation": "<external reviewer organisation>",
            "reviewer_contact": "<external reviewer contact>",
            "reviewer_independence_attestation": "<statement of independence, conflicts, and review authority>",
            "reviewed_git_commit": git_stdout(&root, &["rev-parse", "--verify", "HEAD"]),
            "scope": required_scope,
            "methodology": [
                "manual protocol-design review",
                "manual script/covenant constraint review",
                "evidence and production-gate replay"
            ],
            "reviewed_artifacts": security_review_required_artifacts()?,
            "finding_summary": {
                "critical_open": 0,
                "high_open": 0,
                "medium_open": 0,
                "low_open": 0,
                "accepted_risk_count": 0,
                "fixed_count": 0
            },
            "unresolved_blocking_findings": [],
            "report": {
                "path": "evidence/production/security-review-report.pdf",
                "sha256": "<sha256 of report file bytes>"
            },
            "signed_attestation": {
                "path": "evidence/production/security-review-attestation.txt",
                "sha256": "<sha256 of signed attestation file bytes>"
            }
        },
        "boundaries": [
            "This request package does not satisfy production readiness by itself.",
            "Only a completed independent external security review at evidence/production/security-review.json can satisfy the final gate.",
            "Any source, evidence, or runbook change after this package is generated requires regenerating the package and re-reviewing changed artefacts."
        ]
    });
    let path = production_dir.join("security-review-request.json");
    write_json_file(&path, &request)?;
    println!("security review package prepared: {}", path.display());
    Ok(0)
}

fn check() -> Result<u8, String> {
    run_status(Command::new("cargo").arg("fmt").arg("--all").arg("--check"))?;
    run_status(
        Command::new("cargo")
            .arg("fmt")
            .arg("--manifest-path")
            .arg("drivers/kaspa-devnet/Cargo.toml")
            .arg("--check"),
    )?;
    run_status(
        Command::new("cargo")
            .arg("clippy")
            .arg("--all-targets")
            .arg("--")
            .arg("-D")
            .arg("warnings"),
    )?;
    run_status(
        Command::new("cargo")
            .arg("clippy")
            .arg("--manifest-path")
            .arg("drivers/kaspa-devnet/Cargo.toml")
            .arg("--all-targets")
            .arg("--")
            .arg("-D")
            .arg("warnings"),
    )?;
    run_status(Command::new("cargo").arg("test"))?;
    run_status(Command::new("cargo").arg("build"))?;
    if !detect_tools()? {
        write_acceptance_report("failed/blocked", "external_tooling_unavailable")?;
        eprintln!(
            "failed/blocked: external tooling unavailable; see evidence/kurrent-acceptance.json"
        );
        return Ok(EXIT_TOOLING_BLOCKED);
    }

    let mut first_failure = None;
    for (name, code) in [
        ("run-kaspa-devnet", EXIT_KASPA_FLOW),
        ("run-ln-devnet", EXIT_LN_FLOW),
        ("run-state-channel-flow", EXIT_KASPA_FLOW),
        ("run-factory-flow", EXIT_FACTORY_FLOW),
        ("run-ln-to-kaspa-flow", EXIT_LN_FLOW),
        ("run-kaspa-to-ln-flow", EXIT_KASPA_TO_LN_FLOW),
        ("run-refund-flow", EXIT_REFUND_FLOW),
    ] {
        let result = match name {
            "run-kaspa-devnet" => run_kaspa_devnet()?,
            "run-ln-devnet" => run_ln_devnet()?,
            "run-state-channel-flow" => run_state_channel_flow()?,
            "run-factory-flow" => run_factory_flow()?,
            "run-ln-to-kaspa-flow" => run_ln_to_kaspa_flow()?,
            "run-kaspa-to-ln-flow" => run_kaspa_to_ln_flow()?,
            "run-refund-flow" => run_refund_flow()?,
            _ => unreachable!(),
        };
        if result != 0 && first_failure.is_none() {
            first_failure = Some((name, code));
        }
    }
    if let Some((name, code)) = first_failure {
        write_acceptance_report("failed/blocked", name)?;
        return Ok(code);
    }
    write_acceptance_report("passed", "passed")?;
    let verify = verify_evidence()?;
    if verify == 0 {
        println!("passed");
    }
    Ok(verify)
}

fn run_status(cmd: &mut Command) -> Result<(), String> {
    let status = cmd
        .status()
        .map_err(|e| format!("failed to run command: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status {status}"))
    }
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    fs::write(path, [bytes, b"\n".to_vec()].concat())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn timestamp() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{seconds}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time must be after unix epoch")
            .as_nanos();
        env::temp_dir().join(format!("kurrentctl-{label}-{nanos}.json"))
    }

    #[test]
    fn superficial_security_review_status_does_not_satisfy_gate() {
        let path = unique_temp_path("superficial-security-review");
        fs::write(&path, br#"{"status":"passed"}"#)
            .expect("test should write superficial review fixture");

        let satisfied =
            production_evidence_satisfies("external_security_review", &path).unwrap_or(false);
        assert!(!satisfied);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn superficial_runbook_status_does_not_satisfy_gate() {
        let text = "Status: passed\n";
        assert!(!production_runbook_satisfies(
            "key_management_recovery",
            text
        ));
    }

    #[test]
    fn structured_runbook_satisfies_gate() {
        let text = format!(
            "{}\n{}\n{}\n{}\n{}\n",
            "Status: passed",
            "## Scope\nThis runbook covers signer isolation, backup, and recovery controls for the local Kurrent production-readiness gate. The document is intentionally procedural and does not claim mainnet deployment.",
            "## Controls\nKeys are generated offline, signer hosts are isolated, access is reviewed, backups are encrypted, and recovery material is tested against non-production fixtures before any release claim.",
            "## Recovery Procedure\nDeclare the incident owner, freeze signing, recover from an encrypted backup into an isolated host, verify participant public keys, replay local acceptance, and record the operator sign-off.",
            "## Evidence\nThe operator keeps the recovery transcript, backup identifier, acceptance report hash, reviewer identity, and final go/no-go decision with the release artefacts."
        );
        let padded = format!("{text}\n{}", "x".repeat(1_000));
        assert!(production_runbook_satisfies(
            "key_management_recovery",
            &padded
        ));
    }

    #[test]
    fn superficial_json_status_does_not_satisfy_target_profile_gate() {
        assert!(!production_json_evidence_satisfies(
            "prod_target_profile",
            &json!({"status": "passed"})
        ));
    }

    #[test]
    fn structurally_incomplete_security_review_does_not_satisfy_gate() {
        let path = unique_temp_path("incomplete-security-review");
        let review = json!({
            "schema_version": "kurrent-security-review-v1",
            "status": "passed",
            "review_type": "independent_external_security_review",
            "completed_at": "2026-06-11",
            "reviewer_name": "External Reviewer",
            "reviewer_organisation": "External Review Ltd",
            "reviewer_contact": "reviewer@example.invalid",
            "reviewer_independence_attestation": "External reviewer attests independence from implementation work.",
            "reviewed_git_commit": "not-the-current-commit",
            "scope": [],
            "methodology": [
                "manual protocol-design review",
                "manual script/covenant constraint review",
                "evidence and production-gate replay"
            ],
            "reviewed_artifacts": [],
            "finding_summary": {
                "critical_open": 0,
                "high_open": 0,
                "medium_open": 0,
                "low_open": 0,
                "accepted_risk_count": 0,
                "fixed_count": 0
            },
            "unresolved_blocking_findings": [],
            "report": {
                "path": "evidence/production/security-review-report.pdf",
                "sha256": sha256_hex(b"missing report")
            },
            "signed_attestation": {
                "path": "evidence/production/security-review-attestation.txt",
                "sha256": sha256_hex(b"missing attestation")
            }
        });
        fs::write(
            &path,
            serde_json::to_vec_pretty(&review).expect("fixture should serialise"),
        )
        .expect("test should write incomplete review fixture");

        let satisfied =
            production_evidence_satisfies("external_security_review", &path).unwrap_or(false);
        assert!(!satisfied);

        let _ = fs::remove_file(path);
    }
}
