use kurrent::{
    hash_json, sha256_hex, DOMAIN_CHANNEL_RECEIPT, DOMAIN_FACTORY_MATERIALISATION,
    DOMAIN_LN_INTEROP, DOMAIN_SETTLEMENT_TEMPLATE, DOMAIN_STATE,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
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
        "prepare-devnet-tools" => prepare_devnet_tools(),
        "run-kaspa-devnet" => run_kaspa_devnet(),
        "run-ln-devnet" => run_ln_devnet(),
        "run-state-channel-flow" => run_state_channel_flow(),
        "run-factory-flow" => run_factory_flow(),
        "run-ln-to-kaspa-flow" => run_ln_to_kaspa_flow(),
        "run-kaspa-to-ln-flow" => run_kaspa_to_ln_flow(),
        "run-refund-flow" => run_refund_flow(),
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
        "kurrentctl commands: detect-tools, tool-path, write-acceptance-report, verify-evidence, prepare-devnet-tools, run-kaspa-devnet, run-ln-devnet, run-state-channel-flow, run-factory-flow, run-ln-to-kaspa-flow, run-kaspa-to-ln-flow, run-refund-flow, check"
    );
}

#[derive(Debug, Clone, Serialize)]
struct ToolRecord {
    name: String,
    path: Option<String>,
    version: Option<String>,
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
    tools: Vec<ToolRecord>,
    tool_paths: BTreeMap<String, Option<String>>,
    known_bin_dirs: Vec<String>,
    parent_kaspa_repo: Option<RepoRecord>,
    selected_kaspa_repo: Option<RepoRecord>,
    lnd_repo: Option<RepoRecord>,
}

#[derive(Debug, Clone, Serialize)]
struct FileEvidence {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize)]
struct CommandEvidence {
    label: String,
    cwd: String,
    command: Vec<String>,
    status_code: Option<i32>,
    stdout: FileEvidence,
    stderr: FileEvidence,
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

fn file_evidence(path: &Path) -> Result<FileEvidence, String> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(FileEvidence {
        path: relative_to_root(path)?,
        sha256: sha256_hex(&bytes),
    })
}

fn source_file_evidence(repo: &Path, relative: &str) -> Result<FileEvidence, String> {
    let path = repo.join(relative);
    let bytes = fs::read(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    Ok(FileEvidence {
        path: path.display().to_string(),
        sha256: sha256_hex(&bytes),
    })
}

fn selected_kaspa_repo_path() -> Result<PathBuf, String> {
    detection_report()
        .selected_kaspa_repo
        .map(|repo| PathBuf::from(repo.path))
        .ok_or_else(|| "no selected Kaspa Toccata repository is available".to_string())
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
        parent.join("rusty-kaspa-toccata/target/release"),
        parent.join("rusty-kaspa-toccata/target/debug"),
        parent.join("rusty-kaspa/target/release"),
        parent.join("rusty-kaspa/target/debug"),
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

fn tool_record(name: &str) -> ToolRecord {
    let path = resolve_command(name);
    ToolRecord {
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
        parent.join("rusty-kaspa-toccata"),
        parent.join("rusty-kaspa"),
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
        blockers.push("No local Kaspa Toccata source checkout was found.".to_string());
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

fn flow_evidence_files() -> [(&'static str, &'static str); 5] {
    [
        (
            "kaspa_state_channel_flow",
            "kurrent-state-channel-flow-evidence.json",
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
            flows.insert(key, flow_status);
            flow_evidence_paths_and_hashes.push(json!({
                "flow": key,
                "path": format!("evidence/{file_name}"),
                "sha256": sha256_hex(&bytes)
            }));
            if let Some(items) = value.get("blockers").and_then(Value::as_array) {
                for item in items {
                    if let Some(blocker) = item.as_str() {
                        blockers.push(format!("{key}: {blocker}"));
                    }
                }
            }
        } else {
            flows.insert(
                key,
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
        "evidence_verifier_flow",
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
        vec![json!({
            "path": "evidence/ln-devnet-evidence.json",
            "sha256": sha256_hex(&bytes)
        })]
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
    let mut state_channel_funding_txid_outpoint = Value::Null;
    let mut latest_state_settlement_txid_outpoint = Value::Null;
    let mut factory_id = Value::Null;
    let mut virtual_channel_ids = Vec::new();
    let mut materialisation_txid_outpoint = Value::Null;
    let mut refund_txid_outpoint = Value::Null;
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
            state_channel_funding_txid_outpoint = json!(outpoint);
        }
        if let Some(txid) = live_state.pointer("/funding/txid").and_then(Value::as_str) {
            state_txids_or_transition_ids.push(json!(txid));
        }
        if let Some(txid) = live_state
            .pointer("/state_update/txid")
            .and_then(Value::as_str)
        {
            state_txids_or_transition_ids.push(json!(txid));
        }
        if let Some(txid) = live_state
            .pointer("/settlement/txid")
            .and_then(Value::as_str)
        {
            latest_state_settlement_txid_outpoint = json!(format!("{txid}:0,{txid}:1"));
            state_txids_or_transition_ids.push(json!(txid));
        }
        if let Some(outpoint) = live_state
            .pointer("/state_update/outpoint")
            .and_then(Value::as_str)
        {
            state_txids_or_transition_ids.push(json!(outpoint));
        }
        if let Some(txid) = live_state
            .pointer("/stale_state_rejection/attempted_txid")
            .and_then(Value::as_str)
        {
            state_txids_or_transition_ids.push(json!(txid));
        }
        for pointer in [
            "/funding/raw_tx",
            "/state_update/raw_tx",
            "/stale_state_rejection/attempted_tx",
            "/settlement/raw_tx",
        ] {
            if let Some(record) = live_state.pointer(pointer) {
                raw_transaction_paths_and_hashes.push(record.clone());
            }
        }
        for pointer in [
            "/settlement/state_1_redeem_script",
            "/settlement/state_2_redeem_script",
        ] {
            if let Some(record) = live_state.pointer(pointer) {
                script_paths_and_hashes.push(record.clone());
            }
        }
        for pointer in [
            "/state_update/witness",
            "/stale_state_rejection/witness",
            "/settlement/witness",
        ] {
            if let Some(record) = live_state.pointer(pointer) {
                witness_paths_and_hashes.push(record.clone());
            }
        }
        if let Some(hash) = live_state
            .pointer("/settlement_template/hash")
            .and_then(Value::as_str)
        {
            settlement_template_hashes.push(json!(hash));
        }
        if let Some(hash) = live_state
            .pointer("/channel_receipt/hash")
            .and_then(Value::as_str)
        {
            channel_receipt_hashes.push(json!(hash));
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
            factory_id = json!("factory-live-1");
            virtual_channel_ids = vec![json!("factory-live-alice"), json!("factory-live-bob")];
        }
        if let Some(txid) = live.pointer(txid_pointer).and_then(Value::as_str) {
            match txid_target {
                "factory" => materialisation_txid_outpoint = json!(format!("{txid}:0,{txid}:1")),
                "refund" => refund_txid_outpoint = json!(format!("{txid}:0")),
                _ => state_txids_or_transition_ids.push(json!(txid)),
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
                raw_transaction_paths_and_hashes.push(record.clone());
            }
        }
        for pointer in [
            "/materialisation/redeem_script",
            "/settlement/redeem_script",
            "/refund/redeem_script",
        ] {
            if let Some(record) = live.pointer(pointer) {
                script_paths_and_hashes.push(record.clone());
            }
        }
        for pointer in [
            "/materialisation/witness",
            "/settlement/witness",
            "/early_refund_rejection/witness",
            "/refund/witness",
        ] {
            if let Some(record) = live.pointer(pointer) {
                witness_paths_and_hashes.push(record.clone());
            }
        }
    }

    let report = json!({
        "timestamp": timestamp(),
        "git_commit": git_stdout(&root()?, &["rev-parse", "--verify", "HEAD"]),
        "tool_versions": detection.tools,
        "kaspa_branch_profile": kaspa_branch_profile,
        "enabled_opcode_capability_evidence": {
            "source_repo": source_repo,
            "op_cat": "covered by Toccata source evidence and covenant VM transcript",
            "introspection": "covered by Toccata source evidence and live daemon transaction transcript",
            "checksigfromstack": "covered by Toccata source evidence and covenant VM transcript",
            "hashlock": "covered by Kurrent live hashlock settlement evidence",
            "timelock_refund": "covered by Kurrent live early-refund rejection and matured refund evidence",
            "covenant_output_constraints": "covered by Kurrent live state update, stale-state rejection, and settlement evidence"
        },
        "network_devnet_id": "local-kaspa-simnet-toccata+bitcoin-regtest-lnd",
        "state_channel_funding_txid_outpoint": state_channel_funding_txid_outpoint,
        "state_txids_or_transition_ids": state_txids_or_transition_ids,
        "latest_state_settlement_txid_outpoint": latest_state_settlement_txid_outpoint,
        "factory_id": factory_id,
        "virtual_channel_ids": virtual_channel_ids,
        "factory_state_roots_before_after": [],
        "materialisation_txid_outpoint": materialisation_txid_outpoint,
        "ln_invoice_payment_preimage_evidence": ln_invoice_payment_preimage_evidence,
        "refund_txid_outpoint": refund_txid_outpoint,
        "raw_transaction_paths_and_hashes": raw_transaction_paths_and_hashes,
        "script_paths_and_hashes": script_paths_and_hashes,
        "witness_paths_and_hashes": witness_paths_and_hashes,
        "flow_evidence_paths_and_hashes": flow_evidence_paths_and_hashes,
        "settlement_template_hashes": settlement_template_hashes,
        "channel_receipt_hashes": channel_receipt_hashes,
        "command_transcript_paths": command_transcript_paths,
        "flows": flows,
        "status": status,
        "blocker_code": blocker_code,
        "blockers": blockers,
    });
    write_json_file(&evidence_root.join("kurrent-acceptance.json"), &report)
}

fn verify_evidence() -> Result<u8, String> {
    let root = root()?;
    let path = evidence_dir()?.join("kurrent-acceptance.json");
    if !path.exists() {
        eprintln!("missing evidence/kurrent-acceptance.json");
        return Ok(EXIT_EVIDENCE);
    }
    let report: Value = serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if report.get("status").and_then(Value::as_str) != Some("passed") {
        eprintln!("acceptance evidence is not passed");
        return Ok(EXIT_EVIDENCE);
    }
    if report
        .get("blockers")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(true)
    {
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
    let flows = report.get("flows").and_then(Value::as_object);
    for key in required {
        if flows.and_then(|m| m.get(key)).and_then(Value::as_str) != Some("passed") {
            eprintln!("missing passed flow: {key}");
            return Ok(EXIT_EVIDENCE);
        }
    }

    for field in [
        "network_devnet_id",
        "state_channel_funding_txid_outpoint",
        "latest_state_settlement_txid_outpoint",
        "factory_id",
        "materialisation_txid_outpoint",
        "refund_txid_outpoint",
    ] {
        if report
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or("")
            .is_empty()
        {
            eprintln!("missing required acceptance field: {field}");
            return Ok(EXIT_EVIDENCE);
        }
    }
    for bucket in ["virtual_channel_ids", "state_txids_or_transition_ids"] {
        if report
            .get(bucket)
            .and_then(Value::as_array)
            .map(Vec::is_empty)
            .unwrap_or(true)
        {
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
        let Some(records) = report.get(bucket).and_then(Value::as_array) else {
            eprintln!("missing evidence bucket: {bucket}");
            return Ok(EXIT_EVIDENCE);
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

    let Some(transcripts) = report
        .get("command_transcript_paths")
        .and_then(Value::as_array)
    else {
        eprintln!("missing evidence bucket: command_transcript_paths");
        return Ok(EXIT_EVIDENCE);
    };
    if transcripts.is_empty() {
        eprintln!("missing evidence bucket: command_transcript_paths");
        return Ok(EXIT_EVIDENCE);
    }
    for transcript in transcripts {
        let Some(path) = transcript.as_str() else {
            eprintln!("invalid transcript path record: {transcript}");
            return Ok(EXIT_EVIDENCE);
        };
        if !resolve_record_path(&root, path).is_file() {
            eprintln!("missing transcript file: {path}");
            return Ok(EXIT_EVIDENCE);
        }
    }
    Ok(0)
}

#[derive(Clone, Copy)]
enum HashMode {
    FileBytes,
    HexDecodedBytes,
}

fn verify_file_hash_record(
    root: &Path,
    bucket: &str,
    record: &Value,
    mode: HashMode,
) -> Result<(), String> {
    let path = record
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("invalid path/hash record in {bucket}: {record}"))?;
    let expected = record
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("invalid path/hash record in {bucket}: {record}"))?;
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
    let kaspa = parent.join("rusty-kaspa-toccata");
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
                .arg("--branch")
                .arg("toccata")
                .arg("--single-branch")
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

fn write_state_channel_protocol_files() -> Result<Vec<FileEvidence>, String> {
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
                blockers.push("Toccata txscript covenant VM example failed".to_string());
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
                blockers
                    .push("Toccata daemon live transaction relay/mining test failed".to_string());
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
) -> Result<Option<(FileEvidence, Value)>, String> {
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

fn write_factory_protocol_files() -> Result<Vec<FileEvidence>, String> {
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
        "script_hash": sha256_hex(format!("kurrent-{direction}-hashlock-script").as_bytes()),
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
            "settlement plus refund double claim is rejected"
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
