use crate::{sha256_hex, EvidenceFile};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPaths {
    pub kaspad: PathBuf,
    pub kaspa_cli: PathBuf,
    pub kaspa_wallet: PathBuf,
    pub lnd: PathBuf,
    pub lncli: PathBuf,
    pub bitcoind: PathBuf,
    pub bitcoin_cli: PathBuf,
}

impl ToolPaths {
    pub fn missing(&self) -> Vec<String> {
        [
            ("kaspad", &self.kaspad),
            ("kaspa-cli", &self.kaspa_cli),
            ("kaspa-wallet", &self.kaspa_wallet),
            ("lnd", &self.lnd),
            ("lncli", &self.lncli),
            ("bitcoind", &self.bitcoind),
            ("bitcoin-cli", &self.bitcoin_cli),
        ]
        .into_iter()
        .filter_map(|(name, path)| (!path.is_file()).then_some(name.to_string()))
        .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.missing().is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevnetProfile {
    pub name: String,
    pub kaspa_network: String,
    pub kaspa_rpc: String,
    pub kaspa_p2p: String,
    pub bitcoin_rpc: String,
    pub lnd_alice_rpc: String,
    pub lnd_bob_rpc: String,
    pub data_dir: PathBuf,
}

impl Default for DevnetProfile {
    fn default() -> Self {
        Self {
            name: "kurrent-local-devnet".to_string(),
            kaspa_network: "simnet".to_string(),
            kaspa_rpc: "127.0.0.1:16210".to_string(),
            kaspa_p2p: "127.0.0.1:16211".to_string(),
            bitcoin_rpc: "127.0.0.1:18443".to_string(),
            lnd_alice_rpc: "127.0.0.1:10009".to_string(),
            lnd_bob_rpc: "127.0.0.1:10010".to_string(),
            data_dir: PathBuf::from(".kurrent-devnet"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BusinessFlow {
    KaspaStateChannel,
    KaspaFactory,
    LnToKaspa,
    KaspaToLn,
    RefundTimeout,
    EvidenceVerifier,
}

impl BusinessFlow {
    pub fn id(&self) -> &'static str {
        match self {
            Self::KaspaStateChannel => "kaspa_state_channel_flow",
            Self::KaspaFactory => "kaspa_factory_flow",
            Self::LnToKaspa => "ln_to_kaspa_atomic_settlement",
            Self::KaspaToLn => "kaspa_to_ln_atomic_settlement",
            Self::RefundTimeout => "refund_timeout_flow",
            Self::EvidenceVerifier => "evidence_verifier_flow",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::KaspaStateChannel,
            Self::KaspaFactory,
            Self::LnToKaspa,
            Self::KaspaToLn,
            Self::RefundTimeout,
            Self::EvidenceVerifier,
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandReceipt {
    pub id: String,
    pub command: Vec<String>,
    pub status_code: Option<i32>,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
    pub started_at_unix: u64,
    pub finished_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowEvidence {
    pub flow: BusinessFlow,
    pub status: String,
    pub command_receipts: Vec<CommandReceipt>,
    pub required_evidence: Vec<EvidenceFile>,
    pub blockers: Vec<String>,
}

impl FlowEvidence {
    pub fn is_passed(&self) -> bool {
        self.status == "passed" && self.blockers.is_empty() && !self.required_evidence.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductionReadinessAudit {
    pub status: String,
    pub tool_blockers: Vec<String>,
    pub flow_status: BTreeMap<String, String>,
    pub missing_flow_evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KurrentClient {
    pub tools: ToolPaths,
    pub profile: DevnetProfile,
    pub evidence_dir: PathBuf,
}

impl KurrentClient {
    pub fn new(tools: ToolPaths, profile: DevnetProfile, evidence_dir: PathBuf) -> Self {
        Self {
            tools,
            profile,
            evidence_dir,
        }
    }

    pub fn audit_readiness(&self, flows: &[FlowEvidence]) -> ProductionReadinessAudit {
        let tool_blockers = self.tools.missing();
        let mut flow_status = BTreeMap::new();
        let mut missing_flow_evidence = Vec::new();
        for flow in BusinessFlow::all() {
            let id = flow.id().to_string();
            match flows.iter().find(|candidate| candidate.flow == flow) {
                Some(evidence) if evidence.is_passed() => {
                    flow_status.insert(id, "passed".to_string());
                }
                Some(evidence) => {
                    flow_status.insert(id.clone(), evidence.status.clone());
                    missing_flow_evidence.push(id);
                }
                None => {
                    flow_status.insert(id.clone(), "missing".to_string());
                    missing_flow_evidence.push(id);
                }
            }
        }
        let status = if tool_blockers.is_empty() && missing_flow_evidence.is_empty() {
            "passed"
        } else {
            "failed/blocked"
        }
        .to_string();
        ProductionReadinessAudit {
            status,
            tool_blockers,
            flow_status,
            missing_flow_evidence,
        }
    }

    pub fn run_capture(
        &self,
        id: &str,
        program: &Path,
        args: &[&str],
    ) -> Result<CommandReceipt, String> {
        fs::create_dir_all(&self.evidence_dir).map_err(|e| e.to_string())?;
        let stdout_path = self.evidence_dir.join(format!("{id}.stdout.log"));
        let stderr_path = self.evidence_dir.join(format!("{id}.stderr.log"));
        let started_at_unix = unix_now();
        let output = Command::new(program)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| format!("failed to run {}: {e}", program.display()))?;
        fs::write(&stdout_path, &output.stdout).map_err(|e| e.to_string())?;
        fs::write(&stderr_path, &output.stderr).map_err(|e| e.to_string())?;
        Ok(CommandReceipt {
            id: id.to_string(),
            command: std::iter::once(program.display().to_string())
                .chain(args.iter().map(|arg| (*arg).to_string()))
                .collect(),
            status_code: output.status.code(),
            stdout_sha256: sha256_hex(&output.stdout),
            stderr_sha256: sha256_hex(&output.stderr),
            stdout_path,
            stderr_path,
            started_at_unix,
            finished_at_unix: unix_now(),
        })
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
