use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub mod client;

pub const DOMAIN_STATE: &str = "KURRENT_STATE_V1";
pub const DOMAIN_SETTLEMENT_TEMPLATE: &str = "KURRENT_SETTLEMENT_TEMPLATE_V1";
pub const DOMAIN_CHANNEL_RECEIPT: &str = "KURRENT_CHANNEL_RECEIPT_V1";
pub const DOMAIN_FACTORY_MATERIALISATION: &str = "KURRENT_FACTORY_MATERIALISATION_V1";
pub const DOMAIN_LN_INTEROP: &str = "KURRENT_LN_INTEROP_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KurrentError {
    NonMonotonicState {
        current: u64,
        attempted: u64,
    },
    SameNumberConflict {
        state_number: u64,
    },
    UnknownChannel(String),
    StaleState {
        latest: u64,
        attempted: u64,
    },
    SettlementTemplateMismatch,
    DuplicateSettlement(String),
    DuplicateReceipt(String),
    WrongFactoryId {
        expected: String,
        actual: String,
    },
    WrongVirtualChannelId(String),
    DoubleMaterialisation(String),
    MutatedUntouchedVirtualChannel(String),
    FeePrincipalNotSeparated,
    ConservationFailure {
        expected: u64,
        actual: u64,
    },
    WrongPreimage,
    ReceiptReplay,
    RefundNotMature {
        current_daa: u64,
        required_daa: u64,
    },
    DoubleClaim(String),
    MissingEvidenceFile(String),
    EvidenceHashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}

pub type Result<T> = std::result::Result<T, KurrentError>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KurrentChannelConfig {
    pub protocol_version: u16,
    pub network_profile: String,
    pub genesis_or_devnet_id: Option<String>,
    pub channel_id: String,
    pub participants: Vec<String>,
    pub challenge_policy: ChallengePolicy,
    pub access_manifest: AccessManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FundingState {
    pub funding_outpoint: String,
    pub total_principal: u64,
    pub principal_by_participant: BTreeMap<String, u64>,
    pub fee_reserve: u64,
    pub script_covenant_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LatestStateHeader {
    pub network_profile: String,
    pub genesis_or_devnet_id: Option<String>,
    pub funding_outpoint: String,
    pub channel_id: String,
    pub factory_id: Option<String>,
    pub virtual_channel_id: Option<String>,
    pub state_number: u64,
    pub previous_state_commitment: String,
    pub new_state_commitment: String,
    pub settlement_template_hash: String,
    pub challenge_policy_hash: String,
    pub participant_set_hash: String,
    pub script_covenant_hash: String,
    pub protocol_version: u16,
    pub domain_separator: String,
}

impl LatestStateHeader {
    pub fn hash(&self) -> String {
        hash_json(DOMAIN_STATE, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateUpdate {
    pub header: LatestStateHeader,
    pub balances: BTreeMap<String, u64>,
    pub participant_signatures: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementTemplate {
    pub template_id: String,
    pub outputs: BTreeMap<String, u64>,
    pub refund_after_daa: Option<u64>,
    pub script_covenant_hash: String,
}

impl SettlementTemplate {
    pub fn hash(&self) -> String {
        hash_json(DOMAIN_SETTLEMENT_TEMPLATE, self)
    }

    pub fn output_sum(&self) -> u64 {
        self.outputs.values().sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengePolicy {
    pub mode: String,
    pub challenge_window_daa: u64,
    pub same_number_conflict_rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelReceipt {
    pub protocol_version: u16,
    pub network_profile: String,
    pub channel_id: String,
    pub factory_id: Option<String>,
    pub virtual_channel_id: Option<String>,
    pub funding_outpoint: String,
    pub output_id: String,
    pub state_number: u64,
    pub settlement_template_hash: String,
    pub swap_id: Option<String>,
    pub direction: Option<String>,
    pub receipt_hash: String,
}

impl ChannelReceipt {
    pub fn new(
        protocol_version: u16,
        network_profile: impl Into<String>,
        channel_id: impl Into<String>,
        funding_outpoint: impl Into<String>,
        output_id: impl Into<String>,
        state_number: u64,
        settlement_template_hash: impl Into<String>,
    ) -> Self {
        let mut receipt = Self {
            protocol_version,
            network_profile: network_profile.into(),
            channel_id: channel_id.into(),
            factory_id: None,
            virtual_channel_id: None,
            funding_outpoint: funding_outpoint.into(),
            output_id: output_id.into(),
            state_number,
            settlement_template_hash: settlement_template_hash.into(),
            swap_id: None,
            direction: None,
            receipt_hash: String::new(),
        };
        receipt.receipt_hash = hash_json(DOMAIN_CHANNEL_RECEIPT, &receipt.scope());
        receipt
    }

    pub fn scope_key(&self) -> String {
        hash_json(DOMAIN_CHANNEL_RECEIPT, &self.scope())
    }

    fn scope(&self) -> ChannelReceiptScope<'_> {
        ChannelReceiptScope {
            protocol_version: self.protocol_version,
            network_profile: &self.network_profile,
            channel_id: &self.channel_id,
            factory_id: self.factory_id.as_deref(),
            virtual_channel_id: self.virtual_channel_id.as_deref(),
            funding_outpoint: &self.funding_outpoint,
            output_id: &self.output_id,
            state_number: self.state_number,
            settlement_template_hash: &self.settlement_template_hash,
            swap_id: self.swap_id.as_deref(),
            direction: self.direction.as_deref(),
        }
    }
}

#[derive(Debug, Serialize)]
struct ChannelReceiptScope<'a> {
    protocol_version: u16,
    network_profile: &'a str,
    channel_id: &'a str,
    factory_id: Option<&'a str>,
    virtual_channel_id: Option<&'a str>,
    funding_outpoint: &'a str,
    output_id: &'a str,
    state_number: u64,
    settlement_template_hash: &'a str,
    swap_id: Option<&'a str>,
    direction: Option<&'a str>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FactoryState {
    pub factory_id: String,
    pub network_profile: String,
    pub total_principal: u64,
    pub fee_reserve: u64,
    pub virtual_channels: BTreeMap<String, VirtualChannelState>,
    pub materialised_receipts: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirtualChannelState {
    pub virtual_channel_id: String,
    pub channel_id: String,
    pub balance_by_participant: BTreeMap<String, u64>,
    pub state_number: u64,
    pub state_commitment: String,
}

impl VirtualChannelState {
    pub fn principal(&self) -> u64 {
        self.balance_by_participant.values().sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessManifest {
    pub authorised_participants: Vec<String>,
    pub required_signatures: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TouchedLeaves {
    pub virtual_channel_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaterialisationPlan {
    pub materialisation_id: String,
    pub factory_id: String,
    pub virtual_channel_id: String,
    pub touched_leaves: TouchedLeaves,
    pub principal_input_ids: BTreeSet<String>,
    pub fee_input_ids: BTreeSet<String>,
    pub principal_amount: u64,
    pub fee_amount: u64,
    pub output_amounts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnInteropConfig {
    pub protocol_version: u16,
    pub network_profile: String,
    pub gateway_id: String,
    pub settlement_timeout_daa: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LnSwapEvidence {
    pub protocol_version: u16,
    pub network_profile: String,
    pub swap_id: String,
    pub direction: String,
    pub ln_payment_hash: String,
    pub preimage: String,
    pub preimage_hash: String,
    pub kaspa_funding_outpoint: String,
    pub kaspa_settlement_outpoint: String,
    pub amount: u64,
    pub recipient: String,
    pub script_hash: String,
    pub evidence_file_hashes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceFile {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceBundle {
    pub acceptance_json: String,
    pub referenced_files: Vec<EvidenceFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptanceReport {
    pub timestamp: String,
    pub git_commit: Option<String>,
    pub status: String,
    pub blockers: Vec<String>,
    pub evidence_bundle: EvidenceBundle,
}

#[derive(Default, Debug)]
pub struct SettlementRegistry {
    latest_by_channel: BTreeMap<String, LatestStateHeader>,
    seen_commitments: BTreeMap<(String, u64), String>,
    settled_channels: BTreeSet<String>,
    receipts: BTreeSet<String>,
    claims: BTreeSet<String>,
}

impl SettlementRegistry {
    pub fn accept_update(&mut self, update: StateUpdate) -> Result<()> {
        let channel_id = update.header.channel_id.clone();
        let state_number = update.header.state_number;

        if let Some(seen) = self
            .seen_commitments
            .get(&(channel_id.clone(), state_number))
        {
            if seen != &update.header.new_state_commitment {
                return Err(KurrentError::SameNumberConflict { state_number });
            }
        }

        if let Some(current) = self.latest_by_channel.get(&channel_id) {
            if state_number != current.state_number + 1 {
                return Err(KurrentError::NonMonotonicState {
                    current: current.state_number,
                    attempted: state_number,
                });
            }
        } else if state_number != 0 {
            return Err(KurrentError::NonMonotonicState {
                current: 0,
                attempted: state_number,
            });
        }

        self.seen_commitments.insert(
            (channel_id.clone(), state_number),
            update.header.new_state_commitment.clone(),
        );
        self.latest_by_channel.insert(channel_id, update.header);
        Ok(())
    }

    pub fn settle(
        &mut self,
        update: &StateUpdate,
        template: &SettlementTemplate,
    ) -> Result<ChannelReceipt> {
        let latest = self
            .latest_by_channel
            .get(&update.header.channel_id)
            .ok_or_else(|| KurrentError::UnknownChannel(update.header.channel_id.clone()))?;

        if latest.state_number != update.header.state_number
            || latest.new_state_commitment != update.header.new_state_commitment
        {
            return Err(KurrentError::StaleState {
                latest: latest.state_number,
                attempted: update.header.state_number,
            });
        }

        if update.header.settlement_template_hash != template.hash() {
            return Err(KurrentError::SettlementTemplateMismatch);
        }

        if !self
            .settled_channels
            .insert(update.header.channel_id.clone())
        {
            return Err(KurrentError::DuplicateSettlement(
                update.header.channel_id.clone(),
            ));
        }

        let receipt = ChannelReceipt::new(
            update.header.protocol_version,
            update.header.network_profile.clone(),
            update.header.channel_id.clone(),
            update.header.funding_outpoint.clone(),
            template.template_id.clone(),
            update.header.state_number,
            update.header.settlement_template_hash.clone(),
        );
        self.register_receipt(&receipt)?;
        Ok(receipt)
    }

    pub fn register_receipt(&mut self, receipt: &ChannelReceipt) -> Result<()> {
        let key = receipt.scope_key();
        if self.receipts.insert(key.clone()) {
            Ok(())
        } else {
            Err(KurrentError::DuplicateReceipt(key))
        }
    }

    pub fn settle_claim(&mut self, claim_id: impl Into<String>) -> Result<()> {
        let claim_id = claim_id.into();
        if self.claims.insert(claim_id.clone()) {
            Ok(())
        } else {
            Err(KurrentError::DoubleClaim(claim_id))
        }
    }

    pub fn refund_claim(
        &mut self,
        claim_id: impl Into<String>,
        current_daa: u64,
        required_daa: u64,
    ) -> Result<()> {
        if current_daa < required_daa {
            return Err(KurrentError::RefundNotMature {
                current_daa,
                required_daa,
            });
        }
        self.settle_claim(claim_id)
    }
}

pub fn validate_materialisation(
    before: &FactoryState,
    after: &FactoryState,
    plan: &MaterialisationPlan,
) -> Result<ChannelReceipt> {
    if before.factory_id != plan.factory_id {
        return Err(KurrentError::WrongFactoryId {
            expected: before.factory_id.clone(),
            actual: plan.factory_id.clone(),
        });
    }
    if before.factory_id != after.factory_id {
        return Err(KurrentError::WrongFactoryId {
            expected: before.factory_id.clone(),
            actual: after.factory_id.clone(),
        });
    }
    if before
        .materialised_receipts
        .contains(&plan.materialisation_id)
    {
        return Err(KurrentError::DoubleMaterialisation(
            plan.materialisation_id.clone(),
        ));
    }
    if !before
        .virtual_channels
        .contains_key(&plan.virtual_channel_id)
    {
        return Err(KurrentError::WrongVirtualChannelId(
            plan.virtual_channel_id.clone(),
        ));
    }
    if !plan
        .touched_leaves
        .virtual_channel_ids
        .contains(&plan.virtual_channel_id)
    {
        return Err(KurrentError::WrongVirtualChannelId(
            plan.virtual_channel_id.clone(),
        ));
    }
    if !plan.principal_input_ids.is_disjoint(&plan.fee_input_ids) {
        return Err(KurrentError::FeePrincipalNotSeparated);
    }

    for (id, channel) in &before.virtual_channels {
        if !plan.touched_leaves.virtual_channel_ids.contains(id) {
            let Some(after_channel) = after.virtual_channels.get(id) else {
                return Err(KurrentError::MutatedUntouchedVirtualChannel(id.clone()));
            };
            if after_channel != channel {
                return Err(KurrentError::MutatedUntouchedVirtualChannel(id.clone()));
            }
        }
    }

    let expected = before.total_principal + before.fee_reserve;
    let actual =
        after.total_principal + after.fee_reserve + plan.output_amounts.values().sum::<u64>();
    if expected != actual {
        return Err(KurrentError::ConservationFailure { expected, actual });
    }

    let mut receipt = ChannelReceipt::new(
        1,
        before.network_profile.clone(),
        plan.virtual_channel_id.clone(),
        before.factory_id.clone(),
        plan.materialisation_id.clone(),
        before.virtual_channels[&plan.virtual_channel_id].state_number,
        hash_json(DOMAIN_FACTORY_MATERIALISATION, plan),
    );
    receipt.factory_id = Some(before.factory_id.clone());
    receipt.virtual_channel_id = Some(plan.virtual_channel_id.clone());
    receipt.receipt_hash = receipt.scope_key();
    Ok(receipt)
}

pub fn validate_preimage(preimage: &str, expected_hash: &str) -> Result<()> {
    let bytes = decode_preimage(preimage)?;
    validate_preimage_bytes(&bytes, expected_hash)
}

pub fn validate_preimage_bytes(preimage: &[u8], expected_hash: &str) -> Result<()> {
    let actual = sha256_hex(preimage);
    if actual == expected_hash {
        Ok(())
    } else {
        Err(KurrentError::WrongPreimage)
    }
}

fn decode_preimage(preimage: &str) -> Result<Vec<u8>> {
    if preimage.len().is_multiple_of(2) && preimage.chars().all(|ch| ch.is_ascii_hexdigit()) {
        hex::decode(preimage).map_err(|_| KurrentError::WrongPreimage)
    } else {
        Ok(preimage.as_bytes().to_vec())
    }
}

pub fn validate_ln_swap(evidence: &LnSwapEvidence, receipt: &ChannelReceipt) -> Result<()> {
    validate_preimage(&evidence.preimage, &evidence.ln_payment_hash)?;
    if evidence.preimage_hash != evidence.ln_payment_hash {
        return Err(KurrentError::WrongPreimage);
    }
    if receipt.network_profile != evidence.network_profile
        || receipt.swap_id.as_deref() != Some(evidence.swap_id.as_str())
        || receipt.direction.as_deref() != Some(evidence.direction.as_str())
    {
        return Err(KurrentError::ReceiptReplay);
    }
    Ok(())
}

pub fn verify_evidence_bundle(root: &Path, bundle: &EvidenceBundle) -> Result<()> {
    for file in &bundle.referenced_files {
        let path = root.join(&file.path);
        if !path.exists() {
            return Err(KurrentError::MissingEvidenceFile(file.path.clone()));
        }
        let actual = sha256_hex(
            &fs::read(&path).map_err(|_| KurrentError::MissingEvidenceFile(file.path.clone()))?,
        );
        if actual != file.sha256 {
            return Err(KurrentError::EvidenceHashMismatch {
                path: file.path.clone(),
                expected: file.sha256.clone(),
                actual,
            });
        }
    }
    Ok(())
}

pub fn hash_json<T: Serialize>(domain: &str, value: &T) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(
        serde_json::to_vec(value).expect("serialisation for protocol objects must be infallible"),
    );
    hex::encode(hasher.finalize())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
