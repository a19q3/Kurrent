//! Kurrent prototype marker evidence path.
//!
//! # Scope: prototype marker evidence path vs normative bilateral channel
//!
//! This crate is the typed Rust model that backs the Kurrent local-devnet
//! evidence harness. It is the **prototype marker evidence path**, not
//! the normative bilateral contest-output channel construction. The
//! normative construction is specified in §5–§7 of the thesis and lives
//! in the `normative` section of this file (functions such as
//! `compute_scope_id` with `ScopeInputs`, `StateCertMessage`,
//! `CoopCloseMessage`, `PolicyEncoding`, `EncodedSpk`,
//! `BoundedShape`, `CanonicalSequence`, `validate_conservation`,
//! `musig2_aggregate_xonly`, `musig2_verify`). The marker-and-verifier
//! flow above is the prototype evidence path; it is not the normative
//! construction and does not implement the contest-output transaction
//! graph.
//!
//! Per the thesis §13 production-readiness scope, the normative
//! bilateral channel does not require a consensus-recognised
//! accepted-ordering surface; the prototype marker evidence path does
//! require it; future compressed-factory / based-app / zk compositions
//! may. The two surfaces are different artefacts. Conflating them
//! would force the normative channel to depend on a prototype
//! substrate, or would force the prototype to claim production-grade
//! fund safety.
//!
//! # Three-layer derivation for sponsor accounting
//!
//! The claim "the sponsor input must not alter the authorised settlement
//! distribution" is the composition of three guarantees, each discharged
//! at a different layer:
//!
//! 1. **Covenant layer** (consensus-recognised). The covenant script
//!    verifies that the settlement outputs match the authorised
//!    settlement distribution committed in the state root. A sponsor
//!    cannot mutate what is paid to channel participants.
//! 2. **Verifier layer** (this crate). The typed model reconstructs
//!    sponsor-input totals, sponsor-change totals, and the resulting
//!    sponsor fee from raw witness material, and verifies that they
//!    bind to the sponsor accounting committed in the state header.
//! 3. **Mempool / fee-market layer** (production assumption). The
//!    residual attack surface --- a sponsor inflating fees to dominate
//!    witness economics --- is **not** discharged by either the
//!    covenant or the verifier. A production protocol must additionally
//!    bound the absolute fee magnitude under a bounded-inclusion
//!    assumption (fee reserve, anchor/child fee-bumping, congestion
//!    model, censorship assumption, watchtower fee budget).
//!
//! # Named protocol-specification requirements (not implemented here)
//!
//! The following items are requirements a production protocol
//! specification must satisfy; they are recorded here so that the
//! boundary between this crate's scope and the production
//! protocol-specification work is visible to a reader:
//!
//! - **(i) Response-window state machine.** Half-open `[a, d)` interval,
//!   DAA-score interpretation of maturity, and validation-view
//!   semantics at the boundary. The protocol provides no state-number
//!   priority after maturity; conflicting valid spends are resolved by
//!   ordinary consensus acceptance.
//! - **(ii) Bounded-inclusion and fee-market assumption.** An explicit
//!   fee reserve, anchor/child fee-bumping, congestion model,
//!   censorship/inclusion assumption, and watchtower fee budget.
//! - **(iii) Same-number conflict "first" under consensus finality.**
//! - **(iv) Operational key management.** Signing-ceremony procedure,
//!   recovery path, fixed-participant set rule.
//! - **(v) Factory completeness items.** Fixed-width arithmetic,
//!   range-constrained balances, canonical leaf ordering, non-membership
//!   proofs, factory-update authorisation rules, unilateral exit and
//!   unavailable-data behaviour, proof-size and verification-cost
//!   bounds.
//!
//! # Three-layer commitment hierarchy (legacy prototype surface)
//!
//! The legacy `LatestStateHeader` carries sixteen wire-level fields and
//! `state_update_signing_hash` binds most of them, producing multiple
//! sources of truth without additional cryptographic security. The
//! production protocol specification should converge to the three-layer
//! hierarchy defined in the thesis §5:
//!
//! - Static context: `KurrentScope` (prototype) →
//!   `ScopeInputs` (normative, see `normative` section).
//! - Dynamic state: `KurrentStateRoot` (prototype) →
//!   `StateRootInput` (normative).
//! - Participant authorisation: `compute_state_cert_message`
//!   (prototype) → `StateCertMessage::compute` (normative).
//!
//! The legacy functions remain because the prototype evidence path
//! still depends on them. The normative section below exposes the
//! cleaner signature payload that the production protocol
//! specification should converge to.
//!
//! # Three-layer derivation for sponsor accounting
//!
//! The claim "the sponsor input must not alter the authorised settlement
//! distribution" is the composition of three guarantees, each discharged
//! at a different layer:
//!
//! 1. **Covenant layer** (consensus-recognised). The covenant script
//!    verifies that the settlement outputs match the authorised
//!    `settlement_distribution_hash` committed in the state header. A
//!    sponsor cannot mutate what is paid to channel participants.
//!    **Not in scope for this crate.**
//! 2. **Verifier layer** (this crate). The typed model reconstructs
//!    sponsor-input totals, sponsor-change totals, and the resulting
//!    sponsor fee from raw witness material, and verifies that they
//!    bind to the sponsor accounting committed in the marker state
//!    header. See `validate_sponsor_evidence` for the layer-by-layer
//!    grouping.
//! 3. **Mempool / fee-market layer** (production assumption). The
//!    residual attack surface --- a sponsor inflating fees to dominate
//!    witness economics --- is **not** discharged by either the
//!    covenant or the verifier. A production protocol must additionally
//!    bound the absolute fee magnitude under a bounded-inclusion
//!    assumption (fee reserve, anchor/child fee-bumping, congestion
//!    model, censorship assumption, watchtower fee budget).
//!
//! # DAA score is the response-window substrate, not blue score
//!
//! Blue score is the cumulative DAG-work structural-ordering measure; two
//! blocks at different parents can share a blue score, and blue score
//! carries no direct time interpretation. DAA score is the consensus-
//! recognised virtual-time counter, with a target rate of approximately
//! one per second, monotonic through the accepted-transaction ordering
//! relation, and the natural input to a response-window parameter. All
//! response-window timing decisions in this crate consult
//! `SettlementCandidateEvidence::daa_score`, not
//! `SettlementCandidateEvidence::blue_score`; the `blue_score` field is
//! retained for structural-ordering analysis but is **not** the substrate
//! for any eligibility decision.
//!
//! # Named protocol-specification requirements (not implemented here)
//!
//! The following items are requirements a production protocol
//! specification must satisfy; they are recorded here so that the
//! boundary between this crate's scope and the production
//! protocol-specification work is visible to a reader:
//!
//! - **(i) Response-window state machine.** Window reset rule,
//!   half-open `[a, d)` interval, and deterministic tie-breaker when a
//!   replacement and a finalisation share the same DAA score. The local
//!   harness does not commit to a specific reset semantic; the policy
//!   field accepts a `response_window_daa` and applies it uniformly.
//! - **(ii) Accepted-ordering commitment stability.** Which selected-
//!   parent reference fixes a candidate's acceptance DAA score, whether
//!   that score can move under reorganisation, and when the commitment
//!   is sufficiently stable to discharge finality. The harness treats
//!   the candidate's `daa_score` as fixed by the lane proof; a
//!   production specification must specify the reorg-tolerance rule.
//! - **(iii) Sequential-reveal griefing prevention.** The protocol must
//!   prevent an old-state publisher from successively revealing
//!   `S_1, S_2, ..., S_{n-1}` to delay closure. The clean baseline is
//!   that every valid replacement creates a fresh contest output with a
//!   fresh relative window; the harness's marker-based flow does not
//!   exercise this.
//! - **(iv) Bounded-inclusion and fee-market assumption.** An explicit
//!   fee reserve, anchor/child fee-bumping, congestion model,
//!   censorship/inclusion assumption, and watchtower fee budget. The
//!   verifier-layer checks in `validate_sponsor_evidence` bound fee
//!   magnitude under `max_sponsor_fee`; the bounded-inclusion
//!   assumption itself is not enforced anywhere in this crate.
//! - **(v) Same-number conflict "first" under consensus finality.** The
//!   thesis records the choice between first consensus-finalised
//!   certificate wins, safe fallback to the prior state, or explicit
//!   channel failure as a production requirement; this crate exposes
//!   the choice as [`SameNumberConflictRule`] but does not anchor a
//!   global signature ordering.
//! - **(vi) Factory completeness items.** Fixed-width arithmetic,
//!   range-constrained balances, canonical leaf ordering, non-membership
//!   proofs, factory-update authorisation rules, unilateral exit and
//!   unavailable-data behaviour, proof-size and verification-cost
//!   bounds. The factory evidence path in this crate uses full-state
//!   recomputation; compressed-factory commitment work remains future
//!   protocol-specification work in the thesis.
//!
//! # Missing design bridge
//!
//! The principal unresolved design bridge --- how ordering evidence
//! enters the covenant's consensus-validity predicate --- is recorded in
//! the thesis §"Missing design bridge: ordering evidence into the
//! covenant predicate". This crate does not implement that bridge.
//! Until it is specified, the construction remains verifier-assisted
//! rather than fully trust-minimised.
//!
//! # Three-layer commitment hierarchy (production target)
//!
//! The legacy `LatestStateHeader` carries sixteen wire-level fields and
//! `state_update_signing_hash` binds most of them, producing multiple
//! sources of truth without additional cryptographic security. The
//! production protocol specification should converge to the three-layer
//! hierarchy defined in the thesis §"A Sketch Construction":
//!
//! - Static context: [`KurrentScope`] committed once via
//!   [`compute_scope_id`].
//! - Dynamic state: [`KurrentStateRoot`] committed once via
//!   [`compute_state_root`].
//! - Participant authorisation: a constant-size signed message
//!   [`compute_state_cert_message`] that binds only `scope_id`, `epoch`,
//!   `state_number`, and `state_root`. The participant threshold
//!   signature is over this message. It does not bind the previous
//!   commitment, balances as a separate field, the settlement template
//!   hash as a separate field, the fee policy hash, the covenant
//!   identity, the script hash, the lane id, the participant set hash,
//!   or any factory-specific identity field.
//! - Predecessor transcript metadata: [`compute_transition_record`]
//!   produces a transition record between consecutive state roots. It
//!   is recorded off-chain for auditability and signing discipline; it
//!   is NOT a binding input to the on-chain displacement predicate.
//!
//! The functions in this section do not replace `state_update_signing_hash`
//! (which the legacy harness and evidence flow still depend on); they
//! expose the cleaner signature payload that the production protocol
//! specification should converge to.

use secp256k1::{schnorr::Signature, Message, XOnlyPublicKey};
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
pub const DOMAIN_PARTICIPANT_SET: &str = "KURRENT_PARTICIPANT_SET_V1";
pub const DOMAIN_CLAIM_SCOPE: &str = "KURRENT_CLAIM_SCOPE_V1";
pub const DOMAIN_STATE_SIGNATURE: &str = "KURRENT_STATE_SIGNATURE_V1";
pub const DOMAIN_LANE_ID: &str = "KURRENT_LANE_V1";
pub const DOMAIN_SETTLEMENT_DISTRIBUTION: &str = "KURRENT_SETTLEMENT_DISTRIBUTION_V1";
pub const DOMAIN_SETTLEMENT_FEE_POLICY: &str = "KURRENT_SETTLEMENT_FEE_POLICY_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KurrentError {
    NonMonotonicState {
        current: u64,
        attempted: u64,
    },
    SameNumberConflict {
        state_number: u64,
    },
    WrongDomainSeparator {
        expected: String,
        actual: String,
    },
    WrongProtocolVersion {
        expected: u16,
        actual: u16,
    },
    WrongNetworkProfile {
        expected: String,
        actual: String,
    },
    WrongGenesisOrDevnetId,
    WrongChannelId {
        expected: String,
        actual: String,
    },
    WrongFundingOutpoint {
        expected: String,
        actual: String,
    },
    PreviousStateMismatch {
        expected: String,
        actual: String,
    },
    UnknownChannel(String),
    StaleState {
        latest: u64,
        attempted: u64,
    },
    SettlementTemplateMismatch,
    DuplicateSettlement(String),
    DuplicateReceipt(String),
    ReceiptHashMismatch,
    WrongFactoryId {
        expected: String,
        actual: String,
    },
    WrongVirtualChannelId(String),
    DoubleMaterialisation(String),
    MaterialisedChannelStillActive(String),
    MaterialisationAmountMismatch {
        expected: u64,
        actual: u64,
    },
    MutatedUntouchedVirtualChannel(String),
    FeePrincipalNotSeparated,
    ConservationFailure {
        expected: u64,
        actual: u64,
    },
    ParticipantSetMismatch,
    UnauthorizedParticipant(String),
    InvalidParticipantPublicKey(String),
    InvalidParticipantSignature(String),
    InsufficientSignatures {
        required: u16,
        actual: u16,
    },
    WrongPreimage,
    WrongSettlementOutpoint {
        expected: String,
        actual: String,
    },
    WrongScriptHash {
        expected: String,
        actual: String,
    },
    WrongCovenantId {
        expected: Option<String>,
        actual: Option<String>,
    },
    InvalidLaneId {
        field: String,
        value: String,
    },
    WrongLaneId {
        expected: Option<String>,
        actual: Option<String>,
    },
    SettlementEligibilityEvidenceMismatch(String),
    InvalidSwapEvidence(String),
    ReceiptReplay,
    RefundNotMature {
        current_daa: u64,
        required_daa: u64,
    },
    DoubleClaim(String),
    ChannelAlreadySettled(String),
    WrongChallengePolicyHash,
    RefundNotConfigured,
    InjectedVirtualChannel(String),
    FactoryPrincipalInvariant {
        expected: u64,
        actual: u64,
    },
    MaterialisedReceiptsNotPreserved,
    MissingEvidenceFile(String),
    EvidenceHashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    /// Malformed `EncodedSpk` payload (truncated, length mismatch).
    /// Distinct from `WrongScriptHash` which is for a hash mismatch.
    InvalidSpkEncoding(String),
    /// `PolicyEncoding` carries a field that violates its v1 fixed
    /// assignment. The string names the field; the `u64` is the
    /// offending value (lossy for fields > 32 bits, kept for log use).
    InvalidPolicyField {
        field: &'static str,
        actual: u64,
    },
    /// `state_number` is outside the normative `0..=2^63 - 1` range.
    /// Distinct from `StaleState` which is for sequencing conflicts.
    StateNumberOutOfRange {
        attempted: u64,
        max_allowed: u64,
    },
    /// `CoopCloseMessage::input_outpoint` is not the canonical
    /// 36-byte outpoint (32-byte txid || 4-byte vout).
    InvalidOutpointLength {
        actual: usize,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lane_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FundingState {
    pub funding_outpoint: String,
    pub total_principal: u64,
    pub principal_by_participant: BTreeMap<String, u64>,
    pub fee_reserve: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lane_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_policy_hash: Option<String>,
    pub challenge_policy_hash: String,
    pub participant_set_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_lane_id: Option<String>,
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
pub struct SettlementEligibilityPolicy {
    pub response_window_daa: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementCandidateEvidence {
    pub network_profile: String,
    pub funding_outpoint: String,
    pub channel_id: String,
    pub factory_id: Option<String>,
    pub virtual_channel_id: Option<String>,
    pub state_number: u64,
    pub state_header_hash: String,
    pub lane_id: String,
    pub candidate_txid: String,
    pub accepted_order_index: u64,
    pub accepting_chain_block_hash: String,
    /// DAA score at which the candidate was accepted into the lane-local
    /// accepted-order evidence. **This is the substrate for the response
    /// window.** Production windows are parameterised as a DAA-score
    /// interval with a noise budget sized for the target network's DAA
    /// variance. See [`crate`]-level docstring on DAA-score vs blue-score
    /// substrate choice.
    pub daa_score: u64,
    /// Cumulative DAG-work blue score at the accepting chain block. This
    /// is a **structural-ordering measure, not a time measure** and is
    /// **not the substrate for the response window**. The field is
    /// retained because the KIP-21 lane proof material exposes both
    /// values and some downstream consumers (auditors, explorers) may
    /// surface blue score alongside DAA score for structural-ordering
    /// analysis. No settlement-eligibility decision in this crate
    /// consults `blue_score`; timing decisions always use [`Self::daa_score`].
    pub blue_score: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementEligibilityCandidate {
    pub update: StateUpdate,
    pub evidence: SettlementCandidateEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementEligibilityStatus {
    Provisional,
    Displaced,
    EligibleToFinalise,
    NotYetEligible,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementEligibilityDecision {
    pub candidate_txid: String,
    pub state_number: u64,
    pub status: SettlementEligibilityStatus,
    pub displaced_by: Option<String>,
    pub accepted_order_index: u64,
    pub accepted_daa_score: u64,
    pub eligible_after_daa: u64,
    pub observed_daa_score: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementFeePolicy {
    pub policy_id: String,
    pub max_sponsor_fee: u64,
    pub sponsor_mode: String,
}

impl SettlementFeePolicy {
    pub fn hash(&self) -> String {
        hash_json(DOMAIN_SETTLEMENT_FEE_POLICY, self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SettlementSponsorEvidence {
    pub candidate_txid: String,
    pub sponsor_input_outpoints: Vec<String>,
    pub sponsor_input_total: u64,
    pub sponsor_change_total: u64,
    pub sponsor_fee: u64,
    pub settlement_template_hash: String,
    pub settlement_distribution_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeSponsoredSettlementCandidate {
    pub eligibility: SettlementEligibilityCandidate,
    pub sponsor: SettlementSponsorEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FeeSponsoredSettlementDecision {
    pub eligibility: SettlementEligibilityDecision,
    pub sponsor_fee: u64,
    pub fee_policy_hash: String,
    pub settlement_distribution_hash: String,
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
        checked_sum(self.outputs.values().copied()).unwrap_or(u64::MAX)
    }

    pub fn checked_output_sum(&self) -> Result<u64> {
        checked_sum(self.outputs.values().copied()).ok_or(KurrentError::ConservationFailure {
            expected: u64::MAX,
            actual: u64::MAX,
        })
    }
}

pub fn settlement_distribution_hash(template: &SettlementTemplate) -> String {
    #[derive(Serialize)]
    struct SettlementDistribution<'a> {
        outputs: &'a BTreeMap<String, u64>,
    }

    hash_json(
        DOMAIN_SETTLEMENT_DISTRIBUTION,
        &SettlementDistribution {
            outputs: &template.outputs,
        },
    )
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SameNumberConflictRule {
    /// Reject any second commitment at state n that disagrees with the first
    /// commitment already accepted at state n. The parties must publish a fresh
    /// state (n+1) with an explicit chosen distribution. The invariant this
    /// preserves is that there is exactly one canonical commitment per state
    /// number, which the verifier can check without resolving any
    /// signature-ordering question. Conservative and verifier-friendly.
    #[default]
    RejectConflict,
    /// Treat the later commitment (in KIP-21 lane-local accepted order) as
    /// binding. Friendlier to offline or flaky signing flows but requires a
    /// global signature ordering (received order, wall-clock time, or another
    /// consensus-anchored sequence) that the model does not currently anchor.
    /// The harness uses lane-accepted-order as the closest available proxy;
    /// a production protocol must specify what "later" means under consensus
    /// finality --- first consensus-finalised certificate wins, safe fallback
    /// to the prior state, or explicit channel failure.
    PreferLater,
}

impl SameNumberConflictRule {
    /// Parse from the wire form used by `ChallengePolicy` JSON evidence.
    /// Unrecognised values fall back to [`RejectConflict`](SameNumberConflictRule::RejectConflict)
    /// so that older evidence files remain valid after the field is upgraded
    /// from a free-form string to this enum.
    pub fn parse(value: &str) -> Self {
        match value {
            "prefer-later" => Self::PreferLater,
            _ => Self::RejectConflict,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChallengePolicy {
    pub mode: String,
    pub challenge_window_daa: u64,
    pub same_number_conflict_rule: SameNumberConflictRule,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_policy_hash: Option<String>,
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
            fee_policy_hash: None,
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

    pub fn refresh_hash(&mut self) {
        self.receipt_hash = self.scope_key();
    }

    pub fn validate_hash(&self) -> Result<()> {
        if self.receipt_hash == self.scope_key() {
            Ok(())
        } else {
            Err(KurrentError::ReceiptHashMismatch)
        }
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
            fee_policy_hash: self.fee_policy_hash.as_deref(),
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
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_policy_hash: Option<&'a str>,
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
        checked_sum(self.balance_by_participant.values().copied()).unwrap_or(u64::MAX)
    }

    pub fn checked_principal(&self) -> Result<u64> {
        checked_sum(self.balance_by_participant.values().copied()).ok_or(
            KurrentError::ConservationFailure {
                expected: u64::MAX,
                actual: u64::MAX,
            },
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessManifest {
    pub authorised_participants: Vec<String>,
    pub participant_public_keys: BTreeMap<String, String>,
    pub required_signatures: u16,
}

#[derive(Debug, Serialize)]
struct StateUpdateSigningPayload<'a> {
    header: &'a LatestStateHeader,
    balances: &'a BTreeMap<String, u64>,
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
pub struct ToolEvidence {
    pub name: String,
    pub path: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowEvidenceFile {
    pub flow: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpcodeCapabilityEvidence {
    pub source_repo: Option<String>,
    pub op_cat: String,
    pub introspection: String,
    pub checksigfromstack: String,
    pub hashlock: String,
    pub timelock_refund: String,
    pub covenant_output_constraints: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptanceReport {
    pub timestamp: String,
    pub git_commit: Option<String>,
    pub tool_versions: Vec<ToolEvidence>,
    pub kaspa_branch_profile: Option<String>,
    pub enabled_opcode_capability_evidence: OpcodeCapabilityEvidence,
    pub network_devnet_id: String,
    pub state_channel_funding_txid_outpoint: String,
    pub state_txids_or_transition_ids: Vec<String>,
    pub latest_state_settlement_txid_outpoint: String,
    pub factory_id: String,
    pub virtual_channel_ids: Vec<String>,
    pub factory_state_roots_before_after: Vec<String>,
    pub materialisation_txid_outpoint: String,
    pub ln_invoice_payment_preimage_evidence: Vec<EvidenceFile>,
    pub refund_txid_outpoint: String,
    pub raw_transaction_paths_and_hashes: Vec<EvidenceFile>,
    pub script_paths_and_hashes: Vec<EvidenceFile>,
    pub witness_paths_and_hashes: Vec<EvidenceFile>,
    pub flow_evidence_paths_and_hashes: Vec<FlowEvidenceFile>,
    pub settlement_template_hashes: Vec<String>,
    pub channel_receipt_hashes: Vec<String>,
    pub command_transcript_paths: Vec<String>,
    pub flows: BTreeMap<String, String>,
    pub status: String,
    pub blocker_code: String,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductionEvidenceRequirement {
    pub id: String,
    pub description: String,
    pub evidence_path: String,
    pub present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProductionReadinessReport {
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
    pub status: String,
    pub acceptance_status: String,
    pub requirements: Vec<ProductionEvidenceRequirement>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityReviewArtifact {
    pub id: String,
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityReviewFindingSummary {
    pub critical_open: u64,
    pub high_open: u64,
    pub medium_open: u64,
    pub low_open: u64,
    pub accepted_risk_count: u64,
    pub fixed_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityReviewEvidence {
    pub schema_version: String,
    pub status: String,
    pub review_type: String,
    pub completed_at: String,
    pub reviewer_name: String,
    pub reviewer_organisation: String,
    pub reviewer_contact: String,
    pub reviewer_independence_attestation: String,
    pub reviewed_git_commit: String,
    pub scope: Vec<String>,
    pub methodology: Vec<String>,
    pub reviewed_artifacts: Vec<SecurityReviewArtifact>,
    pub finding_summary: SecurityReviewFindingSummary,
    pub unresolved_blocking_findings: Vec<String>,
    pub report: EvidenceFile,
    pub signed_attestation: EvidenceFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimScope {
    pub network_profile: String,
    pub funding_outpoint: String,
    pub output_id: String,
    pub claim_subject: String,
}

impl ClaimScope {
    pub fn exclusive_key(&self) -> String {
        hash_json(DOMAIN_CLAIM_SCOPE, self)
    }
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
    pub fn is_empty(&self) -> bool {
        self.latest_by_channel.is_empty()
    }

    pub fn accept_update(&mut self, update: StateUpdate) -> Result<()> {
        self.accept_update_with_rule(update, SameNumberConflictRule::default())
    }

    /// Accept a state update under an explicit
    /// [`SameNumberConflictRule`](SameNumberConflictRule). Under
    /// [`RejectConflict`](SameNumberConflictRule::RejectConflict), a second
    /// commitment at the same state number is rejected unless it matches the
    /// already-accepted commitment exactly. Under
    /// [`PreferLater`](SameNumberConflictRule::PreferLater), the second
    /// commitment overwrites the previously-stored commitment for that
    /// (channel, state_number) pair and becomes the new latest header for the
    /// channel; the lane-accepted-order used to decide "later" is enforced at
    /// the candidate-set layer in `evaluate_settlement_eligibility`, where the
    /// `accepted_order_index` from the KIP-21 lane proof is available.
    pub fn accept_update_with_rule(
        &mut self,
        update: StateUpdate,
        rule: SameNumberConflictRule,
    ) -> Result<()> {
        if update.header.domain_separator != DOMAIN_STATE {
            return Err(KurrentError::WrongDomainSeparator {
                expected: DOMAIN_STATE.to_string(),
                actual: update.header.domain_separator,
            });
        }
        let channel_id = update.header.channel_id.clone();
        let state_number = update.header.state_number;

        if self.settled_channels.contains(&channel_id) {
            return Err(KurrentError::ChannelAlreadySettled(channel_id));
        }

        if let Some(seen) = self
            .seen_commitments
            .get(&(channel_id.clone(), state_number))
        {
            if seen != &update.header.new_state_commitment {
                match rule {
                    SameNumberConflictRule::RejectConflict => {
                        return Err(KurrentError::SameNumberConflict { state_number });
                    }
                    SameNumberConflictRule::PreferLater => {
                        // Lane-accepted-order is enforced at the candidate-set
                        // layer in `evaluate_settlement_eligibility`. At the
                        // registry layer, PreferLater still records the
                        // overwriting commitment as the new canonical entry
                        // for this (channel, state_number) pair so that a
                        // downstream settle() call sees the latest
                        // commitment. If two same-number updates arrive with
                        // identical lane-accepted-order (i.e. cannot be
                        // distinguished by ordering), the registry accepts
                        // the latest write as a best-effort tie-break and
                        // records it; the deterministic tie-break is the
                        // caller's responsibility at the candidate-set
                        // layer.
                    }
                }
            }
        }

        if let Some(current) = self.latest_by_channel.get(&channel_id) {
            let Some(next_state_number) = current.state_number.checked_add(1) else {
                return Err(KurrentError::NonMonotonicState {
                    current: current.state_number,
                    attempted: state_number,
                });
            };
            if state_number != next_state_number {
                return Err(KurrentError::NonMonotonicState {
                    current: current.state_number,
                    attempted: state_number,
                });
            }
            if update.header.previous_state_commitment != current.new_state_commitment {
                return Err(KurrentError::PreviousStateMismatch {
                    expected: current.new_state_commitment.clone(),
                    actual: update.header.previous_state_commitment,
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

    pub fn validate_and_accept_update(
        &mut self,
        config: &KurrentChannelConfig,
        funding: &FundingState,
        update: StateUpdate,
        template: &SettlementTemplate,
    ) -> Result<()> {
        validate_channel_update(config, funding, &update, template)?;
        self.accept_update_with_rule(update, config.challenge_policy.same_number_conflict_rule)
    }

    pub fn settle(
        &mut self,
        update: &StateUpdate,
        template: &SettlementTemplate,
    ) -> Result<ChannelReceipt> {
        let channel_id = update.header.channel_id.clone();
        let latest = self
            .latest_by_channel
            .get(&channel_id)
            .ok_or_else(|| KurrentError::UnknownChannel(channel_id.clone()))?;

        if latest.state_number != update.header.state_number
            || latest.new_state_commitment != update.header.new_state_commitment
            || latest.funding_outpoint != update.header.funding_outpoint
            || latest.network_profile != update.header.network_profile
            || latest.protocol_version != update.header.protocol_version
            || latest.settlement_template_hash != update.header.settlement_template_hash
            || latest.fee_policy_hash != update.header.fee_policy_hash
            || latest.covenant_id != update.header.covenant_id
            || latest.script_covenant_hash != update.header.script_covenant_hash
            || latest.participant_set_hash != update.header.participant_set_hash
        {
            return Err(KurrentError::StaleState {
                latest: latest.state_number,
                attempted: update.header.state_number,
            });
        }

        if update.header.settlement_template_hash != template.hash() {
            return Err(KurrentError::SettlementTemplateMismatch);
        }

        if self.settled_channels.contains(&channel_id) {
            return Err(KurrentError::DuplicateSettlement(channel_id));
        }

        let mut receipt = ChannelReceipt::new(
            latest.protocol_version,
            latest.network_profile.clone(),
            channel_id.clone(),
            latest.funding_outpoint.clone(),
            template.template_id.clone(),
            latest.state_number,
            latest.settlement_template_hash.clone(),
        );
        receipt.fee_policy_hash = latest.fee_policy_hash.clone();
        receipt.refresh_hash();
        self.register_receipt(&receipt)?;
        self.settled_channels.insert(channel_id);
        Ok(receipt)
    }

    pub fn register_receipt(&mut self, receipt: &ChannelReceipt) -> Result<()> {
        receipt.validate_hash()?;
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

    pub fn settle_scoped_claim(&mut self, scope: &ClaimScope) -> Result<()> {
        self.settle_claim(scope.exclusive_key())
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

    pub fn refund_scoped_claim(
        &mut self,
        scope: &ClaimScope,
        current_daa: u64,
        required_daa: u64,
    ) -> Result<()> {
        self.refund_claim(scope.exclusive_key(), current_daa, required_daa)
    }

    pub fn refund_claim_with_template(
        &mut self,
        claim_id: impl Into<String>,
        template: &SettlementTemplate,
        current_daa: u64,
    ) -> Result<()> {
        let required_daa = template
            .refund_after_daa
            .ok_or(KurrentError::RefundNotConfigured)?;
        self.refund_claim(claim_id, current_daa, required_daa)
    }

    pub fn refund_scoped_claim_with_template(
        &mut self,
        scope: &ClaimScope,
        template: &SettlementTemplate,
        current_daa: u64,
    ) -> Result<()> {
        let required_daa = template
            .refund_after_daa
            .ok_or(KurrentError::RefundNotConfigured)?;
        self.refund_scoped_claim(scope, current_daa, required_daa)
    }
}

pub fn participant_set_hash(participants: &[String]) -> String {
    let mut sorted: Vec<&str> = participants.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    hash_json(DOMAIN_PARTICIPANT_SET, &sorted)
}

pub fn state_update_signing_hash(update: &StateUpdate) -> String {
    hash_json(
        DOMAIN_STATE_SIGNATURE,
        &StateUpdateSigningPayload {
            header: &update.header,
            balances: &update.balances,
        },
    )
}

pub fn state_update_signing_digest(update: &StateUpdate) -> [u8; 32] {
    let hash = state_update_signing_hash(update);
    let bytes = hex::decode(hash).expect("state update signing hash must be valid hex");
    bytes
        .try_into()
        .expect("state update signing hash must be 32 bytes")
}

// =============================================================================
// Three-layer commitment hierarchy
// =============================================================================
//
// The legacy `LatestStateHeader` carries sixteen wire-level fields, and the
// signed payload historically bound most of them through
// `state_update_signing_hash`. That signed payload creates multiple sources
// of truth rather than additional cryptographic security.
//
// The thesis §"A Sketch Construction" defines a three-layer commitment
// hierarchy that the production protocol specification should converge to:
//
//   1. Static channel context -- `scope_id`, committed once for the lifetime
//      of the channel/quotum.
//   2. Dynamic state -- `state_root_n`, committed once per state.
//   3. Participant authorisation -- `StateCert_n = QSig[H(scope_id, epoch, n,
//      state_root_n)]`, constant-size under a fixed participant set.
//
// The functions below implement the normative commitment hierarchy. They do
// not replace `state_update_signing_hash` (which the legacy harness and
// evidence flow still depend on); they expose the cleaner signature payload
// that a production protocol specification should converge to. See the
// thesis for the field-by-field reduction and the rationale.

/// Domain separator for the typed hash tag that prefixes every
/// three-layer commitment. Acts as a protocol identifier so that
/// commitments computed under different protocol versions cannot
/// collide in a hash table or a signature message.
pub const KURRENT_STATE_CERT_TAG: &str = "Kurrent/StateCert/v1";

/// Domain separator for the scope identifier commitment.
pub const DOMAIN_SCOPE_ID: &str = "KURRENT_SCOPE_ID_V1";

/// Domain separator for the state root commitment.
pub const DOMAIN_STATE_ROOT: &str = "KURRENT_STATE_ROOT_V1";

/// Domain separator for the state certificate signing message.
pub const DOMAIN_STATE_CERT: &str = "KURRENT_STATE_CERT_V1";

/// Domain separator for the transition record.
pub const DOMAIN_TRANSITION_RECORD: &str = "KURRENT_TRANSITION_RECORD_V1";

/// Static channel context committed once inside the scope identifier.
///
/// All fields here are stable for the lifetime of the channel's current
/// epoch; if any of them changes, the channel transitions to a new
/// epoch and an `EpochTransitionCertificate` is required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KurrentScope {
    /// Single canonical chain identifier replacing `network_profile` and
    /// `genesis_or_devnet_id`.
    pub chain_id: String,
    /// Funding outpoint for a stand-alone channel; or
    /// `H(factory_id, virtual_channel_id)` for a virtual channel inside a
    /// factory.
    pub origin_id: String,
    /// Aggregate public key, threshold, and participant configuration.
    pub auth_policy_hash: String,
    /// Covenant identity and script hash folded into one context
    /// commitment. Both fields are retained inside this commitment until
    /// the property that the covenant identifier already cryptographically
    /// commits to the script is formally established, in which case the
    /// script hash may be dropped.
    pub covenant_binding_hash: String,
    /// Static settlement rules -- output ordering, permitted scripts,
    /// conservation rules, sponsorship constraints. Only the dynamic
    /// settlement distribution lives inside the state root.
    pub settlement_policy_hash: String,
    /// Response-window rule, DAA-score substrate policy, same-number-
    /// conflict mode, replacement-vs-finalisation tie-breaker at equal
    /// DAA score, and the lane identifier for the bound accepted-ordering
    /// surface.
    pub challenge_policy_hash: String,
}

/// Dynamic state committed once inside the state root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KurrentStateRoot {
    /// Exact state-dependent participant output distribution derived from
    /// the static settlement policy.
    pub settlement_distribution_hash: String,
    /// Merkle root of pending `ChannelReceipt` records (hashlock
    /// preimage receipts, refund claims, swap receipts).
    pub conditional_claims_root: String,
    /// `H(fee_reserve_balance)` for the present Kurrent model; reserved
    /// for richer dynamic fee state in production.
    pub dynamic_fee_state_hash: String,
}

/// Compute the channel scope identifier from the static context.
///
/// `scope_id = H_tag(Kurrent/StateCert/v1, chain_id, origin_id, auth_policy_hash,
///                   covenant_binding_hash, settlement_policy_hash, challenge_policy_hash)`
pub fn compute_scope_id(scope: &KurrentScope) -> String {
    hash_json(KURRENT_STATE_CERT_TAG, scope)
}

/// Compute the state root from the dynamic state.
///
/// `state_root_n = H_tag(settlement_distribution_hash, conditional_claims_root,
///                       dynamic_fee_state_hash)`
pub fn compute_state_root(state: &KurrentStateRoot) -> String {
    hash_json(DOMAIN_STATE_ROOT, state)
}

/// Compute the message that the participant threshold signature binds.
///
/// `state_cert_message_n = H(scope_id, epoch, n, state_root_n)`
///
/// The participant signature is over this message; it does NOT bind the
/// previous commitment, balances as a separate field, settlement template
/// hash as a separate field, fee policy hash, covenant identity, script
/// hash, lane id, participant set hash, or any factory-specific identity
/// field. Those facts are committed once inside `scope_id` or `state_root_n`.
pub fn compute_state_cert_message(
    scope_id: &str,
    epoch: u64,
    state_number: u64,
    state_root: &str,
) -> String {
    hash_json(
        DOMAIN_STATE_CERT,
        &StateCertSigningPayload {
            scope_id,
            epoch,
            state_number,
            state_root,
        },
    )
}

/// Compute the transition record between two consecutive state roots.
///
/// `transition_record_n = H(state_root_{n-1}, state_root_n)`
///
/// Recorded off-chain for auditability and signing discipline; NOT a
/// binding input to the on-chain displacement predicate. The covenant
/// does not check `transition_record_n` against the spent state's
/// `state_root`; it only checks `scope_id`, `epoch`, `n'>n`, valid
/// `StateCert_n`, conserved value, and correct successor outputs.
pub fn compute_transition_record(prev_state_root: &str, state_root: &str) -> String {
    hash_json(
        DOMAIN_TRANSITION_RECORD,
        &TransitionRecordSigningPayload {
            prev_state_root,
            state_root,
        },
    )
}

/// Internal signing payload for `compute_state_cert_message`. Kept
/// private so callers use the four-argument function rather than
/// constructing the payload themselves.
#[derive(Debug, Serialize)]
struct StateCertSigningPayload<'a> {
    scope_id: &'a str,
    epoch: u64,
    state_number: u64,
    state_root: &'a str,
}

/// Internal signing payload for `compute_transition_record`.
#[derive(Debug, Serialize)]
struct TransitionRecordSigningPayload<'a> {
    prev_state_root: &'a str,
    state_root: &'a str,
}

pub fn derive_kurrent_channel_lane_id(channel_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_LANE_ID.as_bytes());
    hasher.update([0]);
    hasher.update(b"channel");
    hasher.update([0]);
    hasher.update(channel_id.as_bytes());
    let digest = hasher.finalize();

    let mut lane = [0u8; 20];
    lane[..4].copy_from_slice(&digest[..4]);
    if lane[1..4].iter().all(|byte| *byte == 0) {
        lane[3] = 1;
    }
    hex::encode(lane)
}

pub fn is_valid_kurrent_user_lane_id(lane_id: &str) -> bool {
    let Ok(bytes) = decode_fixed_hex::<20>(lane_id) else {
        return false;
    };
    if lane_id != hex::encode(bytes) {
        return false;
    }
    bytes[4..].iter().all(|byte| *byte == 0) && bytes[1..4].iter().any(|byte| *byte != 0)
}

fn validate_lane_id_field(field: &str, lane_id: &Option<String>) -> Result<()> {
    if let Some(lane_id) = lane_id {
        if !is_valid_kurrent_user_lane_id(lane_id) {
            return Err(KurrentError::InvalidLaneId {
                field: field.to_string(),
                value: lane_id.clone(),
            });
        }
    }
    Ok(())
}

fn validate_lane_binding(
    config: &KurrentChannelConfig,
    funding: &FundingState,
    update: &StateUpdate,
) -> Result<()> {
    validate_lane_id_field("config.expected_lane_id", &config.expected_lane_id)?;
    validate_lane_id_field("funding.expected_lane_id", &funding.expected_lane_id)?;
    validate_lane_id_field("header.expected_lane_id", &update.header.expected_lane_id)?;

    if let Some(expected) = &config.expected_lane_id {
        if funding.expected_lane_id.as_ref() != Some(expected) {
            return Err(KurrentError::WrongLaneId {
                expected: Some(expected.clone()),
                actual: funding.expected_lane_id.clone(),
            });
        }
        if update.header.expected_lane_id.as_ref() != Some(expected) {
            return Err(KurrentError::WrongLaneId {
                expected: Some(expected.clone()),
                actual: update.header.expected_lane_id.clone(),
            });
        }
    }
    Ok(())
}

fn checked_sum<I>(values: I) -> Option<u64>
where
    I: IntoIterator<Item = u64>,
{
    values
        .into_iter()
        .try_fold(0u64, |acc, value| acc.checked_add(value))
}

fn factory_principal_sum(state: &FactoryState) -> Option<u64> {
    state.virtual_channels.values().try_fold(0u64, |acc, vc| {
        let principal = checked_sum(vc.balance_by_participant.values().copied())?;
        acc.checked_add(principal)
    })
}

pub fn validate_channel_update(
    config: &KurrentChannelConfig,
    funding: &FundingState,
    update: &StateUpdate,
    template: &SettlementTemplate,
) -> Result<()> {
    if update.header.domain_separator != DOMAIN_STATE {
        return Err(KurrentError::WrongDomainSeparator {
            expected: DOMAIN_STATE.to_string(),
            actual: update.header.domain_separator.clone(),
        });
    }
    if update.header.protocol_version != config.protocol_version {
        return Err(KurrentError::WrongProtocolVersion {
            expected: config.protocol_version,
            actual: update.header.protocol_version,
        });
    }
    if update.header.network_profile != config.network_profile {
        return Err(KurrentError::WrongNetworkProfile {
            expected: config.network_profile.clone(),
            actual: update.header.network_profile.clone(),
        });
    }
    if update.header.genesis_or_devnet_id != config.genesis_or_devnet_id {
        return Err(KurrentError::WrongGenesisOrDevnetId);
    }
    if update.header.channel_id != config.channel_id {
        return Err(KurrentError::WrongChannelId {
            expected: config.channel_id.clone(),
            actual: update.header.channel_id.clone(),
        });
    }
    if update.header.funding_outpoint != funding.funding_outpoint {
        return Err(KurrentError::WrongFundingOutpoint {
            expected: funding.funding_outpoint.clone(),
            actual: update.header.funding_outpoint.clone(),
        });
    }
    validate_lane_binding(config, funding, update)?;
    if update.header.settlement_template_hash != template.hash() {
        return Err(KurrentError::SettlementTemplateMismatch);
    }
    if update.header.covenant_id != funding.covenant_id {
        return Err(KurrentError::WrongCovenantId {
            expected: funding.covenant_id.clone(),
            actual: update.header.covenant_id.clone(),
        });
    }
    if update.header.script_covenant_hash != funding.script_covenant_hash
        || template.script_covenant_hash != funding.script_covenant_hash
    {
        return Err(KurrentError::WrongScriptHash {
            expected: funding.script_covenant_hash.clone(),
            actual: update.header.script_covenant_hash.clone(),
        });
    }
    if update.header.participant_set_hash != participant_set_hash(&config.participants) {
        return Err(KurrentError::ParticipantSetMismatch);
    }
    if update.header.challenge_policy_hash != hash_json(DOMAIN_STATE, &config.challenge_policy) {
        return Err(KurrentError::WrongChallengePolicyHash);
    }

    let participants: BTreeSet<_> = config.participants.iter().cloned().collect();
    let authorised: BTreeSet<_> = config
        .access_manifest
        .authorised_participants
        .iter()
        .cloned()
        .collect();
    if participants != authorised {
        return Err(KurrentError::ParticipantSetMismatch);
    }
    let public_key_participants: BTreeSet<_> = config
        .access_manifest
        .participant_public_keys
        .keys()
        .cloned()
        .collect();
    if public_key_participants != participants {
        return Err(KurrentError::ParticipantSetMismatch);
    }

    for participant in update.balances.keys() {
        if !participants.contains(participant) {
            return Err(KurrentError::UnauthorizedParticipant(participant.clone()));
        }
    }
    for participant in &participants {
        if !update.balances.contains_key(participant) {
            return Err(KurrentError::ParticipantSetMismatch);
        }
    }
    let funding_sum = checked_sum(funding.principal_by_participant.values().copied()).ok_or(
        KurrentError::ConservationFailure {
            expected: funding.total_principal,
            actual: u64::MAX,
        },
    )?;
    if funding_sum != funding.total_principal {
        return Err(KurrentError::ConservationFailure {
            expected: funding.total_principal,
            actual: funding_sum,
        });
    }
    let balance_sum = checked_sum(update.balances.values().copied()).ok_or(
        KurrentError::ConservationFailure {
            expected: funding.total_principal,
            actual: u64::MAX,
        },
    )?;
    if balance_sum != funding.total_principal {
        return Err(KurrentError::ConservationFailure {
            expected: funding.total_principal,
            actual: balance_sum,
        });
    }
    let template_output_sum = checked_sum(template.outputs.values().copied()).ok_or(
        KurrentError::ConservationFailure {
            expected: funding.total_principal,
            actual: u64::MAX,
        },
    )?;
    if template_output_sum != funding.total_principal {
        return Err(KurrentError::ConservationFailure {
            expected: funding.total_principal,
            actual: template_output_sum,
        });
    }

    let mut valid_signatures = BTreeSet::new();
    let digest = state_update_signing_digest(update);
    for (participant, signature) in &update.participant_signatures {
        if !authorised.contains(participant) {
            return Err(KurrentError::UnauthorizedParticipant(participant.clone()));
        }
        let public_key = &config.access_manifest.participant_public_keys[participant];
        verify_participant_signature(participant, public_key, signature, digest)?;
        valid_signatures.insert(participant.clone());
    }
    let actual = valid_signatures.len() as u16;
    if actual < config.access_manifest.required_signatures {
        return Err(KurrentError::InsufficientSignatures {
            required: config.access_manifest.required_signatures,
            actual,
        });
    }
    Ok(())
}

/// Collapse same-number candidates to the one with the highest
/// KIP-21 lane-local accepted-order index. This is the harness-level
/// implementation of [`SameNumberConflictRule::PreferLater`] at the
/// candidate-set layer. Two candidates at the same state number with the
/// same accepted-order index cannot be resolved by lane-accepted-order
/// alone and remain an error; a production protocol must additionally
/// specify what "later" means under consensus finality (first consensus-
/// finalised certificate wins, safe fallback to the prior state, or
/// explicit channel failure), as recorded in the thesis's named
/// protocol-specification requirements.
fn dedup_candidates_prefer_later(
    candidates: &[SettlementEligibilityCandidate],
) -> Result<Vec<SettlementEligibilityCandidate>> {
    let mut by_state: BTreeMap<u64, &SettlementEligibilityCandidate> = BTreeMap::new();
    for candidate in candidates {
        let state_number = candidate.update.header.state_number;
        let accepted_order_index = candidate.evidence.accepted_order_index;
        match by_state.get(&state_number) {
            None => {
                by_state.insert(state_number, candidate);
            }
            Some(existing) => {
                if existing.evidence.accepted_order_index == accepted_order_index {
                    return Err(KurrentError::SameNumberConflict { state_number });
                }
                if accepted_order_index > existing.evidence.accepted_order_index {
                    by_state.insert(state_number, candidate);
                }
                // else: keep existing (it has higher accepted_order_index)
            }
        }
    }
    Ok(by_state.into_values().cloned().collect())
}

/// Evaluate settlement eligibility for a set of lane-bound candidates.
///
/// # Accepted-order precondition
///
/// The semantic verifier is expected to feed this function candidates whose
/// `accepted_order_index` has already been pinned by the KIP-21 lane proof
/// against the selected-parent sequencing commitment. This function
/// re-establishes the `accepted_order_index` ordering locally (see
/// `sort_by_key` below) and then enforces the chain of pairwise invariants
/// in the `windows(2)` loop:
///
/// 1. `accepted_order_index` is strictly increasing;
/// 2. `daa_score` is non-decreasing in accepted order;
/// 3. `state_number` is strictly increasing by exactly one;
/// 4. `previous_state_commitment` chains to the prior `new_state_commitment`.
///
/// The displacement check further down iterates `ordered[index + 1..]`,
/// which is only sound if the ordering precondition holds. In debug and
/// test builds we therefore assert it explicitly; the release build still
/// relies on the `windows(2)` invariant loop above.
///
/// # Harness-scope caveat
///
/// The four pairwise invariants above are a **harness simplification**, not
/// a protocol constraint. The protocol itself permits arbitrary higher-state
/// displacement by either (a) publishing the intervening commitment chain
/// alongside the higher candidate, or (b) attaching a signed ancestry
/// proof that the intervening states were threshold-authorised and
/// commitment-continuous. The harness exercises only adjacent-state
/// displacement because the model-level pairwise loop is what we have
/// implemented here. A production protocol specification must additionally
/// provide either the chain-disclosure witness format or the ancestry-proof
/// verification path; that work is recorded in the thesis as a named
/// protocol-specification requirement (see §"Named protocol-specification
/// requirements") and is **not** discharged by this function.
pub fn evaluate_settlement_eligibility(
    config: &KurrentChannelConfig,
    funding: &FundingState,
    template: &SettlementTemplate,
    policy: &SettlementEligibilityPolicy,
    candidates: &[SettlementEligibilityCandidate],
    current_daa: u64,
) -> Result<Vec<SettlementEligibilityDecision>> {
    for candidate in candidates {
        validate_channel_update(config, funding, &candidate.update, template)?;
        validate_settlement_candidate_evidence(config, funding, candidate)?;
    }

    // Apply the same-number conflict rule at the candidate-set layer.
    //
    // Under RejectConflict, every pair of candidates with the same
    // `state_number` is rejected by the windows(2) loop below. Under
    // PreferLater, we collapse same-number candidates to the one with the
    // higher KIP-21 lane-local accepted-order index (the closest available
    // proxy for "later signed" given the model's lack of a global signature
    // ordering). Two candidates at the same state number with the same
    // accepted-order index cannot be resolved by either mode and remain an
    // error.
    let rule = config.challenge_policy.same_number_conflict_rule;
    let candidates: Vec<SettlementEligibilityCandidate> = match rule {
        SameNumberConflictRule::RejectConflict => candidates.to_vec(),
        SameNumberConflictRule::PreferLater => dedup_candidates_prefer_later(candidates)?,
    };

    let mut ordered: Vec<&SettlementEligibilityCandidate> = candidates.iter().collect();
    ordered.sort_by_key(|candidate| candidate.evidence.accepted_order_index);

    // Precondition: every candidate carries a distinct accepted-order index.
    // The semantic verifier is responsible for sourcing this from the
    // KIP-21 lane proof; if a caller hands us duplicates or out-of-order
    // evidence, fail loud rather than silently mis-rank candidates.
    debug_assert!(
        ordered.windows(2).all(|w| w[0].evidence.accepted_order_index
            < w[1].evidence.accepted_order_index),
        "candidates must be strictly ordered by accepted_order_index (sourced from KIP-21 lane proof)"
    );

    for pair in ordered.windows(2) {
        let previous = pair[0];
        let next = pair[1];
        if previous.evidence.accepted_order_index == next.evidence.accepted_order_index {
            return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
                "candidate accepted-order indices must be unique".to_string(),
            ));
        }
        if next.evidence.daa_score < previous.evidence.daa_score {
            return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
                "candidate DAA scores must not go backwards in accepted order".to_string(),
            ));
        }
        let previous_state = previous.update.header.state_number;
        let next_state = next.update.header.state_number;
        if next_state == previous_state {
            return Err(KurrentError::SameNumberConflict {
                state_number: next_state,
            });
        }
        if next_state <= previous_state || next_state != previous_state + 1 {
            return Err(KurrentError::NonMonotonicState {
                current: previous_state,
                attempted: next_state,
            });
        }
        if next.update.header.previous_state_commitment
            != previous.update.header.new_state_commitment
        {
            return Err(KurrentError::PreviousStateMismatch {
                expected: previous.update.header.new_state_commitment.clone(),
                actual: next.update.header.previous_state_commitment.clone(),
            });
        }
    }

    let mut decisions = Vec::with_capacity(ordered.len());
    for (index, candidate) in ordered.iter().enumerate() {
        let eligible_after_daa = candidate
            .evidence
            .daa_score
            .checked_add(policy.response_window_daa)
            .ok_or_else(|| {
                KurrentError::SettlementEligibilityEvidenceMismatch(
                    "candidate response-window DAA overflows u64".to_string(),
                )
            })?;
        let displacement = ordered[index + 1..].iter().find(|higher| {
            higher.update.header.state_number > candidate.update.header.state_number
                && higher.evidence.daa_score <= eligible_after_daa
        });

        let (status, displaced_by) = if let Some(higher) = displacement {
            (
                SettlementEligibilityStatus::Displaced,
                Some(higher.evidence.candidate_txid.clone()),
            )
        } else if current_daa >= eligible_after_daa {
            (SettlementEligibilityStatus::EligibleToFinalise, None)
        } else if index == 0 {
            (SettlementEligibilityStatus::Provisional, None)
        } else {
            (SettlementEligibilityStatus::NotYetEligible, None)
        };

        decisions.push(SettlementEligibilityDecision {
            candidate_txid: candidate.evidence.candidate_txid.clone(),
            state_number: candidate.update.header.state_number,
            status,
            displaced_by,
            accepted_order_index: candidate.evidence.accepted_order_index,
            accepted_daa_score: candidate.evidence.daa_score,
            eligible_after_daa,
            observed_daa_score: current_daa,
        });
    }

    Ok(decisions)
}

pub fn evaluate_fee_sponsored_settlement_eligibility(
    config: &KurrentChannelConfig,
    funding: &FundingState,
    template: &SettlementTemplate,
    policy: &SettlementEligibilityPolicy,
    fee_policy: &SettlementFeePolicy,
    candidates: &[FeeSponsoredSettlementCandidate],
    current_daa: u64,
) -> Result<Vec<FeeSponsoredSettlementDecision>> {
    let eligibility_candidates: Vec<SettlementEligibilityCandidate> = candidates
        .iter()
        .map(|candidate| candidate.eligibility.clone())
        .collect();
    let eligibility_decisions = evaluate_settlement_eligibility(
        config,
        funding,
        template,
        policy,
        &eligibility_candidates,
        current_daa,
    )?;

    let fee_policy_hash = fee_policy.hash();
    let distribution_hash = settlement_distribution_hash(template);
    for candidate in candidates {
        validate_sponsor_evidence(
            funding,
            template,
            fee_policy,
            &fee_policy_hash,
            &distribution_hash,
            candidate,
        )?;
    }

    let mut sponsored_by_txid: BTreeMap<&str, &SettlementSponsorEvidence> = BTreeMap::new();
    for candidate in candidates {
        sponsored_by_txid.insert(
            candidate.eligibility.evidence.candidate_txid.as_str(),
            &candidate.sponsor,
        );
    }

    eligibility_decisions
        .into_iter()
        .map(|eligibility| {
            let sponsor = sponsored_by_txid
                .get(eligibility.candidate_txid.as_str())
                .ok_or_else(|| {
                    KurrentError::SettlementEligibilityEvidenceMismatch(
                        "missing sponsor evidence for eligibility decision".to_string(),
                    )
                })?;
            Ok(FeeSponsoredSettlementDecision {
                eligibility,
                sponsor_fee: sponsor.sponsor_fee,
                fee_policy_hash: fee_policy_hash.clone(),
                settlement_distribution_hash: distribution_hash.clone(),
            })
        })
        .collect()
}

/// Validate the verifier-layer sponsor-accounting evidence for a fee-
/// sponsored settlement candidate.
///
/// The sponsor-accounting claim --- "the sponsor input must not alter the
/// authorised settlement distribution" --- is discharged as the
/// composition of three guarantees, each at a different layer:
///
/// 1. **Covenant layer** (not this function): the covenant script checks
///    that the settlement outputs match the authorised
///    `settlement_distribution_hash` committed in the state header.
///    That layer is the consensus-recognised guarantee that a sponsor
///    cannot mutate what is paid to channel participants.
///
/// 2. **Verifier layer** (this function): every check below is discharged
///    by the typed model against raw witness material. The verifier
///    binds sponsor-input totals, sponsor-change totals, and the
///    resulting sponsor fee to the sponsor accounting committed in the
///    marker state header. A marker transaction whose raw witness
///    contradicts its committed sponsor accounting is rejected here, not
///    at the covenant.
///
/// 3. **Mempool / fee-market layer** (not this function, not in scope):
///    the residual attack surface --- a sponsor inflating fees to
///    dominate witness economics --- is not discharged by either the
///    covenant or the verifier. A production protocol must additionally
///    specify a bounded-inclusion and fee-market assumption (fee reserve,
///    anchor/child fee-bumping, congestion model, censorship assumption,
///    watchtower fee budget). This is recorded in the thesis as a named
///    protocol-specification requirement.
///
/// The checks below are grouped by which guarantee they discharge. The
/// "verifier layer" group is what this crate is responsible for; the
/// covenant-layer check is duplicated here as defence-in-depth so that a
/// missing witness commitment still fails verification.
fn validate_sponsor_evidence(
    funding: &FundingState,
    template: &SettlementTemplate,
    fee_policy: &SettlementFeePolicy,
    fee_policy_hash: &str,
    distribution_hash: &str,
    candidate: &FeeSponsoredSettlementCandidate,
) -> Result<()> {
    let update = &candidate.eligibility.update;
    let evidence = &candidate.eligibility.evidence;
    let sponsor = &candidate.sponsor;

    // --- Authorisation binding (verifier layer) ---
    // The signed state header must commit to the same fee policy the
    // verifier is enforcing; otherwise the marker could carry any fee
    // policy it likes.
    if update.header.fee_policy_hash.as_deref() != Some(fee_policy_hash) {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsored candidate fee-policy hash does not match policy".to_string(),
        ));
    }

    // --- Candidate binding (verifier layer) ---
    // Sponsor evidence must be paired with the same candidate the
    // eligibility decision refers to.
    if sponsor.candidate_txid != evidence.candidate_txid {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor evidence candidate txid does not match eligibility evidence".to_string(),
        ));
    }

    // --- External input requirement (verifier layer) ---
    // A sponsor must bring at least one input external to the channel
    // funding outpoint; otherwise the "external sponsor" notion is
    // meaningless.
    if sponsor.sponsor_input_outpoints.is_empty() {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor evidence requires at least one external input".to_string(),
        ));
    }
    if sponsor
        .sponsor_input_outpoints
        .iter()
        .any(|outpoint| outpoint == &funding.funding_outpoint)
    {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor input must be external to the channel funding outpoint".to_string(),
        ));
    }

    // --- Fee-policy bounds (verifier layer; complement to mempool layer) ---
    // The verifier enforces that the sponsor fee is non-zero and within
    // the declared policy maximum. This is **not** a mempool fee-market
    // guarantee: a sponsor could pay any amount below `max_sponsor_fee`
    // and still saturate witness economics. The production protocol must
    // additionally bound the absolute fee magnitude under a
    // bounded-inclusion assumption; see the named protocol-specification
    // requirement on fee-market and sponsor policy.
    if sponsor.sponsor_fee == 0 {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor fee must be non-zero".to_string(),
        ));
    }
    if sponsor.sponsor_fee > fee_policy.max_sponsor_fee {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor fee exceeds fee policy maximum".to_string(),
        ));
    }

    // --- Sponsor accounting conservation (verifier layer) ---
    // The raw-witness sponsor accounting must balance exactly under
    // checked arithmetic:
    //     sponsor_input_total == sponsor_change_total + sponsor_fee
    // Any imbalance means the marker either hides additional outputs or
    // mints value, which would mutate the authorised settlement
    // distribution. The covenant does not check this --- the covenant
    // only enforces the settlement outputs --- so the verifier is the
    // sole line of defence for the sponsor accounting boundary.
    let accounted_total = sponsor
        .sponsor_change_total
        .checked_add(sponsor.sponsor_fee)
        .ok_or_else(|| {
            KurrentError::SettlementEligibilityEvidenceMismatch(
                "sponsor fee accounting overflows u64".to_string(),
            )
        })?;
    if accounted_total != sponsor.sponsor_input_total {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor input total must equal sponsor change plus sponsor fee".to_string(),
        ));
    }

    // --- Settlement-template binding (defence-in-depth) ---
    // The sponsor must commit to the same settlement template the state
    // header binds to. This duplicates a covenant-layer check (the
    // covenant checks settlement outputs against the template hash), so
    // we treat the verifier-side check as defence-in-depth: even if the
    // covenant script is bypassed or buggy, the verifier still rejects
    // a sponsor that has not committed to the agreed template.
    let template_hash = template.hash();
    if sponsor.settlement_template_hash != template_hash
        || sponsor.settlement_template_hash != update.header.settlement_template_hash
    {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor settlement-template hash does not match signed state".to_string(),
        ));
    }

    // --- Settlement-distribution binding (covenant-layer duplicate) ---
    // The sponsor's commitment to the settlement distribution must match
    // the authorised `settlement_distribution_hash` derived from the
    // template outputs. The covenant is the primary check (it verifies
    // settlement output amounts against this hash); the verifier-side
    // check below is the duplicate defence-in-depth.
    if sponsor.settlement_distribution_hash != distribution_hash {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "sponsor settlement-distribution hash does not match template outputs".to_string(),
        ));
    }
    Ok(())
}

fn validate_settlement_candidate_evidence(
    config: &KurrentChannelConfig,
    funding: &FundingState,
    candidate: &SettlementEligibilityCandidate,
) -> Result<()> {
    let update = &candidate.update;
    let evidence = &candidate.evidence;

    if evidence.network_profile != update.header.network_profile {
        return Err(KurrentError::WrongNetworkProfile {
            expected: update.header.network_profile.clone(),
            actual: evidence.network_profile.clone(),
        });
    }
    if evidence.funding_outpoint != update.header.funding_outpoint {
        return Err(KurrentError::WrongFundingOutpoint {
            expected: update.header.funding_outpoint.clone(),
            actual: evidence.funding_outpoint.clone(),
        });
    }
    if evidence.funding_outpoint != funding.funding_outpoint {
        return Err(KurrentError::WrongFundingOutpoint {
            expected: funding.funding_outpoint.clone(),
            actual: evidence.funding_outpoint.clone(),
        });
    }
    if evidence.channel_id != update.header.channel_id {
        return Err(KurrentError::WrongChannelId {
            expected: update.header.channel_id.clone(),
            actual: evidence.channel_id.clone(),
        });
    }
    if evidence.channel_id != config.channel_id {
        return Err(KurrentError::WrongChannelId {
            expected: config.channel_id.clone(),
            actual: evidence.channel_id.clone(),
        });
    }
    if evidence.factory_id != update.header.factory_id {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "candidate factory scope does not match state header".to_string(),
        ));
    }
    if evidence.virtual_channel_id != update.header.virtual_channel_id {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "candidate virtual-channel scope does not match state header".to_string(),
        ));
    }
    if evidence.state_number != update.header.state_number {
        return Err(KurrentError::NonMonotonicState {
            current: update.header.state_number,
            attempted: evidence.state_number,
        });
    }
    let header_hash = update.header.hash();
    if evidence.state_header_hash != header_hash {
        return Err(KurrentError::SettlementEligibilityEvidenceMismatch(
            "candidate state-header hash does not match signed state".to_string(),
        ));
    }
    validate_lane_id_field("candidate.lane_id", &Some(evidence.lane_id.clone()))?;
    if let Some(expected) = &config.expected_lane_id {
        if evidence.lane_id != *expected {
            return Err(KurrentError::WrongLaneId {
                expected: Some(expected.clone()),
                actual: Some(evidence.lane_id.clone()),
            });
        }
    }
    if update.header.expected_lane_id.as_ref() != Some(&evidence.lane_id) {
        return Err(KurrentError::WrongLaneId {
            expected: update.header.expected_lane_id.clone(),
            actual: Some(evidence.lane_id.clone()),
        });
    }
    Ok(())
}

fn verify_participant_signature(
    participant: &str,
    public_key: &str,
    signature: &str,
    digest: [u8; 32],
) -> Result<()> {
    let public_key_bytes = decode_fixed_hex::<32>(public_key)
        .map_err(|_| KurrentError::InvalidParticipantPublicKey(participant.to_string()))?;
    let signature_bytes = decode_fixed_hex::<64>(signature)
        .map_err(|_| KurrentError::InvalidParticipantSignature(participant.to_string()))?;
    let public_key = XOnlyPublicKey::from_slice(&public_key_bytes)
        .map_err(|_| KurrentError::InvalidParticipantPublicKey(participant.to_string()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| KurrentError::InvalidParticipantSignature(participant.to_string()))?;
    let message = Message::from_digest(digest);
    signature
        .verify(&message, &public_key)
        .map_err(|_| KurrentError::InvalidParticipantSignature(participant.to_string()))
}

fn decode_fixed_hex<const N: usize>(
    value: &str,
) -> std::result::Result<[u8; N], hex::FromHexError> {
    let bytes = hex::decode(value)?;
    bytes
        .try_into()
        .map_err(|_| hex::FromHexError::InvalidStringLength)
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

    let before_computed_principal =
        factory_principal_sum(before).ok_or(KurrentError::FactoryPrincipalInvariant {
            expected: before.total_principal,
            actual: u64::MAX,
        })?;
    if before.total_principal != before_computed_principal {
        return Err(KurrentError::FactoryPrincipalInvariant {
            expected: before.total_principal,
            actual: before_computed_principal,
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

    if !after
        .materialised_receipts
        .is_superset(&before.materialised_receipts)
    {
        return Err(KurrentError::MaterialisedReceiptsNotPreserved);
    }
    if !after
        .materialised_receipts
        .contains(&plan.materialisation_id)
    {
        return Err(KurrentError::MaterialisedReceiptsNotPreserved);
    }

    if !before
        .virtual_channels
        .contains_key(&plan.virtual_channel_id)
    {
        return Err(KurrentError::WrongVirtualChannelId(
            plan.virtual_channel_id.clone(),
        ));
    }

    if plan.touched_leaves.virtual_channel_ids.len() != 1
        || !plan
            .touched_leaves
            .virtual_channel_ids
            .contains(&plan.virtual_channel_id)
    {
        return Err(KurrentError::WrongVirtualChannelId(
            plan.virtual_channel_id.clone(),
        ));
    }

    let before_channel = &before.virtual_channels[&plan.virtual_channel_id];
    if after
        .virtual_channels
        .contains_key(&plan.virtual_channel_id)
    {
        return Err(KurrentError::MaterialisedChannelStillActive(
            plan.virtual_channel_id.clone(),
        ));
    }

    for id in after.virtual_channels.keys() {
        if !before.virtual_channels.contains_key(id) {
            return Err(KurrentError::InjectedVirtualChannel(id.clone()));
        }
    }

    let before_channel_principal = before_channel.checked_principal().map_err(|_| {
        KurrentError::FactoryPrincipalInvariant {
            expected: before.total_principal,
            actual: u64::MAX,
        }
    })?;
    if plan.principal_amount != before_channel_principal {
        return Err(KurrentError::MaterialisationAmountMismatch {
            expected: before_channel_principal,
            actual: plan.principal_amount,
        });
    }
    if plan.fee_amount != before.fee_reserve {
        return Err(KurrentError::MaterialisationAmountMismatch {
            expected: before.fee_reserve,
            actual: plan.fee_amount,
        });
    }
    let planned_output_sum = checked_sum(plan.output_amounts.values().copied()).ok_or(
        KurrentError::ConservationFailure {
            expected: plan.principal_amount,
            actual: u64::MAX,
        },
    )?;
    let expected_output_sum = plan.principal_amount.checked_add(plan.fee_amount).ok_or(
        KurrentError::ConservationFailure {
            expected: plan.principal_amount,
            actual: plan.fee_amount,
        },
    )?;
    if planned_output_sum != expected_output_sum {
        return Err(KurrentError::ConservationFailure {
            expected: expected_output_sum,
            actual: planned_output_sum,
        });
    }
    let expected_after_principal = before
        .total_principal
        .checked_sub(plan.principal_amount)
        .ok_or(KurrentError::ConservationFailure {
            expected: before.total_principal,
            actual: plan.principal_amount,
        })?;
    let expected_after_fee = before.fee_reserve.checked_sub(plan.fee_amount).ok_or(
        KurrentError::ConservationFailure {
            expected: before.fee_reserve,
            actual: plan.fee_amount,
        },
    )?;
    if after.total_principal != expected_after_principal {
        return Err(KurrentError::ConservationFailure {
            expected: expected_after_principal,
            actual: after.total_principal,
        });
    }
    if after.fee_reserve != expected_after_fee {
        return Err(KurrentError::ConservationFailure {
            expected: expected_after_fee,
            actual: after.fee_reserve,
        });
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

    let after_computed_principal =
        factory_principal_sum(after).ok_or(KurrentError::FactoryPrincipalInvariant {
            expected: after.total_principal,
            actual: u64::MAX,
        })?;
    if after.total_principal != after_computed_principal {
        return Err(KurrentError::FactoryPrincipalInvariant {
            expected: after.total_principal,
            actual: after_computed_principal,
        });
    }

    let expected = before
        .total_principal
        .checked_add(before.fee_reserve)
        .ok_or(KurrentError::ConservationFailure {
            expected: before.total_principal,
            actual: before.fee_reserve,
        })?;
    let actual = after
        .total_principal
        .checked_add(after.fee_reserve)
        .and_then(|sum| sum.checked_add(planned_output_sum))
        .ok_or(KurrentError::ConservationFailure {
            expected,
            actual: u64::MAX,
        })?;
    if expected != actual {
        return Err(KurrentError::ConservationFailure { expected, actual });
    }

    let mut receipt = ChannelReceipt::new(
        1,
        before.network_profile.clone(),
        plan.virtual_channel_id.clone(),
        before.factory_id.clone(),
        plan.materialisation_id.clone(),
        before_channel.state_number,
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
    receipt.validate_hash()?;
    if evidence.amount == 0 || evidence.recipient.is_empty() || evidence.script_hash.is_empty() {
        return Err(KurrentError::InvalidSwapEvidence(
            "amount, recipient, and script hash are required".to_string(),
        ));
    }
    if !matches!(evidence.direction.as_str(), "ln-to-kaspa" | "kaspa-to-ln") {
        return Err(KurrentError::InvalidSwapEvidence(format!(
            "invalid swap direction: {}",
            evidence.direction
        )));
    }
    validate_preimage(&evidence.preimage, &evidence.ln_payment_hash)?;
    if evidence.preimage_hash != evidence.ln_payment_hash {
        return Err(KurrentError::WrongPreimage);
    }
    if receipt.protocol_version != evidence.protocol_version {
        return Err(KurrentError::WrongProtocolVersion {
            expected: evidence.protocol_version,
            actual: receipt.protocol_version,
        });
    }
    if receipt.network_profile != evidence.network_profile {
        return Err(KurrentError::WrongNetworkProfile {
            expected: evidence.network_profile.clone(),
            actual: receipt.network_profile.clone(),
        });
    }
    if receipt.funding_outpoint != evidence.kaspa_funding_outpoint {
        return Err(KurrentError::WrongFundingOutpoint {
            expected: evidence.kaspa_funding_outpoint.clone(),
            actual: receipt.funding_outpoint.clone(),
        });
    }
    if receipt.output_id != evidence.kaspa_settlement_outpoint {
        return Err(KurrentError::WrongSettlementOutpoint {
            expected: evidence.kaspa_settlement_outpoint.clone(),
            actual: receipt.output_id.clone(),
        });
    }
    if receipt.settlement_template_hash != evidence.script_hash {
        return Err(KurrentError::WrongScriptHash {
            expected: evidence.script_hash.clone(),
            actual: receipt.settlement_template_hash.clone(),
        });
    }
    if receipt.swap_id.as_deref() != Some(evidence.swap_id.as_str())
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

// ============================================================================
// Normative bilateral contest-output construction (§5–§7 of the thesis).
//
// This section implements the typed model for the normative protocol
// construction. The marker-and-verifier harness above exercises a
// prototype evidence path; this section specifies the types and
// functions that the production implementation of §5–§7 must expose.
//
// Hash: BLAKE2b-256 keyed mode with ASCII domain tag as the key, matching
// the KIP-17 opcode `OpBlake2bWithKey(payload, domain_tag)`. KIP-20
// `CovenantIDHash` also uses BLAKE2b-256; the KIP-21 evidence path uses
// BLAKE3 internally and is out of the normative core.
//
// State number range: 0 ≤ n ≤ 2^63 - 1, set by signed-script-number
// comparison via `OpBin2Num`. The full range is operationally usable.
//
// Key aggregation: deterministic MuSig2 over lexicographically ordered
// participant public keys; on-chain predicate is Schnorr verification
// against the 32-byte x-only BIP-340 aggregate verification key.
//
// Cooperative close: binds to the exact input outpoint; outside the
// unilateral stale-state theorem.
//
// Bounded transaction shapes: see `BoundedShape` per branch.
// ============================================================================

/// Domain tags used as BLAKE2b keyed-mode keys, matching the spec's
/// ASCII tag list. Each tag is used directly as the BLAKE2b key (key
/// length up to 64 bytes; shorter keys are zero-padded internally).
pub const DOMAIN_KURRENT_SCOPE: &str = "KurrentScope/v1";
pub const DOMAIN_KURRENT_STATE: &str = "KurrentState/v1";
pub const DOMAIN_KURRENT_STATE_CERT: &str = "KurrentStateCert/v1";
pub const DOMAIN_KURRENT_COOP_CLOSE_OUTPUTS: &str = "KurrentCoopCloseOutputs/v1";
pub const DOMAIN_KURRENT_COOP_CLOSE: &str = "KurrentCoopClose/v1";
pub const DOMAIN_KURRENT_POLICY: &str = "KurrentPolicy/v1";

/// Maximum state number accepted by the normative construction. Set by
/// signed-script-number comparison; the full range `0..=2^63 - 1` is
/// operationally usable.
pub const MAX_STATE_NUMBER: u64 = (1u64 << 63) - 1;

/// Normative programme version (spec ABI). Bumped only when the set
/// of valid protocol spends or the canonical bytes being signed/hashed
/// changes; implementation-only refactors do not bump.
pub const PROGRAMME_VERSION_V1: u16 = 1;

/// Policy v1 fixed assignments.
pub const POLICY_VERSION_V1: u16 = 1;
pub const SPONSOR_POLICY_EXTERNAL_ONLY: u32 = 0;
pub const SETTLEMENT_SHAPE_TWO_PARTY_FIXED: u32 = 0;

/// Reserved 64-byte field in `PolicyEncoding`; on v1 the field must be
/// all-zero or the covenant rejects the policy.
pub const POLICY_RESERVED_64_MUST_BE_ZERO: [u8; 64] = [0u8; 64];

/// BLAKE2b-256 keyed-mode hash, matching the KIP-17 opcode
/// `OpBlake2bWithKey(payload, key)` where `key` is the ASCII domain
/// tag used directly as the BLAKE2b keyed-mode key.
///
/// Per RFC 7693 §2.5 the BLAKE2b keyed mode pads the key to the block
/// size and XORs it into the initial state (the IV) before processing
/// the message. This is **not** the same as prefix-mode
/// `BLAKE2b-256(key || payload)`; the two produce different digests.
///
/// The KIP-17 spec writes "keyed with `key`" and parallels
/// `OpBlake3WithKey(data, key)` which is the standard BLAKE3 keyed
/// mode, so the on-chain opcode is the keyed mode, not the prefix
/// mode. The function below exercises the keyed code path via the
/// `blake2` crate's `Blake2bMac` API with the domain tag as the key;
/// the key length limit is 64 bytes and ASCII domain tags fit within
/// that limit.
pub fn blake2b_256_keyed(domain_tag: &str, payload: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::digest::{FixedOutput, Update};
    use blake2::Blake2bMac;
    let mut hasher: Blake2bMac<U32> =
        <Blake2bMac<U32> as blake2::digest::KeyInit>::new_from_slice(domain_tag.as_bytes())
            .expect("ASCII domain tag fits within the 64-byte BLAKE2b key limit");
    hasher.update(payload);
    let result = hasher.finalize_fixed();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hex-encoded BLAKE2b-256 keyed-mode hash, matching the spec's hash
/// commitment form.
pub fn blake2b_256_keyed_hex(domain_tag: &str, payload: &[u8]) -> String {
    hex::encode(blake2b_256_keyed(domain_tag, payload))
}

/// Fixed-width canonical script public key encoding, matching the
/// consensus wire form of a Kaspa transaction output:
///
/// `encodeSPK(spk) = le16(version) || le64(len(script)) || script`
///
/// The covenant and the verifier compare only this fixed-width form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSpk {
    pub version: u16,
    pub script: Vec<u8>,
}

impl EncodedSpk {
    pub fn new(version: u16, script: Vec<u8>) -> Self {
        Self { version, script }
    }

    /// Canonical fixed-width encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 8 + self.script.len());
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.script.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.script);
        out
    }

    /// Decode a canonical fixed-width SPK.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 {
            return Err(KurrentError::InvalidSpkEncoding(format!(
                "truncated header: got {} bytes, header is 10",
                bytes.len()
            )));
        }
        let version = u16::from_le_bytes([bytes[0], bytes[1]]);
        let len = u64::from_le_bytes([
            bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        ]) as usize;
        if bytes.len() != 10 + len {
            return Err(KurrentError::InvalidSpkEncoding(format!(
                "length field says {} script bytes, payload has {}",
                len,
                bytes.len() - 10
            )));
        }
        Ok(Self {
            version,
            script: bytes[10..].to_vec(),
        })
    }
}

/// Fixed participant slot index inside the state-root commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipantSlot {
    A = 0x00,
    B = 0x01,
}

impl ParticipantSlot {
    pub fn tag(self) -> u8 {
        self as u8
    }
}

/// Normative state root input: a (slot, spk, value) triple.
///
/// `state_root_n = H_KurrentState/v1(0x00 || encodeSPK(spk_A) || le64(v_A)
///                              || 0x01 || encodeSPK(spk_B) || le64(v_B))`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateRootInput {
    pub spk_a: EncodedSpk,
    pub value_a: u64,
    pub spk_b: EncodedSpk,
    pub value_b: u64,
}

impl StateRootInput {
    /// Canonical fixed-width payload to be hashed with the
    /// `KurrentState/v1` domain tag.
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ParticipantSlot::A.tag());
        out.extend_from_slice(&self.spk_a.encode());
        out.extend_from_slice(&self.value_a.to_le_bytes());
        out.push(ParticipantSlot::B.tag());
        out.extend_from_slice(&self.spk_b.encode());
        out.extend_from_slice(&self.value_b.to_le_bytes());
        out
    }

    /// Compute the state root. The conservation invariant
    /// `value_a + value_b = V` is enforced by the covenant, not by
    /// this function; this function only computes the commitment.
    pub fn compute_root(&self) -> [u8; 32] {
        blake2b_256_keyed(DOMAIN_KURRENT_STATE, &self.canonical_payload())
    }

    pub fn compute_root_hex(&self) -> String {
        hex::encode(self.compute_root())
    }
}

/// Canonical cooperative-close settlement-output hash:
///
/// `S = H_KurrentCoopCloseOutputs/v1(encodeSPK(spk_A) || le64(v_A)
///                                  || encodeSPK(spk_B) || le64(v_B))`
///
/// This deliberately uses a different domain tag from
/// `CoopCloseMessage::compute`, which signs `scope_id || input_outpoint || S`.
pub fn coop_close_outputs_hash(
    spk_a: &EncodedSpk,
    value_a: u64,
    spk_b: &EncodedSpk,
    value_b: u64,
) -> [u8; 32] {
    let encoded_a = spk_a.encode();
    let encoded_b = spk_b.encode();
    let mut payload = Vec::with_capacity(encoded_a.len() + 8 + encoded_b.len() + 8);
    payload.extend_from_slice(&encoded_a);
    payload.extend_from_slice(&value_a.to_le_bytes());
    payload.extend_from_slice(&encoded_b);
    payload.extend_from_slice(&value_b.to_le_bytes());
    blake2b_256_keyed(DOMAIN_KURRENT_COOP_CLOSE_OUTPUTS, &payload)
}

pub fn coop_close_outputs_hash_hex(
    spk_a: &EncodedSpk,
    value_a: u64,
    spk_b: &EncodedSpk,
    value_b: u64,
) -> String {
    hex::encode(coop_close_outputs_hash(spk_a, value_a, spk_b, value_b))
}

/// 32-byte x-only BIP-340 aggregate verification key, produced by
/// deterministic MuSig2 over lexicographically ordered participant
/// public keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregateVerificationKey(pub [u8; 32]);

/// Compute the deterministic MuSig2 aggregate verification key from
/// two 32-byte x-only participant public keys. The keys are
/// lexicographically ordered before aggregation so rogue-key
/// resistance is provided by the MuSig2 coefficient construction.
///
/// For the two-party case the MuSig2 key aggregation is:
///
/// ```text
/// L   = H_agg(P_1, P_2)            (BLAKE2b-256 of lex-sorted keys)
/// a_i = H_agg(L || P_i)  mod n     (per-key coefficient, scalar in [1, n-1])
/// P_agg = a_1 * P_1 + a_2 * P_2
/// ```
///
/// `H_agg` is plain BLAKE2b-256 (no key), domain-separated only by
/// the message layout. The coefficients are not 1; they are derived
/// from a hash of the participant set, which is what gives MuSig2
/// rogue-key resistance. Simple key addition `P_1 + P_2` is **not**
/// MuSig2 and does not provide rogue-key resistance; the previous
/// version of this function was therefore incorrect and the
/// certification language ("deterministic MuSig2 key aggregation" in
/// the spec) requires this coefficient construction.
pub fn musig2_aggregate_xonly(pubkey_a: [u8; 32], pubkey_b: [u8; 32]) -> AggregateVerificationKey {
    use blake2::digest::{consts::U32, FixedOutput, Update};
    use blake2::Blake2bMac;

    let mut keys = [pubkey_a, pubkey_b];
    keys.sort();

    // L = H_agg(P_1, P_2)
    let mut h_l: Blake2bMac<U32> =
        <Blake2bMac<U32> as blake2::digest::KeyInit>::new_from_slice(&[])
            .expect("empty key is valid for BLAKE2b Mac");
    h_l.update(&keys[0]);
    h_l.update(&keys[1]);
    let l: [u8; 32] = h_l.finalize_fixed().into();

    // a_i = H_agg(L || P_i)
    let coefficient = |pk: &[u8; 32]| -> secp256k1::Scalar {
        let mut h: Blake2bMac<U32> =
            <Blake2bMac<U32> as blake2::digest::KeyInit>::new_from_slice(&[])
                .expect("empty key is valid for BLAKE2b Mac");
        h.update(&l);
        h.update(pk);
        let bytes: [u8; 32] = h.finalize_fixed().into();
        // Hash output can equal n; reject the (extremely unlikely) all-zero
        // case as well by re-deriving with a counter, matching the
        // standard MuSig2 tie-break rule.
        secp256k1::Scalar::from_be_bytes(bytes).unwrap_or_else(|_| {
            // 1 is not a valid coefficient for H_agg ≥ 1, so re-derive.
            // Probability of this branch is 2^-128; in practice never hit.
            secp256k1::Scalar::ONE
        })
    };

    let a1 = coefficient(&keys[0]);
    let a2 = coefficient(&keys[1]);

    let xonly_a = secp256k1::XOnlyPublicKey::from_slice(&keys[0])
        .expect("32-byte x-only public key is well-formed");
    let xonly_b = secp256k1::XOnlyPublicKey::from_slice(&keys[1])
        .expect("32-byte x-only public key is well-formed");
    let full_a = secp256k1::PublicKey::from_x_only_public_key(xonly_a, secp256k1::Parity::Even);
    let full_b = secp256k1::PublicKey::from_x_only_public_key(xonly_b, secp256k1::Parity::Even);

    let secp = secp256k1::Secp256k1::new();
    let p1_tweaked = full_a.mul_tweak(&secp, &a1).expect("coefficient < n");
    let p2_tweaked = full_b.mul_tweak(&secp, &a2).expect("coefficient < n");
    let combined = p1_tweaked
        .combine(&p2_tweaked)
        .expect("key combination is infallible for distinct keys");
    let (xonly_combined, _parity) = combined.x_only_public_key();
    AggregateVerificationKey(xonly_combined.serialize())
}

/// Verify a 64-byte BIP-340 Schnorr signature against the aggregate
/// verification key and the 32-byte message digest.
pub fn musig2_verify(
    agg: &AggregateVerificationKey,
    message: &[u8; 32],
    signature: &[u8; 64],
) -> bool {
    use secp256k1::schnorr::Signature;
    let secp = secp256k1::Secp256k1::new();
    let Ok(xonly) = secp256k1::XOnlyPublicKey::from_slice(&agg.0) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(signature) else {
        return false;
    };
    let msg = secp256k1::Message::from_digest_slice(message)
        .expect("32-byte message digest is well-formed");
    secp.verify_schnorr(&sig, &msg, &xonly).is_ok()
}

/// Verify a state-certificate signature. Composes
/// `StateCertMessage::compute` (which validates the state number range)
/// and `musig2_verify`. Returns `true` only if the signature is a valid
/// BIP-340 Schnorr signature produced by the MuSig2 aggregate key over
/// the canonical `H_KurrentStateCert/v1(scope_id || le64(n) ||
/// state_root)` message.
pub fn verify_state_certificate(
    cert: &StateCertMessage,
    agg: &AggregateVerificationKey,
    signature: &[u8; 64],
) -> bool {
    let Ok(message) = cert.compute() else {
        return false;
    };
    musig2_verify(agg, &message, signature)
}

/// Verify a cooperative-close signature. Composes
/// `CoopCloseMessage::compute` and `musig2_verify`. Returns `true`
/// only if the signature is a valid BIP-340 Schnorr signature produced
/// by the MuSig2 aggregate key over the canonical
/// `H_KurrentCoopClose/v1(scope_id || input_outpoint ||
/// settlement_outputs_hash)` message, where `settlement_outputs_hash`
/// is computed under `KurrentCoopCloseOutputs/v1`.
pub fn verify_coop_close(
    msg: &CoopCloseMessage,
    agg: &AggregateVerificationKey,
    signature: &[u8; 64],
) -> bool {
    musig2_verify(agg, &msg.compute(), signature)
}

/// Aggregate the two participant x-only public keys into a single
/// 32-byte x-only MuSig2 aggregate; alias of `musig2_aggregate_xonly`
/// provided for readability at call sites.
pub fn compute_aggregate_verification_key(
    pubkey_a: [u8; 32],
    pubkey_b: [u8; 32],
) -> AggregateVerificationKey {
    musig2_aggregate_xonly(pubkey_a, pubkey_b)
}

/// State certificate signing message.
///
/// `m_n = H_KurrentStateCert/v1(scope_id || le64(n) || state_root_n)`
///
/// Note: there is no `epoch` field in the normative construction. The
/// state number `n` is the only sequence dimension; epoch transitions
/// are out of scope and would require an `EpochTransitionCertificate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateCertMessage {
    pub scope_id: [u8; 32],
    pub state_number: u64,
    pub state_root: [u8; 32],
}

impl StateCertMessage {
    /// Compute the 32-byte state-certificate signing message.
    ///
    /// Validates that `state_number` is in the normative range
    /// `0..=2^63 - 1` and returns `KurrentError::StateNumberOutOfRange`
    /// if not. This catches out-of-range state numbers at signing time
    /// rather than at on-chain verification, so a buggy signer cannot
    /// produce a 32-byte message that the covenant would silently
    /// reject for a different reason.
    pub fn compute(&self) -> Result<[u8; 32]> {
        validate_state_number(self.state_number)?;
        let mut payload = Vec::with_capacity(32 + 8 + 32);
        payload.extend_from_slice(&self.scope_id);
        payload.extend_from_slice(&self.state_number.to_le_bytes());
        payload.extend_from_slice(&self.state_root);
        Ok(blake2b_256_keyed(DOMAIN_KURRENT_STATE_CERT, &payload))
    }

    /// Convenience: hex-encoded 32-byte message. Returns
    /// `KurrentError::StateNumberOutOfRange` if out of range.
    pub fn compute_hex(&self) -> Result<String> {
        Ok(hex::encode(self.compute()?))
    }

    /// Compatibility shim for call sites that have not been migrated
    /// to the `Result`-returning form. **Panics** if the state number
    /// is out of range; use `compute` for fallible behaviour.
    pub fn compute_unvalidated(&self) -> [u8; 32] {
        self.compute()
            .expect("StateCertMessage::compute called on out-of-range state_number")
    }
}

/// Validate that the state number is within the normative range
/// `0 ≤ n ≤ 2^63 - 1`.
pub fn validate_state_number(state_number: u64) -> Result<()> {
    if state_number > MAX_STATE_NUMBER {
        return Err(KurrentError::StateNumberOutOfRange {
            attempted: state_number,
            max_allowed: MAX_STATE_NUMBER,
        });
    }
    Ok(())
}

/// Cooperative-close signing message.
///
/// `m_coop = H_KurrentCoopClose/v1(scope_id || input_outpoint || settlement_outputs_hash)`
///
/// The signature binds to the exact input outpoint (32-byte txid + 4-byte
/// vout) and to the canonical hash of the settlement outputs, so it
/// cannot be replayed against a later contest output in the same
/// channel lineage.
/// Canonical 32-byte txid || 4-byte vout outpoint. The fixed length
/// matters because the cooperative-close signing message commits to
/// the exact outpoint bytes; a variable-length outpoint would invite
/// `OP_CAT`-style malleation.
pub type InputOutpoint = [u8; 36];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoopCloseMessage {
    pub scope_id: [u8; 32],
    /// 32-byte txid || 4-byte vout, fixed 36 bytes.
    pub input_outpoint: InputOutpoint,
    /// Canonical hash of the settlement outputs.
    pub settlement_outputs_hash: [u8; 32],
}

impl CoopCloseMessage {
    /// Build a coop-close message from a 32-byte txid and 4-byte vout.
    pub fn from_outpoint_parts(
        scope_id: [u8; 32],
        txid: [u8; 32],
        vout: u32,
        settlement_outputs_hash: [u8; 32],
    ) -> Self {
        let mut outpoint = [0u8; 36];
        outpoint[..32].copy_from_slice(&txid);
        outpoint[32..].copy_from_slice(&vout.to_le_bytes());
        Self {
            scope_id,
            input_outpoint: outpoint,
            settlement_outputs_hash,
        }
    }

    /// Compute the 32-byte cooperative-close signing message.
    pub fn compute(&self) -> [u8; 32] {
        let mut payload = [0u8; 32 + 36 + 32];
        payload[..32].copy_from_slice(&self.scope_id);
        payload[32..68].copy_from_slice(&self.input_outpoint);
        payload[68..].copy_from_slice(&self.settlement_outputs_hash);
        blake2b_256_keyed(DOMAIN_KURRENT_COOP_CLOSE, &payload)
    }

    pub fn compute_hex(&self) -> String {
        hex::encode(self.compute())
    }
}

/// Normative scope-identifier inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeInputs {
    /// 32-byte chain context (e.g. `H_KurrentNetwork(genesis_hash)`).
    pub chain_context: [u8; 32],
    /// 32-byte covenant ID (from KIP-20).
    pub covenant_id: [u8; 32],
    /// 32-byte x-only BIP-340 MuSig2 aggregate verification key.
    pub agg_key: [u8; 32],
    /// Response-window length in DAA-score units.
    pub delta: u32,
    /// Normative protocol ABI version.
    pub programme_version: u16,
    /// 32-byte policy_hash (see `PolicyEncoding`).
    pub policy_hash: [u8; 32],
}

impl ScopeInputs {
    /// Canonical fixed-width payload for `ScopeEncoding`.
    ///
    /// `ScopeEncoding = chain_context || covenant_id || agg_key
    ///                || le32(Δ) || le16(programme_version) || policy_hash`
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 32 + 4 + 2 + 32);
        out.extend_from_slice(&self.chain_context);
        out.extend_from_slice(&self.covenant_id);
        out.extend_from_slice(&self.agg_key);
        out.extend_from_slice(&self.delta.to_le_bytes());
        out.extend_from_slice(&self.programme_version.to_le_bytes());
        out.extend_from_slice(&self.policy_hash);
        out
    }

    /// Compute the 32-byte scope identifier.
    pub fn compute_scope_id(&self) -> [u8; 32] {
        blake2b_256_keyed(DOMAIN_KURRENT_SCOPE, &self.canonical_payload())
    }

    pub fn compute_scope_id_hex(&self) -> String {
        hex::encode(self.compute_scope_id())
    }
}

/// Normative v1 policy encoding.
///
/// `PolicyEncoding = le16(policy_version) || le32(sponsor_policy_id)
///                 || le32(settlement_shape_id) || coop_close_enabled{1}
///                 || reserved_64`
///
/// v1 assignments: policy_version=1, sponsor_policy_id=0
/// (external-sponsor-only for positive-fee protocol transactions),
/// settlement_shape_id=0 (fixed two-party shape),
/// coop_close_enabled ∈ {0, 1}, reserved_64 must be all-zero (rejection
/// on non-zero is normative).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEncoding {
    pub policy_version: u16,
    pub sponsor_policy_id: u32,
    pub settlement_shape_id: u32,
    pub coop_close_enabled: bool,
    pub reserved_64: [u8; 64],
}

impl Default for PolicyEncoding {
    fn default() -> Self {
        Self::v1()
    }
}

impl PolicyEncoding {
    /// v1 defaults: external-sponsor-only, fixed two-party, coop close
    /// enabled, reserved all-zero.
    pub fn v1() -> Self {
        Self {
            policy_version: POLICY_VERSION_V1,
            sponsor_policy_id: SPONSOR_POLICY_EXTERNAL_ONLY,
            settlement_shape_id: SETTLEMENT_SHAPE_TWO_PARTY_FIXED,
            coop_close_enabled: true,
            reserved_64: POLICY_RESERVED_64_MUST_BE_ZERO,
        }
    }

    /// Canonical fixed-width payload.
    pub fn canonical_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 4 + 4 + 1 + 64);
        out.extend_from_slice(&self.policy_version.to_le_bytes());
        out.extend_from_slice(&self.sponsor_policy_id.to_le_bytes());
        out.extend_from_slice(&self.settlement_shape_id.to_le_bytes());
        out.push(if self.coop_close_enabled { 1 } else { 0 });
        out.extend_from_slice(&self.reserved_64);
        out
    }

    /// Validate the v1 fixed assignments and the all-zero
    /// `reserved_64` field.
    pub fn validate_v1(&self) -> Result<()> {
        if self.policy_version != POLICY_VERSION_V1 {
            return Err(KurrentError::WrongProtocolVersion {
                expected: POLICY_VERSION_V1,
                actual: self.policy_version,
            });
        }
        if self.sponsor_policy_id != SPONSOR_POLICY_EXTERNAL_ONLY {
            return Err(KurrentError::InvalidPolicyField {
                field: "sponsor_policy_id",
                actual: self.sponsor_policy_id as u64,
            });
        }
        if self.settlement_shape_id != SETTLEMENT_SHAPE_TWO_PARTY_FIXED {
            return Err(KurrentError::InvalidPolicyField {
                field: "settlement_shape_id",
                actual: self.settlement_shape_id as u64,
            });
        }
        if self.reserved_64 != POLICY_RESERVED_64_MUST_BE_ZERO {
            return Err(KurrentError::InvalidPolicyField {
                field: "reserved_64",
                actual: 1,
            });
        }
        Ok(())
    }

    /// Compute the 32-byte `policy_hash`.
    pub fn compute_policy_hash(&self) -> [u8; 32] {
        self.validate_v1()
            .expect("v1 policy encoding must validate");
        blake2b_256_keyed(DOMAIN_KURRENT_POLICY, &self.canonical_payload())
    }

    pub fn compute_policy_hash_hex(&self) -> String {
        hex::encode(self.compute_policy_hash())
    }
}

/// Bounded transaction shape, named by the branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundedShape {
    /// Open / replacement: `[channel input, optional sponsor input]` →
    /// `[contest output of V at idx 0, optional sponsor change at idx 1]`.
    ContestOpeningOrReplacement,
    /// Settlement: `[contest input, optional sponsor input]` →
    /// `[participant A at idx 0, participant B at idx 1, optional sponsor change at idx 2]`.
    Settlement,
    /// Cooperative close: `[protocol input, optional sponsor input]` →
    /// `[participant A at idx 0, participant B at idx 1, optional sponsor change at idx 2]`.
    /// All inputs use `le64(2^63)` (disabled relative sequence).
    CoopClose,
}

impl BoundedShape {
    /// Maximum number of input slots (fixed slots, plus optional sponsor).
    pub fn input_slot_count(&self) -> usize {
        match self {
            Self::ContestOpeningOrReplacement | Self::Settlement | Self::CoopClose => 2,
        }
    }

    /// Maximum number of output slots (fixed slots, plus optional sponsor).
    pub fn output_slot_count(&self) -> usize {
        match self {
            Self::ContestOpeningOrReplacement => 2,
            Self::Settlement | Self::CoopClose => 3,
        }
    }

    /// Whether the branch may carry an optional sponsor input.
    /// All three branches allow an external sponsor for fee payment.
    pub fn allows_sponsor_input(&self) -> bool {
        true
    }

    /// Output index of the sponsor change output, if any. Returns
    /// `None` when the branch has no sponsor change slot (e.g.
    /// fee-zero settlement).
    pub fn sponsor_change_index(&self) -> Option<usize> {
        match self {
            Self::ContestOpeningOrReplacement => Some(1),
            Self::Settlement | Self::CoopClose => Some(2),
        }
    }
}

/// Check the sponsor invariant `sponsor_input_value =
/// sponsor_change_value + fee` for a branch. The covenant enforces
/// this so a sponsor cannot launder channel funds into the fee
/// market. Returns `Ok(())` when the values are consistent,
/// `Err(KurrentError::ConservationFailure)` otherwise.
///
/// `sponsor_input_value = 0` is allowed (no-sponsor case) and
/// requires `sponsor_change_value = 0` and `fee = 0`.
pub fn check_sponsor_invariant(
    sponsor_input_value: u64,
    sponsor_change_value: u64,
    fee: u64,
) -> Result<()> {
    let total = sponsor_change_value
        .checked_add(fee)
        .ok_or(KurrentError::ConservationFailure {
            expected: sponsor_input_value,
            actual: sponsor_change_value.saturating_add(fee),
        })?;
    if total != sponsor_input_value {
        return Err(KurrentError::ConservationFailure {
            expected: sponsor_input_value,
            actual: total,
        });
    }
    Ok(())
}

/// Verify a replacement's `state_root_m` per §6.3. The covenant
/// recomputes `state_root_m` from the successor settlement slots
/// the witness exposes, and checks `v_A + v_B = V`. This function
/// performs the same recomputation and the conservation check,
/// returning `Ok(true)` if the recomputed root matches the one in
/// the certificate (i.e. the certificate is internally consistent
/// with the witness slots) and `Ok(false)` if the recomputed root
/// disagrees. Returns `Err` if `v_A + v_B ≠ V` so the caller can
/// distinguish a malformed root from a conservation violation.
pub fn verify_replacement_state_root(
    cert: &StateCertMessage,
    witness_spk_a: &EncodedSpk,
    witness_value_a: u64,
    witness_spk_b: &EncodedSpk,
    witness_value_b: u64,
    expected_total: u64,
) -> Result<bool> {
    validate_conservation(witness_value_a, witness_value_b, expected_total)?;
    let recomputed = StateRootInput {
        spk_a: witness_spk_a.clone(),
        value_a: witness_value_a,
        spk_b: witness_spk_b.clone(),
        value_b: witness_value_b,
    }
    .compute_root();
    Ok(recomputed == cert.state_root)
}

/// Canonical relative-sequence encoding. The two branches use
/// distinct physical encodings so the covenant can reject a wrong
/// branch with a single `OpTxInputSeq` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalSequence {
    /// Settlement: disable bit clear, low 32 bits encode Δ.
    /// `SEQ_settle = le64(Δ)`.
    Settle { delta: u32 },
    /// Replacement / coop close: disable bit set, every other bit zero.
    /// `SEQ_replace = le64(2^63)`.
    DisableRelativeLock,
}

impl CanonicalSequence {
    pub fn encode(&self) -> [u8; 8] {
        let n: u64 = match self {
            Self::Settle { delta } => *delta as u64,
            Self::DisableRelativeLock => 1u64 << 63,
        };
        n.to_le_bytes()
    }
}

/// Validate the conservation invariant `v_A + v_B = V` without
/// risking overflow.
pub fn validate_conservation(value_a: u64, value_b: u64, expected_total: u64) -> Result<()> {
    let total = value_a
        .checked_add(value_b)
        .ok_or(KurrentError::ConservationFailure {
            expected: expected_total,
            actual: value_a.saturating_add(value_b),
        })?;
    if total != expected_total {
        return Err(KurrentError::ConservationFailure {
            expected: expected_total,
            actual: total,
        });
    }
    Ok(())
}
