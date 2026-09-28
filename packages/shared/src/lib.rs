#![no_std]

use soroban_sdk::{contracterror, contracttype, xdr::ToXdr, Address, BytesN, Env, Symbol};

pub mod storage_namespaces;

pub use storage_namespaces::{StorageClass, StorageNamespace, STORAGE_NAMESPACES};
pub mod error_catalog;

pub use error_catalog::{Domain, ErrorSpec, Retry, Status, ERROR_CATALOG};

// Export upgrade approval types for use across all contracts
pub use soroban_sdk::String as SorobanString;

pub const TTL_THRESHOLD_LEDGERS: u32 = 50_000;

/// Target ledgers for extended TTL after triggering a preemptive extension.
pub const TTL_EXTEND_TO_LEDGERS: u32 = 500_000;

/// Minimum ledgers between approval and execution (timelock).
/// Prevents immediate execution of just-approved upgrades.
/// ~1 day at 5s/ledger = 17,280 ledgers
pub const UPGRADE_TIMELOCK_LEDGERS: u32 = 17_280;

/// Maximum ledgers an approval remains valid after creation.
/// Stale approvals expire and must be re-approved.
/// ~30 days at 5s/ledger = 518_400 ledgers
pub const UPGRADE_APPROVAL_EXPIRY_LEDGERS: u32 = 518_400;
/// Storage layout version for the migration checkpoint record.
pub const MIGRATION_STATUS_VERSION: u32 = 1;

/// Maximum number of records a single migration invocation may commit.
pub const MAX_MIGRATION_BATCH: u32 = 100;

/// Maximum number of proofs a single batch registration or batch revocation
/// call may contain. Bounded not just by CPU/memory but by Soroban's
/// per-invocation ledger footprint limit (100 entries in this environment):
/// each proof touches a persistent data entry and its TTL entry, and a
/// batch revocation touching state written by prior calls was measured to
/// exceed that footprint limit at 25. 20 leaves comfortable headroom on
/// both the registration and revocation paths.
pub const MAX_PROOF_BATCH_SIZE: u32 = 20;

/// Resumable progress marker shared by every contract upgrade path.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationStatus {
    pub status_version: u32,
    pub target_contract_version: u32,
    pub cursor: u32,
    pub total_items: u32,
    pub complete: bool,
}

/// Canonical configuration digest payload version.
pub const CONFIG_DIGEST_VERSION: u32 = 1;

pub fn protocol_config_digest(
    env: &Env,
    admin: &Address,
    paused: bool,
    config_version: u32,
    contract_version: u32,
) -> BytesN<32> {
    let payload = (
        CONFIG_DIGEST_VERSION,
        Symbol::new(env, "earnproof_protocol_config"),
        admin.clone(),
        paused,
        config_version,
        contract_version,
    )
        .to_xdr(env);
    env.crypto().sha256(&payload).to_bytes()
}

pub fn issuer_registry_digest(env: &Env, admin: &Address, contract_version: u32) -> BytesN<32> {
    let payload = (
        CONFIG_DIGEST_VERSION,
        Symbol::new(env, "earnproof_issuer_registry"),
        admin.clone(),
        contract_version,
    )
        .to_xdr(env);
    env.crypto().sha256(&payload).to_bytes()
}

pub fn proof_registry_digest(
    env: &Env,
    admin: &Address,
    issuer_registry: &Address,
    protocol_config: &Address,
    contract_version: u32,
) -> BytesN<32> {
    let payload = (
        CONFIG_DIGEST_VERSION,
        Symbol::new(env, "earnproof_proof_registry"),
        admin.clone(),
        issuer_registry.clone(),
        protocol_config.clone(),
        contract_version,
    )
        .to_xdr(env);
    env.crypto().sha256(&payload).to_bytes()
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TtlHealth {
    Missing,
    NearExpiry,
    Healthy,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TtlStatus {
    pub health: TtlHealth,
    pub remaining_ledgers: u32,
    pub threshold_ledgers: u32,
}

pub fn ttl_status(current_ledger: u32, exists: bool, live_until: Option<u32>) -> TtlStatus {
    let remaining = live_until
        .filter(|_| exists)
        .map(|ledger| ledger.saturating_sub(current_ledger))
        .unwrap_or(0);
    let health = if !exists || live_until.is_none() || remaining == 0 {
        TtlHealth::Missing
    } else if remaining <= TTL_THRESHOLD_LEDGERS {
        TtlHealth::NearExpiry
    } else {
        TtlHealth::Healthy
    };
    TtlStatus {
        health,
        remaining_ledgers: remaining,
        threshold_ledgers: TTL_THRESHOLD_LEDGERS,
    }
}

// A Stellar strkey address (G...) is always exactly 56 ASCII characters.
// soroban_sdk::String has no .chars() (unlike std::string::String, and
// unlike Symbol, this isn't even gated off-WASM only - it simply doesn't
// exist on any target in this SDK version) and doesn't implement
// PartialEq<&str>, only String == String - copy_into_slice() into a fixed
// buffer and comparing raw ASCII bytes is the actual supported way to
// inspect a soroban_sdk::String's contents on every target.
const STRKEY_ADDRESS_LEN: usize = 56;

fn address_bytes(address: &Address) -> [u8; STRKEY_ADDRESS_LEN] {
    let value = address.to_string();
    let mut buf = [0u8; STRKEY_ADDRESS_LEN];
    if value.len() as usize == STRKEY_ADDRESS_LEN {
        value.copy_into_slice(&mut buf);
    }
    buf
}

// The strkey encoding of an all-zero (32-byte) ed25519 public key: version
// byte 'G' + 32 zero payload bytes + a real CRC16/XMODEM checksum over
// those 33 bytes, base32-encoded. The checksum is NOT itself all zero bits
// (a correct checksum over an all-zero payload is not the all-zero
// checksum), so this string does not end in all 'A's — comparing the
// full string against this one known-correct value is the only way to
// recognize it; a pattern check like "G followed by all A's" would (and
// previously did) silently never match a real, correctly-checksummed
// all-zero-payload address at all.
const ZERO_PAYLOAD_STRKEY: &[u8; STRKEY_ADDRESS_LEN] =
    b"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";

pub fn is_zero_or_sentinel_address(address: &Address) -> bool {
    let bytes = address_bytes(address);
    &bytes == ZERO_PAYLOAD_STRKEY
}

pub fn is_valid_principal_address(address: &Address) -> bool {
    let value = address.to_string();
    if value.is_empty() || value.len() as usize != STRKEY_ADDRESS_LEN {
        return false;
    }
    let bytes = address_bytes(address);
    if is_zero_or_sentinel_address(address) {
        return false;
    }
    bytes
        .iter()
        .all(|&byte| matches!(byte, b'A'..=b'Z' | b'2'..=b'7'))
}

// ---------------------------------------------------------------------------
// Error Codes
//
// Error ranges are allocated to prevent collisions:
// - Common errors:       1-99
// - Protocol Config:     100-199
// - Issuer Registry:     200-299
// - Proof Registry:      300-399
//
// Each error code is stable and machine-readable. Backend integrations
// should map these codes to appropriate HTTP status codes and user messages.
// ---------------------------------------------------------------------------

/// Common errors shared across all contracts.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    // Initialization errors (1-19)
    AlreadyInitialized = 1,
    NotInitialized = 2,

    // Authorization errors (20-39)
    Unauthorized = 20,

    // State errors (40-59)
    AlreadyExists = 40,
    NotFound = 41,
    InvalidState = 42,

    // Input validation errors (60-79)
    InvalidInput = 60,
    InvalidAddress = 61,

    // Protocol state errors (80-99)
    ProtocolPaused = 80,

    // Upgrade timing errors (90-99)
    NoUpgradeApproval = 90,
    UpgradeTimelockNotElapsed = 91,
    UpgradeApprovalExpired = 92,
    WasmHashMismatch = 93,
    InvalidTimingConfig = 94,
}

/// Issuer-specific errors (200-299).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum IssuerError {
    IssuerAlreadyRegistered = 200,
    IssuerNotFound = 201,
    IssuerAddressAlreadyRegistered = 202,
    IssuerAddressNotFound = 203,
    IssuerRevoked = 204,
    IssuerInactive = 205,
    InvalidTransition = 206,
    InvalidAddress = 207,
}

/// Proof-specific errors (300-399).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProofError {
    ProofAlreadyRegistered = 300,
    ProofNotFound = 301,
    ProofAlreadyRevoked = 302,
    ProofExpired = 303,
    InvalidSchemaVersion = 304,
    SchemaVersionNotApproved = 305,
    InvalidAddress = 306,
    // Separated precondition errors (307-310)
    /// Contract is paused — proof registration is temporarily disabled.
    /// Recovery: monitor for unpause event before retrying.
    ContractPaused = 307,
    /// Issuer account is not active or not authorized to register proofs.
    /// Distinct from authorization failure — the issuer exists but is inactive.
    /// Recovery: contact platform to activate the issuer account.
    IssuerInactive = 308,
    /// The proof schema identifier is not supported or not registered.
    /// Distinct from malformed input — the schema reference is well-formed
    /// but unknown to this contract.
    /// Recovery: check supported schemas via get_supported_schemas().
    UnsupportedSchema = 309,
    /// Proof input data is malformed — fails format or size validation.
    /// Distinct from unsupported schema — the input itself is invalid.
    /// Recovery: validate input against the schema before resubmitting.
    MalformedInput = 310,
    /// A batch operation was given zero entries or more than
    /// `MAX_PROOF_BATCH_SIZE` entries.
    /// Recovery: split the batch into chunks of at most `MAX_PROOF_BATCH_SIZE`.
    InvalidBatchSize = 311,
    /// `register_proof_with_activation` was given an `activates_at` at or
    /// after `expires_at`, so the proof could never be valid.
    /// Recovery: choose an activation time strictly before the expiration.
    InvalidActivationTime = 312,
    /// `open_dispute` was called for a proof that already has an `Open`
    /// dispute. Recovery: withdraw, resolve, or reject the existing dispute
    /// before opening a new one — retrying the identical request will not
    /// help, since the dispute is cleared by a different call, not by this
    /// one succeeding on its own.
    DisputeAlreadyOpen = 313,
    /// `withdraw_dispute`, `resolve_dispute`, or `reject_dispute` referenced
    /// a proof with no dispute record.
    /// Recovery: open a dispute first, or confirm the proof id.
    DisputeNotFound = 314,
    /// A dispute transition was attempted on a dispute that is not `Open`
    /// (already withdrawn, resolved, or rejected).
    /// Recovery: read the dispute's current status; it is terminal.
    DisputeNotOpen = 315,
}

#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PauseScope {
    Global,
    Registration,
    Updates,
    Revocation,
    Upgrades,
    Disputes,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssuerStatus {
    Active,
    Suspended,
    Revoked,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofStatus {
    Active,
    Revoked,
}

/// Stores temporal metadata for an upgrade approval.
///
/// # Timing invariants
/// - `created_at` ≤ `earliest_execution` ≤ `expires_at`
/// - execution is rejected before `earliest_execution`
/// - execution is rejected at or after `expires_at`
/// - re-approval resets ALL three fields (no stale reuse)
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeApproval {
    /// WASM hash approved for upgrade
    pub wasm_hash: BytesN<32>,
    /// Ledger sequence when approval was created
    pub created_at: u32,
    /// Earliest ledger at which execution is permitted
    /// = created_at + UPGRADE_TIMELOCK_LEDGERS
    pub earliest_execution: u32,
    /// Ledger sequence after which approval is invalid
    /// = created_at + UPGRADE_APPROVAL_EXPIRY_LEDGERS
    pub expires_at: u32,
    /// Address that created this approval
    pub approved_by: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerRecord {
    pub issuer_id_hash: BytesN<32>,
    pub issuer_address: Address,
    pub metadata_hash: BytesN<32>,
    pub provenance_commitment: BytesN<32>,
    pub status: IssuerStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub reason_commitment: Option<BytesN<32>>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRecord {
    pub proof_id_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub issuer_address: Address,
    pub status: ProofStatus,
    pub schema_version: u32,
    pub expires_at: u64,
    pub created_at: u64,
    pub revoked_at: u64,
    /// Ledger timestamp at or after which this proof is considered active.
    /// `0` means the proof was registered without a delay and is active
    /// immediately (subject to `status` and `expires_at` as before). This
    /// field is fixed at registration and is never mutated afterward — there
    /// is no operation that moves it, earlier or later.
    pub activates_at: u64,
}

/// The full validity state of a proof, distinguishing every reason a proof
/// might not currently verify from the single boolean `is_valid_proof`
/// returns.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofValidity {
    /// `status == Active`, `activates_at` has been reached, and `expires_at`
    /// has not.
    Active,
    /// Registered and not revoked, but the ledger has not yet reached
    /// `activates_at`. Carries that timestamp (`Pending(activates_at)`) so a
    /// caller can know when to check again.
    Pending(u64),
    /// `status == Revoked`. Terminal: a revoked proof never becomes valid
    /// again, including one revoked while still pending.
    Revoked,
    /// Active and past its activation time, but at or after `expires_at`.
    Expired,
    /// No record exists for this proof id.
    NotFound,
}

/// One entry of a bounded batch registration request.
///
/// Mirrors the per-proof arguments of `register_proof` minus `issuer_address`,
/// since a batch registers proofs for a single authorized issuer.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProofRegistrationInput {
    pub proof_id_hash: BytesN<32>,
    pub commitment_hash: BytesN<32>,
    pub schema_version: u32,
    pub expires_at: u64,
}

/// Lifecycle state of a proof dispute. Terminal once `Withdrawn`, `Resolved`,
/// or `Rejected`: none of those transitions back to `Open`, and a new
/// dispute can only be opened once the previous one has reached one of them.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DisputeStatus {
    /// Under review. The only status a proof may have at most one of at a
    /// time.
    Open,
    /// Withdrawn by whoever opened it, before any resolution.
    Withdrawn,
    /// Resolved by the admin in the disputant's favor.
    Resolved,
    /// Rejected by the admin as without merit.
    Rejected,
}

/// Coarse category of who took a dispute action, recorded alongside the
/// address itself so an indexer can distinguish "the issuer disputed their
/// own proof" from "a third party disputed it" without re-deriving it from
/// other contract state.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DisputeActorClass {
    /// The address is the proof's own recorded issuer.
    Issuer,
    /// The address is the proof-registry contract's admin.
    Admin,
    /// Any other address.
    ThirdParty,
}

/// Bounded, on-chain dispute state for one proof.
///
/// Deliberately does not store raw evidence or a free-form reason: only a
/// commitment hash to evidence held off-chain, mirroring how issuer-registry
/// records a `reason_commitment` rather than the reason text itself. Dispute
/// status is tracked independently of `ProofRecord.status`: opening,
/// resolving, or rejecting a dispute never changes a proof's validity or
/// revocation state, and revoking or expiring a proof never changes its
/// dispute state.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisputeRecord {
    pub proof_id_hash: BytesN<32>,
    /// Hash of off-chain evidence. Never the evidence itself.
    pub evidence_commitment: BytesN<32>,
    pub status: DisputeStatus,
    pub opened_by: Address,
    pub opened_by_class: DisputeActorClass,
    pub opened_at: u64,
    /// Address that produced the current `status` — the opener while still
    /// `Open`, or whoever withdrew/resolved/rejected it.
    pub updated_by: Address,
    pub updated_by_class: DisputeActorClass,
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchemaRecord {
    pub version: u32,
    pub metadata_hash: BytesN<32>,
    pub is_approved: bool,
    pub activated_at: u64,
    pub deprecated_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeReceipt {
    pub wasm_hash: BytesN<32>,
    pub old_version: u32,
    pub new_version: u32,
    pub upgraded_at: u64,
    pub upgraded_by: Address,
}
// ── Upgrade Approval Metadata ──────────────────────────────────────────────────
// Metadata for an upgrade approval, exposed for off-chain verification.
//
// This is the single shared structure used across all contracts that
// implement upgrade approval workflows. Generated clients see a consistent
// type regardless of which contract they interact with.
//
// # Off-chain verification use cases
// - Verify an upgrade plan matches the approved hash and version
// - Check the approval window (creation → expiry) to assess staleness
// - Confirm the execution ledger matches when approval was consumed
// - Audit which approver authorized the upgrade

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct UpgradeApprovalMetadata {
    /// SHA-256 hash of the WASM bytecode approved for upgrade.
    /// Operators compare this against the upgrade package hash.
    pub target_hash: BytesN<32>,

    /// Semantic version string of the target contract version.
    /// Format: "MAJOR.MINOR.PATCH" (e.g. "1.2.0")
    pub target_version: u32,

    /// Address that submitted and signed this approval.
    pub approver: Address,

    /// Ledger sequence when the approval was created.
    pub creation_ledger: u32,

    /// Ledger sequence when the approved upgrade was executed.
    /// None if the approval has not yet been consumed.
    pub execution_ledger: Option<u32>,

    /// Ledger sequence after which this approval expires and cannot be used.
    pub expiry_ledger: u32,

    /// Current status of this approval.
    pub status: ApprovalStatus,
}

/// Unambiguous status for an upgrade approval.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ApprovalStatus {
    /// Approval is valid and within its window.
    Active,

    /// Approval was used — upgrade has been executed.
    Executed,

    /// Approval was explicitly revoked before execution.
    Revoked,

    /// Approval window has passed without execution.
    Expired,
}

/// Result of an approval metadata query.
/// Distinguishes "unknown" from "revoked" unambiguously.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum ApprovalQuery {
    /// Approval exists — metadata included.
    Found(UpgradeApprovalMetadata),

    /// No approval record exists for this hash.
    /// Distinct from Revoked — the approval never existed or was pruned.
    NotFound,

    /// Approval existed but was explicitly revoked.
    /// Included metadata shows who approved and when, for audit purposes.
    Revoked(UpgradeApprovalMetadata),
}

// ── Shared Test Utilities ──────────────────────────────────────────────────────
// These utilities provide common patterns for initialization adversarial testing
// across all contracts, ensuring consistent test coverage for re-initialization
// guards, invalid dependencies, and state/event immutability on failure.

#[cfg(test)]
pub mod test_utils {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    /// Represents the expected state after successful initialization.
    /// Used to verify that first initialization produces exactly the documented
    /// state with no partial writes.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct InitializedState {
        /// The admin address that was set during initialization.
        pub admin: Address,
        /// True if the contract emitted an event during initialization.
        pub event_emitted: bool,
        /// Additional state keys that should be present after initialization.
        pub expected_keys: Vec<&'static str>,
    }

    /// Test result for re-initialization attempts.
    /// Captures whether the attempt failed and whether state remained unchanged.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct ReinitAttemptResult {
        /// True if re-initialization attempt failed (panicked or errored).
        pub failed: bool,
        /// True if storage state is byte-for-byte identical before and after attempt.
        pub state_unchanged: bool,
        /// True if no new events were emitted during the failed attempt.
        pub no_new_events: bool,
    }

    /// Test result for invalid dependency/configuration initialization attempts.
    /// Captures whether the attempt failed and whether state remained atomic.
    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct InvalidDependencyResult {
        /// True if initialization attempt failed.
        pub failed: bool,
        /// True if storage state is unchanged after the failed attempt.
        pub atomic_failure: bool,
        /// True if no events were emitted during the failed attempt.
        pub no_events: bool,
    }

    /// Documents the initialization contract's behavior for test purposes.
    /// This structure is filled out for each contract being tested and serves
    /// as the specification against which adversarial tests validate behavior.
    #[derive(Clone, Debug)]
    pub struct ContractInitSpec {
        /// Name of the contract being tested.
        pub contract_name: &'static str,
        /// True if this contract has a re-initialization guard.
        pub has_reinit_guard: bool,
        /// True if this contract emits an event during initialization.
        pub emits_init_event: bool,
        /// True if this contract takes dependency addresses as initialization parameters.
        pub takes_dependencies: bool,
        /// List of dependency contract names this contract requires (e.g., ["issuer-registry", "protocol-config"]).
        pub dependency_names: Vec<&'static str>,
    }

    impl ContractInitSpec {
        /// Helper to create a spec for a standalone contract with a re-initialization guard.
        pub fn standalone_with_guard(name: &'static str, emits_event: bool) -> Self {
            ContractInitSpec {
                contract_name: name,
                has_reinit_guard: true,
                emits_init_event: emits_event,
                takes_dependencies: false,
                dependency_names: vec![],
            }
        }

        /// Helper to create a spec for a contract with dependencies and a re-initialization guard.
        pub fn with_dependencies_and_guard(
            name: &'static str,
            deps: Vec<&'static str>,
            emits_event: bool,
        ) -> Self {
            ContractInitSpec {
                contract_name: name,
                has_reinit_guard: true,
                emits_init_event: emits_event,
                takes_dependencies: true,
                dependency_names: deps,
            }
        }
    }
}
