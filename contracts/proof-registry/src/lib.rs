#![no_std]

#[allow(unused_imports)]
use earnproof_shared::{
    ContractError, MigrationStatus, PauseScope, ProofError, ProofRecord, ProofRegistrationInput,
    ProofStatus, TtlStatus, UpgradeApproval, UpgradeReceipt, MAX_MIGRATION_BATCH,
    MAX_PROOF_BATCH_SIZE, MIGRATION_STATUS_VERSION, TTL_EXTEND_TO_LEDGERS, TTL_THRESHOLD_LEDGERS,
};
use soroban_sdk::{
    contract, contractclient, contractevent, contractimpl, contracttype, Address, BytesN, Env, Vec,
};

#[contractclient(name = "ProtocolConfigContractClient")]
pub trait ProtocolConfigInterface {
    fn is_paused(env: Env) -> bool;
    fn is_scope_paused(env: Env, scope: PauseScope) -> bool;
    fn is_schema_version_approved(env: Env, version: u32) -> bool;
}

#[contractclient(name = "IssuerRegistryContractClient")]
pub trait IssuerRegistryInterface {
    fn is_active_address(env: Env, issuer_address: Address) -> bool;
}

#[contract]
pub struct ProofRegistryContract;

#[contracttype]
enum DataKey {
    MigrationStatus,
    Admin,
    IssuerRegistry,
    ProtocolConfig,
    Proof(BytesN<32>),
    /// Allowlist entry: maps a WASM hash to the target contract version.
    AllowedWasm(BytesN<32>),
    /// Monotonically-increasing contract version.  Prevents downgrade.
    ContractVersion,
    Successor,
    Decommissioned,
    PendingAdmin,
}

#[contractevent]
pub struct AdminTransferNominated {
    pub pending_admin: Address,
    pub nominated_by: Address,
}

#[contractevent]
pub struct AdminTransferAccepted {
    pub new_admin: Address,
}

#[contractevent]
pub struct AdminTransferCancelled {
    pub pending_admin: Address,
    pub cancelled_by: Address,
}

// ── upgrade events ────────────────────────────────────────────────────────────

/// Emitted when the admin adds a WASM hash to the upgrade allowlist.
#[contractevent]
pub struct UpgradeAllowlisted {
    pub wasm_hash: BytesN<32>,
    pub new_contract_version: u32,
    pub approved_by: Address,
}

/// Emitted when the admin removes a WASM hash from the allowlist without
/// applying it.
#[contractevent]
pub struct UpgradeRevoked {
    pub wasm_hash: BytesN<32>,
    pub revoked_by: Address,
}

/// Emitted when a WASM upgrade is successfully applied.
#[contractevent]
pub struct ContractUpgraded {
    pub new_wasm_hash: BytesN<32>,
    pub old_contract_version: u32,
    pub new_contract_version: u32,
    pub upgraded_by: Address,
}

#[contractevent]
pub struct SuccessorNominated {
    pub successor: Address,
    pub nominated_by: Address,
}

#[contractevent]
pub struct ContractDecommissioned {
    pub old_instance: Address,
    pub successor_instance: Address,
    pub activated_by: Address,
}

/// Emitted once per proof successfully registered via `register_proofs_batch`,
/// in the same order the entries were supplied.
#[contractevent]
pub struct ProofRegisteredInBatch {
    pub proof_id_hash: BytesN<32>,
    pub issuer_address: Address,
}

/// Emitted once per proof successfully revoked via `revoke_proofs_batch` or
/// `admin_revoke_proofs_batch`, in the same order the identifiers were
/// supplied. `revoked_by` is the proof's own issuer address for the former
/// and the admin address for the latter.
#[contractevent]
pub struct ProofRevokedInBatch {
    pub proof_id_hash: BytesN<32>,
    pub revoked_by: Address,
}

#[contractimpl]
impl ProofRegistryContract {
    pub fn is_decommissioned(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Decommissioned)
            .unwrap_or(false)
    }

    fn ensure_not_decommissioned(env: &Env) -> Result<(), ProofError> {
        if Self::is_decommissioned(env.clone()) {
            Err(ProofError::ProofNotFound)
        } else {
            Ok(())
        }
    }

    pub fn initialize(
        env: Env,
        admin: Address,
        issuer_registry: Address,
        protocol_config: Address,
    ) -> Result<(), ContractError> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(ContractError::AlreadyInitialized);
        }

        Self::require_valid_principal(&admin)?;
        Self::validate_dependency_addresses(&env, &issuer_registry, &protocol_config)?;
        Self::require_auth(&admin);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .set(&DataKey::IssuerRegistry, &issuer_registry);
        env.storage()
            .instance()
            .set(&DataKey::ProtocolConfig, &protocol_config);
        env.storage()
            .instance()
            .set(&DataKey::ContractVersion, &1_u32);
        Self::extend_instance_ttl(env);
        Ok(())
    }

    pub fn nominate_successor(env: Env, successor: Address) -> Result<(), ProofError> {
        Self::ensure_not_decommissioned(&env)?;
        let admin = Self::get_admin(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
        Self::require_valid_issuer_address(&successor)?;
        Self::require_auth(&admin);
        env.storage()
            .instance()
            .set(&DataKey::Successor, &successor);
        SuccessorNominated {
            successor: successor.clone(),
            nominated_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn get_successor(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Successor)
    }

    pub fn activate_successor(env: Env) -> Result<(), ProofError> {
        Self::ensure_not_decommissioned(&env)?;
        let admin = Self::get_admin(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
        Self::require_auth(&admin);
        let successor: Address = env
            .storage()
            .instance()
            .get(&DataKey::Successor)
            .ok_or(ProofError::ProofNotFound)?;

        env.storage()
            .instance()
            .set(&DataKey::Decommissioned, &true);
        ContractDecommissioned {
            old_instance: env.current_contract_address(),
            successor_instance: successor,
            activated_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn keepalive_instance(env: Env) -> bool {
        if !env.storage().instance().has(&DataKey::Admin) {
            return false;
        }
        Self::extend_instance_ttl(env);
        true
    }

    pub fn keepalive_proof(env: Env, proof_id_hash: BytesN<32>) -> bool {
        let key = DataKey::Proof(proof_id_hash);
        if env.storage().persistent().has(&key) {
            Self::extend_proof_key_ttl(env, &key);
            true
        } else {
            false
        }
    }

    pub fn register_proof(
        env: Env,
        proof_id_hash: BytesN<32>,
        commitment_hash: BytesN<32>,
        issuer_address: Address,
        schema_version: u32,
        expires_at: u64,
    ) -> Result<(), ProofError> {
        Self::ensure_not_decommissioned(&env)?;
        Self::require_valid_issuer_address(&issuer_address)?;
        let protocol_config =
            Self::get_protocol_config(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
        let issuer_registry =
            Self::get_issuer_registry(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
        if issuer_address == env.current_contract_address()
            || issuer_address == protocol_config
            || issuer_address == issuer_registry
        {
            return Err(ProofError::InvalidAddress);
        }
        Self::require_auth(&issuer_address);

        // Input validation (proof-specific data validation — checked before cross-contract calls)
        if schema_version == 0 {
            return Err(ProofError::InvalidSchemaVersion);
        }

        if expires_at <= env.ledger().timestamp() {
            return Err(ProofError::ProofExpired);
        }

        // Check 1: Contract paused (highest precedence — most external state)
        let protocol_client = ProtocolConfigContractClient::new(&env, &protocol_config);
        if protocol_client.is_paused() {
            return Err(ProofError::ContractPaused);
        }

        // Check 2: Issuer active (issuer-specific state)
        let issuer_client = IssuerRegistryContractClient::new(&env, &issuer_registry);
        if !issuer_client.is_active_address(&issuer_address) {
            return Err(ProofError::IssuerInactive);
        }

        // Check 3: Schema supported (protocol configuration state)
        if !protocol_client.is_schema_version_approved(&schema_version) {
            return Err(ProofError::UnsupportedSchema);
        }

        // Check 5: Uniqueness constraint (storage precondition)
        let key = DataKey::Proof(proof_id_hash.clone());
        if env.storage().persistent().has(&key) {
            return Err(ProofError::ProofAlreadyRegistered);
        }

        let now = env.ledger().timestamp();
        let record = ProofRecord {
            proof_id_hash,
            commitment_hash,
            issuer_address,
            status: ProofStatus::Active,
            schema_version,
            expires_at,
            created_at: now,
            revoked_at: 0,
        };

        env.storage().persistent().set(&key, &record);
        Self::extend_proof_key_ttl(env, &key);
        Ok(())
    }

    /// Registers a strictly bounded batch of proofs for a single authorized
    /// issuer, atomically.
    ///
    /// The batch is validated and written entry-by-entry, in order. If any
    /// entry fails validation (duplicate proof id — whether already on chain
    /// or repeated within this batch, zero schema version, expired
    /// timestamp, or an unapproved schema version), the call returns that
    /// entry's error and — per Soroban's invocation semantics — every write
    /// and event already produced earlier in this same call is discarded
    /// along with it, so no partial batch is ever committed.
    ///
    /// Issuer authorization, pause state, and issuer-active state are each
    /// checked once for the whole batch, reusing the same checks
    /// `register_proof` performs for a single proof. `is_schema_version_approved`
    /// is checked per entry, since entries may use different schema versions.
    ///
    /// Emits one [`ProofRegisteredInBatch`] event per registered proof, in
    /// input order.
    pub fn register_proofs_batch(
        env: Env,
        entries: Vec<ProofRegistrationInput>,
        issuer_address: Address,
    ) -> Result<(), ProofError> {
        Self::ensure_not_decommissioned(&env)?;
        Self::require_valid_issuer_address(&issuer_address)?;

        let len = entries.len();
        if len == 0 || len > MAX_PROOF_BATCH_SIZE {
            return Err(ProofError::InvalidBatchSize);
        }

        let protocol_config =
            Self::get_protocol_config(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
        let issuer_registry =
            Self::get_issuer_registry(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
        if issuer_address == env.current_contract_address()
            || issuer_address == protocol_config
            || issuer_address == issuer_registry
        {
            return Err(ProofError::InvalidAddress);
        }
        Self::require_auth(&issuer_address);

        // Check 1: Contract paused (highest precedence — most external state)
        let protocol_client = ProtocolConfigContractClient::new(&env, &protocol_config);
        if protocol_client.is_paused() {
            return Err(ProofError::ContractPaused);
        }

        // Check 2: Issuer active (issuer-specific state) — checked once for
        // the whole batch, since every entry shares the same issuer.
        let issuer_client = IssuerRegistryContractClient::new(&env, &issuer_registry);
        if !issuer_client.is_active_address(&issuer_address) {
            return Err(ProofError::IssuerInactive);
        }

        let now = env.ledger().timestamp();

        for entry in entries.iter() {
            if entry.schema_version == 0 {
                return Err(ProofError::InvalidSchemaVersion);
            }

            if entry.expires_at <= now {
                return Err(ProofError::ProofExpired);
            }

            // Check 3: Schema supported (protocol configuration state)
            if !protocol_client.is_schema_version_approved(&entry.schema_version) {
                return Err(ProofError::UnsupportedSchema);
            }

            // Check 4: Uniqueness constraint (storage precondition). A proof
            // id repeated earlier in this same batch is already visible here,
            // since writes made earlier in this call are readable within it —
            // so this single check also rejects intra-batch duplicates.
            let key = DataKey::Proof(entry.proof_id_hash.clone());
            if env.storage().persistent().has(&key) {
                return Err(ProofError::ProofAlreadyRegistered);
            }

            let record = ProofRecord {
                proof_id_hash: entry.proof_id_hash.clone(),
                commitment_hash: entry.commitment_hash.clone(),
                issuer_address: issuer_address.clone(),
                status: ProofStatus::Active,
                schema_version: entry.schema_version,
                expires_at: entry.expires_at,
                created_at: now,
                revoked_at: 0,
            };

            env.storage().persistent().set(&key, &record);
            Self::extend_proof_key_ttl(env.clone(), &key);

            ProofRegisteredInBatch {
                proof_id_hash: entry.proof_id_hash.clone(),
                issuer_address: issuer_address.clone(),
            }
            .publish(&env);
        }

        Ok(())
    }

    pub fn revoke_proof(env: Env, proof_id_hash: BytesN<32>) -> Result<(), ProofError> {
        Self::set_revoked(env, proof_id_hash, false)
    }

    pub fn admin_revoke_proof(env: Env, proof_id_hash: BytesN<32>) -> Result<(), ProofError> {
        Self::set_revoked(env, proof_id_hash, true)
    }

    /// Revokes a strictly bounded batch of proofs, atomically, authorizing
    /// each entry against its own recorded issuer address — mirroring
    /// `revoke_proof`'s per-item authorization so a batch may mix proofs
    /// owned by different issuers as long as every one of those issuers
    /// signs the invocation.
    ///
    /// See [`Self::admin_revoke_proofs_batch`] for the admin-authorized
    /// variant, and [`Self::revoke_batch`] for the shared atomicity and
    /// per-entry outcome rules both share.
    pub fn revoke_proofs_batch(
        env: Env,
        proof_id_hashes: Vec<BytesN<32>>,
    ) -> Result<(), ProofError> {
        Self::revoke_batch(env, proof_id_hashes, false)
    }

    /// Admin-authorized counterpart of [`Self::revoke_proofs_batch`]: a
    /// single admin authorization covers every entry in the batch,
    /// regardless of which issuer originally registered each proof.
    pub fn admin_revoke_proofs_batch(
        env: Env,
        proof_id_hashes: Vec<BytesN<32>>,
    ) -> Result<(), ProofError> {
        Self::revoke_batch(env, proof_id_hashes, true)
    }

    pub fn get_proof(env: Env, proof_id_hash: BytesN<32>) -> Result<ProofRecord, ProofError> {
        let key = DataKey::Proof(proof_id_hash);
        let record = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ProofError::ProofNotFound)?;
        Self::extend_proof_key_ttl(env, &key);
        Ok(record)
    }

    pub fn is_valid_proof(env: Env, proof_id_hash: BytesN<32>) -> bool {
        match Self::get_proof(env.clone(), proof_id_hash) {
            Ok(record) => {
                record.status == ProofStatus::Active
                    && env.ledger().timestamp() <= record.expires_at
            }
            Err(_) => false,
        }
    }

    pub fn is_revoked(env: Env, proof_id_hash: BytesN<32>) -> bool {
        match Self::get_proof(env, proof_id_hash) {
            Ok(record) => record.status == ProofStatus::Revoked,
            Err(_) => false,
        }
    }

    pub fn nominate_admin(env: Env, new_admin: Address) -> Result<(), ContractError> {
        Self::ensure_not_decommissioned(&env).map_err(|_| ContractError::InvalidState)?;
        let admin = Self::get_admin(env.clone())?;
        Self::require_valid_principal(&new_admin)?;
        Self::require_auth(&admin);

        env.storage()
            .instance()
            .set(&DataKey::PendingAdmin, &new_admin);
        AdminTransferNominated {
            pending_admin: new_admin.clone(),
            nominated_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn accept_admin(env: Env) -> Result<(), ContractError> {
        Self::ensure_not_decommissioned(&env).map_err(|_| ContractError::InvalidState)?;
        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(ContractError::NotFound)?;
        Self::require_auth(&pending_admin);

        env.storage()
            .instance()
            .set(&DataKey::Admin, &pending_admin);
        env.storage().instance().remove(&DataKey::PendingAdmin);

        AdminTransferAccepted {
            new_admin: pending_admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn cancel_admin_transfer(env: Env) -> Result<(), ContractError> {
        Self::ensure_not_decommissioned(&env).map_err(|_| ContractError::InvalidState)?;
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);

        let pending_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::PendingAdmin)
            .ok_or(ContractError::NotFound)?;
        env.storage().instance().remove(&DataKey::PendingAdmin);

        AdminTransferCancelled {
            pending_admin,
            cancelled_by: admin,
        }
        .publish(&env);
        Ok(())
    }

    pub fn get_admin(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn get_issuer_registry(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::IssuerRegistry)
            .ok_or(ContractError::NotInitialized)
    }

    pub fn get_protocol_config(env: Env) -> Result<Address, ContractError> {
        env.storage()
            .instance()
            .get(&DataKey::ProtocolConfig)
            .ok_or(ContractError::NotInitialized)
    }

    // ── upgrade governance ────────────────────────────────────────────────────

    /// Returns the stored monotonic contract version.  Starts at 1.
    pub fn get_contract_version(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ContractVersion)
            .unwrap_or(0)
    }

    /// Admin-only: add `wasm_hash` to the upgrade allowlist.
    ///
    /// `new_version` must be strictly greater than the current contract
    /// version to prevent pre-approving a downgrade.
    pub fn approve_upgrade(env: Env, wasm_hash: BytesN<32>, new_version: u32) {
        if Self::is_decommissioned(env.clone()) {
            panic!("contract is decommissioned");
        }
        if let Ok(protocol_config) = Self::get_protocol_config(env.clone()) {
            let protocol_client = ProtocolConfigContractClient::new(&env, &protocol_config);
            if protocol_client.is_scope_paused(&PauseScope::Upgrades) {
                panic!("upgrades are paused");
            }
        }
        let admin = Self::get_admin(env.clone()).expect("contract not initialized");
        Self::require_auth(&admin);

        let current = Self::get_contract_version(env.clone());
        if new_version <= current {
            panic!("new_version must be greater than current contract version");
        }

        env.storage()
            .instance()
            .set(&DataKey::AllowedWasm(wasm_hash.clone()), &new_version);
        Self::extend_instance_ttl(env.clone());

        UpgradeAllowlisted {
            wasm_hash,
            new_contract_version: new_version,
            approved_by: admin,
        }
        .publish(&env);
    }

    /// Admin-only: remove a hash from the allowlist without applying it.
    pub fn revoke_upgrade(env: Env, wasm_hash: BytesN<32>) {
        if Self::is_decommissioned(env.clone()) {
            panic!("contract is decommissioned");
        }
        let admin = Self::get_admin(env.clone()).expect("contract not initialized");
        Self::require_auth(&admin);

        env.storage()
            .instance()
            .remove(&DataKey::AllowedWasm(wasm_hash.clone()));

        UpgradeRevoked {
            wasm_hash,
            revoked_by: admin,
        }
        .publish(&env);
    }

    /// Returns true when `wasm_hash` is on the allowlist.
    pub fn is_upgrade_allowed(env: Env, wasm_hash: BytesN<32>) -> bool {
        env.storage()
            .instance()
            .has(&DataKey::AllowedWasm(wasm_hash))
    }

    /// Admin-only: apply an in-place WASM upgrade.
    ///
    /// Requirements:
    /// 1. Caller is the admin.
    /// 2. `wasm_hash` is on the allowlist.
    /// 3. Target version is strictly greater than current (downgrade guard).
    ///
    /// On success the allowlist entry is consumed and `ContractVersion` is
    /// advanced.
    pub fn upgrade_contract(env: Env, wasm_hash: BytesN<32>) {
        if Self::is_decommissioned(env.clone()) {
            panic!("contract is decommissioned");
        }
        if let Ok(protocol_config) = Self::get_protocol_config(env.clone()) {
            let protocol_client = ProtocolConfigContractClient::new(&env, &protocol_config);
            if protocol_client.is_scope_paused(&PauseScope::Upgrades) {
                panic!("upgrades are paused");
            }
        }
        let admin = Self::get_admin(env.clone()).expect("contract not initialized");
        Self::require_auth(&admin);

        let new_version: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AllowedWasm(wasm_hash.clone()))
            .expect("wasm hash not on allowlist");

        let old_version = Self::get_contract_version(env.clone());
        if new_version <= old_version {
            panic!("upgrade would not advance contract version");
        }

        // Consume allowlist entry before applying to prevent replay.
        env.storage()
            .instance()
            .remove(&DataKey::AllowedWasm(wasm_hash.clone()));

        #[cfg(not(test))]
        env.deployer()
            .update_current_contract_wasm(wasm_hash.clone());

        env.storage()
            .instance()
            .set(&DataKey::ContractVersion, &new_version);
        Self::extend_instance_ttl(env.clone());

        ContractUpgraded {
            new_wasm_hash: wasm_hash,
            old_contract_version: old_version,
            new_contract_version: new_version,
            upgraded_by: admin,
        }
        .publish(&env);
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn validate_dependency_addresses(
        env: &Env,
        issuer_registry: &Address,
        protocol_config: &Address,
    ) -> Result<(), ContractError> {
        if !earnproof_shared::is_valid_principal_address(issuer_registry)
            || !earnproof_shared::is_valid_principal_address(protocol_config)
        {
            return Err(ContractError::InvalidInput);
        }
        let current = env.current_contract_address();
        if issuer_registry == &current
            || protocol_config == &current
            || issuer_registry == protocol_config
        {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }

    fn require_valid_principal(address: &Address) -> Result<(), ContractError> {
        if !earnproof_shared::is_valid_principal_address(address) {
            return Err(ContractError::InvalidInput);
        }
        Ok(())
    }

    fn require_valid_issuer_address(address: &Address) -> Result<(), ProofError> {
        if !earnproof_shared::is_valid_principal_address(address) {
            return Err(ProofError::InvalidAddress);
        }
        Ok(())
    }

    fn set_revoked(env: Env, proof_id_hash: BytesN<32>, by_admin: bool) -> Result<(), ProofError> {
        Self::ensure_not_decommissioned(&env)?;
        if let Ok(protocol_config) = Self::get_protocol_config(env.clone()) {
            let protocol_client = ProtocolConfigContractClient::new(&env, &protocol_config);
            if protocol_client.is_scope_paused(&PauseScope::Revocation) {
                return Err(ProofError::ProofNotFound);
            }
        }
        let key = DataKey::Proof(proof_id_hash.clone());
        let mut record: ProofRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(ProofError::ProofNotFound)?;

        if by_admin {
            let admin = Self::get_admin(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
            Self::require_auth(&admin);
        } else {
            Self::require_auth(&record.issuer_address);
        }

        if record.status == ProofStatus::Revoked {
            return Err(ProofError::ProofAlreadyRevoked);
        }

        record.status = ProofStatus::Revoked;
        record.revoked_at = env.ledger().timestamp();
        env.storage().persistent().set(&key, &record);
        Self::extend_proof_key_ttl(env, &key);
        Ok(())
    }

    /// Shared implementation behind [`Self::revoke_proofs_batch`] and
    /// [`Self::admin_revoke_proofs_batch`].
    ///
    /// Entries are processed in order, and the whole call is atomic: if any
    /// entry fails (unknown proof id, an unauthorized issuer, or an entry
    /// already revoked — whether it was already revoked on chain or revoked
    /// earlier in this same batch), the call returns that entry's error and
    /// every write and event already produced earlier in this same call is
    /// discarded along with it, per Soroban's invocation semantics. A
    /// repeated identifier within one batch is therefore a documented
    /// failure of the whole batch, not a silently-skipped duplicate — the
    /// same outcome as revoking an already-revoked proof.
    ///
    /// The pause check and (for the admin path) admin authorization are each
    /// performed once for the whole batch, reusing `set_revoked`'s checks.
    /// For the issuer path, authorization is instead performed per entry
    /// against that entry's own recorded `issuer_address`, so an entry the
    /// caller is not authorized for can never be hidden behind valid entries
    /// earlier in the batch: `require_auth` aborts the entire invocation the
    /// moment it fails.
    fn revoke_batch(
        env: Env,
        proof_id_hashes: Vec<BytesN<32>>,
        by_admin: bool,
    ) -> Result<(), ProofError> {
        Self::ensure_not_decommissioned(&env)?;

        let len = proof_id_hashes.len();
        if len == 0 || len > MAX_PROOF_BATCH_SIZE {
            return Err(ProofError::InvalidBatchSize);
        }

        if let Ok(protocol_config) = Self::get_protocol_config(env.clone()) {
            let protocol_client = ProtocolConfigContractClient::new(&env, &protocol_config);
            if protocol_client.is_scope_paused(&PauseScope::Revocation) {
                return Err(ProofError::ProofNotFound);
            }
        }

        // Admin authorization is shared across the whole batch; the issuer
        // path instead authorizes per entry below, against each entry's own
        // recorded issuer.
        let admin = if by_admin {
            let admin = Self::get_admin(env.clone()).map_err(|_| ProofError::ProofNotFound)?;
            Self::require_auth(&admin);
            Some(admin)
        } else {
            None
        };

        let now = env.ledger().timestamp();

        for proof_id_hash in proof_id_hashes.iter() {
            let key = DataKey::Proof(proof_id_hash.clone());
            let mut record: ProofRecord = env
                .storage()
                .persistent()
                .get(&key)
                .ok_or(ProofError::ProofNotFound)?;

            let revoked_by = match &admin {
                Some(admin) => admin.clone(),
                None => {
                    Self::require_auth(&record.issuer_address);
                    record.issuer_address.clone()
                }
            };

            if record.status == ProofStatus::Revoked {
                return Err(ProofError::ProofAlreadyRevoked);
            }

            record.status = ProofStatus::Revoked;
            record.revoked_at = now;
            env.storage().persistent().set(&key, &record);
            Self::extend_proof_key_ttl(env.clone(), &key);

            ProofRevokedInBatch {
                proof_id_hash: proof_id_hash.clone(),
                revoked_by,
            }
            .publish(&env);
        }

        Ok(())
    }

    fn extend_instance_ttl(env: Env) {
        env.storage()
            .instance()
            .extend_ttl(TTL_THRESHOLD_LEDGERS, TTL_EXTEND_TO_LEDGERS);
    }

    fn extend_proof_key_ttl(env: Env, key: &DataKey) {
        env.storage()
            .persistent()
            .extend_ttl(key, TTL_THRESHOLD_LEDGERS, TTL_EXTEND_TO_LEDGERS);
    }

    pub fn get_migration_status(env: Env) -> Option<MigrationStatus> {
        env.storage().instance().get(&DataKey::MigrationStatus)
    }

    pub fn begin_migration(
        env: Env,
        target_contract_version: u32,
        total_items: u32,
    ) -> Result<MigrationStatus, ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        if target_contract_version <= Self::get_contract_version(env.clone()) || total_items == 0 {
            return Err(ContractError::InvalidInput);
        }
        if let Some(status) = Self::get_migration_status(env.clone()) {
            return if status.target_contract_version == target_contract_version
                && status.total_items == total_items
            {
                Ok(status)
            } else {
                Err(ContractError::InvalidState)
            };
        }
        let status = MigrationStatus {
            status_version: MIGRATION_STATUS_VERSION,
            target_contract_version,
            cursor: 0,
            total_items,
            complete: false,
        };
        env.storage()
            .instance()
            .set(&DataKey::MigrationStatus, &status);
        Self::extend_instance_ttl(env);
        Ok(status)
    }

    pub fn advance_migration(
        env: Env,
        expected_cursor: u32,
        processed_items: u32,
    ) -> Result<MigrationStatus, ContractError> {
        let admin = Self::get_admin(env.clone())?;
        Self::require_auth(&admin);
        if processed_items == 0 || processed_items > MAX_MIGRATION_BATCH {
            return Err(ContractError::InvalidInput);
        }
        let mut status =
            Self::get_migration_status(env.clone()).ok_or(ContractError::InvalidState)?;
        if expected_cursor < status.cursor {
            return if expected_cursor.saturating_add(processed_items) <= status.cursor {
                Ok(status)
            } else {
                Err(ContractError::InvalidState)
            };
        }
        if expected_cursor != status.cursor || status.complete {
            return Err(ContractError::InvalidState);
        }
        let next = status
            .cursor
            .checked_add(processed_items)
            .ok_or(ContractError::InvalidInput)?;
        if next > status.total_items {
            return Err(ContractError::InvalidInput);
        }
        status.cursor = next;
        status.complete = next == status.total_items;
        env.storage()
            .instance()
            .set(&DataKey::MigrationStatus, &status);
        Self::extend_instance_ttl(env);
        Ok(status)
    }

    fn require_auth(address: &Address) {
        address.require_auth();
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::{DataKey, ProofRegistryContract, ProofRegistryContractClient};
    use earnproof_shared::{
        PauseScope, ProofError, ProofStatus, MAX_PROOF_BATCH_SIZE, TTL_THRESHOLD_LEDGERS,
    };
    use issuer_registry::{IssuerRegistryContract, IssuerRegistryContractClient};
    use protocol_config::{ProtocolConfigContract, ProtocolConfigContractClient};
    use soroban_sdk::{testutils::storage::Persistent as _, Address, BytesN, Env};

    const ADMIN: &str = "GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR";
    const ISSUER: &str = "GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U";

    fn bytes(env: &Env, value: u8) -> BytesN<32> {
        BytesN::from_array(env, &[value; 32])
    }

    fn setup() -> (
        Env,
        ProofRegistryContractClient<'static>,
        ProtocolConfigContractClient<'static>,
        IssuerRegistryContractClient<'static>,
        Address,
    ) {
        let env = Env::default();
        env.mock_all_auths();
        let protocol_config_id = env.register(ProtocolConfigContract, ());
        let protocol_config_client = ProtocolConfigContractClient::new(&env, &protocol_config_id);
        let issuer_registry_id = env.register(IssuerRegistryContract, ());
        let issuer_registry_client = IssuerRegistryContractClient::new(&env, &issuer_registry_id);
        let contract_id = env.register(ProofRegistryContract, ());
        let client = ProofRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);
        let issuer_id = bytes(&env, 9);

        protocol_config_client.initialize(&admin);
        protocol_config_client.approve_schema_version(&1);
        issuer_registry_client.initialize(&admin);
        issuer_registry_client.register_issuer(
            &issuer_id,
            &issuer,
            &bytes(&env, 8),
            &bytes(&env, 99),
        );
        client.initialize(&admin, &issuer_registry_id, &protocol_config_id);

        (
            env,
            client,
            protocol_config_client,
            issuer_registry_client,
            issuer_registry_id,
        )
    }

    // ── existing tests ────────────────────────────────────────────────────────

    #[test]
    fn registers_and_validates_proof() {
        let (env, client, _protocol_config, _issuer_registry, issuer_registry_id) = setup();
        let proof_id = bytes(&env, 1);
        let commitment = bytes(&env, 2);
        let issuer = Address::from_str(&env, ISSUER);

        client.register_proof(&proof_id, &commitment, &issuer, &1, &2_000);

        let record = client.get_proof(&proof_id);
        assert_eq!(record.proof_id_hash, proof_id);
        assert_eq!(record.commitment_hash, commitment);
        assert_eq!(record.issuer_address, issuer);
        assert_eq!(record.status, ProofStatus::Active);
        assert_eq!(client.get_issuer_registry(), issuer_registry_id);
        assert!(client.is_valid_proof(&proof_id));
        assert!(!client.is_revoked(&proof_id));
    }

    #[test]
    fn issuer_can_revoke_proof() {
        let (env, client, _protocol_config, _issuer_registry, _issuer_registry_id) = setup();
        let proof_id = bytes(&env, 1);
        let issuer = Address::from_str(&env, ISSUER);

        client.register_proof(&proof_id, &bytes(&env, 2), &issuer, &1, &2_000);
        client.revoke_proof(&proof_id);

        let record = client.get_proof(&proof_id);
        assert_eq!(record.status, ProofStatus::Revoked);
        assert!(client.is_revoked(&proof_id));
        assert!(!client.is_valid_proof(&proof_id));
    }

    #[test]
    fn rejects_expired_proof() {
        let (env, client, _protocol_config, _issuer_registry, _issuer_registry_id) = setup();
        use earnproof_shared::ProofError;

        let result = client.try_register_proof(
            &bytes(&env, 1),
            &bytes(&env, 2),
            &Address::from_str(&env, ISSUER),
            &1,
            &0,
        );
        assert_eq!(result, Err(Ok(ProofError::ProofExpired)));
    }

    #[test]
    fn rejects_duplicate_proof_id() {
        let (env, client, _protocol_config, _issuer_registry, _issuer_registry_id) = setup();
        use earnproof_shared::ProofError;
        let proof_id = bytes(&env, 1);
        let issuer = Address::from_str(&env, ISSUER);

        client.register_proof(&proof_id, &bytes(&env, 2), &issuer, &1, &2_000);

        let result = client.try_register_proof(&proof_id, &bytes(&env, 3), &issuer, &1, &2_000);
        assert_eq!(result, Err(Ok(ProofError::ProofAlreadyRegistered)));
    }

    #[test]
    fn rejects_unapproved_schema_version() {
        let (env, client, _protocol_config, _issuer_registry, _issuer_registry_id) = setup();
        use earnproof_shared::ProofError;

        let result = client.try_register_proof(
            &bytes(&env, 1),
            &bytes(&env, 2),
            &Address::from_str(&env, ISSUER),
            &2,
            &2_000,
        );
        assert_eq!(result, Err(Ok(ProofError::UnsupportedSchema)));
    }

    #[test]
    fn rejects_registration_when_protocol_is_paused() {
        let (env, client, protocol_config, _issuer_registry, _issuer_registry_id) = setup();
        use earnproof_shared::ProofError;
        protocol_config.pause();

        let result = client.try_register_proof(
            &bytes(&env, 1),
            &bytes(&env, 2),
            &Address::from_str(&env, ISSUER),
            &1,
            &2_000,
        );
        assert_eq!(result, Err(Ok(ProofError::ContractPaused)));
    }

    #[test]
    fn rejects_inactive_issuer_address() {
        let (env, client, _protocol_config, issuer_registry, _issuer_registry_id) = setup();
        use earnproof_shared::ProofError;
        let inactive_issuer = Address::from_str(
            &env,
            "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
        );
        issuer_registry.register_issuer(
            &bytes(&env, 10),
            &inactive_issuer,
            &bytes(&env, 11),
            &bytes(&env, 99),
        );
        issuer_registry.suspend_issuer(
            &bytes(&env, 10),
            &soroban_sdk::BytesN::from_array(&env, &[1u8; 32]),
        );

        let result = client.try_register_proof(
            &bytes(&env, 1),
            &bytes(&env, 2),
            &inactive_issuer,
            &1,
            &2_000,
        );
        assert_eq!(result, Err(Ok(ProofError::IssuerInactive)));
    }

    #[test]
    fn extends_proof_storage_ttl() {
        let (env, client, _protocol_config, _issuer_registry, _issuer_registry_id) = setup();
        let proof_id = bytes(&env, 1);
        let issuer = Address::from_str(&env, ISSUER);

        client.register_proof(&proof_id, &bytes(&env, 2), &issuer, &1, &2_000);

        env.as_contract(&client.address, || {
            assert!(
                env.storage()
                    .persistent()
                    .get_ttl(&DataKey::Proof(proof_id.clone()))
                    > TTL_THRESHOLD_LEDGERS
            );
        });
    }

    // ── upgrade governance tests ──────────────────────────────────────────────

    #[test]
    fn contract_version_initialized_to_one() {
        let (_env, client, ..) = setup();
        assert_eq!(client.get_contract_version(), 1);
    }

    #[test]
    fn approve_and_check_allowlist() {
        let (env, client, ..) = setup();
        let hash = bytes(&env, 0xab);

        assert!(!client.is_upgrade_allowed(&hash));
        client.approve_upgrade(&hash, &2);
        assert!(client.is_upgrade_allowed(&hash));
    }

    #[test]
    fn revoke_removes_from_allowlist() {
        let (env, client, ..) = setup();
        let hash = bytes(&env, 0xcd);

        client.approve_upgrade(&hash, &2);
        client.revoke_upgrade(&hash);
        assert!(!client.is_upgrade_allowed(&hash));
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn approve_upgrade_rejects_downgrade_version() {
        let (env, client, ..) = setup();
        client.approve_upgrade(&bytes(&env, 1), &1);
    }

    #[test]
    #[should_panic(expected = "wasm hash not on allowlist")]
    fn upgrade_contract_rejects_non_allowlisted_hash() {
        let (env, client, ..) = setup();
        client.upgrade_contract(&bytes(&env, 0xff));
    }

    #[test]
    #[should_panic]
    fn upgrade_contract_requires_admin_auth() {
        let env = Env::default();
        let protocol_config_id = env.register(ProtocolConfigContract, ());
        let issuer_registry_id = env.register(IssuerRegistryContract, ());
        let contract_id = env.register(ProofRegistryContract, ());
        let client = ProofRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);
        let issuer_id = bytes(&env, 9);

        env.mock_all_auths();
        let pc_client = ProtocolConfigContractClient::new(&env, &protocol_config_id);
        let ir_client = IssuerRegistryContractClient::new(&env, &issuer_registry_id);
        pc_client.initialize(&admin);
        pc_client.approve_schema_version(&1);
        ir_client.initialize(&admin);
        ir_client.register_issuer(&issuer_id, &issuer, &bytes(&env, 8), &bytes(&env, 99));
        client.initialize(&admin, &issuer_registry_id, &protocol_config_id);

        let hash = BytesN::from_array(&env, &[0xde; 32]);
        client.approve_upgrade(&hash, &2);
        env.set_auths(&[]);

        client.upgrade_contract(&hash);
    }

    #[test]
    fn upgrade_advances_version_and_consumes_allowlist() {
        let (env, client, ..) = setup();
        let hash = bytes(&env, 0x42);

        client.approve_upgrade(&hash, &2);
        client.upgrade_contract(&hash);

        assert_eq!(client.get_contract_version(), 2);
        assert!(!client.is_upgrade_allowed(&hash));
    }

    #[test]
    #[should_panic(expected = "wasm hash not on allowlist")]
    fn upgrade_hash_cannot_be_replayed() {
        let (env, client, ..) = setup();
        let hash = bytes(&env, 0x42);

        client.approve_upgrade(&hash, &2);
        client.upgrade_contract(&hash);
        client.upgrade_contract(&hash);
    }

    /// Persistent proof state must survive an upgrade.
    #[test]
    fn state_preserved_across_upgrade() {
        let (env, client, ..) = setup();
        let proof_id = bytes(&env, 1);
        let issuer = Address::from_str(&env, ISSUER);

        client.register_proof(&proof_id, &bytes(&env, 2), &issuer, &1, &2_000);
        assert!(client.is_valid_proof(&proof_id));

        let hash = bytes(&env, 0x77);
        client.approve_upgrade(&hash, &2);
        client.upgrade_contract(&hash);

        assert!(client.is_valid_proof(&proof_id));
        assert_eq!(client.get_contract_version(), 2);
    }

    #[test]
    #[should_panic(expected = "new_version must be greater than current contract version")]
    fn cannot_re_approve_old_version_after_upgrade() {
        let (env, client, ..) = setup();
        let hash_v2 = bytes(&env, 0x01);
        let old_hash = bytes(&env, 0x02);

        client.approve_upgrade(&hash_v2, &2);
        client.upgrade_contract(&hash_v2);

        client.approve_upgrade(&old_hash, &1);
    }

    // ── numeric boundary tests ────────────────────────────────────────────────

    /// Table-driven tests for schema version boundaries in proof registration.
    /// Schema versions must be >= MIN_SCHEMA_VERSION (1).
    #[test]
    fn register_proof_schema_version_boundaries() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);

        // Valid: minimum allowed schema version
        client.register_proof(&bytes(&env, 1), &bytes(&env, 2), &issuer, &1, &2_000);
        assert!(client.is_valid_proof(&bytes(&env, 1)));

        // Valid: typical schema version
        _pc.approve_schema_version(&99);
        client.register_proof(&bytes(&env, 10), &bytes(&env, 11), &issuer, &99, &2_000);
        assert!(client.is_valid_proof(&bytes(&env, 10)));

        // Valid: large schema version
        _pc.approve_schema_version(&u32::MAX);
        client.register_proof(
            &bytes(&env, 20),
            &bytes(&env, 21),
            &issuer,
            &u32::MAX,
            &2_000,
        );
        assert!(client.is_valid_proof(&bytes(&env, 20)));
    }

    #[test]
    fn register_proof_schema_version_zero_rejected() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);

        // Schema version 0 must be rejected with a typed error.
        let result =
            client.try_register_proof(&bytes(&env, 1), &bytes(&env, 2), &issuer, &0, &2_000);
        assert_eq!(result, Err(Ok(ProofError::InvalidSchemaVersion)));
    }

    /// Table-driven tests for proof expiration boundaries.
    /// Expiration timestamp must be strictly greater than current ledger timestamp.
    #[test]
    fn register_proof_expiration_boundaries() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let current_time = env.ledger().timestamp();

        // Valid: one second in the future (minimum practical offset)
        client.register_proof(
            &bytes(&env, 1),
            &bytes(&env, 2),
            &issuer,
            &1,
            &(current_time + 1),
        );
        assert!(client.is_valid_proof(&bytes(&env, 1)));

        // Valid: reasonable future expiration (1 year in seconds)
        client.register_proof(
            &bytes(&env, 10),
            &bytes(&env, 11),
            &issuer,
            &1,
            &(current_time + 365 * 24 * 3600),
        );
        assert!(client.is_valid_proof(&bytes(&env, 10)));

        // Valid: far future (max u64 is reachable in practice)
        client.register_proof(&bytes(&env, 20), &bytes(&env, 21), &issuer, &1, &u64::MAX);
        assert!(client.is_valid_proof(&bytes(&env, 20)));
    }

    #[test]
    fn register_proof_expiration_at_current_time_rejected() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let current_time = env.ledger().timestamp();

        // Expiration equal to current time is rejected with a typed error.
        let result =
            client.try_register_proof(&bytes(&env, 1), &bytes(&env, 2), &issuer, &1, &current_time);
        assert_eq!(result, Err(Ok(ProofError::ProofExpired)));
    }

    #[test]
    fn register_proof_expiration_in_past_rejected() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let current_time = env.ledger().timestamp();

        // Expiration in the past is rejected with a typed error.
        if current_time > 0 {
            let result = client.try_register_proof(
                &bytes(&env, 1),
                &bytes(&env, 2),
                &issuer,
                &1,
                &(current_time - 1),
            );
            assert_eq!(result, Err(Ok(ProofError::ProofExpired)));
        }
    }

    /// Test storage and event invariants: failed boundary cases
    /// must not modify state or emit events.
    #[test]
    fn failed_register_proof_schema_zero_leaves_state_unchanged() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);

        // Check that no proofs exist initially
        let proof_id = bytes(&env, 99);
        env.as_contract(&client.address, || {
            assert!(
                !env.storage()
                    .persistent()
                    .has(&DataKey::Proof(proof_id.clone())),
                "initial state must not contain the proof"
            );
        });

        // Attempt to register with schema version 0 — should panic
        let register_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.register_proof(&proof_id, &bytes(&env, 88), &issuer, &0, &2_000);
        }));

        // Must have panicked
        assert!(register_result.is_err());

        // State must be unchanged: proof must not exist in storage
        env.as_contract(&client.address, || {
            assert!(
                !env.storage()
                    .persistent()
                    .has(&DataKey::Proof(proof_id.clone())),
                "failed proof registration must not write to storage"
            );
        });
    }

    #[test]
    fn failed_register_proof_expired_leaves_state_unchanged() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let current_time = env.ledger().timestamp();
        let proof_id = bytes(&env, 77);

        // Attempt to register with expired timestamp — should panic
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.register_proof(
                &proof_id,
                &bytes(&env, 66),
                &issuer,
                &1,
                &current_time, // Equal to current time, must be rejected
            );
        }));

        // Must have panicked
        assert!(result.is_err());

        // State must be unchanged: proof must not exist in storage
        env.as_contract(&client.address, || {
            assert!(
                !env.storage().persistent().has(&DataKey::Proof(proof_id)),
                "failed proof registration with expired timestamp must not write to storage"
            );
        });
    }

    /// Verify contract version boundaries in upgrade operations.
    #[test]
    fn contract_version_upgrade_boundaries() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        assert_eq!(client.get_contract_version(), 1);

        // Valid: immediate next version
        client.approve_upgrade(&bytes(&env, 1), &2);
        client.upgrade_contract(&bytes(&env, 1));
        assert_eq!(client.get_contract_version(), 2);

        // Valid: large version number
        client.approve_upgrade(&bytes(&env, 2), &u32::MAX);
        client.upgrade_contract(&bytes(&env, 2));
        assert_eq!(client.get_contract_version(), u32::MAX);
    }

    // ── adversarial initialization tests ───────────────────────────────────────

    /// Verify that first initialization writes exactly the documented state
    /// with no partial writes or missing fields.
    ///
    /// Required behavior: First call to `initialize` results in:
    /// - Admin address set and readable
    /// - IssuerRegistry address set and readable
    /// - ProtocolConfig address set and readable
    /// - ContractVersion = 1
    #[test]
    fn initialization_writes_exactly_documented_state() {
        let env = Env::default();
        env.mock_all_auths();
        let protocol_config_id = env.register(ProtocolConfigContract, ());
        let issuer_registry_id = env.register(IssuerRegistryContract, ());
        let contract_id = env.register(ProofRegistryContract, ());
        let client = ProofRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        let pc_client = ProtocolConfigContractClient::new(&env, &protocol_config_id);
        let ir_client = IssuerRegistryContractClient::new(&env, &issuer_registry_id);
        pc_client.initialize(&admin);
        ir_client.initialize(&admin);

        // Perform initialization
        client.initialize(&admin, &issuer_registry_id, &protocol_config_id);

        // Verify exact state written
        assert_eq!(client.get_admin(), admin, "admin must be set");
        assert_eq!(
            client.get_issuer_registry(),
            issuer_registry_id,
            "issuer registry address must be set"
        );
        assert_eq!(
            client.get_protocol_config(),
            protocol_config_id,
            "protocol config address must be set"
        );
        assert_eq!(
            client.get_contract_version(),
            1,
            "contract version must be exactly 1 after initialization"
        );

        // Verify storage keys are set
        env.as_contract(&contract_id, || {
            let instance = env.storage().instance();
            assert!(
                instance.has(&DataKey::Admin),
                "Admin key must exist in instance storage"
            );
            assert!(
                instance.has(&DataKey::IssuerRegistry),
                "IssuerRegistry key must exist in instance storage"
            );
            assert!(
                instance.has(&DataKey::ProtocolConfig),
                "ProtocolConfig key must exist in instance storage"
            );
            assert!(
                instance.has(&DataKey::ContractVersion),
                "ContractVersion key must exist in instance storage"
            );
        });
    }

    /// Verify that repeated initialization by any address fails without
    /// altering state or emitting events.
    ///
    /// Required behavior for re-initialization guard:
    /// - Second call to `initialize` with any admin (same or different) panics
    /// - Storage is byte-for-byte unchanged
    /// - No additional events are emitted
    #[test]
    fn reinitialization_by_same_admin_fails_atomically() {
        let (env, client, _pc, _ir, ir_id) = setup();
        let admin = Address::from_str(&env, ADMIN);
        let protocol_config_id = env.register(ProtocolConfigContract, ());

        let contract_version_after_first = client.get_contract_version();
        let issuer_registry_after_first = client.get_issuer_registry();

        // Attempt second initialization with same admin
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin, &ir_id, &protocol_config_id);
        }));

        // Must have panicked with "already initialized"
        assert!(result.is_err(), "re-initialization must panic");

        // Verify state is byte-for-byte identical
        assert_eq!(
            client.get_admin(),
            admin,
            "admin must not change after failed re-initialization"
        );
        assert_eq!(
            client.get_issuer_registry(),
            issuer_registry_after_first,
            "issuer registry must not change after failed re-initialization"
        );
        assert_eq!(
            client.get_contract_version(),
            contract_version_after_first,
            "contract version must not change after failed re-initialization"
        );
    }

    /// Verify that re-initialization with different dependency addresses
    /// also fails without state changes.
    ///
    /// This tests that the re-initialization guard prevents address swapping.
    #[test]
    fn reinitialization_with_different_dependencies_fails_atomically() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let admin = Address::from_str(&env, ADMIN);

        let issuer_registry_after_first = client.get_issuer_registry();
        let protocol_config_after_first = client.get_protocol_config();

        // Attempt re-initialization with different dependency addresses
        let new_ir = env.register(IssuerRegistryContract, ());
        let new_pc = env.register(ProtocolConfigContract, ());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin, &new_ir, &new_pc);
        }));

        // Must have panicked
        assert!(
            result.is_err(),
            "re-initialization with different deps must panic"
        );

        // Original dependency addresses must be preserved
        assert_eq!(
            client.get_issuer_registry(),
            issuer_registry_after_first,
            "issuer registry must not change when re-initialization attempts different address"
        );
        assert_eq!(
            client.get_protocol_config(),
            protocol_config_after_first,
            "protocol config must not change when re-initialization attempts different address"
        );
    }

    /// Verify that re-initialization by a different admin also fails.
    ///
    /// Tests that the guard does not discriminate based on caller identity.
    #[test]
    fn reinitialization_by_different_admin_fails() {
        let env = Env::default();
        env.mock_all_auths();
        let protocol_config_id = env.register(ProtocolConfigContract, ());
        let issuer_registry_id = env.register(IssuerRegistryContract, ());
        let contract_id = env.register(ProofRegistryContract, ());
        let client = ProofRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);
        let other_admin = Address::from_str(&env, ISSUER);

        let pc_client = ProtocolConfigContractClient::new(&env, &protocol_config_id);
        let ir_client = IssuerRegistryContractClient::new(&env, &issuer_registry_id);
        pc_client.initialize(&admin);
        ir_client.initialize(&admin);

        // First initialization with original admin
        client.initialize(&admin, &issuer_registry_id, &protocol_config_id);
        let stored_admin = client.get_admin();

        // Attempt re-initialization with different admin
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&other_admin, &issuer_registry_id, &protocol_config_id);
        }));

        // Must have panicked
        assert!(
            result.is_err(),
            "re-initialization by different admin must panic"
        );

        // Original admin must be preserved
        assert_eq!(
            client.get_admin(),
            stored_admin,
            "admin must not change when different address attempts re-initialization"
        );
    }

    /// Verify that invalid dependency addresses are rejected during initialization
    /// and do not write any state.
    ///
    /// Tests initialization with zero/null addresses where contract addresses
    /// are expected. The contract does not validate this at initialization time
    /// (it validates at runtime when dependencies are called), but we should
    /// verify that any panic during initialization leaves state atomic.
    #[test]
    fn reinitialization_guard_is_absolute() {
        let (env, client, _pc, _ir, ir_id) = setup();
        let admin = Address::from_str(&env, ADMIN);
        let pc_id = env.register(ProtocolConfigContract, ());

        // Multiple re-initialization attempts must all fail
        for attempt in 1..=3 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                client.initialize(&admin, &ir_id, &pc_id);
            }));

            assert!(
                result.is_err(),
                "re-initialization attempt {} must fail",
                attempt
            );

            // Admin must remain unchanged
            assert_eq!(
                client.get_admin(),
                admin,
                "admin must not change after re-initialization attempt {}",
                attempt
            );
        }
    }

    /// Verify that initialization state is maintained across proof registration
    /// and other operations.
    ///
    /// Tests that the initialization state (admin, dependencies, contract version)
    /// is stable after initialization and before any subsequent operations.
    #[test]
    fn initialization_state_stable_across_operations() {
        let (env, client, _pc, _ir, ir_id) = setup();

        let admin = Address::from_str(&env, ADMIN);
        let protocol_config_id = client.get_protocol_config();

        // State immediately after initialization (from setup())
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_issuer_registry(), ir_id);
        assert_eq!(client.get_protocol_config(), protocol_config_id);
        assert_eq!(client.get_contract_version(), 1);

        // Perform proof registration
        let proof_id = bytes(&env, 1);
        let issuer = Address::from_str(&env, ISSUER);
        client.register_proof(&proof_id, &bytes(&env, 2), &issuer, &1, &2_000);

        // Dependencies must remain unchanged
        assert_eq!(
            client.get_admin(),
            admin,
            "admin must not change after proof registration"
        );
        assert_eq!(
            client.get_issuer_registry(),
            ir_id,
            "issuer registry must not change after proof registration"
        );
        assert_eq!(
            client.get_protocol_config(),
            protocol_config_id,
            "protocol config must not change after proof registration"
        );
        // Contract version must still be 1 (no upgrade yet)
        assert_eq!(
            client.get_contract_version(),
            1,
            "contract version must not change on proof registration"
        );
    }

    /// Summary test: proof-registry initialization spec verification.
    ///
    /// This test serves as executable documentation of what the test matrix
    /// expects from proof-registry initialization:
    /// - Depends on two other contracts (issuer-registry, protocol-config)
    /// - Has re-initialization guard
    /// - Does NOT emit an event during initialization
    /// - Sets: admin, issuer_registry, protocol_config, contract_version=1
    #[test]
    fn proof_registry_initialization_spec_summary() {
        // CONTRACT SPEC: proof-registry
        // - Name: "proof-registry"
        // - Has re-initialization guard: YES (panics "already initialized")
        // - Emits initialization event: NO
        // - Takes dependency addresses: YES
        // - Dependencies: ["issuer-registry", "protocol-config"]
        // - First init writes:
        //   - Admin: passed address (requires auth)
        //   - IssuerRegistry: passed address (no validation at init time)
        //   - ProtocolConfig: passed address (no validation at init time)
        //   - ContractVersion: 1
        // - Re-init guard: DataKey::Admin presence check; panics if set
        // - Re-init allowed by different admin: NO (guard blocks all)
        // - Invalid config cases: Dependency validation happens at runtime (register_proof)
        //   not at initialization time

        let env = Env::default();
        env.mock_all_auths();
        let protocol_config_id = env.register(ProtocolConfigContract, ());
        let issuer_registry_id = env.register(IssuerRegistryContract, ());
        let contract_id = env.register(ProofRegistryContract, ());
        let client = ProofRegistryContractClient::new(&env, &contract_id);
        let admin = Address::from_str(&env, ADMIN);

        let pc_client = ProtocolConfigContractClient::new(&env, &protocol_config_id);
        let ir_client = IssuerRegistryContractClient::new(&env, &issuer_registry_id);
        pc_client.initialize(&admin);
        ir_client.initialize(&admin);

        // Verify the spec
        client.initialize(&admin, &issuer_registry_id, &protocol_config_id);
        assert_eq!(client.get_admin(), admin);
        assert_eq!(client.get_issuer_registry(), issuer_registry_id);
        assert_eq!(client.get_protocol_config(), protocol_config_id);
        assert_eq!(client.get_contract_version(), 1);

        // Re-initialization must fail
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.initialize(&admin, &issuer_registry_id, &protocol_config_id)
        }))
        .is_err());
    }

    // ── cross-contract initialization and ordering tests ──────────────────────

    /// Verify that the required deployment and initialization ordering is enforced.
    ///
    /// The correct order is:
    /// 1. Deploy protocol-config, initialize with admin
    /// 2. Deploy issuer-registry, initialize with admin
    /// 3. Approve schema version in protocol-config
    /// 4. Register at least one issuer in issuer-registry
    /// 5. Deploy proof-registry, initialize with admin + both dependency addresses
    ///
    /// This test deploys contracts in the correct order and verifies that
    /// the full system initializes successfully end-to-end.
    #[test]
    fn cross_contract_initialization_correct_order_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);
        let issuer_id = bytes(&env, 9);

        // Step 1: Deploy and initialize protocol-config
        let pc_id = env.register(ProtocolConfigContract, ());
        let pc_client = ProtocolConfigContractClient::new(&env, &pc_id);
        pc_client.initialize(&admin);
        assert_eq!(pc_client.get_admin(), admin);
        assert_eq!(pc_client.get_contract_version(), 1);

        // Step 2: Deploy and initialize issuer-registry
        let ir_id = env.register(IssuerRegistryContract, ());
        let ir_client = IssuerRegistryContractClient::new(&env, &ir_id);
        ir_client.initialize(&admin);
        assert_eq!(ir_client.get_admin(), admin);
        assert_eq!(ir_client.get_contract_version(), 1);

        // Step 3: Approve schema version in protocol-config
        pc_client.approve_schema_version(&1);
        assert!(pc_client.is_schema_version_approved(&1));

        // Step 4: Register an issuer in issuer-registry
        ir_client.register_issuer(&issuer_id, &issuer, &bytes(&env, 8), &bytes(&env, 99));
        assert!(ir_client.is_active_address(&issuer));

        // Step 5: Deploy and initialize proof-registry with both dependencies
        let proof_id = env.register(ProofRegistryContract, ());
        let proof_client = ProofRegistryContractClient::new(&env, &proof_id);
        proof_client.initialize(&admin, &ir_id, &pc_id);
        assert_eq!(proof_client.get_admin(), admin);
        assert_eq!(proof_client.get_issuer_registry(), ir_id);
        assert_eq!(proof_client.get_protocol_config(), pc_id);
        assert_eq!(proof_client.get_contract_version(), 1);

        // Verify the full system is functional: proof registration works
        let proof_id_hash = bytes(&env, 1);
        proof_client.register_proof(&proof_id_hash, &bytes(&env, 2), &issuer, &1, &2_000);
        assert!(proof_client.is_valid_proof(&proof_id_hash));
    }

    /// Verify that proof-registry initialization with uninitialized dependencies
    /// succeeds (no validation at init time), but proof registration fails when
    /// those dependencies are actually needed.
    ///
    /// This tests that initialization stores the dependency addresses without
    /// validating them, and validation happens at runtime (register_proof).
    #[test]
    fn proof_registry_init_with_uninitialized_dependencies_defers_validation() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);

        // Deploy contracts but DON'T initialize the dependencies
        let pc_id = env.register(ProtocolConfigContract, ());
        let ir_id = env.register(IssuerRegistryContract, ());
        let proof_id = env.register(ProofRegistryContract, ());
        let proof_client = ProofRegistryContractClient::new(&env, &proof_id);

        // Proof-registry initialization should succeed even with uninitialized deps
        // (initialization does not validate dependency addresses)
        proof_client.initialize(&admin, &ir_id, &pc_id);
        assert_eq!(proof_client.get_admin(), admin);
        assert_eq!(proof_client.get_issuer_registry(), ir_id);
        assert_eq!(proof_client.get_protocol_config(), pc_id);

        // However, attempting to use the proof registry should fail because
        // the dependencies are not initialized
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            proof_client.register_proof(&bytes(&env, 1), &bytes(&env, 2), &issuer, &1, &2_000);
        }));

        // Must have panicked (dependencies are not initialized)
        assert!(
            result.is_err(),
            "proof registration must fail with uninitialized dependencies"
        );
    }

    /// Verify that proof-registry with swapped dependency addresses
    /// (issuer-registry address passed where protocol-config address expected)
    /// results in runtime failure when proof operations are attempted.
    ///
    /// This demonstrates that dependency address validation is runtime, not compile-time.
    #[test]
    fn proof_registry_swapped_dependencies_fails_at_runtime() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);
        let issuer_id = bytes(&env, 9);

        // Deploy and initialize all contracts correctly
        let pc_id = env.register(ProtocolConfigContract, ());
        let pc_client = ProtocolConfigContractClient::new(&env, &pc_id);
        pc_client.initialize(&admin);
        pc_client.approve_schema_version(&1);

        let ir_id = env.register(IssuerRegistryContract, ());
        let ir_client = IssuerRegistryContractClient::new(&env, &ir_id);
        ir_client.initialize(&admin);
        ir_client.register_issuer(&issuer_id, &issuer, &bytes(&env, 8), &bytes(&env, 99));

        // Deploy proof-registry
        let proof_id = env.register(ProofRegistryContract, ());
        let proof_client = ProofRegistryContractClient::new(&env, &proof_id);

        // Initialize proof-registry with SWAPPED dependency addresses
        // (pass issuer-registry where protocol-config expected, and vice versa)
        proof_client.initialize(&admin, &pc_id, &ir_id); // Intentionally swapped!
        assert_eq!(proof_client.get_issuer_registry(), pc_id); // Swapped!
        assert_eq!(proof_client.get_protocol_config(), ir_id); // Swapped!

        // Initialization succeeds, but proof registration must fail at runtime
        // because the dependencies are the wrong contracts
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            proof_client.register_proof(&bytes(&env, 1), &bytes(&env, 2), &issuer, &1, &2_000);
        }));

        // Must have panicked
        assert!(
            result.is_err(),
            "proof registration must fail when dependencies are swapped"
        );
    }

    /// Verify that initialization order matters: proof-registry can be deployed
    /// and initialized BEFORE its dependencies, but operations fail at runtime.
    ///
    /// This demonstrates that Soroban does not enforce deployment-time ordering,
    /// only runtime contract calls enforce dependencies.
    #[test]
    fn proof_registry_initialized_before_dependencies_fails_at_operations() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);

        // Deploy proof-registry FIRST, before dependencies are even deployed
        let proof_id = env.register(ProofRegistryContract, ());
        let proof_client = ProofRegistryContractClient::new(&env, &proof_id);

        // Deploy dependencies (but order is reversed)
        let pc_id = env.register(ProtocolConfigContract, ());
        let ir_id = env.register(IssuerRegistryContract, ());

        // Initialize proof-registry with dependency addresses
        // (they exist as addresses, but aren't initialized yet)
        proof_client.initialize(&admin, &ir_id, &pc_id);

        // Now initialize dependencies
        let pc_client = ProtocolConfigContractClient::new(&env, &pc_id);
        pc_client.initialize(&admin);
        pc_client.approve_schema_version(&1);

        let ir_client = IssuerRegistryContractClient::new(&env, &ir_id);
        ir_client.initialize(&admin);
        let issuer_id = bytes(&env, 9);
        ir_client.register_issuer(&issuer_id, &issuer, &bytes(&env, 8), &bytes(&env, 99));

        // Now proof registration should work because dependencies are initialized
        let proof_id_hash = bytes(&env, 1);
        proof_client.register_proof(&proof_id_hash, &bytes(&env, 2), &issuer, &1, &2_000);
        assert!(proof_client.is_valid_proof(&proof_id_hash));
    }

    /// Verify that attempting to initialize proof-registry without initializing
    /// its dependencies' prerequisites fails at operation time.
    ///
    /// For example: schema version not approved in protocol-config, or issuer
    /// not registered in issuer-registry.
    #[test]
    fn proof_registry_operations_fail_without_dependency_configuration() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);

        // Deploy and initialize all contracts in correct order
        let pc_id = env.register(ProtocolConfigContract, ());
        let pc_client = ProtocolConfigContractClient::new(&env, &pc_id);
        pc_client.initialize(&admin);
        // NOTE: NOT approving schema version 1!

        let ir_id = env.register(IssuerRegistryContract, ());
        let ir_client = IssuerRegistryContractClient::new(&env, &ir_id);
        ir_client.initialize(&admin);
        // NOTE: NOT registering any issuer!

        let proof_id = env.register(ProofRegistryContract, ());
        let proof_client = ProofRegistryContractClient::new(&env, &proof_id);
        proof_client.initialize(&admin, &ir_id, &pc_id);

        // Proof registration should fail because:
        // 1. Schema version 1 is not approved
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            proof_client.register_proof(&bytes(&env, 1), &bytes(&env, 2), &issuer, &1, &2_000);
        }));
        assert!(
            result.is_err(),
            "proof registration must fail without approved schema version"
        );

        // Now approve schema version but still no issuer registered
        pc_client.approve_schema_version(&1);

        // Proof registration should fail because issuer is not registered
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            proof_client.register_proof(&bytes(&env, 2), &bytes(&env, 3), &issuer, &1, &2_000);
        }));
        assert!(
            result.is_err(),
            "proof registration must fail with unregistered issuer"
        );

        // Now register the issuer and everything should work
        let issuer_id = bytes(&env, 9);
        ir_client.register_issuer(&issuer_id, &issuer, &bytes(&env, 8), &bytes(&env, 99));

        proof_client.register_proof(&bytes(&env, 3), &bytes(&env, 4), &issuer, &1, &2_000);
        assert!(proof_client.is_valid_proof(&bytes(&env, 3)));
    }

    /// Verify that all three contracts can be initialized successfully
    /// in their respective dependency order, demonstrating a complete,
    /// valid deployment sequence.
    ///
    /// This is the "happy path" test that confirms the full system
    /// can reach a fully-operational state.
    #[test]
    fn complete_system_initialization_happy_path() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::from_str(&env, ADMIN);
        let issuer = Address::from_str(&env, ISSUER);
        let issuer_id = bytes(&env, 9);
        let proof_id_hash = bytes(&env, 1);

        // Initialize protocol-config first (no dependencies)
        let pc_id = env.register(ProtocolConfigContract, ());
        let pc_client = ProtocolConfigContractClient::new(&env, &pc_id);
        pc_client.initialize(&admin);
        pc_client.approve_schema_version(&1);
        assert!(pc_client.is_schema_version_approved(&1));

        // Initialize issuer-registry second (no dependencies on proof-registry)
        let ir_id = env.register(IssuerRegistryContract, ());
        let ir_client = IssuerRegistryContractClient::new(&env, &ir_id);
        ir_client.initialize(&admin);
        ir_client.register_issuer(&issuer_id, &issuer, &bytes(&env, 8), &bytes(&env, 99));
        assert!(ir_client.is_active_address(&issuer));

        // Initialize proof-registry third (depends on both above)
        let proof_id = env.register(ProofRegistryContract, ());
        let proof_client = ProofRegistryContractClient::new(&env, &proof_id);
        proof_client.initialize(&admin, &ir_id, &pc_id);

        // System is now fully operational
        // Verify all initialization invariants
        assert_eq!(pc_client.get_admin(), admin);
        assert_eq!(ir_client.get_admin(), admin);
        assert_eq!(proof_client.get_admin(), admin);

        // Verify all re-initialization guards are in place
        let other_admin = Address::from_str(
            &env,
            "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
        );
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pc_client.initialize(&other_admin)
        }))
        .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ir_client.initialize(&other_admin)
        }))
        .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            proof_client.initialize(&other_admin, &ir_id, &pc_id)
        }))
        .is_err());

        // Verify core operations work as expected
        proof_client.register_proof(&proof_id_hash, &bytes(&env, 2), &issuer, &1, &2_000);
        assert!(proof_client.is_valid_proof(&proof_id_hash));

        // Verify state mutations work
        let new_issuer = Address::from_str(
            &env,
            "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
        );
        let new_issuer_id = bytes(&env, 99);
        ir_client.register_issuer(
            &new_issuer_id,
            &new_issuer,
            &bytes(&env, 88),
            &bytes(&env, 99),
        );
        assert!(ir_client.is_active_issuer(&new_issuer_id));

        // Verify admin can still perform admin operations
        pc_client.pause();
        assert!(pc_client.is_paused());
        pc_client.unpause();
        assert!(!pc_client.is_paused());
    }

    // ── bounded batch proof registration ─────────────────────────────────────

    use earnproof_shared::ProofRegistrationInput;

    fn batch_input(env: &Env, seed: u8, expires_at: u64) -> ProofRegistrationInput {
        ProofRegistrationInput {
            proof_id_hash: bytes(env, seed),
            commitment_hash: bytes(env, seed.wrapping_add(100)),
            schema_version: 1,
            expires_at,
        }
    }

    fn make_batch(
        env: &Env,
        seeds: &[u8],
        expires_at: u64,
    ) -> soroban_sdk::Vec<ProofRegistrationInput> {
        let mut batch = soroban_sdk::Vec::new(env);
        for &seed in seeds {
            batch.push_back(batch_input(env, seed, expires_at));
        }
        batch
    }

    #[test]
    fn register_proofs_batch_registers_every_entry_in_order() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds = [1u8, 2, 3];
        let batch = make_batch(&env, &seeds, 2_000);

        client.register_proofs_batch(&batch, &issuer);

        for &seed in &seeds {
            let proof_id = bytes(&env, seed);
            assert!(client.is_valid_proof(&proof_id));
            let record = client.get_proof(&proof_id);
            assert_eq!(record.issuer_address, issuer);
            assert_eq!(record.status, ProofStatus::Active);
        }
    }

    #[test]
    fn register_proofs_batch_emits_events_in_input_order() {
        use soroban_sdk::testutils::Events as _;
        use soroban_sdk::xdr::{ContractEventBody, ScAddress, ScVal};
        use soroban_sdk::{Map, Symbol, TryFromVal, Val};

        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds = [5u8, 6, 7];
        let batch = make_batch(&env, &seeds, 2_000);

        client.register_proofs_batch(&batch, &issuer);

        let events = env.events().all();
        let proof_ids_in_event_order: std::vec::Vec<BytesN<32>> = events
            .events()
            .iter()
            .filter_map(|event| {
                let contract_id = event.contract_id.clone()?;
                let emitting_contract =
                    Address::try_from_val(&env, &ScVal::Address(ScAddress::Contract(contract_id)))
                        .ok()?;
                if emitting_contract != client.address {
                    return None;
                }
                let ContractEventBody::V0(body) = &event.body;
                let first_topic = body.topics.first()?;
                let first_topic_val = Val::try_from_val(&env, first_topic).ok()?;
                let discriminant = Symbol::try_from_val(&env, &first_topic_val).ok()?;
                if discriminant != Symbol::new(&env, "proof_registered_in_batch") {
                    return None;
                }
                let data_val = Val::try_from_val(&env, &body.data).ok()?;
                let map = Map::<Symbol, Val>::try_from_val(&env, &data_val).ok()?;
                let raw = map.get(Symbol::new(&env, "proof_id_hash"))?;
                BytesN::<32>::try_from_val(&env, &raw).ok()
            })
            .collect();

        assert_eq!(
            proof_ids_in_event_order,
            std::vec![bytes(&env, 5), bytes(&env, 6), bytes(&env, 7)]
        );
    }

    #[test]
    fn register_proofs_batch_rejects_empty_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let empty: soroban_sdk::Vec<ProofRegistrationInput> = soroban_sdk::Vec::new(&env);

        let result = client.try_register_proofs_batch(&empty, &issuer);
        assert_eq!(result, Err(Ok(ProofError::InvalidBatchSize)));
    }

    #[test]
    fn register_proofs_batch_accepts_exact_limit_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds: std::vec::Vec<u8> = (0..MAX_PROOF_BATCH_SIZE as u16).map(|i| i as u8).collect();
        let batch = make_batch(&env, &seeds, 2_000);

        client.register_proofs_batch(&batch, &issuer);

        for &seed in &seeds {
            assert!(client.is_valid_proof(&bytes(&env, seed)));
        }
    }

    #[test]
    fn register_proofs_batch_rejects_over_limit_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds: std::vec::Vec<u8> = (0..(MAX_PROOF_BATCH_SIZE as u16 + 1))
            .map(|i| i as u8)
            .collect();
        let batch = make_batch(&env, &seeds, 2_000);

        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::InvalidBatchSize)));

        // Nothing from the rejected over-limit batch may have been written.
        for &seed in &seeds {
            assert!(!client.is_valid_proof(&bytes(&env, seed)));
        }
    }

    #[test]
    fn register_proofs_batch_rejects_duplicate_within_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let mut batch = soroban_sdk::Vec::new(&env);
        batch.push_back(batch_input(&env, 1, 2_000));
        batch.push_back(batch_input(&env, 2, 2_000));
        batch.push_back(batch_input(&env, 1, 2_000)); // duplicate of the first

        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::ProofAlreadyRegistered)));

        // Atomicity: even the entries that would have succeeded (seed 1, 2)
        // must not have been committed.
        assert!(!client.is_valid_proof(&bytes(&env, 1)));
        assert!(!client.is_valid_proof(&bytes(&env, 2)));
    }

    #[test]
    fn register_proofs_batch_rejects_duplicate_against_existing_chain_state() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        client.register_proof(&bytes(&env, 1), &bytes(&env, 2), &issuer, &1, &2_000);

        let batch = make_batch(&env, &[9, 1, 10], 2_000);
        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::ProofAlreadyRegistered)));

        // The batch entries preceding the collision must not have been committed.
        assert!(!client.is_valid_proof(&bytes(&env, 9)));
        assert!(!client.is_valid_proof(&bytes(&env, 10)));
    }

    #[test]
    fn register_proofs_batch_rejects_mixed_invalid_entries() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let now = env.ledger().timestamp();

        let mut batch = soroban_sdk::Vec::new(&env);
        batch.push_back(batch_input(&env, 1, 2_000)); // valid
        batch.push_back(ProofRegistrationInput {
            proof_id_hash: bytes(&env, 2),
            commitment_hash: bytes(&env, 102),
            schema_version: 0, // invalid: zero schema version
            expires_at: 2_000,
        });
        batch.push_back(batch_input(&env, 3, now)); // invalid: not in the future

        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::InvalidSchemaVersion)));
        assert!(!client.is_valid_proof(&bytes(&env, 1)));
    }

    #[test]
    fn register_proofs_batch_rejects_unapproved_schema_version() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let mut batch = soroban_sdk::Vec::new(&env);
        batch.push_back(batch_input(&env, 1, 2_000));
        batch.push_back(ProofRegistrationInput {
            proof_id_hash: bytes(&env, 2),
            commitment_hash: bytes(&env, 102),
            schema_version: 42, // never approved
            expires_at: 2_000,
        });

        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::UnsupportedSchema)));
        assert!(!client.is_valid_proof(&bytes(&env, 1)));
    }

    #[test]
    fn register_proofs_batch_rejects_expired_entry() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let now = env.ledger().timestamp();
        let batch = make_batch(&env, &[1], now);

        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::ProofExpired)));
    }

    #[test]
    fn register_proofs_batch_rejects_when_paused() {
        let (env, client, pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        pc.pause();
        let batch = make_batch(&env, &[1, 2], 2_000);

        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::ContractPaused)));
    }

    #[test]
    fn register_proofs_batch_rejects_inactive_issuer() {
        let (env, client, _pc, ir, _ir_id) = setup();
        let inactive_issuer = Address::from_str(
            &env,
            "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
        );
        ir.register_issuer(
            &bytes(&env, 10),
            &inactive_issuer,
            &bytes(&env, 11),
            &bytes(&env, 99),
        );
        ir.suspend_issuer(&bytes(&env, 10), &bytes(&env, 1));
        let batch = make_batch(&env, &[1, 2], 2_000);

        let result = client.try_register_proofs_batch(&batch, &inactive_issuer);
        assert_eq!(result, Err(Ok(ProofError::IssuerInactive)));
    }

    #[test]
    fn register_proofs_batch_requires_issuer_auth() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let batch = make_batch(&env, &[1, 2], 2_000);

        env.set_auths(&[]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.register_proofs_batch(&batch, &issuer);
        }));
        assert!(
            result.is_err(),
            "batch registration must require issuer auth"
        );
        assert!(!client.is_valid_proof(&bytes(&env, 1)));
    }

    #[test]
    fn register_proofs_batch_rejects_decommissioned_contract() {
        let (env, client, ..) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let hash = bytes(&env, 0x11);
        let admin = Address::from_str(&env, ADMIN);
        client.nominate_successor(&admin);
        client.activate_successor();
        let _ = hash;

        let batch = make_batch(&env, &[1], 2_000);
        let result = client.try_register_proofs_batch(&batch, &issuer);
        assert_eq!(result, Err(Ok(ProofError::ProofNotFound)));
    }

    // ── bounded batch proof revocation ───────────────────────────────────────

    const ISSUER_TWO: &str = "GDWUSKGGFDI4FRXK5EBTRECZSVQSSWJHHJOGH6JWG3AUMFFMQ435DIAG";

    fn ids(env: &Env, seeds: &[u8]) -> soroban_sdk::Vec<BytesN<32>> {
        let mut v = soroban_sdk::Vec::new(env);
        for &seed in seeds {
            v.push_back(bytes(env, seed));
        }
        v
    }

    #[test]
    fn revoke_proofs_batch_revokes_every_entry_in_order() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds = [1u8, 2, 3];
        for &seed in &seeds {
            client.register_proof(
                &bytes(&env, seed),
                &bytes(&env, seed + 100),
                &issuer,
                &1,
                &2_000,
            );
        }

        client.revoke_proofs_batch(&ids(&env, &seeds));

        for &seed in &seeds {
            assert!(client.is_revoked(&bytes(&env, seed)));
            assert!(!client.is_valid_proof(&bytes(&env, seed)));
        }
    }

    #[test]
    fn revoke_proofs_batch_emits_events_in_input_order() {
        use soroban_sdk::testutils::Events as _;
        use soroban_sdk::xdr::{ContractEventBody, ScAddress, ScVal};
        use soroban_sdk::{Map, Symbol, TryFromVal, Val};

        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds = [5u8, 6, 7];
        for &seed in &seeds {
            client.register_proof(
                &bytes(&env, seed),
                &bytes(&env, seed + 100),
                &issuer,
                &1,
                &2_000,
            );
        }

        client.revoke_proofs_batch(&ids(&env, &seeds));

        let events = env.events().all();
        let proof_ids_in_event_order: std::vec::Vec<BytesN<32>> = events
            .events()
            .iter()
            .filter_map(|event| {
                let contract_id = event.contract_id.clone()?;
                let emitting_contract =
                    Address::try_from_val(&env, &ScVal::Address(ScAddress::Contract(contract_id)))
                        .ok()?;
                if emitting_contract != client.address {
                    return None;
                }
                let ContractEventBody::V0(body) = &event.body;
                let first_topic = body.topics.first()?;
                let first_topic_val = Val::try_from_val(&env, first_topic).ok()?;
                let discriminant = Symbol::try_from_val(&env, &first_topic_val).ok()?;
                if discriminant != Symbol::new(&env, "proof_revoked_in_batch") {
                    return None;
                }
                let data_val = Val::try_from_val(&env, &body.data).ok()?;
                let map = Map::<Symbol, Val>::try_from_val(&env, &data_val).ok()?;
                let raw = map.get(Symbol::new(&env, "proof_id_hash"))?;
                BytesN::<32>::try_from_val(&env, &raw).ok()
            })
            .collect();

        assert_eq!(
            proof_ids_in_event_order,
            std::vec![bytes(&env, 5), bytes(&env, 6), bytes(&env, 7)]
        );
    }

    #[test]
    fn revoke_proofs_batch_rejects_empty_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let empty: soroban_sdk::Vec<BytesN<32>> = soroban_sdk::Vec::new(&env);

        let result = client.try_revoke_proofs_batch(&empty);
        assert_eq!(result, Err(Ok(ProofError::InvalidBatchSize)));
    }

    #[test]
    fn revoke_proofs_batch_accepts_exact_limit_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds: std::vec::Vec<u8> = (0..MAX_PROOF_BATCH_SIZE as u16).map(|i| i as u8).collect();
        for &seed in &seeds {
            client.register_proof(
                &bytes(&env, seed),
                &bytes(&env, seed.wrapping_add(100)),
                &issuer,
                &1,
                &2_000,
            );
        }

        client.revoke_proofs_batch(&ids(&env, &seeds));

        for &seed in &seeds {
            assert!(client.is_revoked(&bytes(&env, seed)));
        }
    }

    #[test]
    fn revoke_proofs_batch_rejects_over_limit_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds: std::vec::Vec<u8> = (0..(MAX_PROOF_BATCH_SIZE as u16 + 1))
            .map(|i| i as u8)
            .collect();
        for &seed in &seeds {
            client.register_proof(
                &bytes(&env, seed),
                &bytes(&env, seed.wrapping_add(100)),
                &issuer,
                &1,
                &2_000,
            );
        }

        let result = client.try_revoke_proofs_batch(&ids(&env, &seeds));
        assert_eq!(result, Err(Ok(ProofError::InvalidBatchSize)));

        for &seed in &seeds {
            assert!(!client.is_revoked(&bytes(&env, seed)));
        }
    }

    #[test]
    fn revoke_proofs_batch_rejects_duplicate_within_batch() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer, &1, &2_000);
        client.register_proof(&bytes(&env, 2), &bytes(&env, 102), &issuer, &1, &2_000);

        let batch = ids(&env, &[1, 2, 1]); // duplicate of the first
        let result = client.try_revoke_proofs_batch(&batch);
        assert_eq!(result, Err(Ok(ProofError::ProofAlreadyRevoked)));

        // Atomicity: even the entries that would have succeeded must not be committed.
        assert!(!client.is_revoked(&bytes(&env, 1)));
        assert!(!client.is_revoked(&bytes(&env, 2)));
    }

    #[test]
    fn revoke_proofs_batch_rejects_already_revoked_entry() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer, &1, &2_000);
        client.register_proof(&bytes(&env, 2), &bytes(&env, 102), &issuer, &1, &2_000);
        client.revoke_proof(&bytes(&env, 1));

        let batch = ids(&env, &[2, 1]);
        let result = client.try_revoke_proofs_batch(&batch);
        assert_eq!(result, Err(Ok(ProofError::ProofAlreadyRevoked)));

        // Entry 2 preceded the failing entry and must not have been committed.
        assert!(!client.is_revoked(&bytes(&env, 2)));
    }

    #[test]
    fn revoke_proofs_batch_rejects_unknown_proof_id() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer, &1, &2_000);

        let batch = ids(&env, &[1, 99]);
        let result = client.try_revoke_proofs_batch(&batch);
        assert_eq!(result, Err(Ok(ProofError::ProofNotFound)));
        assert!(!client.is_revoked(&bytes(&env, 1)));
    }

    #[test]
    fn revoke_proofs_batch_supports_mixed_ownership_when_every_issuer_authorizes() {
        let (env, client, _pc, ir, _ir_id) = setup();
        let issuer_one = Address::from_str(&env, ISSUER);
        let issuer_two = Address::from_str(&env, ISSUER_TWO);
        ir.register_issuer(
            &bytes(&env, 20),
            &issuer_two,
            &bytes(&env, 21),
            &bytes(&env, 99),
        );

        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer_one, &1, &2_000);
        client.register_proof(&bytes(&env, 2), &bytes(&env, 102), &issuer_two, &1, &2_000);

        // env.mock_all_auths() (from setup()) authorizes every address, so a
        // mixed-ownership batch succeeds when both issuers would sign.
        client.revoke_proofs_batch(&ids(&env, &[1, 2]));

        assert!(client.is_revoked(&bytes(&env, 1)));
        assert!(client.is_revoked(&bytes(&env, 2)));
    }

    #[test]
    fn revoke_proofs_batch_rejects_mixed_ownership_without_the_second_issuers_auth() {
        use soroban_sdk::IntoVal;

        let (env, client, _pc, ir, _ir_id) = setup();
        let issuer_one = Address::from_str(&env, ISSUER);
        let issuer_two = Address::from_str(&env, ISSUER_TWO);
        ir.register_issuer(
            &bytes(&env, 20),
            &issuer_two,
            &bytes(&env, 21),
            &bytes(&env, 99),
        );

        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer_one, &1, &2_000);
        client.register_proof(&bytes(&env, 2), &bytes(&env, 102), &issuer_two, &1, &2_000);

        // Only issuer_one is authorized for this invocation; issuer_two's
        // entry must not be smuggled through behind it.
        env.set_auths(&[]);
        let auth_entry = soroban_sdk::testutils::MockAuth {
            address: &issuer_one,
            invoke: &soroban_sdk::testutils::MockAuthInvoke {
                contract: &client.address,
                fn_name: "revoke_proofs_batch",
                args: (ids(&env, &[1, 2]),).into_val(&env),
                sub_invokes: &[],
            },
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client
                .mock_auths(&[auth_entry])
                .revoke_proofs_batch(&ids(&env, &[1, 2]));
        }));
        assert!(
            result.is_err(),
            "batch must fail without issuer_two's authorization"
        );
        assert!(!client.is_revoked(&bytes(&env, 1)));
        assert!(!client.is_revoked(&bytes(&env, 2)));
    }

    #[test]
    fn revoke_proofs_batch_rejects_when_revocation_paused() {
        let (env, client, pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer, &1, &2_000);
        pc.set_scoped_pause(&PauseScope::Revocation, &true);

        let result = client.try_revoke_proofs_batch(&ids(&env, &[1]));
        assert_eq!(result, Err(Ok(ProofError::ProofNotFound)));
        assert!(!client.is_revoked(&bytes(&env, 1)));
    }

    #[test]
    fn revoke_proofs_batch_rejects_decommissioned_contract() {
        let (env, client, ..) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let admin = Address::from_str(&env, ADMIN);
        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer, &1, &2_000);
        client.nominate_successor(&admin);
        client.activate_successor();

        let result = client.try_revoke_proofs_batch(&ids(&env, &[1]));
        assert_eq!(result, Err(Ok(ProofError::ProofNotFound)));
    }

    #[test]
    fn admin_revoke_proofs_batch_revokes_every_entry() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        let seeds = [1u8, 2, 3];
        for &seed in &seeds {
            client.register_proof(
                &bytes(&env, seed),
                &bytes(&env, seed + 100),
                &issuer,
                &1,
                &2_000,
            );
        }

        client.admin_revoke_proofs_batch(&ids(&env, &seeds));

        for &seed in &seeds {
            assert!(client.is_revoked(&bytes(&env, seed)));
        }
    }

    #[test]
    fn admin_revoke_proofs_batch_requires_admin_auth() {
        let (env, client, _pc, _ir, _ir_id) = setup();
        let issuer = Address::from_str(&env, ISSUER);
        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer, &1, &2_000);

        env.set_auths(&[]);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.admin_revoke_proofs_batch(&ids(&env, &[1]));
        }));
        assert!(
            result.is_err(),
            "admin batch revocation must require admin auth"
        );
        assert!(!client.is_revoked(&bytes(&env, 1)));
    }

    #[test]
    fn admin_revoke_proofs_batch_can_revoke_proofs_from_multiple_issuers_with_one_auth() {
        let (env, client, _pc, ir, _ir_id) = setup();
        let issuer_one = Address::from_str(&env, ISSUER);
        let issuer_two = Address::from_str(&env, ISSUER_TWO);
        ir.register_issuer(
            &bytes(&env, 20),
            &issuer_two,
            &bytes(&env, 21),
            &bytes(&env, 99),
        );
        client.register_proof(&bytes(&env, 1), &bytes(&env, 101), &issuer_one, &1, &2_000);
        client.register_proof(&bytes(&env, 2), &bytes(&env, 102), &issuer_two, &1, &2_000);

        // Only the admin needs to authorize; neither issuer does.
        client.admin_revoke_proofs_batch(&ids(&env, &[1, 2]));

        assert!(client.is_revoked(&bytes(&env, 1)));
        assert!(client.is_revoked(&bytes(&env, 2)));
    }
}
