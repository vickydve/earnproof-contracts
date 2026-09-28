//! Inventory of every storage namespace across every contract.

/// Durability class of a storage entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StorageClass {
    /// Shares the contract instance lifetime.
    Instance,
    /// Independent per-key lifetime, restorable after archival.
    Persistent,
    /// Independent per-key lifetime, unrecoverable after expiry.
    Temporary,
}

impl StorageClass {
    /// Stable lower-case name, used in generated documentation and tests.
    pub const fn as_str(self) -> &'static str {
        match self {
            StorageClass::Instance => "instance",
            StorageClass::Persistent => "persistent",
            StorageClass::Temporary => "temporary",
        }
    }
}

/// One `DataKey` variant.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StorageNamespace {
    /// Contract that owns this namespace.
    pub contract: &'static str,
    /// Name of the `DataKey` enum variant.
    pub namespace: &'static str,
    /// Number of payload arguments in the `DataKey` variant.
    ///
    /// Singletons are 0; per-record entries are 1; composite keys are 2+.
    pub arity: u32,
    /// Durability tier in Soroban storage.
    pub class: StorageClass,
    /// Type of value stored under this key (e.g. `"Address"`, `"IssuerRecord"`).
    pub value: &'static str,
    /// Human-readable party that creates or mutates entries under this key.
    pub owner: &'static str,
}

pub const CONTRACTS: [&str; 3] = ["issuer-registry", "proof-registry", "protocol-config"];

/// Inventory of every storage namespace across every contract, sorted by
/// `(contract, namespace)`.
///
/// Adding a row here is the second half of adding a storage key; the first is
/// adding the `DataKey` variant. Doing one without the other fails the tests in
/// `tests/storage-keys/`.
pub const STORAGE_NAMESPACES: [StorageNamespace; 28] = [
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "AddressIssuer",
        arity: 1,
        class: StorageClass::Persistent,
        value: "BytesN<32>",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "AddressTtl",
        arity: 1,
        class: StorageClass::Persistent,
        value: "u32",
        owner: "keepalive operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "Admin",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "ContractVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "Decommissioned",
        arity: 0,
        class: StorageClass::Instance,
        value: "bool",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "InstanceLiveUntil",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "keepalive operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "Issuer",
        arity: 1,
        class: StorageClass::Persistent,
        value: "IssuerRecord",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "IssuerTtl",
        arity: 1,
        class: StorageClass::Persistent,
        value: "u32",
        owner: "keepalive operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "MigrationStatus",
        arity: 0,
        class: StorageClass::Instance,
        value: "MigrationStatus",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "issuer-registry",
        namespace: "Successor",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "registry operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "Admin",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "ContractVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "Decommissioned",
        arity: 0,
        class: StorageClass::Instance,
        value: "bool",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "Dispute",
        arity: 1,
        class: StorageClass::Persistent,
        value: "DisputeRecord",
        owner: "disputing party",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "IssuerRegistry",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "MigrationStatus",
        arity: 0,
        class: StorageClass::Instance,
        value: "MigrationStatus",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "Proof",
        arity: 1,
        class: StorageClass::Persistent,
        value: "ProofRecord",
        owner: "issuing party",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "ProtocolConfig",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "proof-registry",
        namespace: "Successor",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "deployment operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "Admin",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "ConfigVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "ContractVersion",
        arity: 0,
        class: StorageClass::Instance,
        value: "u32",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "Decommissioned",
        arity: 0,
        class: StorageClass::Instance,
        value: "bool",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "MigrationStatus",
        arity: 0,
        class: StorageClass::Instance,
        value: "MigrationStatus",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "Paused",
        arity: 0,
        class: StorageClass::Instance,
        value: "bool",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "SchemaVersion",
        arity: 1,
        class: StorageClass::Persistent,
        value: "bool",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "ScopedPause",
        arity: 1,
        class: StorageClass::Persistent,
        value: "bool",
        owner: "protocol operator",
    },
    StorageNamespace {
        contract: "protocol-config",
        namespace: "Successor",
        arity: 0,
        class: StorageClass::Instance,
        value: "Address",
        owner: "protocol operator",
    },
];

/// Looks up a namespace entry by contract and namespace name.
pub fn namespace(contract: &str, namespace: &str) -> Option<StorageNamespace> {
    STORAGE_NAMESPACES
        .into_iter()
        .find(|entry| entry.contract == contract && entry.namespace == namespace)
}

/// Iterates over every namespace declared for a contract.
pub fn namespaces_for<'a>(
    contract: &'a str,
    class: StorageClass,
) -> impl Iterator<Item = &'static str> + 'a {
    STORAGE_NAMESPACES
        .into_iter()
        .filter(move |entry| entry.contract == contract && entry.class == class)
        .map(|entry| entry.namespace)
}
