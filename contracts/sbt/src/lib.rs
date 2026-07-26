#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, panic_with_error,
    symbol_short, Address, Env, String, Vec,
};

const MINT_TOPIC: soroban_sdk::Symbol = symbol_short!("sbt_mint");
const COMPOSE_TOPIC: soroban_sdk::Symbol = symbol_short!("sbt_cmpse");
const DECOMPOSE_TOPIC: soroban_sdk::Symbol = symbol_short!("sbt_dcmp");
const SHARED_METADATA_TOPIC: soroban_sdk::Symbol = symbol_short!("sbt_smeta");
const BATCH_TRANSFER_TOPIC: soroban_sdk::Symbol = symbol_short!("sbt_btxfr");
const DELEGATE_TOPIC: soroban_sdk::Symbol = symbol_short!("sbt_dlg");
const REVOKE_DELEGATE_TOPIC: soroban_sdk::Symbol = symbol_short!("sbt_rdlg");

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SbtError {
    /// Contract has already been initialized.
    AlreadyInitialized = 1,
    /// Contract has not been initialized.
    NotInitialized = 2,
    /// No SBT exists with the given id.
    TokenNotFound = 3,
    /// Metadata bytes were empty.
    EmptyMetadata = 4,
    /// The SBT is already composed with an NFT.
    AlreadyComposed = 5,
    /// The SBT is not currently composed with any NFT.
    NotComposed = 6,
    /// The caller does not own the referenced NFT on the target contract.
    NftOwnershipMismatch = 7,
    /// Delegation duration must be greater than zero.
    InvalidDuration = 8,
    /// The SBT has no active (non-expired) delegation.
    NoActiveDelegation = 9,
    /// `sbt_ids` and `transfers` must be the same length.
    MismatchedBatchLengths = 10,
    /// A conditional transfer's condition was not satisfied.
    TransferConditionNotMet = 11,
    /// Batch operations require at least one entry.
    EmptyBatch = 12,
    /// An SBT cannot be delegated to its own owner.
    SelfDelegation = 13,
}

/// Storage key discriminants. All SBT state is keyed by `sbt_id`.
#[contracttype]
pub enum DataKey {
    Admin,
    NextTokenId,
    Owner(u64),
    Metadata(u64),
    MintedAt(u64),
    Composition(u64),
    SharedMetadata(u64),
    Delegation(u64),
    DelegationHistory(u64),
}

/// A bridge record linking an SBT to a token on a standard (transferable) NFT
/// contract. While composed, the SBT and the referenced NFT are treated as a
/// linked pair for the purposes of shared metadata; composing does not move
/// or lock the NFT itself, it only records the association on-chain.
#[contracttype]
#[derive(Clone)]
pub struct CompositionRecord {
    pub nft_address: Address,
    pub nft_id: u64,
    pub composed_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct DelegationRecord {
    pub delegate: Address,
    pub delegated_at: u64,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DelegationAction {
    Delegated,
    Revoked,
}

/// An append-only audit entry recording a single delegation lifecycle event.
#[contracttype]
#[derive(Clone)]
pub struct DelegationHistoryEntry {
    pub delegate: Address,
    pub action: DelegationAction,
    pub at: u64,
    pub expires_at: u64,
}

/// A condition gating one leg of a conditional batch transfer.
#[contracttype]
#[derive(Clone)]
pub enum TransferCondition {
    /// No restriction beyond ownership.
    Always,
    /// The SBT must have been held by its current owner for at least this
    /// many seconds (measured from mint time).
    MinHoldSeconds(u64),
    /// The SBT must not currently have an active (non-expired) delegation.
    NoActiveDelegation,
}

/// One leg of a `batch_transfer_sbt_conditional` call: the destination owner
/// and the condition that must hold for the transfer to be applied.
#[contracttype]
#[derive(Clone)]
pub struct TransferInstruction {
    pub to: Address,
    pub condition: TransferCondition,
}

/// Minimal interface bridged to standard (transferable) NFT contracts so an
/// SBT can be composed with an NFT the same owner holds elsewhere.
#[contractclient(name = "NftClient")]
pub trait NftInterface {
    fn owner_of(env: Env, token_id: u64) -> Address;
}

#[contract]
pub struct SbtContract;

#[contractimpl]
impl SbtContract {
    // ---- admin/lifecycle ----

    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(&env, SbtError::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::NextTokenId, &0u64);
    }

    /// Mints a new soulbound token to `to`. Admin only.
    pub fn mint(env: Env, to: Address, metadata: String) -> u64 {
        Self::require_admin(&env);
        if metadata.is_empty() {
            panic_with_error!(&env, SbtError::EmptyMetadata);
        }

        let sbt_id: u64 = env
            .storage()
            .instance()
            .get(&DataKey::NextTokenId)
            .unwrap_or(0);
        env.storage()
            .instance()
            .set(&DataKey::NextTokenId, &(sbt_id + 1));

        env.storage().instance().set(&DataKey::Owner(sbt_id), &to);
        env.storage()
            .instance()
            .set(&DataKey::Metadata(sbt_id), &metadata);
        env.storage()
            .instance()
            .set(&DataKey::MintedAt(sbt_id), &env.ledger().timestamp());

        env.events().publish((MINT_TOPIC,), (sbt_id, to));
        sbt_id
    }

    pub fn owner_of(env: Env, sbt_id: u64) -> Address {
        Self::load_owner(&env, sbt_id)
    }

    pub fn get_metadata(env: Env, sbt_id: u64) -> String {
        env.storage()
            .instance()
            .get(&DataKey::Metadata(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, SbtError::TokenNotFound))
    }

    // ---- #54: SBT composability with other NFTs ----

    /// Bridges this SBT to a token on a standard NFT contract. Requires the
    /// SBT owner to also currently own `nft_id` on `nft_address` (verified
    /// via a cross-contract call to the NFT contract's `owner_of`).
    pub fn compose_sbt_with_nft(env: Env, sbt_id: u64, nft_address: Address, nft_id: u64) {
        let owner = Self::require_owner(&env, sbt_id);

        if env
            .storage()
            .instance()
            .has(&DataKey::Composition(sbt_id))
        {
            panic_with_error!(&env, SbtError::AlreadyComposed);
        }

        let nft_owner = NftClient::new(&env, &nft_address).owner_of(&nft_id);
        if nft_owner != owner {
            panic_with_error!(&env, SbtError::NftOwnershipMismatch);
        }

        let record = CompositionRecord {
            nft_address: nft_address.clone(),
            nft_id,
            composed_at: env.ledger().timestamp(),
        };
        env.storage()
            .instance()
            .set(&DataKey::Composition(sbt_id), &record);

        env.events()
            .publish((COMPOSE_TOPIC,), (sbt_id, nft_address, nft_id));
    }

    /// Removes the SBT's association with any composed NFT. The NFT itself
    /// is untouched — this only clears the on-chain link.
    pub fn decompose_sbt(env: Env, sbt_id: u64) {
        Self::require_owner(&env, sbt_id);

        if !env
            .storage()
            .instance()
            .has(&DataKey::Composition(sbt_id))
        {
            panic_with_error!(&env, SbtError::NotComposed);
        }
        env.storage().instance().remove(&DataKey::Composition(sbt_id));

        env.events().publish((DECOMPOSE_TOPIC,), sbt_id);
    }

    pub fn get_composition(env: Env, sbt_id: u64) -> Option<CompositionRecord> {
        env.storage().instance().get(&DataKey::Composition(sbt_id))
    }

    /// Sets metadata shared across the SBT and any NFT it is composed with.
    /// Owner only.
    pub fn set_shared_metadata(env: Env, sbt_id: u64, metadata: String) {
        Self::require_owner(&env, sbt_id);
        env.storage()
            .instance()
            .set(&DataKey::SharedMetadata(sbt_id), &metadata);
        env.events().publish((SHARED_METADATA_TOPIC,), sbt_id);
    }

    pub fn get_shared_metadata(env: Env, sbt_id: u64) -> Option<String> {
        env.storage().instance().get(&DataKey::SharedMetadata(sbt_id))
    }

    // ---- #53: batch transfer with conditions ----

    /// Transfers multiple SBTs in a single call, each gated by its own
    /// [`TransferCondition`]. `sbt_ids[i]` is transferred per
    /// `transfers[i]`. Every leg's ownership auth and condition are
    /// validated before any storage is mutated, so the whole batch either
    /// fully applies or (on any panic) fully reverts — Soroban only commits
    /// state changes from a top-level invocation that returns successfully.
    pub fn batch_transfer_sbt_conditional(
        env: Env,
        sbt_ids: Vec<u64>,
        transfers: Vec<TransferInstruction>,
    ) {
        if sbt_ids.len() != transfers.len() {
            panic_with_error!(&env, SbtError::MismatchedBatchLengths);
        }
        if sbt_ids.is_empty() {
            panic_with_error!(&env, SbtError::EmptyBatch);
        }

        for (sbt_id, instruction) in sbt_ids.iter().zip(transfers.iter()) {
            let owner = Self::require_owner(&env, sbt_id);
            if !Self::evaluate_condition(&env, sbt_id, &owner, &instruction.condition) {
                panic_with_error!(&env, SbtError::TransferConditionNotMet);
            }
        }

        for (sbt_id, instruction) in sbt_ids.iter().zip(transfers.iter()) {
            env.storage()
                .instance()
                .set(&DataKey::Owner(sbt_id), &instruction.to);
            // A delegation granted by the previous owner should not carry
            // over to the new owner.
            env.storage().instance().remove(&DataKey::Delegation(sbt_id));

            env.events()
                .publish((BATCH_TRANSFER_TOPIC,), (sbt_id, instruction.to.clone()));
        }
    }

    // ---- #52: delegation with time limits ----

    /// Temporarily delegates the SBT to `delegate` for `duration_seconds`.
    /// Does not change ownership. Owner only.
    pub fn delegate_sbt_temporarily(env: Env, sbt_id: u64, delegate: Address, duration_seconds: u64) {
        let owner = Self::require_owner(&env, sbt_id);
        if duration_seconds == 0 {
            panic_with_error!(&env, SbtError::InvalidDuration);
        }
        if delegate == owner {
            panic_with_error!(&env, SbtError::SelfDelegation);
        }

        let now = env.ledger().timestamp();
        let expires_at = now.saturating_add(duration_seconds);

        let record = DelegationRecord {
            delegate: delegate.clone(),
            delegated_at: now,
            expires_at,
        };
        env.storage()
            .instance()
            .set(&DataKey::Delegation(sbt_id), &record);

        Self::push_delegation_history(
            &env,
            sbt_id,
            DelegationHistoryEntry {
                delegate: delegate.clone(),
                action: DelegationAction::Delegated,
                at: now,
                expires_at,
            },
        );

        env.events()
            .publish((DELEGATE_TOPIC,), (sbt_id, delegate, expires_at));
    }

    /// Revokes the SBT's active delegation before it expires. Owner only.
    pub fn revoke_sbt_delegation(env: Env, sbt_id: u64) {
        Self::require_owner(&env, sbt_id);

        let record: DelegationRecord = env
            .storage()
            .instance()
            .get(&DataKey::Delegation(sbt_id))
            .unwrap_or_else(|| panic_with_error!(&env, SbtError::NoActiveDelegation));

        env.storage().instance().remove(&DataKey::Delegation(sbt_id));

        let now = env.ledger().timestamp();
        Self::push_delegation_history(
            &env,
            sbt_id,
            DelegationHistoryEntry {
                delegate: record.delegate.clone(),
                action: DelegationAction::Revoked,
                at: now,
                expires_at: record.expires_at,
            },
        );

        env.events()
            .publish((REVOKE_DELEGATE_TOPIC,), (sbt_id, record.delegate));
    }

    /// Returns the current delegate, or `None` if there is no delegation or
    /// it has expired. Expiry is enforced here at read time rather than by
    /// eagerly clearing storage, mirroring how attestations are honored
    /// elsewhere in this workspace only while still currently valid.
    pub fn get_active_delegate(env: Env, sbt_id: u64) -> Option<Address> {
        let record: DelegationRecord = env.storage().instance().get(&DataKey::Delegation(sbt_id))?;
        if record.expires_at > env.ledger().timestamp() {
            Some(record.delegate)
        } else {
            None
        }
    }

    pub fn get_delegation_history(env: Env, sbt_id: u64) -> Vec<DelegationHistoryEntry> {
        Self::load_delegation_history(&env, sbt_id)
    }

    // ---- helpers ----

    fn require_admin(env: &Env) {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(env, SbtError::NotInitialized));
        admin.require_auth();
    }

    fn load_owner(env: &Env, sbt_id: u64) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Owner(sbt_id))
            .unwrap_or_else(|| panic_with_error!(env, SbtError::TokenNotFound))
    }

    fn require_owner(env: &Env, sbt_id: u64) -> Address {
        let owner = Self::load_owner(env, sbt_id);
        owner.require_auth();
        owner
    }

    fn has_active_delegation(env: &Env, sbt_id: u64) -> bool {
        env.storage()
            .instance()
            .get::<DataKey, DelegationRecord>(&DataKey::Delegation(sbt_id))
            .map(|record| record.expires_at > env.ledger().timestamp())
            .unwrap_or(false)
    }

    fn evaluate_condition(
        env: &Env,
        sbt_id: u64,
        _owner: &Address,
        condition: &TransferCondition,
    ) -> bool {
        match condition {
            TransferCondition::Always => true,
            TransferCondition::MinHoldSeconds(min_seconds) => {
                let minted_at: u64 = env
                    .storage()
                    .instance()
                    .get(&DataKey::MintedAt(sbt_id))
                    .unwrap_or(0);
                env.ledger().timestamp().saturating_sub(minted_at) >= *min_seconds
            }
            TransferCondition::NoActiveDelegation => !Self::has_active_delegation(env, sbt_id),
        }
    }

    fn load_delegation_history(env: &Env, sbt_id: u64) -> Vec<DelegationHistoryEntry> {
        env.storage()
            .instance()
            .get(&DataKey::DelegationHistory(sbt_id))
            .unwrap_or_else(|| Vec::new(env))
    }

    fn push_delegation_history(env: &Env, sbt_id: u64, entry: DelegationHistoryEntry) {
        let mut history = Self::load_delegation_history(env, sbt_id);
        history.push_back(entry);
        env.storage()
            .instance()
            .set(&DataKey::DelegationHistory(sbt_id), &history);
    }
}
