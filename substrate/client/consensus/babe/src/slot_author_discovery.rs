
//! authority discovery functionality for the BABE.
use sc_consensus::authority_discovery::AuthorityDiscoveryForTxPool;
use sp_application_crypto::AppCrypto;
use sp_consensus_babe::{AuthorityId, BabeApi};
use sp_api::ProvideRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_keystore::KeystorePtr;
use sp_runtime::traits::Block as BlockT;
use std::sync::Arc;
use crate::will_author_in_next_slots;

/// A struct that provides authority discovery functionality for the BABE consensus mechanism.
///
/// This struct is used to determine whether the client is a validator and whether it can author
/// blocks in upcoming slots. It integrates with the runtime API and keystore to perform these
/// checks.
///
/// # Type Parameters
/// - `B`: The block type that implements the `BlockT` trait.
/// - `C`: The client type that provides runtime API access and implements `ProvideRuntimeApi`
///   and `HeaderBackend` for the block type `B`.
///
/// # Fields
/// - `client`: A reference-counted pointer to the client, which provides access to the runtime API
///   and blockchain headers.
/// - `keystore`: A pointer to the keystore, which is used to retrieve the public keys of the
///   authority.
/// - `_phantom`: A marker to associate the struct with the block type `B`.
///
/// # Usage
/// This struct is typically used in the context of transaction pools to determine whether the
/// client is an authority and whether it can author blocks in the near future.
pub struct BabeAuthorityDiscovery<B, C> {
    client: Arc<C>,
    keystore: KeystorePtr,
    _phantom: std::marker::PhantomData<B>,
}

impl<B, C> BabeAuthorityDiscovery<B, C> {

    /// Creates a new instance of `BabeAuthorityDiscovery`.
    ///
    /// # Parameters
    ///
    /// - `client`: An `Arc` reference to the client that provides access to the blockchain state.
    /// - `keystore`: A pointer to the keystore used for managing cryptographic keys.
    ///
    /// # Returns
    ///
    /// A new `BabeAuthorityDiscovery` instance initialized with the provided client and keystore.
    pub fn new(client: Arc<C>,  keystore: KeystorePtr,) -> Self {
        Self {
            client,
            keystore,
            _phantom: Default::default(),
        }
    }
}

impl<B, C> AuthorityDiscoveryForTxPool for BabeAuthorityDiscovery<B, C>
where
    B: BlockT,
    C: ProvideRuntimeApi<B> + HeaderBackend<B> + Send + Sync + 'static,
    C::Api: BabeApi<B>,
{
    /// Returns `true` if the client is a validator.
    fn is_authority(&self) -> bool {
        let public_keys = self.keystore.sr25519_public_keys(AuthorityId::ID);
        if public_keys.is_empty() {
            return false;
        }

        let best_hash = self.client.info().best_hash;

        let current_epoch = match self.client.runtime_api().current_epoch(best_hash) {
            Ok(epoch) => epoch,
            Err(e) => {
                log::error!("Failed to get current epoch: {:?}", e);
                return false;
            }
        };

        let current_authorities = current_epoch.authorities;

        // Convert raw keys to AuthorityId and check if they're in current authorities
        public_keys
            .into_iter()
            .map(AuthorityId::from)
            .any(|id| current_authorities.iter().any(|(auth_id, _)| auth_id == &id))
    }

    /// Check if this client can author the block in the next `n` slots.
    fn will_author_in_next_slots(&self, n: u64) -> bool {
        will_author_in_next_slots(&self.client, self.keystore.clone(), n).unwrap_or(false)
    }
}
