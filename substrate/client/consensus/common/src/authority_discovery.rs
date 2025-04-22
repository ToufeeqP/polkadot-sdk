
pub trait AuthorityDiscoveryForTxPool: Send + Sync {
    /// Returns `true` if the client is a validator.
    fn is_authority(&self) -> bool;

    /// Returns `true` if the client will author a block in the next `n` slots.
    fn will_author_in_next_slots(&self, n: u64) -> bool;
}
