/// Global fields that are relevant to the transaction as a whole.
#[derive(Clone, Debug)]
pub(crate) struct Global {
    //
    // Transaction effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Creator when initializing the PCZT.
    //
    pub(crate) tx_version: u32,
    pub(crate) version_group_id: u32,
    /// The consensus branch ID for the chain in which this transaction will be mined.
    ///
    /// Non-optional because this commits to the set of consensus rules that will apply to
    /// the transaction; differences therein can affect every role.
    pub(crate) consensus_branch_id: u32,
    /// TODO: In PSBT this is `fallback_lock_time`; decide whether this should have the
    /// same semantics.
    pub(crate) lock_time: u32,
    pub(crate) expiry_height: u32,
}

impl Global {
    pub(crate) fn merge(self, other: Self) -> Option<Self> {
        let Self {
            tx_version,
            version_group_id,
            consensus_branch_id,
            lock_time,
            expiry_height,
        } = other;

        if self.tx_version != tx_version
            || self.version_group_id != version_group_id
            || self.consensus_branch_id != consensus_branch_id
            || self.lock_time != lock_time
            || self.expiry_height != expiry_height
        {
            return None;
        }

        Some(self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Zip32Derivation {
    /// The [ZIP 32 seed fingerprint](https://zips.z.cash/zip-0032#seed-fingerprints).
    seed_fingerprint: [u8; 32],

    /// The sequence of indices corresponding to the shielded HD path.
    ///
    /// Indices can be hardened or non-hardened (i.e. the hardened flag bit may be set).
    /// When used with a Sapling or Orchard spend, the derivation path will generally be
    /// entirely hardened; when used with a transparent spend, the derivation path will
    /// generally include a non-hardened section matching either the [BIP 44] path, or the
    /// path at which ephemeral addresses are derived for [ZIP 320] transactions.
    ///
    /// [BIP 44]: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
    /// [ZIP 320]: https://zips.z.cash/zip-0320
    derivation_path: Vec<u32>,
}
