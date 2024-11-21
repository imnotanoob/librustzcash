use std::collections::BTreeMap;

use zcash_primitives::{
    legacy::TransparentAddress,
    transaction::components::{transparent, TxOut},
};
use zcash_protocol::value::Zatoshis;

impl super::Constructor {
    /// Adds a transparent coin to be spent in this transaction.
    pub fn add_transparent_input(
        &mut self,
        utxo: transparent::OutPoint,
        coin: TxOut,
        sequence: u32,
        required_locktime: u32,
        sighash_type: u32,
    ) {
        self.pczt
            .transparent
            .inputs
            .push(crate::transparent::Input {
                prevout_txid: *utxo.hash(),
                prevout_index: utxo.n(),
                sequence,
                required_locktime,
                script_sig: None,
                value: coin.value.into_u64(),
                script_pubkey: coin.script_pubkey.0,
                redeem_script: None,
                partial_signatures: BTreeMap::new(),
                sighash_type,
                bip32_derivation: BTreeMap::new(),
                ripemd160_preimages: BTreeMap::new(),
                sha256_preimages: BTreeMap::new(),
                hash160_preimages: BTreeMap::new(),
                hash256_preimages: BTreeMap::new(),
                proprietary: BTreeMap::new(),
            });
    }

    /// Adds a transparent address to send funds to.
    pub fn add_transparent_output(&mut self, to: &TransparentAddress, value: Zatoshis) {
        self.pczt
            .transparent
            .outputs
            .push(crate::transparent::Output {
                value: value.into_u64(),
                script_pubkey: to.script().0,
                redeem_script: None,
                bip32_derivation: BTreeMap::new(),
                proprietary: BTreeMap::new(),
            });
    }
}
