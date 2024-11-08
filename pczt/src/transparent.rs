use std::collections::BTreeMap;

use crate::roles::combiner::{merge_map, merge_optional};

#[cfg(feature = "transparent")]
use {
    zcash_primitives::{
        legacy::Script,
        transaction::components::{transparent, OutPoint},
    },
    zcash_protocol::value::Zatoshis,
};

/// PCZT fields that are specific to producing the transaction's transparent bundle (if
/// any).
#[derive(Clone, Debug)]
pub(crate) struct Bundle {
    pub(crate) inputs: Vec<Input>,
    pub(crate) outputs: Vec<Output>,
}

#[derive(Clone, Debug)]
pub(crate) struct Input {
    //
    // Transparent effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) prevout_txid: [u8; 32],
    pub(crate) prevout_index: u32,
    /// TODO: which role should set this?
    pub(crate) sequence: u32,

    /// TODO: Both time-based and height-based?
    pub(crate) required_locktime: u32,

    /// A satisfying witness for the `script_pubkey` of the input being spent.
    ///
    /// This is set by the Spend Finalizer.
    pub(crate) script_sig: Option<Vec<u8>>,

    // These are required by the Transaction Extractor, to derive the shielded sighash
    // needed for computing the binding signatures.
    pub(crate) value: u64,
    pub(crate) script_pubkey: Vec<u8>,

    /// The script required to spend this output, if it is P2SH.
    ///
    /// Set to `None` if this is a P2PKH output.
    pub(crate) redeem_script: Option<Vec<u8>>,

    /// A map from a pubkey to a signature created by it.
    ///
    /// - Each pubkey should appear in `script_pubkey` or `redeem_script`.
    /// - Each entry is set by a Signer, and should contain an ECDSA signature that is
    ///   valid under the corresponding pubkey.
    /// - These are required by the Spend Finalizer to assemble `script_sig`.
    ///
    /// TODO: Decide on map key type.
    pub(crate) partial_signatures: BTreeMap<Vec<u8>, Vec<u8>>,

    /// The sighash type to be used for this input.
    ///
    /// - Signers must use this sighash type to produce their signatures. Signers that
    ///   cannot produce signatures for this sighash type must not provide a signature.
    /// - Spend Finalizers must fail to finalize inputs which have signatures that do not
    ///   match this sighash type.
    pub(crate) sighash_type: u32,

    /// Mappings of the form `key = RIPEMD160(value)`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) ripemd160_preimages: BTreeMap<[u8; 20], Vec<u8>>,

    /// Mappings of the form `key = SHA256(value)`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) sha256_preimages: BTreeMap<[u8; 32], Vec<u8>>,

    /// Mappings of the form `key = RIPEMD160(SHA256(value))`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) hash160_preimages: BTreeMap<[u8; 20], Vec<u8>>,

    /// Mappings of the form `key = SHA256(SHA256(value))`.
    ///
    /// - These may be used by the Signer to inspect parts of `script_pubkey` or
    ///   `redeem_script`.
    pub(crate) hash256_preimages: BTreeMap<[u8; 32], Vec<u8>>,
}

#[derive(Clone, Debug)]
pub(crate) struct Output {
    //
    // Transparent effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) value: u64,
    pub(crate) script_pubkey: Vec<u8>,

    /// The script required to spend this output, if it is P2SH.
    ///
    /// Set to `None` if this is a P2PKH output.
    pub(crate) redeem_script: Option<Vec<u8>>,
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(mut self, other: Self) -> Option<Self> {
        // Destructure `other` to ensure we handle everything.
        let Self {
            mut inputs,
            mut outputs,
        } = other;

        // If the other bundle has more inputs or outputs than us, move them over; these
        // cannot conflict by construction.
        self.inputs.extend(inputs.drain(self.inputs.len()..));
        self.outputs.extend(outputs.drain(self.outputs.len()..));

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.inputs.iter_mut().zip(inputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Input {
                prevout_txid,
                prevout_index,
                sequence,
                required_locktime,
                script_sig,
                value,
                script_pubkey,
                redeem_script,
                partial_signatures,
                sighash_type,
                ripemd160_preimages,
                sha256_preimages,
                hash160_preimages,
                hash256_preimages,
            } = rhs;

            if lhs.prevout_txid != prevout_txid
                || lhs.prevout_index != prevout_index
                || lhs.sequence != sequence
                || lhs.required_locktime != required_locktime
                || lhs.value != value
                || lhs.script_pubkey != script_pubkey
                || lhs.sighash_type != sighash_type
            {
                return None;
            }

            if !(merge_optional(&mut lhs.script_sig, script_sig)
                && merge_optional(&mut lhs.redeem_script, redeem_script)
                && merge_map(&mut lhs.partial_signatures, partial_signatures)
                && merge_map(&mut lhs.ripemd160_preimages, ripemd160_preimages)
                && merge_map(&mut lhs.sha256_preimages, sha256_preimages)
                && merge_map(&mut lhs.hash160_preimages, hash160_preimages)
                && merge_map(&mut lhs.hash256_preimages, hash256_preimages))
            {
                return None;
            }
        }

        for (lhs, rhs) in self.outputs.iter_mut().zip(outputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Output {
                value,
                script_pubkey,
                redeem_script,
            } = rhs;

            if lhs.value != value || lhs.script_pubkey != script_pubkey {
                return None;
            }

            if !merge_optional(&mut lhs.redeem_script, redeem_script) {
                return None;
            }
        }

        Some(self)
    }
}

#[cfg(feature = "transparent")]
impl Bundle {
    pub(crate) fn to_tx_data<A, E, F, G>(
        &self,
        script_sig: F,
        bundle_auth: G,
    ) -> Result<Option<transparent::Bundle<A>>, E>
    where
        A: transparent::Authorization,
        E: From<Error>,
        F: Fn(&Input) -> Result<<A as transparent::Authorization>::ScriptSig, E>,
        G: FnOnce(&Self) -> Result<A, E>,
    {
        let vin = self
            .inputs
            .iter()
            .map(|input| {
                let prevout = OutPoint::new(input.prevout_txid, input.prevout_index);

                Ok(transparent::TxIn {
                    prevout,
                    script_sig: script_sig(input)?,
                    sequence: input.sequence,
                })
            })
            .collect::<Result<Vec<_>, E>>()?;

        let vout = self
            .outputs
            .iter()
            .map(|output| {
                let value = Zatoshis::from_u64(output.value).map_err(|_| Error::InvalidValue)?;
                let script_pubkey = Script(output.script_pubkey.clone());

                Ok(transparent::TxOut {
                    value,
                    script_pubkey,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(if vin.is_empty() && vout.is_empty() {
            None
        } else {
            Some(transparent::Bundle {
                vin,
                vout,
                authorization: bundle_auth(self)?,
            })
        })
    }
}

#[cfg(feature = "transparent")]
#[derive(Debug)]
pub enum Error {
    InvalidValue,
}
