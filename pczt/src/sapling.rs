use std::collections::BTreeMap;

use crate::{
    common::Zip32Derivation,
    roles::combiner::{merge_map, merge_optional},
    IgnoreMissing,
};

#[cfg(feature = "sapling")]
use {
    ff::PrimeField,
    sapling::{
        keys::SpendValidatingKey, value::NoteValue, value::ValueCommitTrapdoor, MerklePath, Node,
        Note, PaymentAddress, Rseed,
    },
};

const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;

/// PCZT fields that are specific to producing the transaction's Sapling bundle (if any).
#[derive(Clone, Debug)]
pub(crate) struct Bundle {
    pub(crate) spends: Vec<Spend>,
    pub(crate) outputs: Vec<Output>,

    /// The net value of Sapling spends minus outputs.
    ///
    /// This is initialized by the Creator, and updated by the Constructor as spends or
    /// outputs are added to the PCZT. It enables per-spend and per-output values to be
    /// redacted from the PCZT after they are no longer necessary.
    //
    // TODO: This is technically too small to contain the full range of intermediate value
    // balances. Either:
    // - Change to u128 and rely on the circuit to constrain each action balance.
    // - Change to i64 and have it be calculated by the IO Finalizer (which would then
    //   require all values).
    pub(crate) value_balance: u64,

    /// The Sapling anchor for this transaction.
    ///
    /// Set by the Creator.
    pub(crate) anchor: [u8; 32],

    /// The Sapling binding signature signing key.
    ///
    /// - This is `None` until it is set by the IO Finalizer.
    /// - The Transaction Extractor uses this to produce the binding signature.
    pub(crate) bsk: Option<[u8; 32]>,
}

/// Information about a Sapling spend within a transaction.
#[derive(Clone, Debug)]
pub(crate) struct Spend {
    //
    // SpendDescription effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) cv: [u8; 32],
    pub(crate) nullifier: [u8; 32],
    pub(crate) rk: [u8; 32],

    /// The Spend proof.
    ///
    /// This is set by the Prover.
    pub(crate) zkproof: Option<[u8; GROTH_PROOF_SIZE]>,

    /// The spend authorization signature.
    ///
    /// This is set by the Signer.
    pub(crate) spend_auth_sig: Option<[u8; 64]>,

    /// The address that received the note being spent.
    ///
    /// - This is set by the Constructor (or Updater?).
    /// - This is required by the Prover.
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the input being spent.
    ///
    /// This may be used by Signers to verify that the value matches `cv`, and to confirm
    /// the values and change involved in the transaction.
    ///
    /// This exposes the input value to all participants. For Signers who don't need this
    /// information, or after signatures have been applied, this can be redacted.
    pub(crate) value: Option<u64>,

    /// The seed randomness for the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    pub(crate) rseed: Option<[u8; 32]>,

    /// The value commitment randomness.
    ///
    /// - This is set by the Constructor.
    /// - The IO Finalizer compresses it into the bsk.
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value correctly matches `cv`.
    ///
    /// This opens `cv` for all participants. For Signers who don't need this information,
    /// or after proofs / signatures have been applied, this can be redacted.
    pub(crate) rcv: Option<[u8; 32]>,

    /// The proof generation key `(ak, nsk)` corresponding to the recipient that received
    /// the note being spent.
    ///
    /// - This is set by the Updater.
    /// - This is required by the Prover.
    pub(crate) proof_generation_key: Option<([u8; 32], [u8; 32])>,

    /// A witness from the note to the bundle's anchor.
    ///
    /// - This is set by the Updater.
    /// - This is required by the Prover.
    pub(crate) witness: Option<(u32, [[u8; 32]; 32])>,

    /// The spend authorization randomizer.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the Signer for creating `spend_auth_sig`, and may be used to
    ///   validate `rk`.
    /// - After`zkproof` / `spend_auth_sig` has been set, this can be redacted.
    pub(crate) alpha: Option<[u8; 32]>,

    /// The ZIP 32 derivation path at which the spending key can be found for the note
    /// being spent.
    pub(crate) zip32_derivation: Option<Zip32Derivation>,

    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// Information about a Sapling output within a transaction.
#[derive(Clone, Debug)]
pub(crate) struct Output {
    //
    // OutputDescription effecting data.
    //
    // These are required fields that are part of the final transaction, and are filled in
    // by the Constructor when adding an output.
    //
    pub(crate) cv: [u8; 32],
    pub(crate) cmu: [u8; 32],
    pub(crate) ephemeral_key: [u8; 32],
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    ///
    /// Once we have memo bundles, we will be able to set memos independently of Outputs.
    /// For now, the Constructor sets both at the same time.
    pub(crate) enc_ciphertext: Vec<u8>,
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    pub(crate) out_ciphertext: Vec<u8>,

    /// The Output proof.
    ///
    /// This is set by the Prover.
    pub(crate) zkproof: Option<[u8; GROTH_PROOF_SIZE]>,

    /// The address that will receive the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the output.
    ///
    /// This may be used by Signers to verify that the value matches `cv`, and to confirm
    /// the values and change involved in the transaction.
    ///
    /// This exposes the output value to all participants. For Signers who don't need this
    /// information, or after signatures have been applied, this can be redacted.
    pub(crate) value: Option<u64>,

    /// The seed randomness for the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover, instead of disclosing `shared_secret` to them.
    pub(crate) rseed: Option<[u8; 32]>,

    /// The value commitment randomness.
    ///
    /// - This is set by the Constructor.
    /// - The IO Finalizer compresses it into the bsk.
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value correctly matches `cv`.
    ///
    /// This opens `cv` for all participants. For Signers who don't need this information,
    /// or after proofs / signatures have been applied, this can be redacted.
    pub(crate) rcv: Option<[u8; 32]>,

    /// The symmetric shared secret used to encrypt `enc_ciphertext`.
    ///
    /// This enables Signers to verify that `enc_ciphertext` is correctly encrypted (and
    /// contains a note plaintext matching the public commitments), and to confirm the
    /// value of the memo.
    pub(crate) shared_secret: Option<[u8; 32]>,

    /// The `ock` value used to encrypt `out_ciphertext`.
    ///
    /// This enables Signers to verify that `out_ciphertext` is correctly encrypted.
    ///
    /// This may be `None` if the Constructor added the output using an OVK policy of
    /// "None", to make the output unrecoverable from the chain by the sender.
    pub(crate) ock: Option<[u8; 32]>,

    /// The ZIP 32 derivation path at which the spending key can be found for the output.
    pub(crate) zip32_derivation: Option<Zip32Derivation>,

    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(mut self, other: Self) -> Option<Self> {
        // Destructure `other` to ensure we handle everything.
        let Self {
            mut spends,
            mut outputs,
            value_balance,
            anchor,
            bsk,
        } = other;

        // If `bsk` is set on either bundle, the IO Finalizer has run, which means we
        // cannot have differing numbers of spends or outputs, and the value balances must
        // match.
        match (self.bsk.as_mut(), bsk) {
            (Some(lhs), Some(rhs)) if lhs != &rhs => return None,
            (Some(_), _) | (_, Some(_))
                if self.spends.len() != spends.len()
                    || self.outputs.len() != outputs.len()
                    || self.value_balance != value_balance =>
            {
                return None
            }
            // IO Finalizer has run, and neither bundle has excess spends or outputs.
            (Some(_), _) | (_, Some(_)) => (),
            // IO Finalizer has not run on either bundle. If the other bundle has more
            // spends or outputs than us, move them over; these cannot conflict by
            // construction.
            (None, None) => {
                if spends.len() > self.spends.len() {
                    // TODO: Update `self.value_balance`.
                    self.spends.extend(spends.drain(self.spends.len()..));
                }
                if outputs.len() > self.outputs.len() {
                    // TODO: Update `self.value_balance`.
                    self.outputs.extend(outputs.drain(self.outputs.len()..));
                }
            }
        }

        if self.anchor != anchor {
            return None;
        }

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.spends.iter_mut().zip(spends.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Spend {
                cv,
                nullifier,
                rk,
                zkproof,
                spend_auth_sig,
                recipient,
                value,
                rseed,
                rcv,
                proof_generation_key,
                witness,
                alpha,
                zip32_derivation,
                proprietary,
            } = rhs;

            if lhs.cv != cv || lhs.nullifier != nullifier || lhs.rk != rk {
                return None;
            }

            if !(merge_optional(&mut lhs.zkproof, zkproof)
                && merge_optional(&mut lhs.spend_auth_sig, spend_auth_sig)
                && merge_optional(&mut lhs.recipient, recipient)
                && merge_optional(&mut lhs.value, value)
                && merge_optional(&mut lhs.rseed, rseed)
                && merge_optional(&mut lhs.rcv, rcv)
                && merge_optional(&mut lhs.proof_generation_key, proof_generation_key)
                && merge_optional(&mut lhs.witness, witness)
                && merge_optional(&mut lhs.alpha, alpha)
                && merge_optional(&mut lhs.zip32_derivation, zip32_derivation)
                && merge_map(&mut lhs.proprietary, proprietary))
            {
                return None;
            }
        }

        for (lhs, rhs) in self.outputs.iter_mut().zip(outputs.into_iter()) {
            // Destructure `rhs` to ensure we handle everything.
            let Output {
                cv,
                cmu,
                ephemeral_key,
                enc_ciphertext,
                out_ciphertext,
                zkproof,
                recipient,
                value,
                rseed,
                rcv,
                shared_secret,
                ock,
                zip32_derivation,
                proprietary,
            } = rhs;

            if lhs.cv != cv
                || lhs.cmu != cmu
                || lhs.ephemeral_key != ephemeral_key
                || lhs.enc_ciphertext != enc_ciphertext
                || lhs.out_ciphertext != out_ciphertext
            {
                return None;
            }

            if !(merge_optional(&mut lhs.zkproof, zkproof)
                && merge_optional(&mut lhs.recipient, recipient)
                && merge_optional(&mut lhs.value, value)
                && merge_optional(&mut lhs.rseed, rseed)
                && merge_optional(&mut lhs.rcv, rcv)
                && merge_optional(&mut lhs.shared_secret, shared_secret)
                && merge_optional(&mut lhs.ock, ock)
                && merge_optional(&mut lhs.zip32_derivation, zip32_derivation)
                && merge_map(&mut lhs.proprietary, proprietary))
            {
                return None;
            }
        }

        Some(self)
    }
}

#[cfg(feature = "sapling")]
impl Bundle {
    pub(crate) fn to_tx_data<A, E, F, G, H, I>(
        &self,
        spend_proof: F,
        spend_auth: G,
        output_proof: H,
        bundle_auth: I,
    ) -> Result<Option<sapling::Bundle<A, zcash_protocol::value::ZatBalance>>, E>
    where
        A: sapling::bundle::Authorization,
        E: From<Error>,
        F: Fn(&Spend) -> Result<<A as sapling::bundle::Authorization>::SpendProof, E>,
        G: Fn(&Spend) -> Result<<A as sapling::bundle::Authorization>::AuthSig, E>,
        H: Fn(&Output) -> Result<<A as sapling::bundle::Authorization>::OutputProof, E>,
        I: FnOnce(&Self) -> Result<A, E>,
    {
        use sapling::{
            bundle::{OutputDescription, SpendDescription},
            note::ExtractedNoteCommitment,
            value::ValueCommitment,
            Bundle, Nullifier,
        };
        use zcash_note_encryption::EphemeralKeyBytes;
        use zcash_protocol::value::ZatBalance;

        let anchor = bls12_381::Scalar::from_bytes(&self.anchor)
            .into_option()
            .ok_or(Error::InvalidAnchor)?;

        let spends = self
            .spends
            .iter()
            .map(|spend| {
                let cv = ValueCommitment::from_bytes_not_small_order(&spend.cv)
                    .into_option()
                    .ok_or(Error::InvalidValueCommitment)?;

                let nullifier = Nullifier(spend.nullifier);

                let rk = redjubjub::VerificationKey::try_from(spend.rk)
                    .map_err(|_| Error::InvalidRandomizedKey)?;

                Ok(SpendDescription::from_parts(
                    cv,
                    anchor,
                    nullifier,
                    rk,
                    spend_proof(spend)?,
                    spend_auth(spend)?,
                ))
            })
            .collect::<Result<_, E>>()?;

        let outputs = self
            .outputs
            .iter()
            .map(|output| {
                let cv = ValueCommitment::from_bytes_not_small_order(&output.cv)
                    .into_option()
                    .ok_or(Error::InvalidValueCommitment)?;

                let cmu = ExtractedNoteCommitment::from_bytes(&output.cmu)
                    .into_option()
                    .ok_or(Error::InvalidExtractedNoteCommitment)?;

                let ephemeral_key = EphemeralKeyBytes(output.ephemeral_key);

                Ok(OutputDescription::from_parts(
                    cv,
                    cmu,
                    ephemeral_key,
                    output
                        .enc_ciphertext
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidEncCiphertext)?,
                    output
                        .out_ciphertext
                        .as_slice()
                        .try_into()
                        .map_err(|_| Error::InvalidOutCiphertext)?,
                    output_proof(output)?,
                ))
            })
            .collect::<Result<_, E>>()?;

        let value_balance =
            ZatBalance::from_u64(self.value_balance).map_err(|e| Error::InvalidValueBalance(e))?;

        let authorization = bundle_auth(&self)?;

        Ok(Bundle::from_parts(
            spends,
            outputs,
            value_balance,
            authorization,
        ))
    }
}

#[cfg(feature = "sapling")]
impl Spend {
    /// Parses a [`Note`] from the explicit fields of this spend.
    pub(crate) fn note_from_fields(&self) -> Result<Note, Error> {
        // We want to parse all fields that are present for validity, before raising any
        // errors about missing fields.

        let recipient = self
            .recipient
            .as_ref()
            .map(|r| PaymentAddress::from_bytes(r).ok_or(Error::InvalidRecipient))
            .transpose()?;

        let value = self.value.map(NoteValue::from_raw);
        let rseed = self.rseed.map(Rseed::AfterZip212);

        Ok(Note::from_parts(
            recipient.ok_or(Error::MissingRecipient)?,
            value.ok_or(Error::MissingValue)?,
            rseed.ok_or(Error::MissingRandomSeed)?,
        ))
    }

    pub(crate) fn rcv_from_field(&self) -> Result<ValueCommitTrapdoor, Error> {
        ValueCommitTrapdoor::from_bytes(self.rcv.ok_or(Error::MissingValueCommitTrapdoor)?)
            .into_option()
            .ok_or(Error::InvalidValueCommitTrapdoor)
    }

    pub(crate) fn proof_generation_key_from_field(
        &self,
    ) -> Result<sapling::ProofGenerationKey, Error> {
        let (ak, nsk) = self
            .proof_generation_key
            .ok_or(Error::MissingProofGenerationKey)?;

        Ok(sapling::ProofGenerationKey {
            ak: SpendValidatingKey::temporary_zcash_from_bytes(&ak)
                .ok_or(Error::InvalidProofGenerationKey)?,
            nsk: jubjub::Scalar::from_repr(nsk)
                .into_option()
                .ok_or(Error::InvalidProofGenerationKey)?,
        })
    }

    pub(crate) fn witness_from_field(&self) -> Result<MerklePath, Error> {
        let (position, auth_path_bytes) = self.witness.ok_or(Error::MissingWitness)?;

        let path_elems = auth_path_bytes
            .into_iter()
            .map(|hash| {
                Node::from_bytes(hash)
                    .into_option()
                    .ok_or(Error::InvalidWitness)
            })
            .collect::<Result<Vec<_>, _>>()?;

        MerklePath::from_parts(path_elems, u64::from(position).into())
            .map_err(|()| Error::InvalidWitness)
    }

    pub(crate) fn alpha_from_field(&self) -> Result<jubjub::Scalar, Error> {
        jubjub::Scalar::from_repr(self.alpha.ok_or(Error::MissingSpendAuthRandomizer)?)
            .into_option()
            .ok_or(Error::InvalidSpendAuthRandomizer)
    }
}

#[cfg(feature = "sapling")]
impl Output {
    pub(crate) fn rcv_from_field(&self) -> Result<ValueCommitTrapdoor, Error> {
        ValueCommitTrapdoor::from_bytes(self.rcv.ok_or(Error::MissingValueCommitTrapdoor)?)
            .into_option()
            .ok_or(Error::InvalidValueCommitTrapdoor)
    }
}

#[cfg(feature = "sapling")]
#[derive(Debug)]
pub enum Error {
    InvalidAnchor,
    InvalidEncCiphertext,
    InvalidExtractedNoteCommitment,
    InvalidOutCiphertext,
    InvalidProofGenerationKey,
    InvalidRandomizedKey,
    InvalidRecipient,
    InvalidSpendAuthRandomizer,
    InvalidValueBalance(zcash_protocol::value::BalanceError),
    InvalidValueCommitment,
    InvalidValueCommitTrapdoor,
    InvalidWitness,
    MissingProofGenerationKey,
    MissingRandomSeed,
    MissingRecipient,
    MissingSpendAuthRandomizer,
    MissingValue,
    MissingValueCommitTrapdoor,
    MissingWitness,
}

#[cfg(feature = "sapling")]
impl<V> IgnoreMissing for Result<V, Error> {
    type Value = V;
    type Error = Error;

    fn ignore_missing(self) -> Result<Option<Self::Value>, Self::Error> {
        self.map(Some).or_else(|e| match e {
            Error::MissingProofGenerationKey
            | Error::MissingRandomSeed
            | Error::MissingRecipient
            | Error::MissingSpendAuthRandomizer
            | Error::MissingValue
            | Error::MissingValueCommitTrapdoor
            | Error::MissingWitness => Ok(None),
            _ => Err(e),
        })
    }
}
