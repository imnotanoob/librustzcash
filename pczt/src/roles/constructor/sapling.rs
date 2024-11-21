use std::collections::BTreeMap;

use ff::Field;
use rand_core::OsRng;
use sapling::{
    keys::{EphemeralPublicKey, FullViewingKey},
    note_encryption::SaplingDomain,
    value::{ValueCommitTrapdoor, ValueCommitment},
    Note,
};
use zcash_note_encryption::Domain;

impl super::Constructor {
    /// Adds a Sapling note to be spent in this transaction.
    pub fn add_sapling_spend(
        &mut self,
        fvk: &FullViewingKey,
        note: &Note,
        position: u64,
        rcv: &ValueCommitTrapdoor,
    ) -> Result<(), SaplingError> {
        self.pczt.sapling.value_balance = self
            .pczt
            .sapling
            .value_balance
            .checked_add(note.value().inner())
            .ok_or(SaplingError::BalanceViolation)?;

        let cv = ValueCommitment::derive(note.value(), rcv.clone());

        let alpha = jubjub::Scalar::random(OsRng);
        let rk = fvk.vk.ak.randomize(&alpha);

        self.pczt.sapling.spends.push(crate::sapling::Spend {
            cv: cv.to_bytes(),
            nullifier: note.nf(&fvk.vk.nk, position).0,
            rk: rk.into(),
            zkproof: None,
            spend_auth_sig: None,
            recipient: Some(note.recipient().to_bytes()),
            value: Some(note.value().inner()),
            rseed: Some(note.rseed()),
            rcv: Some(rcv.inner().to_bytes()),
            proof_generation_key: None,
            witness: None,
            alpha: Some(alpha.to_bytes()),
            zip32_derivation: None,
            proprietary: BTreeMap::new(),
        });
        Ok(())
    }

    /// Adds a Sapling address to send funds to.
    pub fn add_sapling_output(
        &mut self,
        note: &Note,
        epk: &EphemeralPublicKey,
        enc_ciphertext: &[u8; 580],
        out_ciphertext: &[u8; 80],
        rcv: &ValueCommitTrapdoor,
    ) -> Result<(), SaplingError> {
        self.pczt.sapling.value_balance = self
            .pczt
            .sapling
            .value_balance
            .checked_sub(note.value().inner())
            .ok_or(SaplingError::BalanceViolation)?;

        let cv = ValueCommitment::derive(note.value(), rcv.clone());

        self.pczt.sapling.outputs.push(crate::sapling::Output {
            cv: cv.to_bytes(),
            cmu: note.cmu().to_bytes(),
            ephemeral_key: SaplingDomain::epk_bytes(epk).0,
            enc_ciphertext: enc_ciphertext.to_vec(),
            out_ciphertext: out_ciphertext.to_vec(),
            zkproof: None,
            recipient: Some(note.recipient().to_bytes()),
            value: Some(note.value().inner()),
            rseed: Some(note.rseed()),
            rcv: Some(rcv.inner().to_bytes()),
            shared_secret: None,
            ock: None,
            zip32_derivation: None,
            proprietary: BTreeMap::new(),
        });

        Ok(())
    }
}

/// Errors that can occur while adding Sapling spends or outputs to a PCZT.
#[derive(Debug)]
pub enum SaplingError {
    BalanceViolation,
}
