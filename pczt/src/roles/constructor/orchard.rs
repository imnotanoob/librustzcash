use std::collections::BTreeMap;

use ff::{Field, PrimeField};
use orchard::{
    keys::{EphemeralPublicKey, FullViewingKey, SpendValidatingKey},
    note::ExtractedNoteCommitment,
    note_encryption::OrchardDomain,
    value::{ValueCommitTrapdoor, ValueCommitment},
};
use pasta_curves::pallas;
use rand_core::OsRng;
use zcash_note_encryption::Domain;

impl super::Constructor {
    /// Adds an Orchard action to the PCZT.
    pub fn add_orchard_action(
        &mut self,
        spend_fvk: &FullViewingKey,
        spend_note: &orchard::Note,
        output_note: &orchard::Note,
        epk: &EphemeralPublicKey,
        enc_ciphertext: &[u8; 580],
        out_ciphertext: &[u8; 80],
        rcv: &ValueCommitTrapdoor,
    ) -> Result<(), OrchardError> {
        let action_balance = spend_note.value() - output_note.value();

        self.pczt.orchard.value_balance = self
            .pczt
            .orchard
            .value_balance
            .checked_add_signed(
                // TODO: This can throw an error for a technically legitimate action
                // balance.
                i64::try_from(action_balance).map_err(|_| OrchardError::BalanceViolation)?,
            )
            .ok_or(OrchardError::BalanceViolation)?;

        let cv = ValueCommitment::derive(action_balance, rcv.clone());

        let alpha = pallas::Scalar::random(OsRng);
        let ak = SpendValidatingKey::from(spend_fvk.clone());
        let rk = ak.randomize(&alpha);

        self.pczt.orchard.actions.push(crate::orchard::Action {
            cv: cv.to_bytes(),
            spend: crate::orchard::Spend {
                nullifier: spend_note.nullifier(spend_fvk).to_bytes(),
                rk: rk.into(),
                spend_auth_sig: None,
                recipient: Some(spend_note.recipient().to_raw_address_bytes()),
                value: Some(spend_note.value().inner()),
                rho: Some(spend_note.rho().to_bytes()),
                rseed: Some(*spend_note.rseed().as_bytes()),
                // TODO: Documented as being set by the Updater, but the Constructor needs
                // it to derive rk.
                fvk: Some(spend_fvk.to_bytes()),
                witness: None,
                alpha: Some(alpha.to_repr()),
                zip32_derivation: None,
                proprietary: BTreeMap::new(),
            },
            output: crate::orchard::Output {
                cmx: ExtractedNoteCommitment::from(output_note.commitment()).to_bytes(),
                ephemeral_key: OrchardDomain::epk_bytes(&epk).0,
                enc_ciphertext: enc_ciphertext.to_vec(),
                out_ciphertext: out_ciphertext.to_vec(),
                recipient: Some(output_note.recipient().to_raw_address_bytes()),
                value: Some(output_note.value().inner()),
                rseed: Some(*output_note.rseed().as_bytes()),
                shared_secret: None,
                ock: None,
                zip32_derivation: None,
                proprietary: BTreeMap::new(),
            },
            rcv: Some(rcv.to_bytes()),
        });

        Ok(())
    }
}

/// Errors that can occur while adding Orchard actions to a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    BalanceViolation,
}
