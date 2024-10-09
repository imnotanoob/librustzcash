//! The Partially Created Zcash Transaction (PCZT) format.
//!
//! Goal is to split up the parts of creating a transaction across distinct entities.
//! The entity roles roughly match BIP 174: Partially Signed Bitcoin Transaction Format.
//! - Creator (single entity)
//!   - Creates the base PCZT with no information about spends or outputs.
//! - Constructor (anyone can contribute)
//!   - Adds spends and outputs to the PCZT.
//!   - A single entity is likely to be both a Creator and Constructor.
//! - Combiner (anyone can execute)
//!   - Combines several PCZTs that represent the same transaction into a single PCZT.
//!   - Because we aren't storing the partial transaction in network format, we need to
//!     carefully define equality for PCZTs.
//!     - If we say "pczt.global must be identical" then:
//!       - If we add spends or outputs in series, we should always update bsk when adding
//!         spends or outputs, even if rcv is present.
//!       - If we add spends or outputs in parallel and then combine, we must _never_ update
//!         bsk, and then update it when we prepare for signature creation.
//!       We can't control which happens, ergo we need an IO Finalizer step.
//!     - Once every spend and output has its zkproof field set, PCZT equality MUST include
//!       the SpendDescription and OutputDescription contents being identical.
//!       - In practice enforced by creating a TransactionData / CMutableTransaction from
//!         the PCZT, with spendAuthSigs and bindingSig empty, and then enforcing equality.
//!       - This is equivalent to BIP 147's equality definition (the partial transactions
//!         must be identical).
//! - Transaction Extractor (anyone can execute)
//!   - Creates bindingSig and extracts the final transaction.

pub mod roles;

mod common;
mod orchard;
mod sapling;
mod transparent;

const V5_TX_VERSION: u32 = 5;
const V5_VERSION_GROUP_ID: u32 = 0x26A7270A;

/// A partially-created Zcash transaction.
#[derive(Clone, Debug)]
pub struct Pczt {
    /// Global fields that are relevant to the transaction as a whole.
    global: common::Global,

    //
    // Protocol-specific fields.
    //
    // Unlike the `TransactionData` type in `zcash_primitives`, these are not optional.
    // This is because a PCZT does not always contain a semantically-valid transaction,
    // and there may be phases where we need to store protocol-specific metadata before
    // it has been determined whether there are protocol-specific inputs or outputs.
    //
    transparent: transparent::Bundle,
    sapling: sapling::Bundle,
    orchard: orchard::Bundle,
}
