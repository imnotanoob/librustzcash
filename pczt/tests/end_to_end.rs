use std::sync::OnceLock;

use orchard::{builder::BundleType, value::NoteValue};
use rand_core::OsRng;

static ORCHARD_PROVING_KEY: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

fn orchard_proving_key() -> &'static orchard::circuit::ProvingKey {
    ORCHARD_PROVING_KEY.get_or_init(|| orchard::circuit::ProvingKey::build())
}

#[test]
fn transparent_to_orchard() {
    use pczt::roles::{
        constructor::Constructor, creator::Creator, io_finalizer::IoFinalizer, prover::Prover,
        signer::Signer, tx_extractor::TransactionExtractor,
    };
    use zcash_protocol::consensus::BranchId;

    let sapling_anchor = sapling::Anchor::empty_tree();
    let orchard_anchor = orchard::tree::Anchor::empty_tree();

    // Create an Orchard account to receive funds.
    let orchard_sk = orchard::keys::SpendingKey::from_bytes([0; 32]).unwrap();
    let orchard_fvk = orchard::keys::FullViewingKey::from(&orchard_sk);
    let orchard_ovk = orchard_fvk.to_ovk(orchard::keys::Scope::External);
    let recipient = orchard_fvk.address_at(0, orchard::keys::Scope::External);

    // Build the Orchard bundle we'll be using.
    let builder = orchard::builder::Builder::new(BundleType::DEFAULT, orchard_anchor);
    builder
        .add_output(
            Some(orchard_ovk),
            recipient,
            NoteValue::from_raw(100_000),
            None,
        )
        .unwrap();
    let (unauthed_bundle, _) = builder.build(OsRng).unwrap().unwrap();

    // Create the base PCZT.
    let pczt = Creator::new(
        BranchId::Nu5.into(),
        10_000_000,
        sapling_anchor.to_bytes(),
        orchard_anchor.to_bytes(),
    )
    .build();

    // Add spends and outputs.
    let mut constructor = Constructor::new(pczt);
    for action in unauthed_bundle.actions() {
        constructor
            .add_orchard_action(
                spend_fvk,
                spend_note,
                output_note,
                epk,
                enc_ciphertext,
                out_ciphertext,
                rcv,
            )
            .unwrap();
    }
    let pczt = constructor.finish();

    // Finalize the I/O.
    let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();

    // Create proofs.
    let mut prover = Prover::new(pczt);
    prover.create_orchard_proof(orchard_proving_key()).unwrap();
    let pczt = prover.finish();

    // Apply signatures.
    let signer = Signer::new(pczt).unwrap();
    signer.sign_orchard(index, ask).unwrap();
    let pczt = signer.finish();

    // We should now be able to extract the fully authorized transaction.
    let tx = TransactionExtractor::new(pczt).extract().unwrap();

    assert_eq!(tx.expiry_height().into(), 10_000_000);
}
