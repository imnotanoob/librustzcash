use crate::Pczt;

pub struct IoFinalizer {
    pczt: Pczt,
}

impl IoFinalizer {
    /// Instantiates the IO Finalizer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Finalizes the IO of the PCZT.
    pub fn finalize_io(self) -> Result<Pczt, Error> {
        let Self { mut pczt } = self;

        // We can't build a transaction that has no spends or outputs.
        // However, we don't attempt to reject an entirely dummy transaction.
        if pczt.transparent.inputs.is_empty()
            && pczt.sapling.spends.is_empty()
            && pczt.orchard.actions.is_empty()
        {
            return Err(Error::NoSpends);
        }
        if pczt.transparent.outputs.is_empty()
            && pczt.sapling.outputs.is_empty()
            && pczt.orchard.actions.is_empty()
        {
            return Err(Error::NoOutputs);
        }

        let sapling_bsk = pczt
            .sapling
            .spends
            .iter()
            .map(|spend| {
                spend
                    .rcv_from_field()
                    .map_err(Error::Sapling)
                    .map(|rcv| rcv.inner())
            })
            .chain(pczt.sapling.outputs.iter().map(|output| {
                output
                    .rcv_from_field()
                    .map_err(Error::Sapling)
                    .map(|rcv| -rcv.inner())
            }))
            .try_fold(jubjub::Scalar::zero(), |acc, rcv| Ok(acc + rcv?))?;

        let orchard_rcvs = pczt
            .orchard
            .actions
            .iter()
            .map(|action| action.rcv_from_field().map_err(Error::Orchard))
            .collect::<Result<Vec<_>, _>>()?;
        let orchard_bsk = orchard_rcvs
            .iter()
            .sum::<orchard::value::ValueCommitTrapdoor>();

        pczt.sapling.bsk = Some(sapling_bsk.to_bytes());
        pczt.orchard.bsk = Some(orchard_bsk.to_bytes());

        Ok(pczt)
    }
}

/// Errors that can occur while finalizing the IO of a PCZT.
#[derive(Debug)]
pub enum Error {
    NoOutputs,
    NoSpends,
    Orchard(crate::orchard::Error),
    Sapling(crate::sapling::Error),
}
