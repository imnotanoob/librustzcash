use crate::Pczt;

#[cfg(feature = "orchard")]
mod orchard;

#[cfg(feature = "sapling")]
mod sapling;

pub struct Prover {
    pczt: Pczt,
}

impl Prover {
    /// Instantiates the Prover role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Finishes the Prover role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}
