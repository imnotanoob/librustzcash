use crate::Pczt;

#[cfg(feature = "orchard")]
mod orchard;

// #[cfg(feature = "sapling")]
// mod sapling;

#[cfg(feature = "transparent")]
mod transparent;

pub struct Constructor {
    pczt: Pczt,
}

impl Constructor {
    /// Instantiates the Constructor role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Finishes the Constructor role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}
