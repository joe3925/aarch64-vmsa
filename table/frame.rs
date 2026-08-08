use crate::address::TranslationGranule;

use super::{TableAddr, TableAllocLayout};

pub trait TableFrame<G>
where
    G: TranslationGranule,
{
    fn addr(&self) -> TableAddr<G>;
}

impl<G> TableFrame<G> for TableAddr<G>
where
    G: TranslationGranule,
{
    fn addr(&self) -> TableAddr<G> {
        *self
    }
}

pub trait TableFrameProvider<G>
where
    G: TranslationGranule,
{
    type Error;
    type Frame: TableFrame<G>;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<Self::Frame, Self::Error>;

    unsafe fn free_table(
        &mut self,
        frame: TableAddr<G>,
        layout: TableAllocLayout,
    ) -> Result<(), Self::Error>;
}
