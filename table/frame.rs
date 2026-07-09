use crate::address::{PhysAddr, TranslationGranule};

use super::{TableAllocLayout, TablePhysAddr};

pub trait TableFrame<G>
where
    G: TranslationGranule,
{
    fn addr(&self) -> TablePhysAddr<G>;

    fn phys(&self) -> PhysAddr {
        self.addr().phys()
    }
}

impl<G> TableFrame<G> for TablePhysAddr<G>
where
    G: TranslationGranule,
{
    fn addr(&self) -> TablePhysAddr<G> {
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
        frame: TablePhysAddr<G>,
        layout: TableAllocLayout,
    ) -> Result<(), Self::Error>;
}
