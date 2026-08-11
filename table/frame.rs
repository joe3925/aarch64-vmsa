use crate::address::TranslationGranule;

use super::{TableAddr, TableAllocLayout};

#[derive(Debug, Eq, PartialEq)]
pub struct TableReclaim<G: TranslationGranule> {
    addr: TableAddr<G>,
    layout: TableAllocLayout,
}

impl<G: TranslationGranule> TableReclaim<G> {
    pub(crate) const fn new(addr: TableAddr<G>, layout: TableAllocLayout) -> Self {
        Self { addr, layout }
    }
    pub const fn addr(&self) -> TableAddr<G> {
        self.addr
    }
    pub const fn layout(&self) -> TableAllocLayout {
        self.layout
    }
}

/// This trait allocates and reclaims memory that translation tables use.
///
/// # Safety
/// Each returned address must identify one zero-initialized allocation.
/// An active allocation must not overlap a different active allocation.
/// The allocation must have the specified size and alignment.
/// It must stay allocated and available to hardware until the provider receives the crate-issued
/// [`TableReclaim`] token for the allocation.
pub unsafe trait TableFrameProvider<G>
where
    G: TranslationGranule,
{
    type Error;

    fn allocate_zeroed_table(
        &mut self,
        layout: TableAllocLayout,
    ) -> Result<TableAddr<G>, Self::Error>;

    fn reclaim_table(&mut self, reclaim: TableReclaim<G>) -> Result<(), Self::Error>;
}
