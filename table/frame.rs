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

/// Allocates and reclaims memory used as translation tables.
///
/// # Safety
/// Every returned address must identify a distinct, zero-initialized allocation with the
/// requested size and alignment. It must remain allocated and hardware-accessible until the
/// provider receives the corresponding crate-issued [`TableReclaim`] token.
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
