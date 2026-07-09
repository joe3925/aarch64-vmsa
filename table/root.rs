use core::marker::PhantomData;

use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;

use super::TablePhysAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTable<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    addr: TablePhysAddr<G>,
    level: Level,
    addr_bits: u8,
    _marker: PhantomData<F>,
}

impl<F, G> RootTable<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn new(addr: TablePhysAddr<G>, level: Level, addr_bits: u8) -> Self {
        Self {
            addr,
            level,
            addr_bits,
            _marker: PhantomData,
        }
    }

    pub const fn addr(self) -> TablePhysAddr<G> {
        self.addr
    }

    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn addr_bits(self) -> u8 {
        self.addr_bits
    }
}
