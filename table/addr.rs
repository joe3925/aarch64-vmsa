use core::marker::PhantomData;

use crate::addr::PhysAddr;
use crate::granule::TranslationGranule;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TablePhysAddr<G>
where
    G: TranslationGranule,
{
    addr: PhysAddr,
    _marker: PhantomData<G>,
}

impl<G> TablePhysAddr<G>
where
    G: TranslationGranule,
{
    pub const unsafe fn new_unchecked(addr: PhysAddr) -> Self {
        Self {
            addr,
            _marker: PhantomData,
        }
    }

    pub fn new(addr: PhysAddr) -> Result<Self, TableAddressError> {
        if addr.0 & (G::SIZE - 1) != 0 {
            return Err(TableAddressError::Unaligned {
                addr,
                align: G::SIZE,
            });
        }

        Ok(unsafe { Self::new_unchecked(addr) })
    }

    pub const fn phys(self) -> PhysAddr {
        self.addr
    }

    pub const fn raw(self) -> u64 {
        self.addr.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableAddressError {
    Unaligned { addr: PhysAddr, align: u64 },
}
