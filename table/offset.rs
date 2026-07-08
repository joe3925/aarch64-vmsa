use core::ptr::NonNull;

use crate::addr::VirtAddr;
use crate::format::DescriptorFormat;
use crate::granule::TranslationGranule;

use super::{
    AccessError, TableAccess, TableAccessLocation, TableAccessMut, TablePhysAddr, TranslationTable,
    TranslationTableMut,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffsetTableAccess {
    offset: VirtAddr,
}

impl OffsetTableAccess {
    pub const unsafe fn new(offset: VirtAddr) -> Self {
        Self { offset }
    }

    pub const fn offset(self) -> VirtAddr {
        self.offset
    }

    fn table_ptr<F, G>(&self, addr: TablePhysAddr<G>) -> Result<NonNull<F::Raw>, AccessError>
    where
        F: DescriptorFormat,
        G: TranslationGranule,
    {
        let va = self
            .offset
            .0
            .checked_add(addr.raw())
            .ok_or(AccessError::AddressOverflow)?;

        NonNull::new(va as *mut F::Raw).ok_or(AccessError::NullMapping)
    }
}

unsafe impl<F, G> TableAccess<F, G> for OffsetTableAccess
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type Error = AccessError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        let ptr = self.table_ptr::<F, G>(location.addr)?;

        Ok(unsafe { TranslationTable::from_ptr(ptr, location.level) })
    }
}

unsafe impl<F, G> TableAccessMut<F, G> for OffsetTableAccess
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        let ptr = self.table_ptr::<F, G>(location.addr)?;

        Ok(unsafe { TranslationTableMut::from_ptr(ptr, location.level) })
    }
}
