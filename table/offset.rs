use core::ptr::NonNull;

use crate::address::TranslationGranule;
use crate::address::VirtAddr;
use crate::descriptor::DescriptorFormat;

use super::{
    AccessError, TableAccess, TableAccessLocation, TableAccessMut, TableAddr, TranslationTable,
    TranslationTableMut,
};

#[derive(Debug, Eq, PartialEq)]
pub struct DirectMapRegion {
    offset: VirtAddr,
    table_start: u64,
    table_len: u64,
}

impl DirectMapRegion {
    /// Defines a direct-map region.
    ///
    /// # Safety
    /// The complete address range must map to stable, initialized, writable memory at `offset`.
    pub const unsafe fn from_raw_parts(offset: VirtAddr, table_start: u64, table_len: u64) -> Self {
        Self {
            offset,
            table_start,
            table_len,
        }
    }

    pub const fn offset(&self) -> VirtAddr {
        self.offset
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct OffsetTableAccess {
    region: DirectMapRegion,
}

impl OffsetTableAccess {
    pub const fn new(region: DirectMapRegion) -> Self {
        Self { region }
    }

    pub const fn offset(&self) -> VirtAddr {
        self.region.offset
    }

    fn table_ptr<F, G>(
        &self,
        addr: TableAddr<G>,
        bytes: u64,
    ) -> Result<NonNull<F::Raw>, AccessError>
    where
        F: DescriptorFormat,
        G: TranslationGranule,
    {
        let end = addr
            .raw()
            .checked_add(bytes)
            .ok_or(AccessError::AddressOverflow)?;
        let region_end = self
            .region
            .table_start
            .checked_add(self.region.table_len)
            .ok_or(AccessError::AddressOverflow)?;
        if addr.raw() < self.region.table_start || end > region_end {
            return Err(AccessError::AddressOverflow);
        }
        let va = self
            .region
            .offset
            .0
            .checked_add(addr.raw())
            .ok_or(AccessError::AddressOverflow)?;

        NonNull::new(va as *mut F::Raw).ok_or(AccessError::NullMapping)
    }
}

// SAFETY: The region contract keeps each returned table readable for its borrow.
unsafe impl<F, G> TableAccess<F, G> for OffsetTableAccess
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type Error = AccessError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<'a, F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        let ptr =
            self.table_ptr::<F, G>(location.addr(), location.shape().alloc_layout()?.bytes())?;

        // SAFETY: guaranteed by the unsafe `TableAccess` implementation contract and constructor.
        Ok(unsafe { TranslationTable::from_raw_parts(ptr, location.shape()) })
    }
}

// SAFETY: The region contract keeps each returned table readable for its borrow.
unsafe impl<F, G> TableAccessMut<F, G> for OffsetTableAccess
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<'a, F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        let ptr =
            self.table_ptr::<F, G>(location.addr(), location.shape().alloc_layout()?.bytes())?;

        // SAFETY: guaranteed by the unsafe `TableAccessMut` implementation contract and constructor.
        Ok(unsafe { TranslationTableMut::from_raw_parts(ptr, location.shape()) })
    }
}
