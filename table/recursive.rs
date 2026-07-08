use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::addr::VirtAddr;
use crate::format::DescriptorFormat;
use crate::granule::{Level, TranslationGranule};

use super::{
    AccessError, TableAccess, TableAccessLocation, TableAccessMut, TableGeometry, TablePhysAddr,
    TranslationTable, TranslationTableMut,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    recursive_index: usize,
    recursive_base: VirtAddr,
    root: TablePhysAddr<G>,
    root_level: Level,
    _marker: PhantomData<F>,
}

impl<F, G> RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub unsafe fn new(
        recursive_index: usize,
        recursive_base: VirtAddr,
        root: TablePhysAddr<G>,
        root_level: Level,
    ) -> Result<Self, AccessError> {
        let entries = TableGeometry::<F, G>::entries();

        if recursive_index >= entries {
            return Err(AccessError::RecursiveIndexOutOfRange {
                index: recursive_index,
                entries,
            });
        }

        if root_level.is_after(F::FINAL_LEVEL) {
            return Err(AccessError::RecursiveLevelMismatch);
        }

        if recursive_base.0 == 0 || recursive_base.0 & (G::SIZE - 1) != 0 {
            return Err(AccessError::InvalidRecursiveBase {
                base: recursive_base,
            });
        }

        let mut level = root_level;

        loop {
            let shift = TableGeometry::<F, G>::level_shift(level);

            if shift >= u64::BITS as u8
                || TableGeometry::<F, G>::index_at_level_raw(recursive_base.0, level)
                    != recursive_index
            {
                return Err(AccessError::InvalidRecursiveBase {
                    base: recursive_base,
                });
            }

            if level == F::FINAL_LEVEL {
                break;
            }

            level = level.next();
        }

        Ok(Self {
            recursive_index,
            recursive_base,
            root,
            root_level,
            _marker: PhantomData,
        })
    }

    pub const fn recursive_index(&self) -> usize {
        self.recursive_index
    }

    pub const fn recursive_base(&self) -> VirtAddr {
        self.recursive_base
    }

    pub const fn root(&self) -> TablePhysAddr<G> {
        self.root
    }

    pub const fn root_level(&self) -> Level {
        self.root_level
    }

    fn table_ptr(
        &self,
        location: TableAccessLocation<F, G>,
    ) -> Result<NonNull<F::Raw>, AccessError> {
        if location.root_level != self.root_level {
            return Err(AccessError::RecursiveLevelMismatch);
        }

        if location.level.is_before(self.root_level) || location.level.is_after(F::FINAL_LEVEL) {
            return Err(AccessError::RecursiveLevelMismatch);
        }

        let expected = location
            .level
            .distance_from(self.root_level)
            .ok_or(AccessError::RecursiveLevelMismatch)?;

        if location.path.len() != expected {
            return Err(AccessError::TablePathLengthMismatch {
                expected,
                actual: location.path.len(),
            });
        }

        let entries = TableGeometry::<F, G>::entries();
        let mut depth = location.path.len();
        let mut slot_level = F::FINAL_LEVEL;
        let mut va = self.recursive_base.0;

        while depth > 0 {
            depth -= 1;
            let index = location
                .path
                .index(depth)
                .ok_or(AccessError::TablePathLengthMismatch {
                    expected,
                    actual: location.path.len(),
                })?;

            if index >= entries {
                return Err(AccessError::TablePathIndexOutOfRange { index, entries });
            }

            let shift = TableGeometry::<F, G>::level_shift(slot_level);
            let field_mask = (TableGeometry::<F, G>::index_mask() as u128) << shift;

            if field_mask > u64::MAX as u128 {
                return Err(AccessError::AddressOverflow);
            }

            let field_mask = field_mask as u64;
            va = (va & !field_mask) | ((index as u64) << shift);
            slot_level = slot_level.previous();
        }

        NonNull::new(va as *mut F::Raw).ok_or(AccessError::NullMapping)
    }
}

unsafe impl<F, G> TableAccess<F, G> for RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type Error = AccessError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        let level = location.level;
        let ptr = self.table_ptr(location)?;

        Ok(unsafe { TranslationTable::from_ptr(ptr, level) })
    }
}

unsafe impl<F, G> TableAccessMut<F, G> for RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        let level = location.level;
        let ptr = self.table_ptr(location)?;

        Ok(unsafe { TranslationTableMut::from_ptr(ptr, level) })
    }
}
