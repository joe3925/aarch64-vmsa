use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::address::VirtAddr;
use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;

use super::{
    AccessError, TableAccess, TableAccessLocation, TableAccessMut, TableAddr, TableGeometry,
    TranslationTable, TranslationTableMut,
};

#[derive(Debug, Eq, PartialEq)]
pub struct RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    recursive_index: usize,
    recursive_base: VirtAddr,
    root: TableAddr<G>,
    root_level: Level,
    _marker: PhantomData<F>,
}

impl<F, G> RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    /// Creates access through an active recursive mapping.
    ///
    /// # Safety
    /// The recursive mapping must stay active while this value exists. The mapping must give
    /// valid access to the specified root and its child tables.
    pub unsafe fn new(
        recursive_index: usize,
        recursive_base: VirtAddr,
        root: TableAddr<G>,
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
            if TableGeometry::<F, G>::index_at_level_raw(recursive_base.0, level)
                != Some(recursive_index)
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

    pub const fn root(&self) -> TableAddr<G> {
        self.root
    }

    pub const fn root_level(&self) -> Level {
        self.root_level
    }

    fn table_ptr(
        &self,
        location: TableAccessLocation<'_, F, G>,
    ) -> Result<NonNull<F::Raw>, AccessError> {
        if location.root_level() != self.root_level {
            return Err(AccessError::RecursiveLevelMismatch);
        }

        if location.level().is_before(self.root_level) || location.level().is_after(F::FINAL_LEVEL)
        {
            return Err(AccessError::RecursiveLevelMismatch);
        }

        let path = location.path();
        let actual = path.terminal_level(self.root_level)?;
        if actual != location.level() {
            return Err(AccessError::TablePathTerminalLevelMismatch {
                expected: location.level(),
                actual,
            });
        }

        let mut depth = path.len();
        let mut slot_level = F::FINAL_LEVEL;
        let mut va = self.recursive_base.0;

        while depth > 0 {
            depth -= 1;
            let entry =
                path.entry(self.root_level, depth)
                    .ok_or(AccessError::TablePathLengthMismatch {
                        expected: path.len(),
                        actual: path.len(),
                    })?;
            let stride_count = entry.parent().stride_count().raw();
            let entries = entry.parent().entries();
            let index = entry.index();

            if index >= entries {
                return Err(AccessError::TablePathIndexOutOfRange { index, entries });
            }

            let shift = TableGeometry::<F, G>::level_shift(slot_level);
            let field_mask =
                (TableGeometry::<F, G>::index_mask_for_stride_count(stride_count) as u128) << shift;

            if field_mask > u64::MAX as u128 {
                return Err(AccessError::AddressOverflow);
            }

            let field_mask = field_mask as u64;
            va = (va & !field_mask) | ((index as u64) << shift);
            slot_level = Level::new(slot_level.as_i8() - stride_count as i8);
        }

        NonNull::new(va as *mut F::Raw).ok_or(AccessError::NullMapping)
    }
}

// SAFETY: The constructor contract keeps each returned table readable for its borrow.
unsafe impl<F, G> TableAccess<F, G> for RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    type Error = AccessError;

    fn table_at<'a>(
        &'a self,
        location: TableAccessLocation<'a, F, G>,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        let shape = location.shape();
        let ptr = self.table_ptr(location)?;

        // SAFETY: guaranteed by the recursive mapping contract established at construction.
        Ok(unsafe { TranslationTable::from_raw_parts(ptr, shape) })
    }
}

// SAFETY: The constructor contract keeps each returned table exclusively writable for its borrow.
unsafe impl<F, G> TableAccessMut<F, G> for RecursiveTableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_at_mut<'a>(
        &'a mut self,
        location: TableAccessLocation<'a, F, G>,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        let shape = location.shape();
        let ptr = self.table_ptr(location)?;

        // SAFETY: guaranteed by the recursive mapping contract established at construction.
        Ok(unsafe { TranslationTableMut::from_raw_parts(ptr, shape) })
    }
}
