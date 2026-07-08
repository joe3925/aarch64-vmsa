use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::addr::VirtAddr;
use crate::format::DescriptorFormat;
use crate::granule::{Level, TranslationGranule};

use super::{
    AccessError, TableAccess, TableAccessMut, TableGeometry, TablePhysAddr, TranslationTable,
    TranslationTableMut,
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
        addr: TablePhysAddr<G>,
        level: Level,
    ) -> Result<NonNull<F::Raw>, AccessError> {
        if addr.raw() != self.root.raw() {
            return Err(AccessError::RecursiveAddressUnavailable { table: addr.phys() });
        }

        if level != self.root_level {
            return Err(AccessError::RecursiveLevelMismatch);
        }

        NonNull::new(self.recursive_base.0 as *mut F::Raw).ok_or(AccessError::NullMapping)
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
        addr: TablePhysAddr<G>,
        level: Level,
    ) -> Result<TranslationTable<'a, F, G>, Self::Error> {
        let ptr = self.table_ptr(addr, level)?;

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
        addr: TablePhysAddr<G>,
        level: Level,
    ) -> Result<TranslationTableMut<'a, F, G>, Self::Error> {
        let ptr = self.table_ptr(addr, level)?;

        Ok(unsafe { TranslationTableMut::from_ptr(ptr, level) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecursiveTablePath<const MAX_LEVELS: usize> {
    indices: [usize; MAX_LEVELS],
    len: usize,
}

impl<const MAX_LEVELS: usize> RecursiveTablePath<MAX_LEVELS> {
    pub const fn new(indices: [usize; MAX_LEVELS], len: usize) -> Self {
        assert!(len <= MAX_LEVELS);

        Self { indices, len }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn indices(&self) -> &[usize] {
        self.indices.split_at(self.len).0
    }
}
