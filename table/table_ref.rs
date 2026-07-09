use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::addr::VirtAddr;
use crate::format::DescriptorFormat;
use crate::granule::{Level, TranslationGranule};

use super::{TableError, TableGeometry};

#[derive(Clone, Copy, Debug)]
pub struct TranslationTable<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    base: NonNull<F::Raw>,
    level: Level,
    _marker: PhantomData<(&'a F::Raw, G)>,
}

#[derive(Debug)]
pub struct TranslationTableMut<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    base: NonNull<F::Raw>,
    level: Level,
    _marker: PhantomData<(&'a mut F::Raw, G)>,
}

impl<'a, F, G> TranslationTable<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub unsafe fn from_ptr(base: NonNull<F::Raw>, level: Level) -> Self {
        Self {
            base,
            level,
            _marker: PhantomData,
        }
    }

    pub const fn level(&self) -> Level {
        self.level
    }

    pub const fn base(&self) -> NonNull<F::Raw> {
        self.base
    }

    pub fn entries(&self) -> usize {
        TableGeometry::<F, G>::entries()
    }

    pub fn entry_ptr(&self, index: usize) -> Option<NonNull<F::Raw>> {
        if index >= self.entries() {
            return None;
        }

        let ptr = unsafe { self.base.as_ptr().add(index) };

        NonNull::new(ptr)
    }

    pub fn read(&self, index: usize) -> Option<F::Raw> {
        let ptr = self.entry_ptr(index)?;

        Some(unsafe { F::read_descriptor(ptr.as_ptr()) })
    }

    pub fn index_bits(&self) -> u8 {
        TableGeometry::<F, G>::index_bits()
    }

    pub fn index_mask(&self) -> u64 {
        TableGeometry::<F, G>::index_mask()
    }

    pub fn level_shift(&self) -> u8 {
        TableGeometry::<F, G>::level_shift(self.level)
    }

    pub fn index_for_va(&self, va: VirtAddr) -> Option<usize> {
        TableGeometry::<F, G>::index_at_level_raw(va.0, self.level)
    }
}

impl<'a, F, G> TranslationTableMut<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub unsafe fn from_ptr(base: NonNull<F::Raw>, level: Level) -> Self {
        Self {
            base,
            level,
            _marker: PhantomData,
        }
    }

    pub const fn level(&self) -> Level {
        self.level
    }

    pub const fn base(&self) -> NonNull<F::Raw> {
        self.base
    }

    pub fn as_table(&self) -> TranslationTable<'_, F, G> {
        unsafe { TranslationTable::from_ptr(self.base, self.level) }
    }

    pub fn entries(&self) -> usize {
        TableGeometry::<F, G>::entries()
    }

    pub fn entry_ptr(&self, index: usize) -> Option<NonNull<F::Raw>> {
        if index >= self.entries() {
            return None;
        }

        let ptr = unsafe { self.base.as_ptr().add(index) };

        NonNull::new(ptr)
    }

    pub fn read(&self, index: usize) -> Option<F::Raw> {
        let ptr = self.entry_ptr(index)?;

        Some(unsafe { F::read_descriptor(ptr.as_ptr()) })
    }

    pub fn write(&mut self, index: usize, raw: F::Raw) -> Result<(), TableError> {
        let ptr = self
            .entry_ptr(index)
            .ok_or(TableError::EntryIndexOutOfRange {
                index,
                entries: self.entries(),
            })?;

        unsafe {
            F::write_descriptor(ptr.as_ptr(), raw);
        }

        Ok(())
    }

    pub fn index_bits(&self) -> u8 {
        TableGeometry::<F, G>::index_bits()
    }

    pub fn index_mask(&self) -> u64 {
        TableGeometry::<F, G>::index_mask()
    }

    pub fn level_shift(&self) -> u8 {
        TableGeometry::<F, G>::level_shift(self.level)
    }

    pub fn index_for_va(&self, va: VirtAddr) -> Option<usize> {
        TableGeometry::<F, G>::index_at_level_raw(va.0, self.level)
    }
}
