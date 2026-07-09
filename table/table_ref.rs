use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::address::VirtAddr;
use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;

use super::{TableError, TableGeometry, TableShape, TableStrideCount};

#[derive(Clone, Copy, Debug)]
pub struct TranslationTable<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    base: NonNull<F::Raw>,
    shape: TableShape<F, G>,
    _marker: PhantomData<(&'a F::Raw, G)>,
}

#[derive(Debug)]
pub struct TranslationTableMut<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    base: NonNull<F::Raw>,
    shape: TableShape<F, G>,
    _marker: PhantomData<(&'a mut F::Raw, G)>,
}

impl<'a, F, G> TranslationTable<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub unsafe fn from_ptr(base: NonNull<F::Raw>, shape: TableShape<F, G>) -> Self {
        Self {
            base,
            shape,
            _marker: PhantomData,
        }
    }

    pub const fn level(&self) -> Level {
        self.shape.level()
    }

    pub const fn stride_count(&self) -> TableStrideCount {
        self.shape.stride_count()
    }

    pub const fn shape(&self) -> TableShape<F, G> {
        self.shape
    }

    pub const fn base(&self) -> NonNull<F::Raw> {
        self.base
    }

    pub fn entries(&self) -> usize {
        self.shape.entries()
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
        TableGeometry::<F, G>::level_shift(self.level())
    }

    pub fn index_for_va(&self, va: VirtAddr) -> Option<usize> {
        self.shape.index_for_input(va.0)
    }
}

impl<'a, F, G> TranslationTableMut<'a, F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub unsafe fn from_ptr(base: NonNull<F::Raw>, shape: TableShape<F, G>) -> Self {
        Self {
            base,
            shape,
            _marker: PhantomData,
        }
    }

    pub const fn level(&self) -> Level {
        self.shape.level()
    }

    pub const fn stride_count(&self) -> TableStrideCount {
        self.shape.stride_count()
    }

    pub const fn shape(&self) -> TableShape<F, G> {
        self.shape
    }

    pub const fn base(&self) -> NonNull<F::Raw> {
        self.base
    }

    pub fn as_table(&self) -> TranslationTable<'_, F, G> {
        unsafe { TranslationTable::from_ptr(self.base, self.shape) }
    }

    pub fn entries(&self) -> usize {
        self.shape.entries()
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
        TableGeometry::<F, G>::level_shift(self.level())
    }

    pub fn index_for_va(&self, va: VirtAddr) -> Option<usize> {
        self.shape.index_for_input(va.0)
    }
}
