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
    pub fn from_slice(entries: &'a [F::Raw], shape: TableShape<F, G>) -> Result<Self, TableError> {
        if entries.len() < shape.entries() {
            return Err(TableError::BackingSliceTooShort {
                required: shape.entries(),
                actual: entries.len(),
            });
        }
        let base = NonNull::from(&entries[0]);
        Ok(Self {
            base,
            shape,
            _marker: PhantomData,
        })
    }

    /// Creates a table view over raw descriptor memory.
    ///
    /// # Safety
    /// `base` must point to `shape.entries()` initialized descriptors. The memory must stay
    /// readable for `'a`. Access must follow the aliasing and concurrency rules.
    pub unsafe fn from_raw_parts(base: NonNull<F::Raw>, shape: TableShape<F, G>) -> Self {
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
        // SAFETY: The index is less than the table extent.
        NonNull::new(unsafe { self.base.as_ptr().add(index) })
    }

    pub fn read(&self, index: usize) -> Option<F::Raw> {
        let ptr = self.entry_ptr(index)?;
        // SAFETY: `entry_ptr` returns an initialized descriptor in this readable view.
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
    pub fn from_slice(
        entries: &'a mut [F::Raw],
        shape: TableShape<F, G>,
    ) -> Result<Self, TableError> {
        if entries.len() < shape.entries() {
            return Err(TableError::BackingSliceTooShort {
                required: shape.entries(),
                actual: entries.len(),
            });
        }
        let base = NonNull::from(&mut entries[0]);
        Ok(Self {
            base,
            shape,
            _marker: PhantomData,
        })
    }

    /// Creates a mutable table view over raw descriptor memory.
    ///
    /// # Safety
    /// `base` must point to `shape.entries()` initialized descriptors. The memory must stay
    /// writable for `'a`. Access must follow the aliasing and concurrency rules.
    pub unsafe fn from_raw_parts(base: NonNull<F::Raw>, shape: TableShape<F, G>) -> Self {
        Self {
            base,
            shape,
            _marker: PhantomData,
        }
    }

    pub fn level(&self) -> Level {
        self.as_table().level()
    }

    pub fn stride_count(&self) -> TableStrideCount {
        self.as_table().stride_count()
    }

    pub fn shape(&self) -> TableShape<F, G> {
        self.as_table().shape()
    }

    pub fn base(&self) -> NonNull<F::Raw> {
        self.as_table().base()
    }

    pub fn as_table(&self) -> TranslationTable<'_, F, G> {
        // SAFETY: the mutable view's constructor established the same readable extent, and the
        // returned shared view is bounded by the borrow of `self`.
        unsafe { TranslationTable::from_raw_parts(self.base, self.shape) }
    }

    pub fn entries(&self) -> usize {
        self.as_table().entries()
    }

    pub fn entry_ptr(&self, index: usize) -> Option<NonNull<F::Raw>> {
        self.as_table().entry_ptr(index)
    }

    pub fn read(&self, index: usize) -> Option<F::Raw> {
        self.as_table().read(index)
    }

    pub fn write(&mut self, index: usize, raw: F::Raw) -> Result<(), TableError> {
        let ptr = self
            .entry_ptr(index)
            .ok_or(TableError::EntryIndexOutOfRange {
                index,
                entries: self.entries(),
            })?;

        // SAFETY: `entry_ptr` returns a descriptor in this writable view.
        unsafe {
            F::write_descriptor(ptr.as_ptr(), raw);
        }

        Ok(())
    }

    pub fn index_bits(&self) -> u8 {
        self.as_table().index_bits()
    }

    pub fn index_mask(&self) -> u64 {
        self.as_table().index_mask()
    }

    pub fn level_shift(&self) -> u8 {
        self.as_table().level_shift()
    }

    pub fn index_for_va(&self, va: VirtAddr) -> Option<usize> {
        self.as_table().index_for_va(va)
    }
}
