use crate::format::DescriptorFormat;
use crate::granule::Level;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::addr::VirtAddr;
use crate::granule::TranslationGranule;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RawTableAddr(pub u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTable<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    addr: RawTableAddr,
    level: Level,
    addr_bits: u8,
    _marker: PhantomData<(F, G)>,
}

impl<F, G> RootTable<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    pub const fn new(addr: RawTableAddr, level: Level, addr_bits: u8) -> Self {
        Self {
            addr,
            level,
            addr_bits,
            _marker: PhantomData,
        }
    }

    pub const fn addr(self) -> RawTableAddr {
        self.addr
    }

    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn addr_bits(self) -> u8 {
        self.addr_bits
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TranslationTable<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    base: NonNull<F::Raw>,
    level: Level,
    _marker: PhantomData<G>,
}

impl<F, G> TranslationTable<F, G>
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

    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn base(self) -> NonNull<F::Raw> {
        self.base
    }

    pub fn entries(self) -> usize {
        (G::SIZE as usize) / F::DESCRIPTOR_BYTES
    }

    pub fn entry_ptr(self, index: usize) -> Option<NonNull<F::Raw>> {
        if index >= self.entries() {
            return None;
        }

        let ptr = unsafe { self.base.as_ptr().add(index) };

        NonNull::new(ptr)
    }

    pub fn read(self, index: usize) -> Option<F::Raw> {
        let ptr = self.entry_ptr(index)?;

        Some(unsafe { F::read_descriptor(ptr.as_ptr()) })
    }

    pub fn write(self, index: usize, raw: F::Raw) -> Result<(), TableError> {
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

    pub fn index_bits(self) -> u8 {
        G::SHIFT - F::DESCRIPTOR_SHIFT
    }

    pub fn index_mask(self) -> u64 {
        (1u64 << self.index_bits()) - 1
    }

    pub fn level_shift(self) -> u8 {
        G::SHIFT + self.index_bits() * (Level::L3.as_i8() as u8 - self.level.as_i8() as u8)
    }

    pub fn index_for_va(self, va: VirtAddr) -> usize {
        ((va.0 >> self.level_shift()) & self.index_mask()) as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableError {
    EntryIndexOutOfRange { index: usize, entries: usize },
}

pub trait TableAccess<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    fn table_from_root(&self, root: RootTable<F, G>)
    -> Result<TranslationTable<F, G>, AccessError>;

    fn next_table(
        &self,
        descriptor_addr: RawTableAddr,
        level: Level,
    ) -> Result<TranslationTable<F, G>, AccessError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    // TODO
}
