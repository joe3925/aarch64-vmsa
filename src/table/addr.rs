use core::marker::PhantomData;

use crate::address::TranslationGranule;

/// A `TableAddr` value is an address in the translation-table address space.
///
/// In hardware, this value is usually a physical or intermediate physical address.
/// A simulator can use a stable and aligned numeric address.
/// The [`TableAccess`](super::TableAccess) implementation of the simulator must resolve the
/// address.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TableAddr<G>
where
    G: TranslationGranule,
{
    raw: u64,
    _marker: PhantomData<G>,
}

impl<G> TableAddr<G>
where
    G: TranslationGranule,
{
    /// This function makes a table address and does not validate its granule alignment.
    ///
    /// # Safety
    ///
    /// `raw` must have `G::SIZE` alignment.
    pub(crate) const unsafe fn new_unchecked(raw: u64) -> Self {
        Self {
            raw,
            _marker: PhantomData,
        }
    }

    pub fn new(raw: u64) -> Result<Self, TableAddressError> {
        if raw & (G::SIZE - 1) != 0 {
            return Err(TableAddressError::Unaligned {
                addr: raw,
                align: G::SIZE,
            });
        }

        // SAFETY: The check above validated the granule-alignment requirement.
        Ok(unsafe { Self::new_unchecked(raw) })
    }

    pub const fn raw(self) -> u64 {
        self.raw
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableAddressError {
    Unaligned { addr: u64, align: u64 },
}
