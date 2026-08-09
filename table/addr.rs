use core::marker::PhantomData;

use crate::address::TranslationGranule;

/// An address in the modeled translation-table address space.
///
/// Hardware users normally place a physical or intermediate physical address
/// here. Simulators may instead use any stable, aligned numeric address that
/// their [`TableAccess`](super::TableAccess) implementation can resolve.
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
    /// Creates a table address without checking its granule alignment.
    ///
    /// # Safety
    ///
    /// `raw` must be aligned to `G::SIZE`.
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

        // SAFETY: The granule-alignment requirement was checked above.
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
