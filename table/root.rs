use core::marker::PhantomData;

use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;
use crate::regime::TranslationRegime;

use super::{TableAddr, TableGeometry};

/// Regime-independent root-table geometry for low-level validation and access.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTableGeometry<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    addr: TableAddr<G>,
    level: Level,
    addr_bits: u8,
    output_addr_bits: u8,
    _format: PhantomData<F>,
}

impl<F, G> RootTableGeometry<F, G>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    /// Creates root geometry using the deepest supported level that covers
    /// `addr_bits`.
    pub const fn new(addr: TableAddr<G>, addr_bits: u8, output_addr_bits: u8) -> Self {
        Self::new_at_level(
            addr,
            TableGeometry::<F, G>::root_level_for_addr_bits(addr_bits),
            addr_bits,
            output_addr_bits,
        )
    }

    /// Creates root geometry at an explicitly selected translation level.
    pub const fn new_at_level(
        addr: TableAddr<G>,
        level: Level,
        addr_bits: u8,
        output_addr_bits: u8,
    ) -> Self {
        Self {
            addr,
            level,
            addr_bits,
            output_addr_bits,
            _format: PhantomData,
        }
    }

    pub const fn addr(self) -> TableAddr<G> {
        self.addr
    }

    pub const fn level(self) -> Level {
        self.level
    }

    pub const fn addr_bits(self) -> u8 {
        self.addr_bits
    }

    pub const fn output_addr_bits(self) -> u8 {
        self.output_addr_bits
    }

    pub const fn with_regime<R>(self) -> RootTable<F, R, G>
    where
        R: TranslationRegime,
    {
        RootTable::from_geometry(self)
    }
}

/// A root table with its descriptor format, regime, and granule in its type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTable<F, R, G>
where
    F: DescriptorFormat,
    R: TranslationRegime,
    G: TranslationGranule,
{
    geometry: RootTableGeometry<F, G>,
    _regime: PhantomData<R>,
}

impl<F, R, G> RootTable<F, R, G>
where
    F: DescriptorFormat,
    R: TranslationRegime,
    G: TranslationGranule,
{
    pub const fn from_geometry(geometry: RootTableGeometry<F, G>) -> Self {
        Self {
            geometry,
            _regime: PhantomData,
        }
    }

    pub const fn geometry(self) -> RootTableGeometry<F, G> {
        self.geometry
    }

    pub const fn addr(self) -> TableAddr<G> {
        self.geometry.addr()
    }

    pub const fn level(self) -> Level {
        self.geometry.level()
    }

    pub const fn addr_bits(self) -> u8 {
        self.geometry.addr_bits()
    }

    pub const fn output_addr_bits(self) -> u8 {
        self.geometry.output_addr_bits()
    }
}
