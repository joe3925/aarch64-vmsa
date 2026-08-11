use core::marker::PhantomData;

use crate::address::{Level, TranslationGranule};
use crate::descriptor::DescriptorFormat;
use crate::regime::TranslationRegime;

use super::{TableAddr, TableGeometry};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootGeometryError {
    InvalidLevel,
    InvalidInputAddressBits { requested: u8, maximum: u8 },
    InvalidOutputAddressBits { requested: u8, maximum: u8 },
    TableAddressOutOfRange,
}

/// This type contains regime-independent root-table geometry for low-level validation and access.
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
    /// This function makes root geometry for `addr_bits`.
    /// It uses the root level with the minimum number of table-walk steps.
    pub const fn new(
        addr: TableAddr<G>,
        addr_bits: u8,
        output_addr_bits: u8,
    ) -> Result<Self, RootGeometryError> {
        Self::new_at_level(
            addr,
            TableGeometry::<F, G>::root_level_for_addr_bits(addr_bits),
            addr_bits,
            output_addr_bits,
        )
    }

    /// This function makes root geometry at a specified translation level.
    pub const fn new_at_level(
        addr: TableAddr<G>,
        level: Level,
        addr_bits: u8,
        output_addr_bits: u8,
    ) -> Result<Self, RootGeometryError> {
        if level.is_before(F::EXTENDED_LOWEST_ROOT_LEVEL) || level.is_after(F::FINAL_LEVEL) {
            return Err(RootGeometryError::InvalidLevel);
        }
        let maximum = match TableGeometry::<F, G>::max_addr_bits(level) {
            Some(value) => value,
            None => return Err(RootGeometryError::InvalidLevel),
        };
        if addr_bits == 0 || addr_bits > maximum {
            return Err(RootGeometryError::InvalidInputAddressBits {
                requested: addr_bits,
                maximum,
            });
        }
        if !matches!(output_addr_bits, 32 | 36 | 40 | 42 | 44 | 48 | 52 | 56)
            || output_addr_bits > F::OUTPUT_ADDRESS_BITS
        {
            return Err(RootGeometryError::InvalidOutputAddressBits {
                requested: output_addr_bits,
                maximum: F::OUTPUT_ADDRESS_BITS,
            });
        }
        if output_addr_bits < 64 && addr.raw() >> output_addr_bits != 0 {
            return Err(RootGeometryError::TableAddressOutOfRange);
        }
        Ok(Self {
            addr,
            level,
            addr_bits,
            output_addr_bits,
            _format: PhantomData,
        })
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

/// This type identifies a root table and its descriptor format, regime, and granule.
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
