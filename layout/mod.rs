mod common;
mod vmsa128;
mod vmsa64;
mod vmsa64_lpa2;

pub use common::*;
pub use vmsa64::*;
pub use vmsa64_lpa2::*;
pub use vmsa128::*;

use crate::addr::PhysAddr;
use crate::format::{DescriptorFormat, DescriptorKind};
use crate::granule::{Level, TranslationGranule};
use crate::walkers::TranslationStage;

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawFieldBlock<const BITS: u8> {
    bits: u128,
}

impl<const BITS: u8> RawFieldBlock<BITS> {
    pub const fn bits(self) -> u128 {
        self.bits
    }

    pub(crate) const fn from_masked(bits: u128) -> Self {
        debug_assert!(bits & !lower_bits_mask(BITS) == 0);
        Self { bits }
    }
}

pub trait DescriptorLayout<F, S, G>: Copy + 'static
where
    F: DescriptorFormat,
    S: TranslationStage,
    G: TranslationGranule,
{
    type LeafFields: Copy;
    type TableFields: Copy;

    const ADDRESS_FIELD_MASK: u128;

    fn kind(raw: F::Raw, level: Level) -> DescriptorKind;

    fn decode_leaf_fields(raw: F::Raw, level: Level) -> Self::LeafFields;

    fn decode_table_fields(raw: F::Raw, level: Level) -> Self::TableFields;

    fn leaf_descriptor(output_pa: PhysAddr, level: Level, fields: Self::LeafFields) -> F::Raw;

    fn table_descriptor(table_pa: PhysAddr, fields: Self::TableFields) -> F::Raw;

    fn output_address(raw: F::Raw, level: Level) -> PhysAddr;
}
