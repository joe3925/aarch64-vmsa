mod common;
mod vmsa128;
mod vmsa64;
mod vmsa64_lpa2;

pub use common::*;
pub use vmsa64::*;
pub use vmsa64_lpa2::*;
pub use vmsa128::*;

use crate::address::PhysAddr;
use crate::address::{Level, TranslationGranule};
use crate::descriptor::{DescriptorFormat, DescriptorKind};
use crate::table::TableTransition;
use crate::translation::TranslationStage;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NextTableDescriptor {
    pub address: PhysAddr,
    pub level: Level,
    pub stride_count: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorError {
    InvalidTableTransition {
        parent_level: Level,
        child_level: Level,
        stride_count: u8,
    },
}

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

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<F, G>,
        fields: Self::TableFields,
    ) -> Result<F::Raw, DescriptorError>;

    fn output_address(raw: F::Raw, level: Level) -> PhysAddr;

    fn table_address(raw: F::Raw, level: Level) -> PhysAddr {
        Self::output_address(raw, level)
    }

    fn next_table(raw: F::Raw, level: Level) -> Option<NextTableDescriptor> {
        level
            .is_before(F::FINAL_LEVEL)
            .then(|| NextTableDescriptor {
                address: Self::table_address(raw, level),
                level: level.next(),
                stride_count: 1,
            })
    }

    fn supports_table_transition(transition: TableTransition<F, G>) -> bool {
        transition.level_step() == 1 && transition.child().stride_count().raw() == 1
    }
}

pub(crate) fn require_step_by_one_transition<F, G>(
    transition: TableTransition<F, G>,
) -> Result<(), DescriptorError>
where
    F: DescriptorFormat,
    G: TranslationGranule,
{
    if transition.level_step() == 1 && transition.child().stride_count().raw() == 1 {
        Ok(())
    } else {
        Err(DescriptorError::InvalidTableTransition {
            parent_level: transition.parent_level(),
            child_level: transition.child_level(),
            stride_count: transition.child().stride_count().raw(),
        })
    }
}
