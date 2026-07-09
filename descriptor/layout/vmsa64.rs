use core::marker::PhantomData;

use crate::address::PhysAddr;
use crate::address::{GranuleKind, Level, TranslationGranule};
use crate::descriptor::{DescriptorKind, HasLayout, Vmsa64};
use crate::descriptor::{
    Vmsa64Stage1LeafFields, Vmsa64Stage1TableFields, Vmsa64Stage2LeafFields,
    Vmsa64Stage2TableFields,
};
use crate::translation::{Stage1, Stage2};

use crate::table::TableTransition;

use super::{
    DescriptorError, DescriptorLayout, RawFieldBlock, decode_direct_output_address,
    encode_direct_address, require_step_by_one_transition,
};

pub(super) const VMSA64_VALID: u64 = 1 << 0;
pub(super) const VMSA64_TABLE_OR_PAGE: u64 = 1 << 1;
const VMSA64_TYPE_MASK: u64 = 0b11;
const VMSA64_ADDR_FIELD_MASK: u128 = 0x0000_FFFF_FFFF_F000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Layout<S, G>(PhantomData<(S, G)>);

impl<G: TranslationGranule> HasLayout<Stage1, G> for Vmsa64 {
    type Layout = Vmsa64Layout<Stage1, G>;
}

impl<G: TranslationGranule> HasLayout<Stage2, G> for Vmsa64 {
    type Layout = Vmsa64Layout<Stage2, G>;
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa64, Stage1, G> for Vmsa64Layout<Stage1, G> {
    type LeafFields = Vmsa64Stage1LeafFields;
    type TableFields = Vmsa64Stage1TableFields;

    const ADDRESS_FIELD_MASK: u128 = VMSA64_ADDR_FIELD_MASK;

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        vmsa64_kind(G::KIND, raw, level)
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        Vmsa64Stage1LeafFields {
            lower: RawFieldBlock::from_masked(((raw >> 2) & 0x3ff) as u128),
            upper: RawFieldBlock::from_masked(((raw >> 52) & 0x7) as u128),
            dirty_bit_modifier: raw & (1 << 51) != 0,
            guarded: raw & (1 << 50) != 0,
            software: RawFieldBlock::from_masked(((raw >> 55) & 0xf) as u128),
        }
    }

    fn decode_table_fields(raw: u64, _level: Level) -> Self::TableFields {
        Vmsa64Stage1TableFields {
            upper: RawFieldBlock::from_masked(((raw >> 59) & 0x1f) as u128),
            software: RawFieldBlock::from_masked(((raw >> 55) & 0xf) as u128),
        }
    }

    fn leaf_descriptor(output_pa: PhysAddr, level: Level, fields: Self::LeafFields) -> u64 {
        let address = encode_direct_address(output_pa, Self::ADDRESS_FIELD_MASK);

        address as u64
            | (fields.lower.bits() as u64) << 2
            | (fields.upper.bits() as u64) << 52
            | (fields.guarded as u64) << 50
            | (fields.dirty_bit_modifier as u64) << 51
            | (fields.software.bits() as u64) << 55
            | vmsa64_leaf_kind_bits(G::KIND, level)
    }

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa64, G>,
        fields: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let address = encode_direct_address(table_pa, Self::ADDRESS_FIELD_MASK);

        Ok(address as u64
            | (fields.software.bits() as u64) << 55
            | (fields.upper.bits() as u64) << 59
            | VMSA64_VALID
            | VMSA64_TABLE_OR_PAGE)
    }

    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        decode_direct_output_address(raw as u128, Self::ADDRESS_FIELD_MASK)
    }
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa64, Stage2, G> for Vmsa64Layout<Stage2, G> {
    type LeafFields = Vmsa64Stage2LeafFields;
    type TableFields = Vmsa64Stage2TableFields;

    const ADDRESS_FIELD_MASK: u128 = VMSA64_ADDR_FIELD_MASK;

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        vmsa64_kind(G::KIND, raw, level)
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let upper = (raw >> 52) & 0b111;
        Vmsa64Stage2LeafFields {
            lower: RawFieldBlock::from_masked(((raw >> 2) & 0x1ff) as u128),
            upper: RawFieldBlock::from_masked(upper as u128),
            dirty_bit_modifier: raw & (1 << 51) != 0,
            software: RawFieldBlock::from_masked(((raw >> 55) & 0xf) as u128),
        }
    }

    fn decode_table_fields(raw: u64, _level: Level) -> Self::TableFields {
        Vmsa64Stage2TableFields {
            software: RawFieldBlock::from_masked(((raw >> 55) & 0xf) as u128),
        }
    }

    fn leaf_descriptor(output_pa: PhysAddr, level: Level, fields: Self::LeafFields) -> u64 {
        let address = encode_direct_address(output_pa, Self::ADDRESS_FIELD_MASK);
        let upper = fields.upper.bits() as u64;

        address as u64
            | (fields.lower.bits() as u64) << 2
            | (upper & 1) << 52
            | ((upper >> 1) & 0b11) << 53
            | (fields.dirty_bit_modifier as u64) << 51
            | (fields.software.bits() as u64) << 55
            | vmsa64_leaf_kind_bits(G::KIND, level)
    }

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa64, G>,
        fields: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let address = encode_direct_address(table_pa, Self::ADDRESS_FIELD_MASK);
        Ok(address as u64
            | (fields.software.bits() as u64) << 55
            | VMSA64_VALID
            | VMSA64_TABLE_OR_PAGE)
    }

    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        decode_direct_output_address(raw as u128, Self::ADDRESS_FIELD_MASK)
    }
}

pub fn vmsa64_supports_leaf_level(granule: GranuleKind, level: Level) -> bool {
    level == Level::L3 || vmsa64_supports_block_descriptor(granule, level)
}

pub(super) fn vmsa64_kind(granule: GranuleKind, raw: u64, level: Level) -> DescriptorKind {
    match raw & VMSA64_TYPE_MASK {
        0b00 => DescriptorKind::Invalid,
        0b01 if vmsa64_supports_block_descriptor(granule, level) => DescriptorKind::Block,
        0b11 if level < Level::L3 => DescriptorKind::Table,
        0b11 if level == Level::L3 => DescriptorKind::Page,
        _ => DescriptorKind::Invalid,
    }
}

pub(super) fn vmsa64_leaf_kind_bits(granule: GranuleKind, level: Level) -> u64 {
    if level == Level::L3 {
        VMSA64_VALID | VMSA64_TABLE_OR_PAGE
    } else if vmsa64_supports_block_descriptor(granule, level) {
        VMSA64_VALID
    } else {
        debug_assert!(false, "unsupported VMSAv8-64 block level");
        0
    }
}

const fn vmsa64_supports_block_descriptor(granule: GranuleKind, level: Level) -> bool {
    match (granule, level.as_i8()) {
        (GranuleKind::Size4KiB, 1 | 2) => true,
        (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 2) => true,
        _ => false,
    }
}
