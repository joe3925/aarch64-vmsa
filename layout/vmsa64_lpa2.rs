use core::marker::PhantomData;

use crate::addr::PhysAddr;
use crate::fields::{
    Vmsa64Lpa2Stage1LeafFields, Vmsa64Lpa2Stage2LeafFields, Vmsa64Stage1TableFields,
    Vmsa64Stage2TableFields,
};
use crate::format::{DescriptorKind, HasLayout, Vmsa64Lpa2};
use crate::granule::{Level, TranslationGranule};
use crate::walkers::{Stage1, Stage2};

use super::vmsa64::{VMSA64_TABLE_OR_PAGE, VMSA64_VALID, vmsa64_kind, vmsa64_leaf_kind_bits};
use super::{DescriptorLayout, RawFieldBlock};

const VMSA64_LPA2_ADDR_FIELD_MASK: u128 = 0x0003_FFFF_FFFF_F300;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Lpa2Layout<S, G>(PhantomData<(S, G)>);

impl<G: TranslationGranule> HasLayout<Stage1, G> for Vmsa64Lpa2 {
    type Layout = Vmsa64Lpa2Layout<Stage1, G>;
}

impl<G: TranslationGranule> HasLayout<Stage2, G> for Vmsa64Lpa2 {
    type Layout = Vmsa64Lpa2Layout<Stage2, G>;
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa64Lpa2, Stage1, G>
    for Vmsa64Lpa2Layout<Stage1, G>
{
    type LeafFields = Vmsa64Lpa2Stage1LeafFields;
    type TableFields = Vmsa64Stage1TableFields;

    const ADDRESS_FIELD_MASK: u128 = VMSA64_LPA2_ADDR_FIELD_MASK;

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        vmsa64_kind(raw, level)
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let lower = ((raw >> 2) & 0x3f) | (((raw >> 10) & 0x3) << 6);
        Vmsa64Lpa2Stage1LeafFields {
            lower: RawFieldBlock::from_masked(lower as u128),
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
        let address = encode_lpa2_address(output_pa);
        let lower = fields.lower.bits() as u64;

        address
            | (lower & 0x3f) << 2
            | ((lower >> 6) & 0x3) << 10
            | (fields.upper.bits() as u64) << 52
            | (fields.guarded as u64) << 50
            | (fields.dirty_bit_modifier as u64) << 51
            | (fields.software.bits() as u64) << 55
            | vmsa64_leaf_kind_bits(level)
    }

    fn table_descriptor(table_pa: PhysAddr, fields: Self::TableFields) -> u64 {
        let address = encode_lpa2_address(table_pa);
        address
            | (fields.software.bits() as u64) << 55
            | (fields.upper.bits() as u64) << 59
            | VMSA64_VALID
            | VMSA64_TABLE_OR_PAGE
    }

    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr(unpack_lpa2_address(raw))
    }
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa64Lpa2, Stage2, G>
    for Vmsa64Lpa2Layout<Stage2, G>
{
    type LeafFields = Vmsa64Lpa2Stage2LeafFields;
    type TableFields = Vmsa64Stage2TableFields;

    const ADDRESS_FIELD_MASK: u128 = VMSA64_LPA2_ADDR_FIELD_MASK;

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        vmsa64_kind(raw, level)
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let lower = ((raw >> 2) & 0x3f) | (((raw >> 10) & 1) << 6);
        let upper = (raw >> 52) & 0b111;
        Vmsa64Lpa2Stage2LeafFields {
            lower: RawFieldBlock::from_masked(lower as u128),
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
        let address = encode_lpa2_address(output_pa);
        let lower = fields.lower.bits() as u64;
        let upper = fields.upper.bits() as u64;

        address
            | (lower & 0x3f) << 2
            | ((lower >> 6) & 1) << 10
            | (upper & 1) << 52
            | ((upper >> 1) & 0b11) << 53
            | (fields.dirty_bit_modifier as u64) << 51
            | (fields.software.bits() as u64) << 55
            | vmsa64_leaf_kind_bits(level)
    }

    fn table_descriptor(table_pa: PhysAddr, fields: Self::TableFields) -> u64 {
        let address = encode_lpa2_address(table_pa);
        address | (fields.software.bits() as u64) << 55 | VMSA64_VALID | VMSA64_TABLE_OR_PAGE
    }

    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr(unpack_lpa2_address(raw))
    }
}

fn encode_lpa2_address(address: PhysAddr) -> u64 {
    (address.0 & 0x0003_FFFF_FFFF_F000) | (((address.0 >> 50) & 0x3) << 8)
}

fn unpack_lpa2_address(raw: u64) -> u64 {
    (raw & 0x0003_FFFF_FFFF_F000) | (((raw >> 8) & 0x3) << 50)
}
