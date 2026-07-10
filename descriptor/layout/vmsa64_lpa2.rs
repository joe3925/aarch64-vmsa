use core::marker::PhantomData;

use crate::address::PhysAddr;
use crate::address::{GranuleKind, Level, TranslationGranule};
use crate::descriptor::{DescriptorKind, HasLayout, Vmsa64Lpa2};
use crate::descriptor::{
    Vmsa64Lpa2Stage1LeafFields, Vmsa64Lpa2Stage2LeafFields, Vmsa64Stage1TableFields,
    Vmsa64Stage2TableFields,
};
use crate::table::TableTransition;
use crate::translation::{Stage1, Stage2};

use super::vmsa64::{VMSA64_TABLE_OR_PAGE, VMSA64_VALID};
use super::{DescriptorError, DescriptorLayout, RawFieldBlock, require_step_by_one_transition};

const VMSA64_LPA2_DS_ADDR_FIELD_MASK: u128 = 0x0003_FFFF_FFFF_F300;
const VMSA64_LPA_64K_ADDR_FIELD_MASK: u128 = 0x0000_FFFF_FFFF_F000;

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

    const ADDRESS_FIELD_MASK: u128 = vmsa64_lpa2_address_field_mask(G::KIND);

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        vmsa64_lpa2_kind(G::KIND, raw, level)
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let lower = decode_stage1_leaf_lower::<G>(raw);
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
        let address = encode_lpa2_address::<G>(output_pa);
        let lower = fields.lower.bits() as u64;

        address
            | encode_stage1_leaf_lower::<G>(lower)
            | (fields.upper.bits() as u64) << 52
            | (fields.guarded as u64) << 50
            | (fields.dirty_bit_modifier as u64) << 51
            | (fields.software.bits() as u64) << 55
            | vmsa64_lpa2_leaf_kind_bits(G::KIND, level)
    }

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa64Lpa2, G>,
        fields: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let address = encode_lpa2_address::<G>(table_pa);
        Ok(address
            | (fields.software.bits() as u64) << 55
            | (fields.upper.bits() as u64) << 59
            | VMSA64_VALID
            | VMSA64_TABLE_OR_PAGE)
    }

    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr(unpack_lpa2_address::<G>(raw))
    }
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa64Lpa2, Stage2, G>
    for Vmsa64Lpa2Layout<Stage2, G>
{
    type LeafFields = Vmsa64Lpa2Stage2LeafFields;
    type TableFields = Vmsa64Stage2TableFields;

    const ADDRESS_FIELD_MASK: u128 = vmsa64_lpa2_address_field_mask(G::KIND);

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        vmsa64_lpa2_kind(G::KIND, raw, level)
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let lower = decode_stage2_leaf_lower::<G>(raw);
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
        let address = encode_lpa2_address::<G>(output_pa);
        let lower = fields.lower.bits() as u64;
        let upper = fields.upper.bits() as u64;

        address
            | encode_stage2_leaf_lower::<G>(lower)
            | (upper & 1) << 52
            | ((upper >> 1) & 0b11) << 53
            | (fields.dirty_bit_modifier as u64) << 51
            | (fields.software.bits() as u64) << 55
            | vmsa64_lpa2_leaf_kind_bits(G::KIND, level)
    }

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa64Lpa2, G>,
        fields: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let address = encode_lpa2_address::<G>(table_pa);
        Ok(address | (fields.software.bits() as u64) << 55 | VMSA64_VALID | VMSA64_TABLE_OR_PAGE)
    }

    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr(unpack_lpa2_address::<G>(raw))
    }
}

pub fn vmsa64_lpa2_supports_leaf_level(granule: GranuleKind, level: Level) -> bool {
    matches!(
        (granule, level.as_i8()),
        (GranuleKind::Size4KiB, 0..=3) | (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 1..=3)
    )
}

const fn vmsa64_lpa2_address_field_mask(granule: GranuleKind) -> u128 {
    match granule {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => VMSA64_LPA2_DS_ADDR_FIELD_MASK,
        GranuleKind::Size64KiB => VMSA64_LPA_64K_ADDR_FIELD_MASK,
    }
}

fn encode_lpa2_address<G: TranslationGranule>(address: PhysAddr) -> u64 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => encode_lpa2_ds_address(address),
        GranuleKind::Size64KiB => encode_lpa_64k_address(address),
    }
}

fn unpack_lpa2_address<G: TranslationGranule>(raw: u64) -> u64 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => unpack_lpa2_ds_address(raw),
        GranuleKind::Size64KiB => unpack_lpa_64k_address(raw),
    }
}

fn encode_lpa2_ds_address(address: PhysAddr) -> u64 {
    (address.0 & 0x0003_FFFF_FFFF_F000) | (((address.0 >> 50) & 0x3) << 8)
}

fn unpack_lpa2_ds_address(raw: u64) -> u64 {
    (raw & 0x0003_FFFF_FFFF_F000) | (((raw >> 8) & 0x3) << 50)
}

fn encode_lpa_64k_address(address: PhysAddr) -> u64 {
    (address.0 & 0x0000_FFFF_FFFF_0000) | (((address.0 >> 48) & 0xf) << 12)
}

fn unpack_lpa_64k_address(raw: u64) -> u64 {
    (raw & 0x0000_FFFF_FFFF_0000) | (((raw >> 12) & 0xf) << 48)
}

fn decode_stage1_leaf_lower<G: TranslationGranule>(raw: u64) -> u64 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => {
            ((raw >> 2) & 0x3f) | (((raw >> 10) & 0x3) << 6)
        }
        GranuleKind::Size64KiB => (raw >> 2) & 0x3ff,
    }
}

fn encode_stage1_leaf_lower<G: TranslationGranule>(lower: u64) -> u64 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => {
            debug_assert!(lower & !0xff == 0);
            ((lower & 0x3f) << 2) | (((lower >> 6) & 0x3) << 10)
        }
        GranuleKind::Size64KiB => (lower & 0x3ff) << 2,
    }
}

fn decode_stage2_leaf_lower<G: TranslationGranule>(raw: u64) -> u64 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => {
            ((raw >> 2) & 0x3f) | (((raw >> 10) & 1) << 6)
        }
        GranuleKind::Size64KiB => (raw >> 2) & 0x1ff,
    }
}

fn encode_stage2_leaf_lower<G: TranslationGranule>(lower: u64) -> u64 {
    match G::KIND {
        GranuleKind::Size4KiB | GranuleKind::Size16KiB => {
            debug_assert!(lower & !0x7f == 0);
            ((lower & 0x3f) << 2) | (((lower >> 6) & 1) << 10)
        }
        GranuleKind::Size64KiB => (lower & 0x1ff) << 2,
    }
}

fn vmsa64_lpa2_kind(granule: GranuleKind, raw: u64, level: Level) -> DescriptorKind {
    match raw & 0b11 {
        0b00 => DescriptorKind::Invalid,
        0b01 if vmsa64_lpa2_supports_block_descriptor(granule, level) => DescriptorKind::Block,
        0b11 if level < Level::L3 => DescriptorKind::Table,
        0b11 if level == Level::L3 => DescriptorKind::Page,
        _ => DescriptorKind::Invalid,
    }
}

fn vmsa64_lpa2_leaf_kind_bits(granule: GranuleKind, level: Level) -> u64 {
    if level == Level::L3 {
        VMSA64_VALID | VMSA64_TABLE_OR_PAGE
    } else if vmsa64_lpa2_supports_block_descriptor(granule, level) {
        VMSA64_VALID
    } else {
        debug_assert!(false, "unsupported VMSAv8-64 LPA2 block level");
        0
    }
}

const fn vmsa64_lpa2_supports_block_descriptor(granule: GranuleKind, level: Level) -> bool {
    match (granule, level.as_i8()) {
        (GranuleKind::Size4KiB, 0..=2) => true,
        (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 1 | 2) => true,
        _ => false,
    }
}
