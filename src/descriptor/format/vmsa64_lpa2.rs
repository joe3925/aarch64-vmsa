use core::marker::PhantomData;

use crate::address::{GranuleKind, Level, PhysAddr, TranslationGranule};
use crate::attrs::{
    FourBit, RawShareability, RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs,
    RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs,
};
use crate::config::format::Vmsa64Lpa2;
use crate::descriptor::layout::{vmsa64 as b, vmsa64_lpa2 as lpa2};
use crate::table::{TableAddr, TableTransition};
use crate::translation::{Stage1, Stage2};

use super::vmsa64_family::{
    check_reserved, decode_stage1_table, decode_stage2_table, extract_permission_fields,
    finish_stage1_leaf, finish_stage2_leaf, finish_table,
};
use super::{
    DescriptorError, DescriptorKind, DescriptorLayout, HasLayout, require_step_by_one_transition,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Lpa2Layout<S, G>(PhantomData<(S, G)>);

impl<S, G> super::private::LayoutSealed for Vmsa64Lpa2Layout<S, G> {}

impl<G: TranslationGranule> HasLayout<Stage1, G> for Vmsa64Lpa2 {
    type Layout = Vmsa64Lpa2Layout<Stage1, G>;
}
impl<G: TranslationGranule> HasLayout<Stage2, G> for Vmsa64Lpa2 {
    type Layout = Vmsa64Lpa2Layout<Stage2, G>;
}

impl<G: TranslationGranule> DescriptorLayout<Stage1, G> for Vmsa64Lpa2Layout<Stage1, G> {
    type Format = Vmsa64Lpa2;
    type LeafFields = RawVmsa64Stage1LeafAttrs;
    type TableFields = RawVmsa64Stage1TableAttrs;
    const ADDRESS_FIELD_MASK: u128 = address_field_mask(G::KIND);

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        kind(G::KIND, raw, level)
    }
    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let raw128 = raw as u128;
        let ds = uses_ds(G::KIND);
        RawVmsa64Stage1LeafAttrs {
            attr_index: FourBit::from_masked(
                b::VMSA64_STAGE1_ATTR_INDEX.extract(raw128)
                    | b::VMSA64_STAGE1_ATTR_INDEX_HIGH.extract(raw128) << 3,
            ),
            ns: b::VMSA64_STAGE1_NS.extract(raw128) != 0,
            permissions: extract_permission_fields(raw128),
            shareability: if ds {
                RawShareability::from_masked(0)
            } else {
                RawShareability::from_masked(b::VMSA64_SHAREABILITY.extract(raw128))
            },
            access_flag: if ds {
                lpa2::LPA2_DS_ACCESS_FLAG.extract(raw128) != 0
            } else {
                b::VMSA64_ACCESS_FLAG.extract(raw128) != 0
            },
            alias_bit: if ds {
                lpa2::LPA2_DS_STAGE1_ALIAS.extract(raw128) != 0
            } else {
                b::VMSA64_STAGE1_ALIAS.extract(raw128) != 0
            },
            contiguous: b::VMSA64_CONTIGUOUS.extract(raw128) != 0,
            guarded: b::VMSA64_GUARDED.extract(raw128) != 0,
            software: FourBit::from_masked(b::VMSA64_SOFTWARE.extract(raw128)),
        }
    }
    fn decode_table_fields(raw: u64, _level: Level) -> Self::TableFields {
        decode_stage1_table(raw)
    }
    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        f: Self::LeafFields,
    ) -> Result<u64, DescriptorError> {
        require_leaf_level::<G>(level)?;
        let mut raw = 0;
        raw |= encode_address::<G>(output_pa.0) as u128;
        raw = b::VMSA64_STAGE1_ATTR_INDEX.insert(raw, f.attr_index.bits().into());
        raw = b::VMSA64_STAGE1_ATTR_INDEX_HIGH.insert(raw, ((f.attr_index.bits() >> 3) & 1).into());
        raw = b::VMSA64_STAGE1_NS.insert(raw, f.ns.into());
        if uses_ds(G::KIND) {
            raw = lpa2::LPA2_DS_ACCESS_FLAG.insert(raw, f.access_flag.into());
            raw = lpa2::LPA2_DS_STAGE1_ALIAS.insert(raw, f.alias_bit.into());
        } else {
            raw = b::VMSA64_SHAREABILITY.insert(raw, f.shareability.bits().into());
            raw = b::VMSA64_ACCESS_FLAG.insert(raw, f.access_flag.into());
            raw = b::VMSA64_STAGE1_ALIAS.insert(raw, f.alias_bit.into());
        }
        raw = finish_stage1_leaf(raw, f, leaf_kind_bits(G::KIND, level));
        check_reserved(
            raw,
            stage1_leaf_res0(G::KIND),
            leaf_kind_bits(G::KIND, level).into(),
        )?;
        Ok(raw as u64)
    }
    fn table_descriptor(
        table_addr: TableAddr<G>,
        transition: TableTransition<Vmsa64Lpa2, G>,
        f: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let mut raw = 0;
        raw |= encode_address::<G>(table_addr.raw()) as u128;
        raw = b::VMSA64_PXN_TABLE.insert(raw, f.privileged_execute_never_limit.into());
        raw = b::VMSA64_UXN_TABLE.insert(raw, f.unprivileged_execute_never_limit.into());
        raw = b::VMSA64_AP_TABLE.insert(raw, f.ap_table.bits().into());
        raw = b::VMSA64_NS_TABLE.insert(raw, f.ns_table.into());
        raw = b::VMSA64_ACCESS_FLAG.insert(raw, f.access_flag.into());
        raw = finish_table(raw, f.software);
        check_reserved(raw, table_res0(G::KIND, true), b::stage1_table::RES1_MASK)?;
        Ok(raw as u64)
    }
    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr(decode_address::<G>(raw))
    }
}

impl<G: TranslationGranule> DescriptorLayout<Stage2, G> for Vmsa64Lpa2Layout<Stage2, G> {
    type Format = Vmsa64Lpa2;
    type LeafFields = RawVmsa64Stage2LeafAttrs;
    type TableFields = RawVmsa64Stage2TableAttrs;
    const ADDRESS_FIELD_MASK: u128 = address_field_mask(G::KIND);

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        kind(G::KIND, raw, level)
    }
    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let raw128 = raw as u128;
        RawVmsa64Stage2LeafAttrs {
            mem_attr: FourBit::from_masked(b::VMSA64_STAGE2_MEM_ATTR.extract(raw128)),
            permissions: extract_permission_fields(raw128),
            shareability: if uses_ds(G::KIND) {
                RawShareability::from_masked(0)
            } else {
                RawShareability::from_masked(b::VMSA64_SHAREABILITY.extract(raw128))
            },
            access_flag: if uses_ds(G::KIND) {
                lpa2::LPA2_DS_ACCESS_FLAG.extract(raw128) != 0
            } else {
                b::VMSA64_ACCESS_FLAG.extract(raw128) != 0
            },
            contiguous: b::VMSA64_CONTIGUOUS.extract(raw128) != 0,
            software: FourBit::from_masked(b::VMSA64_SOFTWARE.extract(raw128)),
        }
    }
    fn decode_table_fields(raw: u64, _level: Level) -> Self::TableFields {
        decode_stage2_table(raw)
    }
    fn leaf_descriptor(
        output_pa: PhysAddr,
        level: Level,
        f: Self::LeafFields,
    ) -> Result<u64, DescriptorError> {
        require_leaf_level::<G>(level)?;
        let mut raw = 0;
        raw |= encode_address::<G>(output_pa.0) as u128;
        raw = b::VMSA64_STAGE2_MEM_ATTR.insert(raw, f.mem_attr.bits().into());
        if uses_ds(G::KIND) {
            raw = lpa2::LPA2_DS_ACCESS_FLAG.insert(raw, f.access_flag.into());
        } else {
            raw = b::VMSA64_SHAREABILITY.insert(raw, f.shareability.bits().into());
            raw = b::VMSA64_ACCESS_FLAG.insert(raw, f.access_flag.into());
        }
        raw = finish_stage2_leaf(raw, f, leaf_kind_bits(G::KIND, level));
        check_reserved(
            raw,
            stage2_leaf_res0(G::KIND),
            leaf_kind_bits(G::KIND, level).into(),
        )?;
        Ok(raw as u64)
    }
    fn table_descriptor(
        table_addr: TableAddr<G>,
        transition: TableTransition<Vmsa64Lpa2, G>,
        f: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let mut raw = 0;
        raw |= encode_address::<G>(table_addr.raw()) as u128;
        raw = b::VMSA64_ACCESS_FLAG.insert(raw, f.access_flag.into());
        raw = finish_table(raw, f.software);
        check_reserved(raw, table_res0(G::KIND, false), b::stage2_table::RES1_MASK)?;
        Ok(raw as u64)
    }
    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr(decode_address::<G>(raw))
    }
}

pub(super) fn supports_leaf_level(granule: GranuleKind, level: Level) -> bool {
    matches!(
        (granule, level.as_i8()),
        (GranuleKind::Size4KiB, 0..=3) | (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 1..=3)
    )
}

fn require_leaf_level<G: TranslationGranule>(level: Level) -> Result<(), DescriptorError> {
    if supports_leaf_level(G::KIND, level) {
        Ok(())
    } else {
        Err(DescriptorError::InvalidLeafLevel { level })
    }
}

const fn uses_ds(granule: GranuleKind) -> bool {
    matches!(granule, GranuleKind::Size4KiB | GranuleKind::Size16KiB)
}

const fn address_field_mask(granule: GranuleKind) -> u128 {
    if uses_ds(granule) {
        lpa2::DS_ADDRESS_FIELD_MASK
    } else {
        lpa2::ADDRESS_64K_FIELD_MASK
    }
}

fn encode_address<G: TranslationGranule>(address: u64) -> u64 {
    if uses_ds(G::KIND) {
        (address & 0x0003_ffff_ffff_f000) | (((address >> 50) & 0x3) << 8)
    } else {
        (address & 0x0000_ffff_ffff_0000) | (((address >> 48) & 0xf) << 12)
    }
}

fn decode_address<G: TranslationGranule>(raw: u64) -> u64 {
    if uses_ds(G::KIND) {
        (raw & 0x0003_ffff_ffff_f000) | (((raw >> 8) & 0x3) << 50)
    } else {
        (raw & 0x0000_ffff_ffff_0000) | (((raw >> 12) & 0xf) << 48)
    }
}

fn kind(granule: GranuleKind, raw: u64, level: Level) -> DescriptorKind {
    match raw & 0b11 {
        0b00 => DescriptorKind::Invalid,
        0b01 if supports_block(granule, level) => DescriptorKind::Block,
        0b11 if level < Level::L3 => DescriptorKind::Table,
        0b11 if level == Level::L3 => DescriptorKind::Page,
        _ => DescriptorKind::Invalid,
    }
}

fn leaf_kind_bits(granule: GranuleKind, level: Level) -> u64 {
    if level == Level::L3 {
        0b11
    } else if supports_block(granule, level) {
        0b01
    } else {
        0
    }
}

const fn stage1_leaf_res0(granule: GranuleKind) -> u128 {
    if uses_ds(granule) {
        lpa2::ds_stage1_leaf::RES0_MASK
    } else {
        lpa2::granule64k_stage1_leaf::RES0_MASK
    }
}
const fn stage2_leaf_res0(granule: GranuleKind) -> u128 {
    if uses_ds(granule) {
        lpa2::ds_stage2_leaf::RES0_MASK
    } else {
        lpa2::granule64k_stage2_leaf::RES0_MASK
    }
}
const fn table_res0(granule: GranuleKind, stage1: bool) -> u128 {
    match (uses_ds(granule), stage1) {
        (true, true) => lpa2::ds_stage1_table::RES0_MASK,
        (true, false) => lpa2::ds_stage2_table::RES0_MASK,
        (false, true) => lpa2::granule64k_stage1_table::RES0_MASK,
        (false, false) => lpa2::granule64k_stage2_table::RES0_MASK,
    }
}

const fn supports_block(granule: GranuleKind, level: Level) -> bool {
    matches!(
        (granule, level.as_i8()),
        (GranuleKind::Size4KiB, 0..=2) | (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 1 | 2)
    )
}
