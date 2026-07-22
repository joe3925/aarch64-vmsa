use core::marker::PhantomData;

use crate::address::{GranuleKind, Level, PhysAddr, TranslationGranule};
use crate::attrs::{
    FourBit, LeafAp, RawShareability, RawVmsa64Stage1LeafAttrs, RawVmsa64Stage1TableAttrs,
    RawVmsa64Stage2LeafAttrs, RawVmsa64Stage2TableAttrs, Stage2Ap, Stage2ExecuteNever, ThreeBit,
};
use crate::descriptor::layout::vmsa64 as bits;
use crate::table::TableTransition;
use crate::translation::{Stage1, Stage2};

use super::vmsa64_family::{
    check_reserved, decode_stage1_table, decode_stage2_table, finish_stage1_leaf,
    finish_stage2_leaf, finish_table,
};
use super::{
    DescriptorError, DescriptorKind, DescriptorLayout, HasLayout, Vmsa64, insert_address,
    require_step_by_one_transition,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vmsa64Layout<S, G>(PhantomData<(S, G)>);

impl<G: TranslationGranule> HasLayout<Stage1, G> for Vmsa64 {
    type Layout = Vmsa64Layout<Stage1, G>;
}
impl<G: TranslationGranule> HasLayout<Stage2, G> for Vmsa64 {
    type Layout = Vmsa64Layout<Stage2, G>;
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa64, Stage1, G> for Vmsa64Layout<Stage1, G> {
    type LeafFields = RawVmsa64Stage1LeafAttrs;
    type TableFields = RawVmsa64Stage1TableAttrs;
    const ADDRESS_FIELD_MASK: u128 = bits::ADDRESS_FIELD_MASK;

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        kind(G::KIND, raw, level)
    }

    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let raw = raw as u128;
        RawVmsa64Stage1LeafAttrs {
            attr_index: ThreeBit::from_masked(bits::VMSA64_STAGE1_ATTR_INDEX::extract(raw)),
            ns: bits::VMSA64_STAGE1_NS::extract(raw) != 0,
            ap: LeafAp::from_masked(bits::VMSA64_STAGE1_AP::extract(raw)),
            shareability: RawShareability::from_masked(bits::VMSA64_SHAREABILITY::extract(raw)),
            access_flag: bits::VMSA64_ACCESS_FLAG::extract(raw) != 0,
            alias_bit: bits::VMSA64_STAGE1_ALIAS::extract(raw) != 0,
            dirty_bit_modifier: bits::VMSA64_DIRTY_BIT_MODIFIER::extract(raw) != 0,
            contiguous: bits::VMSA64_CONTIGUOUS::extract(raw) != 0,
            privileged_execute_never: bits::VMSA64_PXN::extract(raw) != 0,
            unprivileged_execute_never: bits::VMSA64_UXN::extract(raw) != 0,
            guarded: bits::VMSA64_GUARDED::extract(raw) != 0,
            software: FourBit::from_masked(bits::VMSA64_SOFTWARE::extract(raw)),
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
        raw = insert_address(raw, output_pa, Self::ADDRESS_FIELD_MASK);
        raw = bits::VMSA64_STAGE1_ATTR_INDEX::insert(raw, f.attr_index.bits().into());
        raw = bits::VMSA64_STAGE1_NS::insert(raw, f.ns.into());
        raw = bits::VMSA64_STAGE1_AP::insert(raw, f.ap.bits().into());
        raw = bits::VMSA64_SHAREABILITY::insert(raw, f.shareability.bits().into());
        raw = bits::VMSA64_ACCESS_FLAG::insert(raw, f.access_flag.into());
        raw = bits::VMSA64_STAGE1_ALIAS::insert(raw, f.alias_bit.into());
        raw = finish_stage1_leaf(raw, f, leaf_kind_bits(G::KIND, level));
        check_reserved(
            raw,
            bits::stage1_leaf::RES0_MASK,
            leaf_kind_bits(G::KIND, level).into(),
        )?;
        Ok(raw as u64)
    }

    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa64, G>,
        f: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let mut raw = 0;
        raw = insert_address(raw, table_pa, Self::ADDRESS_FIELD_MASK);
        raw = bits::VMSA64_PXN_TABLE::insert(raw, f.privileged_execute_never_limit.into());
        raw = bits::VMSA64_UXN_TABLE::insert(raw, f.unprivileged_execute_never_limit.into());
        raw = bits::VMSA64_AP_TABLE::insert(raw, f.ap_table.bits().into());
        raw = bits::VMSA64_NS_TABLE::insert(raw, f.ns_table.into());
        raw = finish_table(raw, f.software);
        check_reserved(
            raw,
            bits::stage1_table::RES0_MASK,
            bits::stage1_table::RES1_MASK,
        )?;
        Ok(raw as u64)
    }

    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr((raw as u128 & Self::ADDRESS_FIELD_MASK) as u64)
    }
}

impl<G: TranslationGranule> DescriptorLayout<Vmsa64, Stage2, G> for Vmsa64Layout<Stage2, G> {
    type LeafFields = RawVmsa64Stage2LeafAttrs;
    type TableFields = RawVmsa64Stage2TableAttrs;
    const ADDRESS_FIELD_MASK: u128 = bits::ADDRESS_FIELD_MASK;

    fn kind(raw: u64, level: Level) -> DescriptorKind {
        kind(G::KIND, raw, level)
    }
    fn decode_leaf_fields(raw: u64, _level: Level) -> Self::LeafFields {
        let raw = raw as u128;
        RawVmsa64Stage2LeafAttrs {
            mem_attr: FourBit::from_masked(bits::VMSA64_STAGE2_MEM_ATTR::extract(raw)),
            access: Stage2Ap::from_masked(bits::VMSA64_STAGE2_AP::extract(raw)),
            shareability: RawShareability::from_masked(bits::VMSA64_SHAREABILITY::extract(raw)),
            access_flag: bits::VMSA64_ACCESS_FLAG::extract(raw) != 0,
            dirty_bit_modifier: bits::VMSA64_DIRTY_BIT_MODIFIER::extract(raw) != 0,
            contiguous: bits::VMSA64_CONTIGUOUS::extract(raw) != 0,
            execute_never: Stage2ExecuteNever::from_masked(bits::VMSA64_STAGE2_XN::extract(raw)),
            software: FourBit::from_masked(bits::VMSA64_SOFTWARE::extract(raw)),
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
        raw = insert_address(raw, output_pa, Self::ADDRESS_FIELD_MASK);
        raw = bits::VMSA64_STAGE2_MEM_ATTR::insert(raw, f.mem_attr.bits().into());
        raw = bits::VMSA64_STAGE2_AP::insert(raw, f.access.bits().into());
        raw = bits::VMSA64_SHAREABILITY::insert(raw, f.shareability.bits().into());
        raw = bits::VMSA64_ACCESS_FLAG::insert(raw, f.access_flag.into());
        raw = finish_stage2_leaf(raw, f, leaf_kind_bits(G::KIND, level));
        check_reserved(
            raw,
            bits::stage2_leaf::RES0_MASK,
            leaf_kind_bits(G::KIND, level).into(),
        )?;
        Ok(raw as u64)
    }
    fn table_descriptor(
        table_pa: PhysAddr,
        transition: TableTransition<Vmsa64, G>,
        f: Self::TableFields,
    ) -> Result<u64, DescriptorError> {
        require_step_by_one_transition(transition)?;
        let mut raw = 0;
        raw = insert_address(raw, table_pa, Self::ADDRESS_FIELD_MASK);
        raw = finish_table(raw, f.software);
        check_reserved(
            raw,
            bits::stage2_table::RES0_MASK,
            bits::stage2_table::RES1_MASK,
        )?;
        Ok(raw as u64)
    }
    fn output_address(raw: u64, _level: Level) -> PhysAddr {
        PhysAddr((raw as u128 & Self::ADDRESS_FIELD_MASK) as u64)
    }
}

pub(super) fn supports_leaf_level(granule: GranuleKind, level: Level) -> bool {
    level == Level::L3 || supports_block(granule, level)
}

pub(super) fn kind(granule: GranuleKind, raw: u64, level: Level) -> DescriptorKind {
    match raw & 0b11 {
        0b00 => DescriptorKind::Invalid,
        0b01 if supports_block(granule, level) => DescriptorKind::Block,
        0b11 if level < Level::L3 => DescriptorKind::Table,
        0b11 if level == Level::L3 => DescriptorKind::Page,
        _ => DescriptorKind::Invalid,
    }
}

pub(super) fn leaf_kind_bits(granule: GranuleKind, level: Level) -> u64 {
    if level == Level::L3 {
        0b11
    } else if supports_block(granule, level) {
        0b01
    } else {
        0
    }
}

const fn supports_block(granule: GranuleKind, level: Level) -> bool {
    matches!(
        (granule, level.as_i8()),
        (GranuleKind::Size4KiB, 1 | 2) | (GranuleKind::Size16KiB | GranuleKind::Size64KiB, 2)
    )
}

fn require_leaf_level<G: TranslationGranule>(level: Level) -> Result<(), DescriptorError> {
    if supports_leaf_level(G::KIND, level) {
        Ok(())
    } else {
        Err(DescriptorError::InvalidLeafLevel { level })
    }
}
